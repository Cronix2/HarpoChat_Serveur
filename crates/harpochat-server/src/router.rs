// SPDX-License-Identifier: Apache-2.0
//! Sphinx router (spec §6–7): peel one layer, enforce replay protection,
//! apply the sender-chosen delay, deliver locally or to a phone inbox.
//!
//! Packets for another node go to its peer link (`Peers`) after the
//! sender-chosen delay. Packets are never processed in arrival order without their delay
//! (spec §6.2: no FIFO).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harpochat_core::descriptor::node_address;
use harpochat_core::envelope;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::sphinx::{self, Processed, LOCAL_DELIVERY};
use tokio::sync::mpsc;

use crate::cover::LoopTracker;
use crate::node::SphinxKeys;
use crate::peers::Peers;
use crate::service::MailboxService;
use crate::store::ReplayFilter;

/// Replay tags remembered per Sphinx key and generation (two generations).
const REPLAY_PER_GENERATION: usize = 1_000_000;
/// False-positive rate of the replay filter (a legitimate packet dropped).
const REPLAY_FALSE_POSITIVE: f64 = 1e-6;

/// Clock returning unix seconds (injectable for tests).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// System clock.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Phone inboxes connected to this gateway: inbox token → link sender.
#[derive(Default)]
pub struct Inboxes {
    map: Mutex<HashMap<[u8; 32], mpsc::Sender<LinkFrame>>>,
}

impl Inboxes {
    /// Register (or replace) a token.
    pub fn register(&self, token: [u8; 32], tx: mpsc::Sender<LinkFrame>) {
        self.map.lock().expect("inboxes").insert(token, tx);
    }

    /// Remove a token.
    pub fn unregister(&self, token: &[u8; 32]) {
        self.map.lock().expect("inboxes").remove(token);
    }

    /// Hand a frame to the phone; `false` if it is gone or its queue is full.
    pub fn deliver(&self, token: &[u8; 32], frame: LinkFrame) -> bool {
        let tx = self.map.lock().expect("inboxes").get(token).cloned();
        match tx {
            Some(tx) => tx.try_send(frame).is_ok(),
            None => false,
        }
    }

    /// Connected inboxes.
    pub fn len(&self) -> usize {
        self.map.lock().expect("inboxes").len()
    }

    /// No inbox connected.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Aggregated, anonymous counters (spec §10).
#[derive(Default, Debug)]
pub struct Counters {
    /// Sphinx packets received.
    pub packets_in: AtomicU64,
    /// Packets dropped (invalid, replayed, unroutable).
    pub packets_dropped: AtomicU64,
    /// Frames handed to phones.
    pub delivered: AtomicU64,
    /// Link frames received (all links, padding included).
    pub frames_in: AtomicU64,
    /// Padding frames sent to phones.
    pub padding_sent: AtomicU64,
    /// Loops emitted by this node.
    pub loops_sent: AtomicU64,
    /// Our loops that came back.
    pub loops_returned: AtomicU64,
    /// Our loops that did not come back in time.
    pub loops_lost: AtomicU64,
    /// Drops emitted by this node.
    pub drops_sent: AtomicU64,
    /// Subscription pushes (PUSH or NOTIFY) sent.
    pub pushes: AtomicU64,
    /// Connections closed at once because a cap was reached.
    pub links_refused: AtomicU64,
}

/// The routing core of a node.
pub struct Router {
    sphinx: Arc<SphinxKeys>,
    own_addr: [u8; 32],
    /// One replay filter per live Sphinx key epoch: tags die with their key.
    replay: Mutex<HashMap<u32, ReplayFilter>>,
    service: Mutex<MailboxService>,
    peers: Arc<Peers>,
    /// Connected phones.
    pub inboxes: Arc<Inboxes>,
    /// Counters.
    pub counters: Counters,
    /// This node's loops in flight and neighbour loss scores.
    pub loops: Mutex<LoopTracker>,
    clock: Clock,
}

impl Router {
    /// New router for a node.
    pub fn new(
        id_pub: &[u8; 32],
        sphinx: Arc<SphinxKeys>,
        service: MailboxService,
        peers: Arc<Peers>,
        clock: Clock,
    ) -> Self {
        Self {
            sphinx,
            own_addr: node_address(id_pub),
            replay: Mutex::new(HashMap::new()),
            service: Mutex::new(service),
            peers,
            inboxes: Arc::new(Inboxes::default()),
            counters: Counters::default(),
            loops: Mutex::new(LoopTracker::new(std::time::Instant::now())),
            clock,
        }
    }

    /// Current time.
    pub fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Run `f` on the mailbox service (sweeper).
    pub fn with_service<R>(&self, f: impl FnOnce(&mut MailboxService) -> R) -> R {
        f(&mut self.service.lock().expect("service"))
    }

    fn drop_packet(&self) {
        self.counters
            .packets_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Rotate the Sphinx key if a new period started (spec §13); replay
    /// filters of keys no longer accepted are freed.
    pub fn rotate_keys(&self, now: u64) -> bool {
        if !self.sphinx.rotate_if_due(now) {
            return false;
        }
        let live: Vec<u32> = self.sphinx.secrets().iter().map(|(_, e)| *e).collect();
        self.replay
            .lock()
            .expect("replay")
            .retain(|e, _| live.contains(e));
        true
    }

    /// Process one incoming Sphinx packet. Must run inside a tokio runtime.
    pub fn submit(self: &Arc<Self>, packet: Vec<u8>) {
        self.counters.packets_in.fetch_add(1, Ordering::Relaxed);
        let now = self.now();
        let found = self
            .sphinx
            .secrets()
            .into_iter()
            .find_map(|(secret, epoch)| sphinx::process(&packet, &secret).ok().map(|r| (epoch, r)));
        let Some((epoch, (tag, out))) = found else {
            return self.drop_packet();
        };
        let fresh = self
            .replay
            .lock()
            .expect("replay")
            .entry(epoch)
            .or_insert_with(|| ReplayFilter::new(REPLAY_PER_GENERATION, REPLAY_FALSE_POSITIVE))
            .insert_new(&tag);
        if !fresh {
            return self.drop_packet();
        }
        match out {
            Processed::Forward {
                next_hop,
                delay_ms,
                packet,
            } => {
                if next_hop != self.own_addr && !self.peers.is_peer_addr(&next_hop) {
                    return self.drop_packet();
                }
                let me = self.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    me.forward(next_hop, packet);
                });
            }
            Processed::Final {
                destination,
                surb_id,
                payload,
            } => {
                if destination == LOCAL_DELIVERY {
                    self.deliver_local(&payload, now);
                } else if self.loops.lock().expect("loops").complete(&destination) {
                    self.counters.loops_returned.fetch_add(1, Ordering::Relaxed);
                } else {
                    let mut body = surb_id.to_vec();
                    body.extend_from_slice(&payload);
                    let frame = LinkFrame {
                        kind: FrameKind::Deliver,
                        body,
                    };
                    if self.inboxes.deliver(&destination, frame) {
                        self.counters.delivered.fetch_add(1, Ordering::Relaxed);
                    } else {
                        self.drop_packet();
                    }
                }
            }
        }
    }

    /// Send a packet to the node at Sphinx address `addr` (ourselves
    /// included); dropped and counted if no link leads there.
    pub fn forward(self: &Arc<Self>, addr: [u8; 32], packet: Vec<u8>) {
        if addr == self.own_addr {
            self.submit(packet);
        } else if !self.peers.send(&addr, packet) {
            self.drop_packet();
        }
    }

    fn deliver_local(self: &Arc<Self>, payload: &[u8], now: u64) {
        let Ok(plain) = sphinx::open_forward_payload(payload) else {
            return self.drop_packet();
        };
        let Ok(msg) = envelope::decode(&plain) else {
            return self.drop_packet();
        };
        let replies = self.service.lock().expect("service").handle(msg, now);
        for r in replies {
            if r.push {
                self.counters.pushes.fetch_add(1, Ordering::Relaxed);
            }
            match sphinx::use_surb(&r.surb, &r.message, SizeClass::Small) {
                Ok((packet, first)) => self.forward(first, packet),
                Err(_) => self.drop_packet(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;
    use harpochat_core::envelope::Message;
    use harpochat_core::keys::SigningKey;
    use harpochat_core::mailbox::{epoch_of, sign_put, sign_read, MailboxKeys, ReadOp};
    use harpochat_core::sphinx::{build_forward, create_surb, recover_reply, Hop, SurbRecovery};

    const NOW: u64 = 1_800_000_000;

    struct Fixture {
        router: Arc<Router>,
        hop: Hop,
    }

    fn fixture() -> Fixture {
        let id = SigningKey::generate();
        let keys = Arc::new(SphinxKeys::new(NOW));
        let hop = Hop {
            id_pub: id.public(),
            sphinx_pub: keys.current_public().0,
        };
        let router = Arc::new(Router::new(
            &id.public(),
            keys,
            MailboxService::new(&Limits::default()),
            Arc::new(Peers::none()),
            Arc::new(|| NOW),
        ));
        Fixture { router, hop }
    }

    fn drop_packet_to(hop: Hop) -> Vec<u8> {
        build_forward(
            &envelope::encode(&Message::Drop),
            &[hop],
            LOCAL_DELIVERY,
            &[0],
            SizeClass::Small,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn replay_after_rotation_refused() {
        let f = fixture();
        let dropped = || f.router.counters.packets_dropped.load(Ordering::Relaxed);
        let pkt = drop_packet_to(f.hop);
        f.router.submit(pkt.clone());
        assert_eq!(dropped(), 0);
        // New week: the old key is still accepted, its replay tags remembered.
        let week = crate::node::SPHINX_KEY_PERIOD_SECS;
        assert!(f.router.rotate_keys(NOW + week));
        f.router.submit(pkt);
        assert_eq!(dropped(), 1, "replay across a rotation");
        f.router.submit(drop_packet_to(f.hop));
        assert_eq!(dropped(), 1, "packet built for last week's key accepted");
        // Two weeks: the old key is erased, its packets undecryptable.
        assert!(f.router.rotate_keys(NOW + 2 * week));
        f.router.submit(drop_packet_to(f.hop));
        assert_eq!(dropped(), 2);
        // The erased key's replay filter is freed with it.
        assert!(f.router.replay.lock().unwrap().is_empty());
    }

    fn keys() -> MailboxKeys {
        MailboxKeys::derive(&[0x11; 32], epoch_of(NOW))
    }

    fn put_packet(f: &Fixture, k: &MailboxKeys, blob: &[u8]) -> Vec<u8> {
        let msg = envelope::encode(&Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(k, blob, harpochat_core::keys::random_bytes()),
            blob: blob.to_vec(),
        });
        build_forward(&msg, &[f.hop], LOCAL_DELIVERY, &[0], SizeClass::Small, None).unwrap()
    }

    fn fetch_packet(f: &Fixture, k: &MailboxKeys, inbox: [u8; 32]) -> (Vec<u8>, SurbRecovery) {
        let (surb, rec) = create_surb(&[f.hop], inbox, [7; 16], &[0]).unwrap();
        let unsigned = Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, ReadOp::Fetch, b"", NOW, [0; 16]),
            max: 10,
            surbs: vec![surb.clone()],
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        let msg = envelope::encode(&Message::Fetch {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(k, op, &bound, NOW, harpochat_core::keys::random_bytes()),
            max: 10,
            surbs: vec![surb],
        });
        let p =
            build_forward(&msg, &[f.hop], LOCAL_DELIVERY, &[0], SizeClass::Small, None).unwrap();
        (p, rec)
    }

    #[tokio::test]
    async fn single_hop_put_and_fetch_via_surb() {
        let f = fixture();
        let k = keys();
        let (tx, mut rx) = mpsc::channel(8);
        f.router.inboxes.register([0xAA; 32], tx);
        f.router.submit(put_packet(&f, &k, b"secret blob"));
        let (fetch, rec) = fetch_packet(&f, &k, [0xAA; 32]);
        f.router.submit(fetch);
        let frame = rx.recv().await.unwrap();
        assert_eq!(frame.kind, FrameKind::Deliver);
        assert_eq!(&frame.body[..16], &[7; 16]);
        let plain = recover_reply(&rec, &frame.body[16..]).unwrap();
        let Message::FetchResponse { blobs, more } = envelope::decode(&plain).unwrap() else {
            panic!("expected FetchResponse")
        };
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].blob, b"secret blob");
        assert!(!more);
    }

    #[tokio::test]
    async fn replayed_packet_dropped() {
        let f = fixture();
        let p = put_packet(&f, &keys(), b"x");
        f.router.submit(p.clone());
        f.router.submit(p);
        assert_eq!(f.router.counters.packets_dropped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn garbage_packet_dropped() {
        let f = fixture();
        f.router
            .submit(vec![0; sphinx::packet_len(SizeClass::Small)]);
        f.router.submit(vec![1, 2, 3]);
        assert_eq!(f.router.counters.packets_dropped.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn deliver_to_gone_inbox_is_dropped() {
        let f = fixture();
        let k = keys();
        let (tx, rx) = mpsc::channel(8);
        f.router.inboxes.register([0xAA; 32], tx);
        drop(rx); // phone disconnected
        f.router.submit(put_packet(&f, &k, b"x"));
        let (fetch, _) = fetch_packet(&f, &k, [0xAA; 32]);
        f.router.submit(fetch);
        assert_eq!(f.router.counters.delivered.load(Ordering::Relaxed), 0);
        assert!(f.router.counters.packets_dropped.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test(start_paused = true)]
    async fn delay_is_applied() {
        let f = fixture();
        let (tx, mut rx) = mpsc::channel(8);
        f.router.inboxes.register([0xBB; 32], tx);
        // Two layers through this node: 200 ms delay, then deliver to inbox.
        let p = build_forward(
            b"hi",
            &[f.hop, f.hop],
            [0xBB; 32],
            &[200, 0],
            SizeClass::Small,
            None,
        )
        .unwrap();
        f.router.submit(p);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(rx.try_recv().is_err(), "delivered before its delay");
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert!(rx.try_recv().is_ok(), "not delivered after its delay");
    }

    #[tokio::test]
    async fn own_loop_is_recognised_not_delivered() {
        let f = fixture();
        let token = [0x42; 32];
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        assert!(f
            .router
            .loops
            .lock()
            .unwrap()
            .start(token, vec![], deadline));
        let pkt = build_forward(
            &envelope::encode(&Message::Loop),
            &[f.hop],
            token,
            &[0],
            SizeClass::Small,
            None,
        )
        .unwrap();
        f.router.submit(pkt);
        assert_eq!(f.router.counters.loops_returned.load(Ordering::Relaxed), 1);
        assert_eq!(f.router.loops.lock().unwrap().in_flight(), 0);
        // An unknown token is a phone inbox; none is connected: dropped.
        let stray = build_forward(
            &envelope::encode(&Message::Loop),
            &[f.hop],
            [0x43; 32],
            &[0],
            SizeClass::Small,
            None,
        )
        .unwrap();
        f.router.submit(stray);
        assert_eq!(f.router.counters.loops_returned.load(Ordering::Relaxed), 1);
        assert_eq!(f.router.counters.packets_dropped.load(Ordering::Relaxed), 1);
    }
}
