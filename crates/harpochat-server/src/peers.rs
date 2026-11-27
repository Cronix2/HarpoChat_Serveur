// SPDX-License-Identifier: Apache-2.0
//! Node-to-node links (spec §5): one outbound, authenticated link per peer.
//!
//! Each node dials every peer with its own identity and requires the peer to
//! prove the expected identity (Noise `NodeAuth`). Outbound links carry our
//! Sphinx packets to the peer; packets the peer sends us arrive on the peer's
//! own outbound link (an inbound link here). Sending never blocks: a full
//! queue or a down peer drops the packet and counts it.
//!
//! Outbound links are shaped (`cover::Shaper`): frames leave at the instants
//! of a Poisson process of rate `[cover] node_link_rate`, padding filling the
//! slots that carry no packet (spec §5).
//!
//! Peers are the configured `[[peers]]` and `[[roots]]`, plus every node the
//! membership view verifies (gossip). Each outbound link pulls the peer's
//! directory every `GOSSIP_EVERY` and hands it to the gossip channel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use harpochat_core::descriptor::node_address;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use tokio::sync::mpsc;

use crate::cover::{os_uniform, Rate, Shaper};
use crate::keystore::NodeKeys;
use crate::membership::GOSSIP_EVERY;
use crate::net;

/// Packets queued per peer before dropping.
pub const PEER_QUEUE: usize = 1024;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Backlog drained at once on an overloaded node link.
const PEER_BURST: usize = 256;
/// Most peers a node links to (full mesh up to this size).
pub const MAX_PEERS: usize = 64;

struct Peer {
    id: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
    up: Arc<AtomicBool>,
}

/// The peer table of a node.
pub struct Peers {
    keys: Option<NodeKeys>,
    inbound: mpsc::Sender<Vec<u8>>,
    gossip: mpsc::Sender<Vec<u8>>,
    link_rate: f64,
    by_addr: RwLock<HashMap<[u8; 32], Peer>>,
}

impl Peers {
    /// Empty table. Packets peers send back on our outbound links go to
    /// `inbound`, their directories to `gossip`; links are shaped at
    /// `link_rate` frames per second (0 = unshaped).
    pub fn new(
        keys: &NodeKeys,
        inbound: mpsc::Sender<Vec<u8>>,
        gossip: mpsc::Sender<Vec<u8>>,
        link_rate: f64,
    ) -> Self {
        Self {
            keys: Some(keys.clone()),
            inbound,
            gossip,
            link_rate,
            by_addr: RwLock::new(HashMap::new()),
        }
    }

    /// No peers, and none can be added (single-node checks).
    pub fn none() -> Self {
        let (inbound, _) = mpsc::channel(1);
        let (gossip, _) = mpsc::channel(1);
        Self {
            keys: None,
            inbound,
            gossip,
            link_rate: 0.0,
            by_addr: RwLock::new(HashMap::new()),
        }
    }

    /// Start linking to `id` at `host:port`. `false` if it is this node,
    /// already a peer, or the table is full. Needs a tokio runtime.
    pub fn add(&self, id: [u8; 32], endpoint: String) -> bool {
        let Some(keys) = &self.keys else { return false };
        if id == keys.identity.public() {
            return false;
        }
        let addr = node_address(&id);
        let mut map = self.by_addr.write().expect("peers");
        if map.contains_key(&addr) || map.len() >= MAX_PEERS {
            return false;
        }
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        let up = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(dialler(
            keys.clone(),
            id,
            endpoint,
            rx,
            Outputs {
                inbound: self.inbound.clone(),
                gossip: self.gossip.clone(),
            },
            Arc::new(Rate::new(self.link_rate)),
            up.clone(),
        ));
        map.insert(addr, Peer { id, tx, task, up });
        true
    }

    /// Stop linking to `id` (revoked or expired node).
    pub fn remove(&self, id: &[u8; 32]) {
        if let Some(p) = self
            .by_addr
            .write()
            .expect("peers")
            .remove(&node_address(id))
        {
            p.task.abort();
        }
    }

    /// Stop every dialler and its link (node shutdown).
    pub fn shutdown(&self) {
        for (_, p) in self.by_addr.write().expect("peers").drain() {
            p.task.abort();
        }
    }

    /// Current peer identities.
    pub fn ids(&self) -> Vec<[u8; 32]> {
        self.by_addr
            .read()
            .expect("peers")
            .values()
            .map(|p| p.id)
            .collect()
    }

    /// Peers whose outbound link is established right now.
    pub fn connected(&self) -> usize {
        self.by_addr
            .read()
            .expect("peers")
            .values()
            .filter(|p| p.up.load(Ordering::Relaxed))
            .count()
    }

    /// Whether `id` is a peer.
    pub fn is_peer(&self, id: &[u8; 32]) -> bool {
        self.is_peer_addr(&node_address(id))
    }

    /// Whether a Sphinx address belongs to a peer.
    pub fn is_peer_addr(&self, node_addr: &[u8; 32]) -> bool {
        self.by_addr.read().expect("peers").contains_key(node_addr)
    }

    /// Queue a packet for the peer at Sphinx address `node_addr`.
    /// `false` if no such peer or its queue is full.
    pub fn send(&self, node_addr: &[u8; 32], packet: Vec<u8>) -> bool {
        match self.by_addr.read().expect("peers").get(node_addr) {
            Some(p) => p.tx.try_send(packet).is_ok(),
            None => false,
        }
    }
}

impl Drop for Peers {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Where a dialler hands what its peer sends back.
#[derive(Clone)]
struct Outputs {
    inbound: mpsc::Sender<Vec<u8>>,
    gossip: mpsc::Sender<Vec<u8>>,
}

fn directory_req() -> LinkFrame {
    LinkFrame {
        kind: FrameKind::DirectoryReq,
        body: Vec::new(),
    }
}

async fn dialler(
    keys: NodeKeys,
    id: [u8; 32],
    endpoint: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
    out: Outputs,
    rate: Arc<Rate>,
    up: Arc<AtomicBool>,
) {
    let mut backoff = BACKOFF_MIN;
    let mut shaper = Shaper::new(rate, PEER_BURST, os_uniform);
    loop {
        let addr = match tokio::net::lookup_host(endpoint.as_str())
            .await
            .ok()
            .and_then(|mut a| a.next())
        {
            Some(a) => a,
            None => {
                if wait_or_closed(&mut rx, &mut backoff).await {
                    return;
                }
                continue;
            }
        };
        let Ok((mut reader, mut writer, _)) =
            net::connect_named(addr, &endpoint, &keys.noise, Some(&keys.identity), Some(id)).await
        else {
            if wait_or_closed(&mut rx, &mut backoff).await {
                return;
            }
            continue;
        };
        backoff = BACKOFF_MIN;
        up.store(true, Ordering::Relaxed);
        // Aborted when this iteration ends (link lost or dialler aborted).
        let mut read_task = AbortOnDrop({
            let Outputs { inbound, gossip } = out.clone();
            tokio::spawn(async move {
                while let Ok((_, frame)) = reader.recv().await {
                    match frame.kind {
                        FrameKind::Sphinx => {
                            let _ = inbound.try_send(frame.body);
                        }
                        FrameKind::Directory => {
                            let _ = gossip.try_send(frame.body);
                        }
                        _ => {}
                    }
                }
            })
        });
        // Gossip: pull the peer's directory now, then periodically.
        let mut pull = tokio::time::interval(GOSSIP_EVERY);
        // Pump our packets (or padding) to the peer until the link breaks.
        loop {
            tokio::select! {
                batch = shaper.next(&mut rx) => {
                    let Some(batch) = batch else { return };
                    if !send_batch(&mut writer, batch).await {
                        break;
                    }
                }
                _ = pull.tick() => {
                    if writer.send(&directory_req(), SizeClass::Small).await.is_err() {
                        break;
                    }
                }
                _ = &mut read_task.0 => break,
            }
        }
        up.store(false, Ordering::Relaxed);
    }
}

/// Send one slot's frames; `false` if the link broke.
async fn send_batch(writer: &mut net::LinkWriter, batch: Vec<Option<Vec<u8>>>) -> bool {
    for item in batch {
        let frame = LinkFrame {
            kind: if item.is_some() {
                FrameKind::Sphinx
            } else {
                FrameKind::Padding
            },
            body: item.unwrap_or_default(),
        };
        let class = if frame.body.len() <= SizeClass::Small.max_body_len() {
            SizeClass::Small
        } else {
            SizeClass::Large
        };
        if writer.send(&frame, class).await.is_err() {
            return false;
        }
    }
    true
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sleep for the back-off (doubling it); `true` if the queue was closed.
async fn wait_or_closed(rx: &mut mpsc::Receiver<Vec<u8>>, backoff: &mut Duration) -> bool {
    tokio::time::sleep(*backoff).await;
    *backoff = (*backoff * 2).min(BACKOFF_MAX);
    // Drop stale packets queued while the peer was down.
    while let Ok(_stale) = rx.try_recv() {}
    rx.is_closed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(keys: &NodeKeys) -> Peers {
        let (tx, _rx) = mpsc::channel(8);
        let (g, _grx) = mpsc::channel(8);
        Peers::new(keys, tx, g, 0.0)
    }

    #[tokio::test]
    async fn peers_add_remove() {
        let keys = NodeKeys::generate();
        let peers = table(&keys);
        assert!(peers.add([5; 32], "127.0.0.1:1".into()));
        assert!(!peers.add([5; 32], "127.0.0.1:1".into()), "no duplicate");
        assert!(
            !peers.add(keys.identity.public(), "127.0.0.1:1".into()),
            "never self"
        );
        assert!(peers.is_peer(&[5; 32]));
        assert!(!peers.is_peer(&[6; 32]));
        assert!(peers.send(&node_address(&[5; 32]), vec![1]));
        assert!(!peers.send(&node_address(&[6; 32]), vec![1]));
        peers.remove(&[5; 32]);
        assert!(!peers.is_peer(&[5; 32]));
        assert!(peers.ids().is_empty());
        assert!(!Peers::none().add([5; 32], "127.0.0.1:1".into()));
    }

    #[tokio::test]
    async fn table_is_bounded() {
        let keys = NodeKeys::generate();
        let peers = table(&keys);
        for i in 0..MAX_PEERS + 5 {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            peers.add(id, "127.0.0.1:1".into());
        }
        assert_eq!(peers.ids().len(), MAX_PEERS);
    }

    #[tokio::test]
    async fn queue_overflow_drops() {
        let keys = NodeKeys::generate();
        let peers = table(&keys);
        // Port 1 refuses connections: nothing drains the queue for a while.
        peers.add([5; 32], "127.0.0.1:1".into());
        let addr = node_address(&[5; 32]);
        let accepted = (0..PEER_QUEUE + 10)
            .filter(|_| peers.send(&addr, vec![0]))
            .count();
        assert!(accepted <= PEER_QUEUE);
        assert!(accepted > 0);
    }
}
