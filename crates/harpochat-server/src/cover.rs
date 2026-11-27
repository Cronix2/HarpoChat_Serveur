// SPDX-License-Identifier: Apache-2.0
//! Cover traffic (spec §5, §6.3, §11).
//!
//! - [`shape`]: a link writer that emits one frame per *slot*, slots being a
//!   Poisson process of rate λ. In each slot it sends the next real frame if
//!   one is queued, a `Padding` frame otherwise. The slot instants come only
//!   from the random source, never from the traffic: an idle link and a link
//!   carrying real frames (below λ) emit the same number of frames at the
//!   same instants. Above λ a backlog builds up; once it reaches `burst` it
//!   is drained at once to bound latency — an overloaded link does reveal
//!   its overload (documented for operators).
//! - [`LoopTracker`]: the node's own loops (sent → returned or lost) and a
//!   local, decaying loss score per neighbour. Nothing is published.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use harpochat_core::descriptor::node_address;
use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::random_bytes;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::path::{self, Candidate};
use harpochat_core::sphinx::{self, LOCAL_DELIVERY};
use tokio::sync::mpsc::{self, error::TryRecvError};

use crate::membership::Membership;
use crate::node::Node;
use crate::router::Router;

/// Longest wait between two slots, whatever the rate.
const MAX_SLOT: Duration = Duration::from_secs(3600);

/// A link rate in millihertz, changeable while the link runs.
#[derive(Debug, Default)]
pub struct Rate(AtomicU32);

impl Rate {
    /// Rate of `hz` frames per second.
    pub fn new(hz: f64) -> Self {
        Self(AtomicU32::new(hz_to_mhz(hz)))
    }

    /// Change the rate (takes effect from the next slot).
    pub fn set_hz(&self, hz: f64) {
        self.0.store(hz_to_mhz(hz), Ordering::Relaxed);
    }

    /// Current rate in frames per second.
    pub fn hz(&self) -> f64 {
        f64::from(self.0.load(Ordering::Relaxed)) / 1000.0
    }
}

/// Frames per second → millihertz (saturating, negative and NaN → 0).
pub fn hz_to_mhz(hz: f64) -> u32 {
    if hz.is_finite() && hz > 0.0 {
        (hz * 1000.0).round().min(f64::from(u32::MAX)) as u32
    } else {
        0
    }
}

/// Uniform `[0, 1)` from the OS RNG.
pub fn os_uniform() -> f64 {
    (u64::from_le_bytes(random_bytes()) >> 11) as f64 / (1u64 << 53) as f64
}

/// Exp(`hz`) wait drawn from `u ∈ [0, 1)`.
pub fn slot_wait(hz: f64, u: f64) -> Duration {
    let u = if u.is_finite() {
        u.clamp(0.0, 1.0 - 1e-12)
    } else {
        0.0
    };
    let secs = -(1.0 - u).ln() / hz;
    Duration::try_from_secs_f64(secs)
        .unwrap_or(MAX_SLOT)
        .min(MAX_SLOT)
}

/// Slot scheduler of a shaped link (see module docs). The caller owns the
/// writer: it sends `Some(item)` as a real frame and `None` as padding.
pub struct Shaper<U> {
    rate: Arc<Rate>,
    burst: usize,
    uniform: U,
    /// Instant of the last slot. Slots are scheduled at absolute instants so
    /// a coarse OS timer (≈ 15 ms on Windows) delays a frame without
    /// lowering the rate.
    last: Option<tokio::time::Instant>,
}

impl<U: FnMut() -> f64> Shaper<U> {
    /// Shaper at `rate`, draining a backlog of `burst` frames at once
    /// (`0` = never).
    pub fn new(rate: Arc<Rate>, burst: usize, uniform: U) -> Self {
        Self {
            rate,
            burst,
            uniform,
            last: None,
        }
    }

    /// Wait for the next slot and return what to send in it (`None` items
    /// are padding). `None` once the queue is closed and empty. With a rate
    /// of 0, returns each item as soon as it is queued (no cover).
    pub async fn next<T>(&mut self, rx: &mut mpsc::Receiver<T>) -> Option<Vec<Option<T>>> {
        let hz = self.rate.hz();
        if hz <= 0.0 {
            return rx.recv().await.map(|t| vec![Some(t)]);
        }
        let now = tokio::time::Instant::now();
        // After a stall (or a rate change from a very slow rate) restart from
        // now rather than emitting a burst of overdue slots.
        let base = match self.last {
            Some(t) if now.duration_since(t) < Duration::from_secs(1) => t,
            _ => now,
        };
        let slot = base + slot_wait(hz, (self.uniform)());
        self.last = Some(slot);
        tokio::time::sleep_until(slot).await;
        let mut out = vec![match rx.try_recv() {
            Ok(t) => Some(t),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => return None,
        }];
        while self.burst > 0 && rx.len() >= self.burst {
            match rx.try_recv() {
                Ok(t) => out.push(Some(t)),
                Err(_) => break,
            }
        }
        Some(out)
    }
}

/// The frame to send for a shaped item: a real frame or padding.
pub fn frame_or_padding(item: Option<LinkFrame>) -> LinkFrame {
    item.unwrap_or(LinkFrame {
        kind: FrameKind::Padding,
        body: Vec::new(),
    })
}

/// Loops are lost once their deadline passes.
const MAX_PENDING_LOOPS: usize = 10_000;
/// Loss scores halve this often, so an old outage is forgotten.
pub const DECAY_EVERY: Duration = Duration::from_secs(600);
/// A neighbour is suspect with at least this many (decayed) samples…
pub const SUSPECT_MIN_SAMPLES: f64 = 10.0;
/// …and a loss ratio above this. A loss is blamed on every node of the
/// loop: next to one dead node, a healthy neighbour of a 5-node mesh loses
/// about a third of its loops, the dead one all of them.
pub const SUSPECT_MAX_LOSS: f64 = 0.75;

#[derive(Debug, Default, Clone, Copy)]
struct Score {
    ok: f64,
    lost: f64,
}

struct Pending {
    hops: Vec<[u8; 32]>,
    deadline: Instant,
}

/// This node's loops in flight and its local view of neighbour losses.
pub struct LoopTracker {
    pending: HashMap<[u8; 32], Pending>,
    scores: HashMap<[u8; 32], Score>,
    last_decay: Instant,
}

impl LoopTracker {
    /// Empty tracker.
    pub fn new(now: Instant) -> Self {
        Self {
            pending: HashMap::new(),
            scores: HashMap::new(),
            last_decay: now,
        }
    }

    /// A loop through `hops` (other nodes) was sent; `false` if too many are
    /// in flight (the loop is then not sent).
    pub fn start(&mut self, token: [u8; 32], hops: Vec<[u8; 32]>, deadline: Instant) -> bool {
        if self.pending.len() >= MAX_PENDING_LOOPS {
            return false;
        }
        self.pending.insert(token, Pending { hops, deadline });
        true
    }

    /// A packet came back addressed to `token`: `true` if it was our loop.
    pub fn complete(&mut self, token: &[u8; 32]) -> bool {
        let Some(p) = self.pending.remove(token) else {
            return false;
        };
        for h in p.hops {
            self.scores.entry(h).or_default().ok += 1.0;
        }
        true
    }

    /// Mark overdue loops as lost; returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        while now.duration_since(self.last_decay) >= DECAY_EVERY {
            self.last_decay += DECAY_EVERY;
            for s in self.scores.values_mut() {
                s.ok *= 0.5;
                s.lost *= 0.5;
            }
            self.scores.retain(|_, s| s.ok + s.lost >= 0.01);
        }
        let overdue: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(t, _)| *t)
            .collect();
        for t in &overdue {
            if let Some(p) = self.pending.remove(t) {
                for h in p.hops {
                    self.scores.entry(h).or_default().lost += 1.0;
                }
            }
        }
        overdue.len()
    }

    /// Neighbours that lose too many of our loops.
    pub fn suspects(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self
            .scores
            .iter()
            .filter(|(_, s)| {
                let n = s.ok + s.lost;
                n >= SUSPECT_MIN_SAMPLES && s.lost / n > SUSPECT_MAX_LOSS
            })
            .map(|(id, _)| *id)
            .collect();
        v.sort();
        v
    }

    /// Loops in flight.
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }
}

/// Extra time a loop is given beyond its mix delays before it counts as lost.
pub const LOOP_GRACE: Duration = Duration::from_secs(10);

/// This node's view for its own cover routes: the verified mesh.
fn candidates(node: &Node, membership: &Membership, now: u64) -> Vec<Candidate> {
    membership
        .nodes(node, now)
        .iter()
        .map(Candidate::from)
        .collect()
}

fn pick(n: usize) -> usize {
    (u64::from_le_bytes(random_bytes()) % n.max(1) as u64) as usize
}

/// Emit one loop (spec §6.3) and start tracking it.
fn emit_loop(
    router: &Arc<Router>,
    cands: &[Candidate],
    own: &[u8; 32],
    cfg: &crate::config::Cover,
) {
    let Ok(route) = path::loop_route(cands, own, &mut pick, &mut os_uniform, cfg.mean_delay_ms)
    else {
        return;
    };
    let token: [u8; 32] = random_bytes();
    let Ok(packet) = sphinx::build_forward(
        &envelope::encode(&Message::Loop),
        &route.hops,
        token,
        &route.delays_ms,
        SizeClass::Small,
        None,
    ) else {
        return;
    };
    let link_slack = if cfg.node_link_rate > 0.0 {
        Duration::from_secs_f64(5.0 * route.hops.len() as f64 / cfg.node_link_rate)
    } else {
        Duration::ZERO
    };
    let deadline = Instant::now()
        + Duration::from_millis(route.delays_ms.iter().sum())
        + LOOP_GRACE
        + link_slack;
    let others: Vec<[u8; 32]> = route
        .hops
        .iter()
        .map(|h| h.id_pub)
        .filter(|id| id != own)
        .collect();
    if !router
        .loops
        .lock()
        .expect("loops")
        .start(token, others, deadline)
    {
        return;
    }
    router.counters.loops_sent.fetch_add(1, Ordering::Relaxed);
    router.forward(node_address(&route.hops[0].id_pub), packet);
}

/// Emit one drop towards a mailbox that is not suspect.
fn emit_drop(
    router: &Arc<Router>,
    cands: &[Candidate],
    own: &[u8; 32],
    cfg: &crate::config::Cover,
) {
    let avoid = router.loops.lock().expect("loops").suspects();
    let Ok(route) = path::drop_route(
        cands,
        own,
        &avoid,
        &mut pick,
        &mut os_uniform,
        cfg.mean_delay_ms,
    ) else {
        return;
    };
    let Ok(packet) = sphinx::build_forward(
        &envelope::encode(&Message::Drop),
        &route.hops,
        LOCAL_DELIVERY,
        &route.delays_ms,
        SizeClass::Small,
        None,
    ) else {
        return;
    };
    router.counters.drops_sent.fetch_add(1, Ordering::Relaxed);
    router.forward(node_address(&route.hops[0].id_pub), packet);
}

/// The node's own cover traffic: loops and drops as a Poisson process of
/// rate `loop_rate + drop_rate`, plus loss accounting. Runs until aborted.
pub async fn node_cover(node: Arc<Node>, router: Arc<Router>, membership: Arc<Membership>) {
    let cfg = node.config.cover.clone();
    let total = cfg.loop_rate + cfg.drop_rate;
    if total <= 0.0 {
        return;
    }
    let own = node.keys.identity.public();
    let mut expiry = tokio::time::interval(Duration::from_secs(1));
    loop {
        // Exponential waits are memoryless: restarting one after an expiry
        // tick keeps the emission a Poisson process.
        tokio::select! {
            _ = tokio::time::sleep(slot_wait(total, os_uniform())) => {
                let cands = candidates(&node, &membership, router.now());
                if cands.len() < 2 {
                    continue;
                }
                if os_uniform() * total < cfg.loop_rate {
                    emit_loop(&router, &cands, &own, &cfg);
                } else {
                    emit_drop(&router, &cands, &own, &cfg);
                }
            }
            _ = expiry.tick() => {
                let lost = router.loops.lock().expect("loops").expire(Instant::now());
                router.counters.loops_lost.fetch_add(lost as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant as TokioInstant;

    struct Xorshift(u64);
    impl Xorshift {
        fn uniform(&mut self) -> f64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    fn real(i: u32) -> LinkFrame {
        LinkFrame {
            kind: FrameKind::Sphinx,
            body: i.to_be_bytes().to_vec(),
        }
    }

    /// Run a shaper at `hz` for `slots` frames, with a producer queueing a
    /// real frame every `every` (None = idle link). Returns what was sent, when.
    async fn run(
        hz: f64,
        slots: usize,
        every: Option<Duration>,
        burst: usize,
    ) -> Vec<(Duration, FrameKind)> {
        let (tx, mut rx) = mpsc::channel(1024);
        let producer = tokio::spawn(async move {
            let mut i = 0;
            loop {
                match every {
                    Some(d) => {
                        tokio::time::sleep(d).await;
                        if tx.send(real(i)).await.is_err() {
                            return;
                        }
                        i += 1;
                    }
                    None => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
        });
        let start = TokioInstant::now();
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        let mut shaper = Shaper::new(Arc::new(Rate::new(hz)), burst, || rng.uniform());
        let mut log = Vec::new();
        while log.len() < slots {
            let Some(batch) = shaper.next(&mut rx).await else {
                break;
            };
            for item in batch {
                log.push((TokioInstant::now() - start, frame_or_padding(item).kind));
            }
        }
        producer.abort();
        log.truncate(slots);
        log
    }

    #[tokio::test(start_paused = true)]
    async fn shaped_instants_do_not_depend_on_traffic() {
        let hz = 20.0;
        let idle = run(hz, 2000, None, 16).await;
        let busy = run(hz, 2000, Some(Duration::from_secs_f64(2.0 / hz)), 16).await;
        let instants = |v: &[(Duration, FrameKind)]| v.iter().map(|(t, _)| *t).collect::<Vec<_>>();
        assert_eq!(instants(&idle), instants(&busy));
        assert!(idle.iter().all(|(_, k)| *k == FrameKind::Padding));
        let reals = busy.iter().filter(|(_, k)| *k == FrameKind::Sphinx).count();
        // Load 0.5·λ: about half the slots carry real frames.
        assert!((800..1200).contains(&reals), "{reals}");
    }

    #[tokio::test(start_paused = true)]
    async fn shape_mean_rate() {
        let hz = 10.0;
        let v = run(hz, 10_000, None, 16).await;
        let secs = v.last().unwrap().0.as_secs_f64();
        let measured = v.len() as f64 / secs;
        assert!((measured - hz).abs() / hz < 0.05, "{measured}");
    }

    #[tokio::test(start_paused = true)]
    async fn every_real_frame_is_delivered_in_order_then_closes() {
        let (tx, mut rx) = mpsc::channel(64);
        for i in 0..10 {
            tx.send(real(i)).await.unwrap();
        }
        drop(tx);
        let mut rng = Xorshift(7);
        let mut shaper = Shaper::new(Arc::new(Rate::new(5.0)), 0, || rng.uniform());
        let mut got = Vec::new();
        while let Some(batch) = shaper.next(&mut rx).await {
            got.extend(
                batch
                    .into_iter()
                    .map(|i| i.expect("no padding before close")),
            );
        }
        assert_eq!(got, (0..10).map(real).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn backlog_bursts() {
        let (tx, mut rx) = mpsc::channel(64);
        for i in 0..40 {
            tx.send(real(i)).await.unwrap();
        }
        let mut rng = Xorshift(3);
        let mut shaper = Shaper::new(Arc::new(Rate::new(1.0)), 8, || rng.uniform());
        // First slot: one frame, then drained down to below the threshold.
        assert_eq!(shaper.next(&mut rx).await.unwrap().len(), 33);
        assert_eq!(shaper.next(&mut rx).await.unwrap().len(), 1);
        drop(tx);
    }

    #[tokio::test]
    async fn zero_rate_passthrough() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(real(1)).await.unwrap();
        drop(tx);
        let mut shaper = Shaper::new(Arc::new(Rate::new(0.0)), 0, || 0.5);
        assert_eq!(shaper.next(&mut rx).await, Some(vec![Some(real(1))]));
        assert_eq!(shaper.next(&mut rx).await, None);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_change_applies_to_next_slot() {
        let (_tx, mut rx) = mpsc::channel::<LinkFrame>(8);
        let rate = Arc::new(Rate::new(1.0));
        let mut shaper = Shaper::new(rate.clone(), 0, || 0.5);
        let t0 = TokioInstant::now();
        shaper.next(&mut rx).await.unwrap();
        let slow = TokioInstant::now() - t0;
        rate.set_hz(100.0);
        let t1 = TokioInstant::now();
        shaper.next(&mut rx).await.unwrap();
        assert!(TokioInstant::now() - t1 < slow / 50);
    }

    #[test]
    fn rate_conversions() {
        assert_eq!(hz_to_mhz(1.5), 1500);
        assert_eq!(hz_to_mhz(-1.0), 0);
        assert_eq!(hz_to_mhz(f64::NAN), 0);
        assert_eq!(hz_to_mhz(1e12), u32::MAX);
        let r = Rate::new(2.0);
        r.set_hz(0.25);
        assert_eq!(r.hz(), 0.25);
        assert_eq!(slot_wait(1.0, 0.0), Duration::ZERO);
        assert!(slot_wait(1.0, 1.0) <= MAX_SLOT);
        assert!(slot_wait(0.0001, 0.999) <= MAX_SLOT);
    }

    #[test]
    fn tracker_counts_and_suspects() {
        let t0 = Instant::now();
        let mut t = LoopTracker::new(t0);
        let good = [1; 32];
        let bad = [2; 32];
        for i in 0..20u8 {
            let tok = [i; 32];
            let hops = if i % 2 == 0 {
                vec![good]
            } else {
                vec![good, bad]
            };
            assert!(t.start(tok, hops, t0 + Duration::from_secs(5)));
            if i % 2 == 0 {
                assert!(t.complete(&tok));
            }
        }
        assert!(!t.complete(&[0xEE; 32]));
        assert_eq!(t.expire(t0 + Duration::from_secs(1)), 0);
        assert_eq!(t.expire(t0 + Duration::from_secs(6)), 10);
        assert_eq!(t.in_flight(), 0);
        // good: 10 ok, 10 lost → 50 %, under the threshold; bad: 10 lost.
        assert_eq!(t.suspects(), vec![bad]);
    }

    #[test]
    fn tracker_forgets_old_losses() {
        let t0 = Instant::now();
        let mut t = LoopTracker::new(t0);
        for i in 0..12u8 {
            t.start([i; 32], vec![[9; 32]], t0);
        }
        t.expire(t0);
        assert_eq!(t.suspects(), vec![[9; 32]]);
        // Two decays: 12 → 3 samples, below the minimum.
        t.expire(t0 + 2 * DECAY_EVERY);
        assert!(t.suspects().is_empty());
    }

    #[test]
    fn tracker_is_bounded() {
        let t0 = Instant::now();
        let mut t = LoopTracker::new(t0);
        for i in 0..MAX_PENDING_LOOPS as u32 {
            let mut tok = [0; 32];
            tok[..4].copy_from_slice(&i.to_be_bytes());
            assert!(t.start(tok, vec![], t0));
        }
        assert!(!t.start([0xFF; 32], vec![], t0));
    }
}
