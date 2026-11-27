// SPDX-License-Identifier: Apache-2.0
//! Accept loop and per-link dispatch.
//!
//! A link whose peer proved the identity of one of this node's peers (a
//! configured or verified mesh node) is a **node link** (Sphinx, directory
//! and padding only). Any other link is a **phone link** (inbox registration,
//! Sphinx, directory, cover rate) — or a new node presenting a `JoinRequest`.
//!
//! What a node sends to a phone is shaped (`cover::Shaper`) at the phone's
//! chosen rate, bounded by `[cover] phone_link_rate_min/max`.
//!
//! No log line mentions a client address, an inbox token or a packet: only
//! startup, shutdown and aggregated counters (spec §10).

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use harpochat_core::directory::Directory;
use harpochat_core::link::{parse_cover_rate, FrameKind, LinkFrame, SizeClass};
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, directory, CoreError};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::{host_port, Cover};
use crate::cover::{self, frame_or_padding, os_uniform, Rate, Shaper};
use crate::membership::{Changes, Membership};
use crate::net::{self, NetError, RateLimit};
use crate::node::Node;
use crate::peers::Peers;
use crate::router::{Clock, Router};
use crate::service::MailboxService;
use crate::sponsor::Sponsor;

/// Frames queued per link before a slow phone starts losing deliveries.
const LINK_QUEUE: usize = 256;
/// Expired-blob sweep period.
const SWEEP_EVERY: Duration = Duration::from_secs(60);
/// Packets received from peers awaiting routing.
const INBOUND_QUEUE: usize = 4096;
/// Node links carry the whole mesh's traffic: a higher frame budget.
const NODE_RATE: u32 = 2_000;
const NODE_BURST: u32 = 8_000;
/// Backlog drained at once on an overloaded phone link (e.g. a FETCH
/// answered through many SURBs).
const PHONE_BURST: usize = 16;
/// Directories received from peers awaiting merge.
const GOSSIP_QUEUE: usize = 256;
/// Re-verification of the view (descriptor expiry).
const REFRESH_EVERY: Duration = Duration::from_secs(30);
/// Aggregated counters are logged this often (spec §10: totals only).
const STATS_EVERY: Duration = Duration::from_secs(600);

/// One log line of anonymous totals: no address, no identifier, no size.
fn log_stats(router: &Router, membership: &Membership, peers: &Peers) {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &router.counters;
    tracing::info!(
        "compteurs : paquets reçus {} · jetés {} · remis {} · push {} · loops {}/{} (perdus {})          · drops {} · nœuds connus {} · pairs {}",
        c.packets_in.load(Relaxed),
        c.packets_dropped.load(Relaxed),
        c.delivered.load(Relaxed),
        c.pushes.load(Relaxed),
        c.loops_returned.load(Relaxed),
        c.loops_sent.load(Relaxed),
        c.loops_lost.load(Relaxed),
        c.drops_sent.load(Relaxed),
        membership.len(),
        peers.ids().len(),
    );
}

fn class_for(frame: &LinkFrame) -> SizeClass {
    if frame.body.len() <= SizeClass::Small.max_body_len() {
        SizeClass::Small
    } else {
        SizeClass::Large
    }
}

/// The configured peers and roots this node always links to.
fn initial_peers(node: &Node) -> Result<Vec<([u8; 32], String)>, NetError> {
    let mut list = node
        .config
        .peer_list()
        .map_err(|_| NetError::Protocol(CoreError::Malformed))?;
    let root_ids = node
        .config
        .root_ids()
        .map_err(|_| NetError::Protocol(CoreError::Malformed))?;
    for (id, r) in root_ids.into_iter().zip(&node.config.roots) {
        if let Some(hp) = r.endpoints.iter().find_map(|e| host_port(e)) {
            list.push((id, hp));
        }
    }
    Ok(list)
}

/// Link to new verified nodes, unlink from those no longer valid (but keep
/// the configured ones).
fn apply(peers: &Peers, statics: &HashSet<[u8; 32]>, changes: Changes) {
    for (id, hp) in changes.added {
        if let Some(hp) = hp {
            peers.add(id, hp);
        }
    }
    for id in changes.removed {
        if !statics.contains(&id) {
            peers.remove(&id);
        }
    }
}

/// A node ready to accept links.
pub struct Server {
    node: Arc<Node>,
    router: Arc<Router>,
    peers: Arc<Peers>,
    membership: Arc<Membership>,
    sponsor: Arc<Sponsor>,
    statics: Arc<HashSet<[u8; 32]>>,
    inbound: Option<mpsc::Receiver<Vec<u8>>>,
    gossip: Option<mpsc::Receiver<Vec<u8>>>,
}

impl Server {
    /// Build the node's router and start its peer links. Needs a tokio runtime.
    pub fn new(node: Node, clock: Clock) -> Result<Self, NetError> {
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        let (gtx, grx) = mpsc::channel(GOSSIP_QUEUE);
        let peers = Arc::new(Peers::new(
            &node.keys,
            tx,
            gtx,
            node.config.cover.node_link_rate,
        ));
        let initial = initial_peers(&node)?;
        let statics: HashSet<[u8; 32]> = initial.iter().map(|(id, _)| *id).collect();
        for (id, hp) in initial {
            peers.add(id, hp);
        }
        let router = Arc::new(Router::new(
            &node.keys.identity.public(),
            node.sphinx.clone(),
            MailboxService::new(&node.config.limits),
            peers.clone(),
            clock,
        ));
        Ok(Self {
            membership: Arc::new(Membership::new(&node)),
            sponsor: Arc::new(Sponsor::new(&node)),
            node: Arc::new(node),
            router,
            peers,
            statics: Arc::new(statics),
            inbound: Some(rx),
            gossip: Some(grx),
        })
    }

    /// The routing core (counters, inboxes) — for tests and `status`.
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// The node's view of the mesh — for tests and `status`.
    pub fn membership(&self) -> Arc<Membership> {
        self.membership.clone()
    }

    /// The peer table — for tests.
    pub fn peers(&self) -> Arc<Peers> {
        self.peers.clone()
    }

    /// Accept links until `shutdown` resolves; all state is then dropped.
    pub async fn run(
        mut self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), NetError> {
        let tls = net::tls_acceptor()?;
        let mut background = Vec::new();
        if let Some(mut rx) = self.inbound.take() {
            let router = self.router.clone();
            background.push(tokio::spawn(async move {
                while let Some(pkt) = rx.recv().await {
                    router.submit(pkt);
                }
            }));
        }
        {
            let router = self.router.clone();
            background.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(SWEEP_EVERY);
                loop {
                    tick.tick().await;
                    let now = router.now();
                    router.with_service(|s| s.sweep(now));
                }
            }));
        }
        if let Some(mut grx) = self.gossip.take() {
            let (membership, peers, statics, router) = (
                self.membership.clone(),
                self.peers.clone(),
                self.statics.clone(),
                self.router.clone(),
            );
            background.push(tokio::spawn(async move {
                let mut refresh = tokio::time::interval(REFRESH_EVERY);
                loop {
                    let changes = tokio::select! {
                        body = grx.recv() => {
                            let Some(body) = body else { return };
                            match cbor::from_slice::<Signed<Directory>>(&body, 1 << 20) {
                                Ok(d) => membership.merge(&d, router.now()),
                                Err(_) => continue,
                            }
                        }
                        _ = refresh.tick() => membership.refresh(router.now()),
                    };
                    apply(&peers, &statics, changes);
                }
            }));
        }
        {
            let (router, membership, peers) = (
                self.router.clone(),
                self.membership.clone(),
                self.peers.clone(),
            );
            background.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(STATS_EVERY);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    log_stats(&router, &membership, &peers);
                }
            }));
        }
        background.push(tokio::spawn(cover::node_cover(
            self.node.clone(),
            self.router.clone(),
            self.membership.clone(),
        )));
        let mut links = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                // Reap finished link tasks so the set does not grow forever.
                Some(_) = links.join_next(), if !links.is_empty() => {}
                accepted = listener.accept() => {
                    let Ok((tcp, _addr)) = accepted else { continue };
                    let _ = tcp.set_nodelay(true);
                    let ctx = LinkCtx {
                        node: self.node.clone(),
                        router: self.router.clone(),
                        peers: self.peers.clone(),
                        membership: self.membership.clone(),
                        sponsor: self.sponsor.clone(),
                        statics: self.statics.clone(),
                    };
                    let tls = tls.clone();
                    links.spawn(async move {
                        if let Err(e) = handle_link(tcp, tls, ctx).await {
                            tracing::debug!("lien fermé : {e}");
                        }
                    });
                }
            }
        }
        links.abort_all();
        self.peers.shutdown();
        for t in background {
            t.abort();
        }
        Ok(())
    }
}

/// What a link handler needs from its node.
struct LinkCtx {
    node: Arc<Node>,
    router: Arc<Router>,
    peers: Arc<Peers>,
    membership: Arc<Membership>,
    sponsor: Arc<Sponsor>,
    statics: Arc<HashSet<[u8; 32]>>,
}

async fn handle_link(
    tcp: tokio::net::TcpStream,
    tls: tokio_rustls::TlsAcceptor,
    ctx: LinkCtx,
) -> Result<(), NetError> {
    let LinkCtx {
        node,
        router,
        peers,
        membership,
        sponsor,
        statics,
    } = ctx;
    let (mut reader, mut writer, peer) =
        net::accept(tcp, &tls, &node.keys.noise, &node.keys.identity).await?;
    let is_node = peer.node_id.is_some_and(|id| peers.is_peer(&id));
    let cfg: &Cover = &node.config.cover;
    // Node links are shaped by the peer's own dialler; only the phone
    // downlink is shaped here.
    let rate = Arc::new(Rate::new(if is_node { 0.0 } else { cfg.phone_link_rate }));
    let (tx, mut rx) = mpsc::channel::<LinkFrame>(LINK_QUEUE);
    let writer_task = {
        let (rate, router) = (rate.clone(), router.clone());
        tokio::spawn(async move {
            let mut shaper = Shaper::new(rate, PHONE_BURST, os_uniform);
            while let Some(batch) = shaper.next(&mut rx).await {
                for item in batch {
                    if item.is_none() {
                        router
                            .counters
                            .padding_sent
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    let frame = frame_or_padding(item);
                    if writer.send(&frame, class_for(&frame)).await.is_err() {
                        return;
                    }
                }
            }
        })
    };

    let mut limit = if is_node {
        RateLimit::new(NODE_RATE, NODE_BURST)
    } else {
        RateLimit::new(RateLimit::DEFAULT_RATE, RateLimit::DEFAULT_BURST)
    };
    let mut inbox: Option<[u8; 32]> = None;
    let result = loop {
        let (_, frame) = match reader.recv().await {
            Ok(f) => f,
            Err(e) => break Err(e),
        };
        if !limit.allow(Instant::now()) {
            break Err(NetError::Protocol(CoreError::TooLarge));
        }
        router
            .counters
            .frames_in
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match frame.kind {
            FrameKind::Sphinx => router.submit(frame.body),
            FrameKind::RegisterInbox if !is_node => {
                let Ok(token) = <[u8; 32]>::try_from(frame.body.as_slice()) else {
                    break Err(NetError::Protocol(CoreError::Malformed));
                };
                if let Some(old) = inbox.replace(token) {
                    router.inboxes.unregister(&old);
                }
                router.inboxes.register(token, tx.clone());
            }
            FrameKind::CoverRate if !is_node => {
                let Ok(mhz) = parse_cover_rate(&frame.body) else {
                    break Err(NetError::Protocol(CoreError::Malformed));
                };
                let hz = f64::from(mhz) / 1000.0;
                rate.set_hz(hz.clamp(cfg.phone_link_rate_min, cfg.phone_link_rate_max));
            }
            FrameKind::DirectoryReq => {
                let dir = membership.directory(&node, router.now());
                let _ = tx.try_send(LinkFrame {
                    kind: FrameKind::Directory,
                    body: cbor::to_vec(&dir),
                });
            }
            FrameKind::JoinRequest if !is_node => {
                let now = router.now();
                let (resp, entry) = sponsor.handle_join(&node, &frame.body, peer.node_id, now);
                if let Some(entry) = entry {
                    apply(&peers, &statics, membership.insert(entry, now));
                    tracing::info!("nouveau nœud parrainé");
                }
                let _ = tx.try_send(LinkFrame {
                    kind: FrameKind::JoinResponse,
                    body: cbor::to_vec(&resp),
                });
            }
            // Link padding; gossip is a pull (DirectoryReq).
            _ => {}
        }
    };
    if let Some(token) = inbox {
        router.inboxes.unregister(&token);
    }
    // A shaped writer only notices a closed queue at its next slot: stop it.
    drop(tx);
    writer_task.abort();
    result
}

/// Run the node until `shutdown` resolves. All state lives in RAM and is
/// dropped on return.
pub async fn serve(
    node: Node,
    listener: TcpListener,
    clock: Clock,
    shutdown: impl Future<Output = ()>,
) -> Result<(), NetError> {
    Server::new(node, clock)?.run(listener, shutdown).await
}

/// Verify our own directory the way a client would (used by `run --check`).
pub fn self_check(node: &Node, now: u64) -> bool {
    let roots = node.trusted_roots().unwrap_or_default();
    let dir = Membership::new(node).directory(node, now);
    match directory::verify_directory(&dir, &roots, now) {
        Ok(nodes) => {
            // A root, or a sponsored node, must appear in its own directory.
            let member_expected = node.config.node.root || !node.chain().is_empty();
            !member_expected || nodes.len() == 1
        }
        Err(_) => false,
    }
}
