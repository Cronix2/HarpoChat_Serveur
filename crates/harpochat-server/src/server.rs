// SPDX-License-Identifier: Apache-2.0
//! Accept loop and per-link dispatch.
//!
//! A link whose peer proved the identity of a configured `[[peers]]` node is
//! a **node link** (Sphinx, directory and padding only). Any other link is a
//! **phone link** (inbox registration, Sphinx, directory, cover rate).
//!
//! What a node sends to a phone is shaped (`cover::Shaper`) at the phone's
//! chosen rate, bounded by `[cover] phone_link_rate_min/max`.
//!
//! No log line mentions a client address, an inbox token or a packet: only
//! startup, shutdown and aggregated counters (spec §10).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use harpochat_core::directory::{Directory, DirectoryEntry, VERSION as DIR_VERSION};
use harpochat_core::link::{parse_cover_rate, FrameKind, LinkFrame, SizeClass};
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, directory, CoreError};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::Cover;
use crate::cover::{self, frame_or_padding, os_uniform, Rate, Shaper};
use crate::net::{self, NetError, RateLimit};
use crate::node::Node;
use crate::peers::Peers;
use crate::router::{Clock, Router};
use crate::service::MailboxService;

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

fn class_for(frame: &LinkFrame) -> SizeClass {
    if frame.body.len() <= SizeClass::Small.max_body_len() {
        SizeClass::Small
    } else {
        SizeClass::Large
    }
}

/// Signed directory as seen by this node: itself (if it is a root) and the
/// self-signed descriptors of its peers. Until gossip and sponsorship (P7),
/// chains are empty, so clients only accept entries of nodes that are roots.
pub fn own_directory(node: &Node, peers: &Peers, now: u64) -> Signed<Directory> {
    let mut entries = Vec::new();
    if node.config.node.root {
        entries.push(DirectoryEntry {
            descriptor: node.descriptor(now),
            chain: Vec::new(),
        });
    }
    for d in peers.descriptors() {
        entries.push(DirectoryEntry {
            descriptor: d,
            chain: Vec::new(),
        });
    }
    Signed::sign(
        &node.keys.identity,
        &Directory {
            v: DIR_VERSION,
            issuer: node.keys.identity.public(),
            issued: now,
            entries,
            revocations: Vec::new(),
        },
    )
}

/// A node ready to accept links.
pub struct Server {
    node: Arc<Node>,
    router: Arc<Router>,
    peers: Arc<Peers>,
    inbound: Option<mpsc::Receiver<Vec<u8>>>,
}

impl Server {
    /// Build the node's router and start its peer links. Needs a tokio runtime.
    pub fn new(node: Node, clock: Clock) -> Result<Self, NetError> {
        let (tx, rx) = mpsc::channel(INBOUND_QUEUE);
        let peer_list = node
            .config
            .peer_list()
            .map_err(|_| NetError::Protocol(CoreError::Malformed))?;
        let peers = Arc::new(if peer_list.is_empty() {
            Peers::none()
        } else {
            Peers::start(&node.keys, peer_list, tx, node.config.cover.node_link_rate)
        });
        let router = Arc::new(Router::new(
            &node.keys.identity.public(),
            node.sphinx.clone(),
            MailboxService::new(&node.config.limits),
            peers.clone(),
            clock,
        ));
        Ok(Self {
            node: Arc::new(node),
            router,
            peers,
            inbound: Some(rx),
        })
    }

    /// The routing core (counters, inboxes) — for tests and `status`.
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
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
        background.push(tokio::spawn(cover::node_cover(
            self.node.clone(),
            self.router.clone(),
            self.peers.clone(),
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
                    let (tls, node, router, peers) =
                        (tls.clone(), self.node.clone(), self.router.clone(), self.peers.clone());
                    links.spawn(async move {
                        if let Err(e) = handle_link(tcp, tls, node, router, peers).await {
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

async fn handle_link(
    tcp: tokio::net::TcpStream,
    tls: tokio_rustls::TlsAcceptor,
    node: Arc<Node>,
    router: Arc<Router>,
    peers: Arc<Peers>,
) -> Result<(), NetError> {
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
                let dir = own_directory(&node, &peers, router.now());
                let _ = tx.try_send(LinkFrame {
                    kind: FrameKind::Directory,
                    body: cbor::to_vec(&dir),
                });
            }
            // Link padding, and kinds handled in later phases (gossip, join).
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
    let dir = own_directory(node, &Peers::none(), now);
    match directory::verify_directory(&dir, &roots, now) {
        Ok(nodes) => !node.config.node.root || nodes.len() == 1,
        Err(_) => false,
    }
}
