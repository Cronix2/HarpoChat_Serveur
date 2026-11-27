// SPDX-License-Identifier: Apache-2.0
//! Accept loop and per-link dispatch.
//!
//! No log line mentions a client address, an inbox token or a packet: only
//! startup, shutdown and aggregated counters (spec §10).

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use harpochat_core::directory::{Directory, DirectoryEntry, VERSION as DIR_VERSION};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, directory};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::net::{self, NetError, RateLimit};
use crate::node::Node;
use crate::router::{Clock, Router};
use crate::service::MailboxService;

/// Frames queued per link before a slow phone starts losing deliveries.
const LINK_QUEUE: usize = 256;
/// Expired-blob sweep period.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

fn class_for(frame: &LinkFrame) -> SizeClass {
    if frame.body.len() <= SizeClass::Small.max_body_len() {
        SizeClass::Small
    } else {
        SizeClass::Large
    }
}

/// Signed directory as seen by this node. Until gossip and sponsorship
/// (P7), a root lists itself and a non-root lists nothing.
pub fn own_directory(node: &Node, now: u64) -> Signed<Directory> {
    let entries = if node.config.node.root {
        vec![DirectoryEntry {
            descriptor: node.descriptor(now),
            chain: Vec::new(),
        }]
    } else {
        Vec::new()
    };
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

async fn handle_link(
    tcp: tokio::net::TcpStream,
    tls: tokio_rustls::TlsAcceptor,
    node: Arc<Node>,
    router: Arc<Router>,
) -> Result<(), NetError> {
    let (mut reader, mut writer, _peer) =
        net::accept(tcp, &tls, &node.keys.noise, &node.keys.identity).await?;
    let (tx, mut rx) = mpsc::channel::<LinkFrame>(LINK_QUEUE);
    let writer_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if writer.send(&frame, class_for(&frame)).await.is_err() {
                break;
            }
        }
    });

    let mut limit = RateLimit::new(RateLimit::DEFAULT_RATE, RateLimit::DEFAULT_BURST);
    let mut inbox: Option<[u8; 32]> = None;
    let result = loop {
        let (_, frame) = match reader.recv().await {
            Ok(f) => f,
            Err(e) => break Err(e),
        };
        if !limit.allow(Instant::now()) {
            break Err(NetError::Protocol(harpochat_core::CoreError::TooLarge));
        }
        match frame.kind {
            FrameKind::Sphinx => router.submit(frame.body),
            FrameKind::RegisterInbox => {
                let Ok(token) = <[u8; 32]>::try_from(frame.body.as_slice()) else {
                    break Err(NetError::Protocol(harpochat_core::CoreError::Malformed));
                };
                if let Some(old) = inbox.replace(token) {
                    router.inboxes.unregister(&old);
                }
                router.inboxes.register(token, tx.clone());
            }
            FrameKind::DirectoryReq => {
                let dir = own_directory(&node, router.now());
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
    drop(tx);
    let _ = writer_task.await;
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
    let tls = net::tls_acceptor()?;
    let router = Arc::new(Router::new(
        &node.keys.identity.public(),
        node.sphinx.clone(),
        MailboxService::new(&node.config.limits),
        clock,
    ));
    let node = Arc::new(node);

    let sweeper = {
        let router = router.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            loop {
                tick.tick().await;
                let now = router.now();
                router.with_service(|s| s.store_mut().sweep(now));
            }
        })
    };

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((tcp, _addr)) = accepted else { continue };
                let _ = tcp.set_nodelay(true);
                let (tls, node, router) = (tls.clone(), node.clone(), router.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle_link(tcp, tls, node, router).await {
                        tracing::debug!("lien fermé : {e}");
                    }
                });
            }
        }
    }
    sweeper.abort();
    Ok(())
}

/// Verify our own directory the way a client would (used by `run --check`).
pub fn self_check(node: &Node, now: u64) -> bool {
    let roots = node.trusted_roots().unwrap_or_default();
    let dir = own_directory(node, now);
    match directory::verify_directory(&dir, &roots, now) {
        Ok(nodes) => !node.config.node.root || nodes.len() == 1,
        Err(_) => false,
    }
}
