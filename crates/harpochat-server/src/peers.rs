// SPDX-License-Identifier: Apache-2.0
//! Node-to-node links (spec §5): one outbound, authenticated link per peer.
//!
//! Each node dials every configured peer with its own identity and requires
//! the peer to prove the expected identity (Noise `NodeAuth`). Outbound links
//! carry our Sphinx packets to the peer; packets the peer sends us arrive on
//! the peer's own outbound link (an inbound link here). Sending never blocks:
//! a full queue or a down peer drops the packet and counts it.
//!
//! Outbound links are shaped (`cover::Shaper`): frames leave at the instants
//! of a Poisson process of rate `[cover] node_link_rate`, padding filling the
//! slots that carry no packet (spec §5).
//!
//! Static peers (`[[peers]]`) until gossip and sponsorship arrive in P7.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use harpochat_core::cbor;
use harpochat_core::descriptor::{node_address, NodeDescriptor};
use harpochat_core::directory::Directory;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::signed::Signed;
use tokio::sync::mpsc;

use crate::cover::{os_uniform, Rate, Shaper};
use crate::keystore::NodeKeys;
use crate::net;

/// Packets queued per peer before dropping.
pub const PEER_QUEUE: usize = 1024;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Backlog drained at once on an overloaded node link.
const PEER_BURST: usize = 256;

struct Peer {
    id: [u8; 32],
    tx: mpsc::Sender<Vec<u8>>,
}

/// The peer table of a node.
pub struct Peers {
    by_addr: HashMap<[u8; 32], Peer>,
    descriptors: Arc<Mutex<HashMap<[u8; 32], Signed<NodeDescriptor>>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Peers {
    /// Start one dialler per peer, its link shaped at `link_rate` frames per
    /// second (0 = unshaped). Packets the peers send back on our outbound
    /// links are handed to `inbound`.
    pub fn start(
        keys: &NodeKeys,
        peers: Vec<([u8; 32], String)>,
        inbound: mpsc::Sender<Vec<u8>>,
        link_rate: f64,
    ) -> Self {
        let descriptors = Arc::new(Mutex::new(HashMap::new()));
        let mut by_addr = HashMap::new();
        let mut tasks = Vec::new();
        let own = keys.identity.public();
        for (id, endpoint) in peers {
            if id == own {
                continue;
            }
            let (tx, rx) = mpsc::channel(PEER_QUEUE);
            tasks.push(tokio::spawn(dialler(
                keys.clone(),
                id,
                endpoint,
                rx,
                inbound.clone(),
                descriptors.clone(),
                Arc::new(Rate::new(link_rate)),
            )));
            by_addr.insert(node_address(&id), Peer { id, tx });
        }
        Self {
            by_addr,
            descriptors,
            tasks: Mutex::new(tasks),
        }
    }

    /// No peers (single-node mode).
    pub fn none() -> Self {
        Self {
            by_addr: HashMap::new(),
            descriptors: Arc::new(Mutex::new(HashMap::new())),
            tasks: Mutex::new(Vec::new()),
        }
    }

    /// Stop every dialler and its link (node shutdown).
    pub fn shutdown(&self) {
        for t in self.tasks.lock().expect("tasks").drain(..) {
            t.abort();
        }
    }

    /// Configured peer identities.
    pub fn ids(&self) -> Vec<[u8; 32]> {
        self.by_addr.values().map(|p| p.id).collect()
    }

    /// Whether `id` is a configured peer.
    pub fn is_peer(&self, id: &[u8; 32]) -> bool {
        self.by_addr.values().any(|p| p.id == *id)
    }

    /// Whether a Sphinx address belongs to a configured peer.
    pub fn is_peer_addr(&self, node_addr: &[u8; 32]) -> bool {
        self.by_addr.contains_key(node_addr)
    }

    /// Queue a packet for the peer at Sphinx address `node_addr`.
    /// `false` if no such peer or its queue is full.
    pub fn send(&self, node_addr: &[u8; 32], packet: Vec<u8>) -> bool {
        match self.by_addr.get(node_addr) {
            Some(p) => p.tx.try_send(packet).is_ok(),
            None => false,
        }
    }

    /// Descriptors learnt from peers (signed by the peers themselves).
    pub fn descriptors(&self) -> Vec<Signed<NodeDescriptor>> {
        self.descriptors
            .lock()
            .expect("descriptors")
            .values()
            .cloned()
            .collect()
    }
}

async fn dialler(
    keys: NodeKeys,
    id: [u8; 32],
    endpoint: String,
    mut rx: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Vec<u8>>,
    descriptors: Arc<Mutex<HashMap<[u8; 32], Signed<NodeDescriptor>>>>,
    rate: Arc<Rate>,
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
            net::connect(addr, &keys.noise, Some(&keys.identity), Some(id)).await
        else {
            if wait_or_closed(&mut rx, &mut backoff).await {
                return;
            }
            continue;
        };
        backoff = BACKOFF_MIN;
        // Learn the peer's descriptor.
        let _ = writer
            .send(
                &LinkFrame {
                    kind: FrameKind::DirectoryReq,
                    body: Vec::new(),
                },
                SizeClass::Small,
            )
            .await;
        // Aborted when this iteration ends (link lost or dialler aborted).
        let mut read_task = AbortOnDrop({
            let (inbound, descriptors) = (inbound.clone(), descriptors.clone());
            tokio::spawn(async move {
                while let Ok((_, frame)) = reader.recv().await {
                    match frame.kind {
                        FrameKind::Sphinx => {
                            let _ = inbound.try_send(frame.body);
                        }
                        FrameKind::Directory => remember_descriptor(&frame.body, &id, &descriptors),
                        _ => {}
                    }
                }
            })
        });
        // Pump our packets (or padding) to the peer until the link breaks.
        loop {
            tokio::select! {
                batch = shaper.next(&mut rx) => {
                    let Some(batch) = batch else { return };
                    if !send_batch(&mut writer, batch).await {
                        break;
                    }
                }
                _ = &mut read_task.0 => break,
            }
        }
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

/// Keep the peer's own self-signed descriptor from its directory.
fn remember_descriptor(
    body: &[u8],
    id: &[u8; 32],
    store: &Mutex<HashMap<[u8; 32], Signed<NodeDescriptor>>>,
) {
    let Ok(dir) = cbor::from_slice::<Signed<Directory>>(body, 1 << 20) else {
        return;
    };
    let Ok(dir) = dir.verify() else { return };
    if dir.issuer != *id {
        return;
    }
    for e in dir.entries {
        if let Ok(d) = e.descriptor.verify() {
            if d.id_pub == *id {
                store.lock().expect("descriptors").insert(*id, e.descriptor);
            }
        }
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

    #[tokio::test]
    async fn addr_maps_to_peer_and_unknown_is_false() {
        let keys = NodeKeys::generate();
        let (tx, _rx) = mpsc::channel(8);
        let peers = Peers::start(&keys, vec![([5; 32], "127.0.0.1:1".into())], tx, 0.0);
        assert!(peers.is_peer(&[5; 32]));
        assert!(!peers.is_peer(&[6; 32]));
        assert!(peers.send(&node_address(&[5; 32]), vec![1]));
        assert!(!peers.send(&node_address(&[6; 32]), vec![1]));
    }

    #[tokio::test]
    async fn own_id_is_not_a_peer() {
        let keys = NodeKeys::generate();
        let (tx, _rx) = mpsc::channel(8);
        let peers = Peers::start(
            &keys,
            vec![(keys.identity.public(), "127.0.0.1:1".into())],
            tx,
            0.0,
        );
        assert!(peers.ids().is_empty());
    }

    #[tokio::test]
    async fn queue_overflow_drops() {
        let keys = NodeKeys::generate();
        let (tx, _rx) = mpsc::channel(8);
        // Port 1 refuses connections: nothing drains the queue for a while.
        let peers = Peers::start(&keys, vec![([5; 32], "127.0.0.1:1".into())], tx, 0.0);
        let addr = node_address(&[5; 32]);
        let accepted = (0..PEER_QUEUE + 10)
            .filter(|_| peers.send(&addr, vec![0]))
            .count();
        assert!(accepted <= PEER_QUEUE);
        assert!(accepted > 0);
    }
}
