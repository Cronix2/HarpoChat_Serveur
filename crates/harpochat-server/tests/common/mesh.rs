// SPDX-License-Identifier: Apache-2.0
//! An in-process mesh: `n` nodes on loopback, each a root and a static peer
//! of every other, all roles. Plus the client-side helpers to use it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use harpochat_core::directory::{verify_directory, Directory, VerifiedNode};
use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::random_bytes;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{epoch_of, sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::path::{self, Candidate, DEFAULT_MEAN_DELAY_MS, MAILBOX_REPLICAS};
use harpochat_core::signed::Signed;
use harpochat_core::sphinx::{self, Hop, LOCAL_DELIVERY};
use harpochat_server::config::{Config, Cover, PeerConfig, RootConfig};
use harpochat_server::keystore::NodeKeys;
use harpochat_server::node::Node;
use harpochat_server::router::{system_clock, Router};
use harpochat_server::server::Server;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::client::{recv_skipping_padding, Client};

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Cover rates high enough for fast tests (links at 50 Hz and 20 Hz).
pub fn fast_cover() -> Cover {
    Cover {
        node_link_rate: 50.0,
        phone_link_rate: 20.0,
        phone_link_rate_min: 0.05,
        phone_link_rate_max: 50.0,
        loop_rate: 2.0,
        drop_rate: 1.0,
        mean_delay_ms: 50,
    }
}

pub struct MeshNode {
    pub addr: SocketAddr,
    pub id: [u8; 32],
    pub router: Arc<Router>,
    pub stop: Option<oneshot::Sender<()>>,
}

impl MeshNode {
    pub fn stop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

pub async fn start_mesh(n: usize, cover: Cover) -> Vec<MeshNode> {
    let mut listeners = Vec::new();
    for _ in 0..n {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addrs: Vec<SocketAddr> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    let keys: Vec<NodeKeys> = (0..n).map(|_| NodeKeys::generate()).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.identity.public()).collect();
    let mut mesh = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let mut config = Config {
            cover: cover.clone(),
            ..Config::default()
        };
        config.node.root = true;
        config.node.public_endpoints = vec![format!("wss://{}", addrs[i])];
        for j in (0..n).filter(|j| *j != i) {
            config.roots.push(RootConfig {
                id_pub: hex::encode(ids[j]),
                endpoints: vec![format!("wss://{}", addrs[j])],
            });
            config.peers.push(PeerConfig {
                id_pub: hex::encode(ids[j]),
                endpoint: format!("wss://{}", addrs[j]),
            });
        }
        let node = Node::new(config, keys[i].clone(), now()).unwrap();
        let server = Server::new(node, system_clock()).unwrap();
        let router = server.router();
        let (stop, rx) = oneshot::channel();
        tokio::spawn(async move {
            server
                .run(listener, async {
                    let _ = rx.await;
                })
                .await
                .unwrap();
        });
        mesh.push(MeshNode {
            addr: addrs[i],
            id: ids[i],
            router,
            stop: Some(stop),
        });
    }
    mesh
}

/// One directory request to the node `id` at `addr`; the verified nodes,
/// if an answer came.
pub async fn directory_at(
    addr: SocketAddr,
    id: [u8; 32],
    roots: &[[u8; 32]],
) -> Option<Vec<VerifiedNode>> {
    let hop = Hop {
        id_pub: id,
        sphinx_pub: [0; 32], // unused for the directory exchange
    };
    let mut c = Client::connect(addr, hop).await.ok()?;
    c.writer
        .send(
            &LinkFrame {
                kind: FrameKind::DirectoryReq,
                body: vec![],
            },
            SizeClass::Small,
        )
        .await
        .ok()?;
    let (_, f) = c.recv_real(Duration::from_secs(2)).await?;
    let d: Signed<Directory> = harpochat_core::cbor::from_slice(&f.body, 1 << 20).ok()?;
    verify_directory(&d, roots, now()).ok()
}

/// One directory request to a mesh node.
pub async fn directory_once(node: &MeshNode, roots: &[[u8; 32]]) -> Option<Vec<VerifiedNode>> {
    directory_at(node.addr, node.id, roots).await
}

/// Ask `node` for its directory until it lists `expected` verified nodes.
pub async fn directory(node: &MeshNode, roots: &[[u8; 32]], expected: usize) -> Vec<VerifiedNode> {
    for _ in 0..100 {
        if let Some(nodes) = directory_once(node, roots).await {
            if nodes.len() >= expected {
                return nodes;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("directory never reached {expected} nodes");
}

fn rng_pick(n: usize) -> usize {
    (u64::from_le_bytes(random_bytes()) % n as u64) as usize
}

fn rng_uniform() -> f64 {
    (u64::from_le_bytes(random_bytes()) >> 11) as f64 / (1u64 << 53) as f64
}

pub fn forward(cands: &[Candidate], gw: &[u8; 32], mbx: &[u8; 32]) -> path::Route {
    path::forward_route(
        cands,
        gw,
        mbx,
        &mut rng_pick,
        &mut rng_uniform,
        DEFAULT_MEAN_DELAY_MS,
    )
    .unwrap()
}

pub fn reply(cands: &[Candidate], gw: &[u8; 32], mbx: &[u8; 32]) -> path::Route {
    path::reply_route(
        cands,
        gw,
        mbx,
        &mut rng_pick,
        &mut rng_uniform,
        DEFAULT_MEAN_DELAY_MS,
    )
    .unwrap()
}

pub fn hop_of(cands: &[Candidate], id: &[u8; 32]) -> Hop {
    cands.iter().find(|c| c.hop.id_pub == *id).unwrap().hop
}

/// Send `msg` along `route` as a Small Sphinx packet.
pub async fn send(c: &mut Client, route: &path::Route, msg: &Message) {
    let pkt = sphinx::build_forward(
        &envelope::encode(msg),
        &route.hops,
        LOCAL_DELIVERY,
        &route.delays_ms,
        SizeClass::Small,
        None,
    )
    .unwrap();
    c.writer
        .send(
            &LinkFrame {
                kind: FrameKind::Sphinx,
                body: pkt,
            },
            SizeClass::Small,
        )
        .await
        .unwrap();
}

/// Next `Deliver` frame within `within`: `(surb_id, payload)`.
pub async fn next_deliver(c: &mut Client, within: Duration) -> Option<([u8; 16], Vec<u8>)> {
    let (_, frame) = recv_skipping_padding(&mut c.reader, within).await?.ok()?;
    assert_eq!(frame.kind, FrameKind::Deliver);
    Some((
        frame.body[..16].try_into().unwrap(),
        frame.body[16..].to_vec(),
    ))
}

/// A puts into every replica that is not its gateway; B fetches the first
/// replica that is neither gateway; returns (replica used, blobs received).
pub async fn exchange(
    mesh: &[(SocketAddr, [u8; 32])],
    cands: &[Candidate],
    gw_a: usize,
    gw_b: usize,
    payload: &[u8],
) -> ([u8; 32], Vec<Vec<u8>>) {
    let k = MailboxKeys::derive(&random_bytes(), epoch_of(now()));
    let replicas = path::mailbox_nodes(&k.mailbox_id(), cands, MAILBOX_REPLICAS);

    let mut alice = Client::connect(mesh[gw_a].0, hop_of(cands, &mesh[gw_a].1))
        .await
        .unwrap();
    for r in replicas.iter().filter(|r| **r != mesh[gw_a].1) {
        let msg = Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(&k, payload, random_bytes()),
            blob: payload.to_vec(),
        };
        send(&mut alice, &forward(cands, &mesh[gw_a].1, r), &msg).await;
    }
    // Mix delays (mean 100 ms), link slots (50 Hz) and loopback latency.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let target = *replicas
        .iter()
        .find(|r| **r != mesh[gw_a].1 && **r != mesh[gw_b].1)
        .expect("a replica outside both gateways");
    let mut bob = Client::connect(mesh[gw_b].0, hop_of(cands, &mesh[gw_b].1))
        .await
        .unwrap();
    let surb_route = reply(cands, &mesh[gw_b].1, &target);
    let surb_id = random_bytes();
    let (surb, rec) =
        sphinx::create_surb(&surb_route.hops, bob.inbox, surb_id, &surb_route.delays_ms).unwrap();
    let unsigned = Message::Fetch {
        mailbox_id: k.mailbox_id(),
        read_auth: sign_read(&k, ReadOp::Fetch, b"", now(), [0; 16]),
        max: 16,
        surbs: vec![surb.clone()],
    };
    let (op, bound) = envelope::read_bound(&unsigned).unwrap();
    let fetch = Message::Fetch {
        mailbox_id: k.mailbox_id(),
        read_auth: sign_read(&k, op, &bound, now(), random_bytes()),
        max: 16,
        surbs: vec![surb],
    };
    send(&mut bob, &forward(cands, &mesh[gw_b].1, &target), &fetch).await;
    let (id, payload) = next_deliver(&mut bob, Duration::from_secs(10))
        .await
        .expect("reply in time");
    assert_eq!(id, surb_id);
    let plain = sphinx::recover_reply(&rec, &payload).unwrap();
    let Message::FetchResponse { blobs, .. } = envelope::decode(&plain).unwrap() else {
        panic!("expected FetchResponse")
    };
    (target, blobs.into_iter().map(|b| b.blob).collect())
}
