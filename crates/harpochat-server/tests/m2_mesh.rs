// SPDX-License-Identifier: Apache-2.0
//! Milestone M2: five nodes, multi-hop Sphinx routes with delays, replies
//! through SURBs, mailboxes that never see the recipient's link.

#[allow(dead_code)] // helpers shared with m1_single_hop
mod common;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use common::client::Client;
use harpochat_core::directory::{verify_directory, Directory, VerifiedNode};
use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::{random_bytes, SigningKey};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{epoch_of, sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::path::{self, Candidate, DEFAULT_MEAN_DELAY_MS, MAILBOX_REPLICAS};
use harpochat_core::signed::Signed;
use harpochat_core::sphinx::{self, Hop, LOCAL_DELIVERY};
use harpochat_server::config::{Config, PeerConfig, RootConfig};
use harpochat_server::keystore::NodeKeys;
use harpochat_server::node::Node;
use harpochat_server::router::{system_clock, Router};
use harpochat_server::server::Server;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct MeshNode {
    addr: SocketAddr,
    id: [u8; 32],
    router: Arc<Router>,
    stop: Option<oneshot::Sender<()>>,
}

async fn start_mesh(n: usize) -> Vec<MeshNode> {
    let mut listeners = Vec::new();
    for _ in 0..n {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    let addrs: Vec<SocketAddr> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    let keys: Vec<NodeKeys> = (0..n).map(|_| NodeKeys::generate()).collect();
    let ids: Vec<[u8; 32]> = keys.iter().map(|k| k.identity.public()).collect();
    let mut mesh = Vec::new();
    for (i, listener) in listeners.into_iter().enumerate() {
        let mut config = Config::default();
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

/// Ask `node` for its directory until it lists `expected` verified nodes.
async fn directory(node: &MeshNode, roots: &[[u8; 32]], expected: usize) -> Vec<VerifiedNode> {
    for _ in 0..100 {
        let hop = Hop {
            id_pub: node.id,
            sphinx_pub: [0; 32], // unused for the directory exchange
        };
        let mut c = Client::connect(node.addr, hop).await.unwrap();
        c.writer
            .send(
                &LinkFrame {
                    kind: FrameKind::DirectoryReq,
                    body: vec![],
                },
                SizeClass::Small,
            )
            .await
            .unwrap();
        if let Ok(Ok((_, f))) = tokio::time::timeout(Duration::from_secs(2), c.reader.recv()).await
        {
            let d: Signed<Directory> = harpochat_core::cbor::from_slice(&f.body, 1 << 20).unwrap();
            let nodes = verify_directory(&d, roots, now()).unwrap();
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

fn forward(cands: &[Candidate], gw: &[u8; 32], mbx: &[u8; 32]) -> path::Route {
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

fn reply(cands: &[Candidate], gw: &[u8; 32], mbx: &[u8; 32]) -> path::Route {
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

async fn send(c: &mut Client, route: &path::Route, msg: &Message) {
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

/// A puts into every replica that is not its gateway; B fetches the first
/// replica that is neither gateway; returns (replica used, blobs received).
async fn exchange(
    mesh: &[MeshNode],
    cands: &[Candidate],
    gw_a: usize,
    gw_b: usize,
    payload: &[u8],
) -> ([u8; 32], Vec<Vec<u8>>) {
    let hop_of = |i: usize| {
        cands
            .iter()
            .find(|c| c.hop.id_pub == mesh[i].id)
            .unwrap()
            .hop
    };
    let k = MailboxKeys::derive(&random_bytes(), epoch_of(now()));
    let replicas = path::mailbox_nodes(&k.mailbox_id(), cands, MAILBOX_REPLICAS);

    let mut alice = Client::connect(mesh[gw_a].addr, hop_of(gw_a))
        .await
        .unwrap();
    for r in replicas.iter().filter(|r| **r != mesh[gw_a].id) {
        let msg = Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(&k, payload, random_bytes()),
            blob: payload.to_vec(),
        };
        send(&mut alice, &forward(cands, &mesh[gw_a].id, r), &msg).await;
    }
    // Mix delays (mean 100 ms) plus link latency.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let target = *replicas
        .iter()
        .find(|r| **r != mesh[gw_a].id && **r != mesh[gw_b].id)
        .expect("a replica outside both gateways");
    let mut bob = Client::connect(mesh[gw_b].addr, hop_of(gw_b))
        .await
        .unwrap();
    let surb_route = reply(cands, &mesh[gw_b].id, &target);
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
    send(&mut bob, &forward(cands, &mesh[gw_b].id, &target), &fetch).await;
    let (_, frame) = tokio::time::timeout(Duration::from_secs(10), bob.reader.recv())
        .await
        .expect("reply in time")
        .unwrap();
    assert_eq!(frame.kind, FrameKind::Deliver);
    assert_eq!(frame.body[..16], surb_id);
    let plain = sphinx::recover_reply(&rec, &frame.body[16..]).unwrap();
    let Message::FetchResponse { blobs, .. } = envelope::decode(&plain).unwrap() else {
        panic!("expected FetchResponse")
    };
    (target, blobs.into_iter().map(|b| b.blob).collect())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_and_fetch_across_five_nodes() {
    let mesh = start_mesh(5).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[0], &roots, 5).await;
    let cands: Vec<Candidate> = nodes.iter().map(Candidate::from).collect();

    let (target, blobs) = exchange(&mesh, &cands, 0, 1, b"across the mesh").await;
    assert_eq!(blobs, vec![b"across the mesh".to_vec()]);

    // The mailbox that answered holds no phone link at all: it only ever saw
    // packets coming from other nodes, never the recipient's connection.
    let mbx = mesh.iter().find(|m| m.id == target).unwrap();
    assert!(mbx.router.inboxes.is_empty());
    assert!(mbx.router.counters.packets_in.load(Ordering::Relaxed) > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directory_lists_whole_mesh() {
    let mesh = start_mesh(5).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[2], &roots, 5).await;
    assert_eq!(nodes.len(), 5);
    // Trusting only a stranger's key, nothing in the same mesh verifies.
    let stranger = [SigningKey::generate().public()];
    let only_stranger = directory_with(&mesh[2], &stranger).await;
    assert!(only_stranger.is_empty());
}

async fn directory_with(node: &MeshNode, roots: &[[u8; 32]]) -> Vec<VerifiedNode> {
    let hop = Hop {
        id_pub: node.id,
        sphinx_pub: [0; 32],
    };
    let mut c = Client::connect(node.addr, hop).await.unwrap();
    c.writer
        .send(
            &LinkFrame {
                kind: FrameKind::DirectoryReq,
                body: vec![],
            },
            SizeClass::Small,
        )
        .await
        .unwrap();
    let (_, f) = tokio::time::timeout(Duration::from_secs(2), c.reader.recv())
        .await
        .unwrap()
        .unwrap();
    let d: Signed<Directory> = harpochat_core::cbor::from_slice(&f.body, 1 << 20).unwrap();
    verify_directory(&d, roots, now()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_survives_a_dead_node() {
    let mut mesh = start_mesh(5).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[0], &roots, 5).await;
    let dead = mesh[4].id;
    let _ = mesh[4].stop.take().unwrap().send(());
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Clients drop the dead node from their view (as a real app would after
    // failed loops); the rest of the mesh keeps working.
    let cands: Vec<Candidate> = nodes
        .iter()
        .map(Candidate::from)
        .filter(|c| c.hop.id_pub != dead)
        .collect();
    let (_, blobs) = exchange(&mesh, &cands, 0, 1, b"still alive").await;
    assert_eq!(blobs, vec![b"still alive".to_vec()]);
}
