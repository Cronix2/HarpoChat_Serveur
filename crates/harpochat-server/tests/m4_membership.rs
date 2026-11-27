// SPDX-License-Identifier: Apache-2.0
//! Milestone M4: a node joins the mesh with one copy-paste; its sponsorship
//! chain is gossiped to every node; a revocation removes it everywhere.
//!
//! R is a root. J joins with a token from R, then K with a token from J
//! (chain K ← J ← R). A phone exchanges a message through the three nodes.
//! R revokes K: K disappears from R's directory, then from J's by gossip.

#[allow(dead_code)] // helpers shared with the other milestone tests
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::mesh::{directory_at, exchange, fast_cover, now};
use harpochat_core::directory::{Revoke, VerifiedNode};
use harpochat_core::invite::encode_token;
use harpochat_core::path::Candidate;
use harpochat_core::signed::Signed;
use harpochat_server::config::Config;
use harpochat_server::join::{join_mesh, JoinError};
use harpochat_server::keystore::{self, NodeKeys};
use harpochat_server::membership::Membership;
use harpochat_server::node::Node;
use harpochat_server::router::system_clock;
use harpochat_server::server::Server;
use harpochat_server::sponsor::create_invite;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

struct Running {
    addr: SocketAddr,
    id: [u8; 32],
    membership: Arc<Membership>,
    router: Arc<harpochat_server::router::Router>,
    peers: Arc<harpochat_server::peers::Peers>,
    _stop: oneshot::Sender<()>,
}

fn counters(name: &str, r: &Running) -> String {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &r.router.counters;
    format!(
        "{name}: in {} dropped {} delivered {} peers {}",
        c.packets_in.load(Relaxed),
        c.packets_dropped.load(Relaxed),
        c.delivered.load(Relaxed),
        r.peers.ids().len()
    )
}

async fn bind() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ep = format!("wss://{}", l.local_addr().unwrap());
    (l, ep)
}

/// Fast cover for tests, written into the node's own configuration.
fn speed_up(dir: &Path) {
    let text = std::fs::read_to_string(dir.join("harpochat-server.toml")).unwrap();
    let mut c = Config::parse(&text).unwrap();
    c.cover = fast_cover();
    c.save(dir).unwrap();
}

fn start(dir: &Path, listener: TcpListener) -> Running {
    let node = Node::load(dir, now()).unwrap();
    let id = node.keys.identity.public();
    let server = Server::new(node, system_clock()).unwrap();
    let membership = server.membership();
    let router = server.router();
    let peers = server.peers();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = server
            .run(listener, async {
                let _ = rx.await;
            })
            .await;
    });
    Running {
        addr,
        id,
        membership,
        router,
        peers,
        _stop: stop,
    }
}

fn token_from(dir: &Path) -> String {
    let node = Node::load(dir, now()).unwrap();
    encode_token(&create_invite(&node, now(), 3600).unwrap())
}

/// Poll `node`'s directory (trusting `roots`) until `pred` holds.
async fn wait_directory(
    node: &Running,
    roots: &[[u8; 32]],
    what: &str,
    pred: impl Fn(&[VerifiedNode]) -> bool,
) -> Vec<VerifiedNode> {
    for _ in 0..120 {
        if let Some(nodes) = directory_at(node.addr, node.id, roots).await {
            if pred(&nodes) {
                return nodes;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("directory never showed: {what}");
}

fn ids(nodes: &[VerifiedNode]) -> Vec<[u8; 32]> {
    nodes.iter().map(|n| n.descriptor.id_pub).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_chain_and_revoke() {
    let tmp = tempfile::tempdir().unwrap();
    let (r_dir, j_dir, k_dir) = (
        tmp.path().join("r"),
        tmp.path().join("j"),
        tmp.path().join("k"),
    );

    // R: a root, as `init --root` makes it.
    let (r_listener, r_ep) = bind().await;
    std::fs::create_dir_all(&r_dir).unwrap();
    let r_keys = NodeKeys::generate();
    keystore::save(&r_dir, &r_keys).unwrap();
    let mut c = Config::default();
    c.node.root = true;
    c.node.public_endpoints = vec![r_ep];
    c.cover = fast_cover();
    c.save(&r_dir).unwrap();
    let roots = [r_keys.identity.public()];

    // One copy-paste: a token from R (issued offline), `join` on J.
    let token = token_from(&r_dir);
    let r = start(&r_dir, r_listener);
    let (j_listener, j_ep) = bind().await;
    let joined = join_mesh(&j_dir, &token, vec![j_ep], now()).await.unwrap();
    assert_eq!(joined.sponsor, r.id);
    assert_eq!(joined.chain_len, 1);
    // The token is burned: a second machine cannot reuse it.
    let again = join_mesh(&tmp.path().join("x"), &token, vec![], now()).await;
    assert!(matches!(again, Err(JoinError::Refused)), "{again:?}");
    assert!(!tmp.path().join("x").exists(), "nothing written on refusal");
    speed_up(&j_dir);
    let j = start(&j_dir, j_listener);

    // R's directory now carries J, anchored to R.
    let nodes = wait_directory(&r, &roots, "J at R", |n| n.len() == 2).await;
    assert!(ids(&nodes).contains(&j.id));
    // J serves the same view.
    wait_directory(&j, &roots, "R and J at J", |n| n.len() == 2).await;

    // K joins through J: chain K ← J ← R.
    let token = token_from(&j_dir);
    let (k_listener, k_ep) = bind().await;
    let joined = join_mesh(&k_dir, &token, vec![k_ep], now()).await.unwrap();
    assert_eq!(joined.chain_len, 2);
    speed_up(&k_dir);
    let k = start(&k_dir, k_listener);
    // R learns K by gossip (it never talked to K's sponsor about it).
    let nodes = wait_directory(&r, &roots, "K at R", |n| n.len() == 3).await;
    let k_entry = nodes.iter().find(|n| n.descriptor.id_pub == k.id).unwrap();
    assert_eq!(k_entry.sponsor, Some(j.id));

    // A message crosses the three admitted nodes (gateway J → mix → mailbox,
    // replies back through a SURB) — once every node knows the others, and
    // R announces the Sphinx key each node uses now (not the one of `join`).
    wait_directory(&j, &roots, "all at J", |n| n.len() == 3).await;
    wait_directory(&k, &roots, "all at K", |n| n.len() == 3).await;
    let current = |who: &Running, own: &[VerifiedNode]| {
        own.iter()
            .find(|n| n.descriptor.id_pub == who.id)
            .unwrap()
            .descriptor
            .sphinx_pub
    };
    let (j_key, k_key) = (
        current(&j, &wait_directory(&j, &roots, "J", |_| true).await),
        current(&k, &wait_directory(&k, &roots, "K", |_| true).await),
    );
    let nodes = wait_directory(&r, &roots, "current keys at R", |n| {
        n.len() == 3 && current(&j, n) == j_key && current(&k, n) == k_key
    })
    .await;
    let cands: Vec<Candidate> = nodes.iter().map(Candidate::from).collect();
    let endpoints = [(r.addr, r.id), (j.addr, j.id), (k.addr, k.id)];
    tokio::time::sleep(Duration::from_secs(2)).await; // links up both ways
    let before = [counters("R", &r), counters("J", &j), counters("K", &k)];
    let ex =
        tokio::spawn(async move { exchange(&endpoints, &cands, 1, 2, b"via joined nodes").await })
            .await;
    let after = [counters("R", &r), counters("J", &j), counters("K", &k)];
    let (_, blobs) = ex.unwrap_or_else(|e| {
        panic!(
            "{e}
before {before:?}
after {after:?}"
        )
    });
    assert_eq!(blobs, vec![b"via joined nodes".to_vec()]);

    // R (a root) revokes K: gone from R at once, then from J by gossip.
    let revoke = Signed::sign(
        &r_keys.identity,
        &Revoke {
            v: 1,
            node_id: k.id,
            sponsor_id: r.id,
            revoked_at: now(),
        },
    );
    let changes = r.membership.revoke(revoke, now());
    assert_eq!(changes.removed, vec![k.id]);
    wait_directory(&r, &roots, "K gone at R", |n| !ids(n).contains(&k.id)).await;
    wait_directory(&j, &roots, "K gone at J", |n| !ids(n).contains(&k.id)).await;
    assert!(!j.membership.is_member(&k.id));
}
