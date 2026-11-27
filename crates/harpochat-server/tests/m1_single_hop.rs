// SPDX-License-Identifier: Apache-2.0
//! Milestone M1: two clients exchange a blob through one node; a restart
//! wipes everything.

#[allow(dead_code)] // helpers shared with m2_mesh
mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::client::Client;
use harpochat_core::directory::{verify_directory, Directory};
use harpochat_core::envelope::Message;
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{epoch_of, MailboxKeys};
use harpochat_core::signed::Signed;
use harpochat_core::sphinx::Hop;
use harpochat_server::config::Config;
use harpochat_server::keystore::NodeKeys;
use harpochat_server::node::Node;
use harpochat_server::server::serve;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Running {
    addr: SocketAddr,
    hop: Hop,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

async fn start(keys: NodeKeys) -> Running {
    let mut config = Config::default();
    config.node.root = true;
    config.node.public_endpoints = vec!["wss://127.0.0.1".into()];
    let node = Node::new(config, keys, now()).unwrap();
    let hop = Hop {
        id_pub: node.keys.identity.public(),
        sphinx_pub: node.sphinx.public(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        serve(
            node,
            listener,
            harpochat_server::router::system_clock(),
            async {
                let _ = rx.await;
            },
        )
        .await
        .unwrap();
    });
    Running {
        addr,
        hop,
        stop,
        task,
    }
}

async fn stop(r: Running) {
    let _ = r.stop.send(());
    r.task.await.unwrap();
}

fn box_a_to_b() -> MailboxKeys {
    MailboxKeys::derive(&[0x42; 32], epoch_of(now()))
}

fn blobs(m: Message) -> Vec<([u8; 16], Vec<u8>)> {
    match m {
        Message::FetchResponse { blobs, .. } => blobs.into_iter().map(|b| (b.id, b.blob)).collect(),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn two_clients_exchange_a_blob() {
    let node = start(NodeKeys::generate()).await;
    let k = box_a_to_b();
    let mut alice = Client::connect(node.addr, node.hop).await.unwrap();
    let mut bob = Client::connect(node.addr, node.hop).await.unwrap();

    alice.put(&k, b"ciphertext from alice").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let got = blobs(bob.fetch(&k, now()).await.expect("reply"));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].1, b"ciphertext from alice");

    bob.ack(&k, vec![got[0].0], now()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(blobs(bob.fetch(&k, now()).await.expect("reply")).is_empty());
    stop(node).await;
}

#[tokio::test]
async fn restart_wipes_mailboxes() {
    let keys = NodeKeys::generate();
    let node = start(keys.clone()).await;
    let k = box_a_to_b();
    let mut alice = Client::connect(node.addr, node.hop).await.unwrap();
    alice.put(&k, b"will not survive").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop(node).await;

    let node = start(keys).await;
    let mut bob = Client::connect(node.addr, node.hop).await.unwrap();
    assert!(blobs(bob.fetch(&k, now()).await.expect("reply")).is_empty());
    stop(node).await;
}

#[tokio::test]
async fn client_authenticates_node_identity() {
    let node = start(NodeKeys::generate()).await;
    let mut wrong = node.hop;
    wrong.id_pub = [9; 32];
    assert!(Client::connect(node.addr, wrong).await.is_err());
    assert!(Client::connect(node.addr, node.hop).await.is_ok());
    stop(node).await;
}

#[tokio::test]
async fn wrong_size_frame_closes_link() {
    let node = start(NodeKeys::generate()).await;
    let mut c = Client::connect(node.addr, node.hop).await.unwrap();
    c.writer.send_raw(vec![0; 100]).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), c.reader.recv())
        .await
        .unwrap();
    assert!(r.is_err(), "link must be closed");
    // The node still serves others.
    assert!(Client::connect(node.addr, node.hop).await.is_ok());
    stop(node).await;
}

#[tokio::test]
async fn directory_request_returns_signed_self() {
    let node = start(NodeKeys::generate()).await;
    let mut c = Client::connect(node.addr, node.hop).await.unwrap();
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
    let (class, frame) = tokio::time::timeout(Duration::from_secs(5), c.reader.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.kind, FrameKind::Directory);
    assert_eq!(class, SizeClass::Small);
    let dir: Signed<Directory> = harpochat_core::cbor::from_slice(&frame.body, 1 << 20).unwrap();
    let nodes = verify_directory(&dir, &[node.hop.id_pub], now()).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].descriptor.sphinx_pub, node.hop.sphinx_pub);
    stop(node).await;
}
