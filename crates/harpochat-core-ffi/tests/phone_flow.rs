// SPDX-License-Identifier: Apache-2.0
//! The Android code path, end to end: a "phone" that only uses the FFI API
//! (exactly what Kotlin will call) talks to a real `harpochat-server` over
//! TLS + WebSocket. The test owns the socket, as the app will.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use harpochat_core_ffi::*;
use harpochat_server::config::Config;
use harpochat_server::keystore::NodeKeys;
use harpochat_server::node::Node;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as Ws;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

struct Phone {
    ws: WsStream,
    transport: std::sync::Arc<FfiTransport>,
    inbox: Vec<u8>,
}

impl Phone {
    async fn connect(addr: std::net::SocketAddr, expected_node: &[u8]) -> Phone {
        // Socket + TLS (any certificate) + WebSocket: the app's job.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = harpochat_server::net::tls_connector()
            .unwrap()
            .connect(rustls_name(), tcp)
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("wss://harpochat/", tls)
            .await
            .unwrap();

        // Noise XX through the FFI.
        let hs = FfiHandshake::initiator().unwrap();
        ws.send(Ws::Binary(hs.write_message().unwrap().into()))
            .await
            .unwrap();
        let m2 = next_binary(&mut ws).await;
        hs.read_message(m2).unwrap();
        ws.send(Ws::Binary(hs.write_message().unwrap().into()))
            .await
            .unwrap();
        let session = hs.finish().unwrap();
        assert_eq!(
            session.peer_node_id.as_deref(),
            Some(expected_node),
            "node identity"
        );

        let mut phone = Phone {
            ws,
            transport: session.transport,
            inbox: random_bytes(32).unwrap(),
        };
        phone
            .send(FfiFrameKind::RegisterInbox, phone.inbox.clone())
            .await;
        phone
    }

    async fn send(&mut self, kind: FfiFrameKind, body: Vec<u8>) {
        let frame = encode_frame(kind, body, FfiSizeClass::Small).unwrap();
        let ct = self.transport.encrypt(frame).unwrap();
        self.ws.send(Ws::Binary(ct.into())).await.unwrap();
    }

    /// Next frame that is not link padding (the app ignores padding).
    async fn recv(&mut self) -> FfiFrame {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let m = tokio::time::timeout_at(deadline, next_binary(&mut self.ws))
                .await
                .expect("frame in time");
            let f = decode_frame(self.transport.decrypt(m).unwrap()).unwrap();
            if f.kind != FfiFrameKind::Padding {
                return f;
            }
        }
    }
}

fn rustls_name() -> rustls_pki_name::ServerName<'static> {
    rustls_pki_name::ServerName::try_from("harpochat").unwrap()
}

mod rustls_pki_name {
    pub use tokio_rustls::rustls::pki_types::ServerName;
}

async fn next_binary(ws: &mut WsStream) -> Vec<u8> {
    loop {
        match ws.next().await.unwrap().unwrap() {
            Ws::Binary(b) => return b.to_vec(),
            Ws::Ping(_) | Ws::Pong(_) => continue,
            other => panic!("unexpected {other:?}"),
        }
    }
}

#[tokio::test]
async fn phone_exchanges_a_blob_through_ffi_only() {
    // A real node.
    let mut config = Config::default();
    config.node.root = true;
    config.node.public_endpoints = vec!["wss://127.0.0.1".into()];
    let node = Node::new(config, NodeKeys::generate(), now()).unwrap();
    let node_id = node.keys.identity.public().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(harpochat_server::server::serve(
        node,
        listener,
        harpochat_server::router::system_clock(),
        std::future::pending(),
    ));

    // Bootstrap-like step: learn the node's Sphinx key from its directory.
    let mut alice = Phone::connect(addr, &node_id).await;
    alice.send(FfiFrameKind::DirectoryReq, vec![]).await;
    let dir = alice.recv().await;
    assert_eq!(dir.kind, FfiFrameKind::Directory);
    let nodes = verify_directory(dir.body, vec![node_id.clone()], now()).unwrap();
    assert_eq!(nodes.len(), 1);
    let hop = FfiHop {
        id_pub: nodes[0].id_pub.clone(),
        sphinx_pub: nodes[0].sphinx_pub.clone(),
    };

    // Alice → Bob mailbox, current epoch.
    let pair_secret = random_bytes(32).unwrap();
    let keys = FfiMailboxKeys::derive(pair_secret.clone(), epoch_of(now())).unwrap();
    let put = build_put(&keys, b"E2EE ciphertext".to_vec()).unwrap();
    let pkt = build_forward(
        put,
        vec![hop.clone()],
        local_delivery(),
        vec![0],
        FfiSizeClass::Small,
    )
    .unwrap();
    alice.send(FfiFrameKind::Sphinx, pkt).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob fetches with a SURB to his own inbox.
    let mut bob = Phone::connect(addr, &node_id).await;
    let bob_keys = FfiMailboxKeys::derive(pair_secret, epoch_of(now())).unwrap();
    let surb_id = random_bytes(16).unwrap();
    let surb = create_surb(
        vec![hop.clone()],
        bob.inbox.clone(),
        surb_id.clone(),
        vec![0],
    )
    .unwrap();
    let fetch = build_fetch(&bob_keys, 10, vec![surb.surb.clone()], now()).unwrap();
    let pkt = build_forward(
        fetch,
        vec![hop.clone()],
        local_delivery(),
        vec![0],
        FfiSizeClass::Small,
    )
    .unwrap();
    bob.send(FfiFrameKind::Sphinx, pkt).await;

    let deliver = bob.recv().await;
    assert_eq!(deliver.kind, FfiFrameKind::Deliver);
    assert_eq!(deliver.body[..16], surb_id[..]);
    let reply = recover_reply(surb.recovery, deliver.body[16..].to_vec()).unwrap();
    match decode_message(reply).unwrap() {
        FfiMessage::FetchResponse { blobs, more } => {
            assert_eq!(blobs.len(), 1);
            assert_eq!(blobs[0].blob, b"E2EE ciphertext");
            assert!(!more);
        }
        other => panic!("unexpected {other:?}"),
    }
}

async fn start_node() -> (std::net::SocketAddr, Vec<u8>) {
    let mut config = Config::default();
    config.node.root = true;
    config.node.public_endpoints = vec!["wss://127.0.0.1".into()];
    let node = Node::new(config, NodeKeys::generate(), now()).unwrap();
    let node_id = node.keys.identity.public().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(harpochat_server::server::serve(
        node,
        listener,
        harpochat_server::router::system_clock(),
        std::future::pending(),
    ));
    (addr, node_id)
}

#[tokio::test]
async fn phone_is_pushed_through_ffi_only() {
    let (addr, node_id) = start_node().await;
    let mut bob = Phone::connect(addr, &node_id).await;
    // App in the foreground: ask for a faster downlink (lower latency).
    bob.send(FfiFrameKind::CoverRate, cover_rate_body(5.0).unwrap())
        .await;
    bob.send(FfiFrameKind::DirectoryReq, vec![]).await;
    let dir = bob.recv().await;
    let nodes = verify_directory(dir.body, vec![node_id.clone()], now()).unwrap();
    let hop = FfiHop {
        id_pub: nodes[0].id_pub.clone(),
        sphinx_pub: nodes[0].sphinx_pub.clone(),
    };
    let pair_secret = random_bytes(32).unwrap();
    let keys = FfiMailboxKeys::derive(pair_secret, epoch_of(now())).unwrap();

    // SUBSCRIBE with as many SURBs as fit a Small packet.
    let n = sizes(FfiSizeClass::Small).max_surbs_per_subscribe;
    let surbs: Vec<(Vec<u8>, FfiSurb)> = (0..n)
        .map(|_| {
            let id = random_bytes(16).unwrap();
            let s = create_surb(vec![hop.clone()], bob.inbox.clone(), id.clone(), vec![0]).unwrap();
            (id, s)
        })
        .collect();
    let sub = build_subscribe(
        &keys,
        surbs.iter().map(|(_, s)| s.surb.clone()).collect(),
        now() + 3600,
        now(),
    )
    .unwrap();
    let pkt = build_forward(
        sub,
        vec![hop.clone()],
        local_delivery(),
        vec![0],
        FfiSizeClass::Small,
    )
    .unwrap();
    bob.send(FfiFrameKind::Sphinx, pkt).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Alice writes; Bob is pushed.
    let mut alice = Phone::connect(addr, &node_id).await;
    let put = build_put(&keys, b"pushed".to_vec()).unwrap();
    let pkt = build_forward(
        put,
        vec![hop],
        local_delivery(),
        vec![0],
        FfiSizeClass::Small,
    )
    .unwrap();
    alice.send(FfiFrameKind::Sphinx, pkt).await;

    let deliver = bob.recv().await;
    assert_eq!(deliver.kind, FfiFrameKind::Deliver);
    let (_, surb) = surbs
        .iter()
        .find(|(id, _)| id[..] == deliver.body[..16])
        .expect("one of our SURBs");
    let reply = recover_reply(surb.recovery.clone(), deliver.body[16..].to_vec()).unwrap();
    match decode_message(reply).unwrap() {
        FfiMessage::Push { blobs, .. } => assert_eq!(blobs[0].blob, b"pushed"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn cover_rate_body_rejects_nonsense() {
    assert_eq!(
        cover_rate_body(1.5).unwrap(),
        1500u32.to_be_bytes().to_vec()
    );
    assert!(cover_rate_body(-1.0).is_err());
    assert!(cover_rate_body(f64::NAN).is_err());
}

#[test]
fn argument_lengths_are_checked() {
    assert_eq!(
        FfiMailboxKeys::derive(vec![0; 31], 1).err(),
        Some(FfiError::InvalidArgument)
    );
    let hop = FfiHop {
        id_pub: vec![0; 31],
        sphinx_pub: vec![0; 32],
    };
    assert_eq!(
        build_forward(
            vec![1],
            vec![hop],
            local_delivery(),
            vec![0],
            FfiSizeClass::Small
        )
        .err(),
        Some(FfiError::InvalidArgument)
    );
    assert_eq!(random_bytes(4096).err(), Some(FfiError::InvalidArgument));
    let keys = FfiMailboxKeys::derive(vec![0; 32], 1).unwrap();
    assert_eq!(
        build_ack(&keys, vec![vec![0; 15]], 1).err(),
        Some(FfiError::InvalidArgument)
    );
}

#[test]
fn handshake_cannot_finish_twice_or_early() {
    let hs = FfiHandshake::initiator().unwrap();
    assert!(hs.finish().is_err()); // not finished yet → consumed with an error
    assert_eq!(hs.write_message().err(), Some(FfiError::InvalidArgument));
}

#[test]
fn sizes_match_core_vectors() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../harpochat-core/test-vectors/v1.json"
    ))
    .unwrap();
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let s = sizes(FfiSizeClass::Small);
    assert_eq!(
        s.max_message as u64,
        doc["sizes"]["small"]["max_message"].as_u64().unwrap()
    );
    assert_eq!(
        s.max_surbs_per_subscribe as u64,
        doc["sizes"]["small"]["max_surbs_per_subscribe"]
            .as_u64()
            .unwrap()
    );
    // mailbox_keys vector through the FFI.
    let v = &doc["vectors"]["mailbox_keys"];
    let k = FfiMailboxKeys::derive(
        hex::decode(v["inputs"]["pair_secret"].as_str().unwrap()).unwrap(),
        v["inputs"]["epoch"].as_u64().unwrap() as u32,
    )
    .unwrap();
    let out = [k.write_pub(), k.read_pub(), k.mailbox_id()].concat();
    assert_eq!(hex::encode(out), v["output"].as_str().unwrap());
    // bootstrap and link-frame vectors.
    let b = hex::decode(doc["vectors"]["bootstrap"]["output"].as_str().unwrap()).unwrap();
    assert_eq!(decode_bootstrap(b).unwrap().len(), 2);
    let f = hex::decode(
        doc["vectors"]["link_frame_small"]["output"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let frame = decode_frame(f.clone()).unwrap();
    assert_eq!(
        encode_frame(frame.kind, frame.body, frame.size_class).unwrap(),
        f
    );
}

fn node(n: u8) -> FfiNode {
    FfiNode {
        id_pub: vec![n; 32],
        noise_pub: vec![n; 32],
        sphinx_pub: vec![n; 32],
        roles: vec!["gateway".into(), "mix".into(), "mailbox".into()],
        endpoints: vec![format!("wss://10.{n}.0.1:443")],
        layer: n % 3,
        valid_until: u64::MAX,
        sponsor: None,
    }
}

#[test]
fn routes_through_ffi() {
    let nodes: Vec<FfiNode> = (1..=5).map(node).collect();
    let r = forward_route(nodes.clone(), vec![1; 32], vec![5; 32], 100).unwrap();
    assert_eq!(r.hops.len(), 3);
    assert_eq!(r.hops[0].id_pub, vec![1; 32]);
    assert_eq!(r.hops[2].id_pub, vec![5; 32]);
    assert_eq!((r.delays_ms[0], r.delays_ms[2]), (0, 0));
    let s = reply_route(nodes.clone(), vec![1; 32], vec![5; 32], 100).unwrap();
    assert_eq!(s.hops.last().unwrap().id_pub, vec![1; 32]);
    let reps = mailbox_nodes(vec![9; 32], nodes.clone()).unwrap();
    assert_eq!(reps.len(), 3);
    assert_eq!(
        reps,
        mailbox_nodes(vec![9; 32], nodes.into_iter().rev().collect()).unwrap()
    );
    assert_eq!(
        forward_route((1..=5).map(node).collect(), vec![2; 32], vec![2; 32], 100).err(),
        Some(FfiError::Malformed)
    );
}
