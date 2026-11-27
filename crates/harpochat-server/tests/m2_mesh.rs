// SPDX-License-Identifier: Apache-2.0
//! Milestone M2: five nodes, multi-hop Sphinx routes with delays, replies
//! through SURBs, mailboxes that never see the recipient's link. Cover
//! traffic runs throughout (padding on every link, node loops and drops).

#[allow(dead_code)] // helpers shared with the other milestone tests
mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::client::Client;
use common::mesh::{
    directory, directory_once, fast_cover, forward, hop_of, next_deliver, now, reply, send,
    start_mesh, MeshNode,
};
use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::{random_bytes, SigningKey};
use harpochat_core::mailbox::{epoch_of, sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::path::{self, Candidate, MAILBOX_REPLICAS};
use harpochat_core::sphinx;

/// A puts into every replica that is not its gateway; B fetches the first
/// replica that is neither gateway; returns (replica used, blobs received).
async fn exchange(
    mesh: &[MeshNode],
    cands: &[Candidate],
    gw_a: usize,
    gw_b: usize,
    payload: &[u8],
) -> ([u8; 32], Vec<Vec<u8>>) {
    let k = MailboxKeys::derive(&random_bytes(), epoch_of(now()));
    let replicas = path::mailbox_nodes(&k.mailbox_id(), cands, MAILBOX_REPLICAS);

    let mut alice = Client::connect(mesh[gw_a].addr, hop_of(cands, &mesh[gw_a].id))
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
    // Mix delays (mean 100 ms), link slots (50 Hz) and loopback latency.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let target = *replicas
        .iter()
        .find(|r| **r != mesh[gw_a].id && **r != mesh[gw_b].id)
        .expect("a replica outside both gateways");
    let mut bob = Client::connect(mesh[gw_b].addr, hop_of(cands, &mesh[gw_b].id))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn put_and_fetch_across_five_nodes() {
    let mesh = start_mesh(5, fast_cover()).await;
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
    let mesh = start_mesh(5, fast_cover()).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[2], &roots, 5).await;
    assert_eq!(nodes.len(), 5);
    // Trusting only a stranger's key, nothing in the same mesh verifies.
    let stranger = [SigningKey::generate().public()];
    let only_stranger = directory_once(&mesh[2], &stranger).await.unwrap();
    assert!(only_stranger.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_survives_a_dead_node() {
    let mut mesh = start_mesh(5, fast_cover()).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[0], &roots, 5).await;
    let dead = mesh[4].id;
    mesh[4].stop();
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
