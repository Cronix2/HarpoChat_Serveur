// SPDX-License-Identifier: Apache-2.0
//! Milestones M3 and M3b: cover traffic and real-time push.
//!
//! - M3: a phone link emits frames at the same rate whether or not real
//!   traffic flows; the phone chooses that rate within the node's bounds;
//!   nodes emit loops that come back, and notice a neighbour that eats them.
//! - M3b: a subscribed phone receives a PUSH in under 2 s on 5 nodes.

#[allow(dead_code)] // helpers shared with the other milestone tests
mod common;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use common::client::Client;
use common::mesh::{
    directory, fast_cover, forward, hop_of, next_deliver, now, reply, send, start_mesh,
};
use harpochat_core::envelope::{self, Message};
use harpochat_core::keys::random_bytes;
use harpochat_core::link::{cover_rate_body, FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{epoch_of, sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::path::{self, Candidate, MAILBOX_REPLICAS};
use harpochat_core::sphinx::{self, SurbRecovery};

/// Frames (any kind) received in `window`.
async fn count_frames(c: &mut Client, window: Duration) -> usize {
    let deadline = tokio::time::Instant::now() + window;
    let mut n = 0;
    while let Ok(Ok(_)) = tokio::time::timeout_at(deadline, c.reader.recv()).await {
        n += 1;
    }
    n
}

/// A Poisson count within 4 standard deviations of its mean.
fn poisson_ok(measured: usize, expected: f64) -> bool {
    (measured as f64 - expected).abs() <= 4.0 * expected.sqrt()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_link_rate_is_independent_of_traffic() {
    let mesh = start_mesh(1, fast_cover()).await;
    let nodes = directory(&mesh[0], &[mesh[0].id], 1).await;
    let gw = Candidate::from(&nodes[0]).hop;
    let mut c = Client::connect(mesh[0].addr, gw).await.unwrap();
    let window = Duration::from_secs(3);
    let expected = 20.0 * window.as_secs_f64();

    let idle = count_frames(&mut c, window).await;

    // Real traffic for this phone: packets the gateway delivers to its
    // inbox, 5 per second (a quarter of the link rate).
    let inbox = c.inbox;
    let mut w = c.writer;
    let sender = tokio::spawn(async move {
        loop {
            let pkt = sphinx::build_forward(
                &envelope::encode(&Message::Drop),
                &[gw],
                inbox,
                &[0],
                SizeClass::Small,
                None,
            )
            .unwrap();
            let f = LinkFrame {
                kind: FrameKind::Sphinx,
                body: pkt,
            };
            if w.send(&f, SizeClass::Small).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let deadline = tokio::time::Instant::now() + window;
    let (mut busy, mut real) = (0, 0);
    while let Ok(Ok((_, f))) = tokio::time::timeout_at(deadline, c.reader.recv()).await {
        busy += 1;
        if f.kind == FrameKind::Deliver {
            real += 1;
        }
    }
    sender.abort();
    assert!(poisson_ok(idle, expected), "idle {idle} vs {expected}");
    assert!(poisson_ok(busy, expected), "busy {busy} vs {expected}");
    assert!(real >= 10, "real frames delivered: {real}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_chooses_its_rate_within_bounds() {
    let mesh = start_mesh(1, fast_cover()).await;
    let nodes = directory(&mesh[0], &[mesh[0].id], 1).await;
    let gw = Candidate::from(&nodes[0]).hop;
    let mut c = Client::connect(mesh[0].addr, gw).await.unwrap();
    let ask = |mhz: u32| LinkFrame {
        kind: FrameKind::CoverRate,
        body: cover_rate_body(mhz),
    };
    let window = Duration::from_secs(3);

    // 10 Hz instead of the default 20 Hz: ~30 frames instead of ~60.
    c.writer.send(&ask(10_000), SizeClass::Small).await.unwrap();
    count_frames(&mut c, Duration::from_millis(500)).await; // let the old slot pass
    let slow = count_frames(&mut c, window).await;
    assert!(poisson_ok(slow, 30.0), "10 Hz: {slow}");

    // 1 000 Hz is clamped to the node's maximum (50 Hz).
    c.writer
        .send(&ask(1_000_000), SizeClass::Small)
        .await
        .unwrap();
    count_frames(&mut c, Duration::from_millis(300)).await;
    let fast = count_frames(&mut c, window).await;
    assert!(poisson_ok(fast, 150.0), "clamped: {fast}");

    // A malformed CoverRate closes the link.
    let bad = LinkFrame {
        kind: FrameKind::CoverRate,
        body: vec![1, 2, 3],
    };
    c.writer.send(&bad, SizeClass::Small).await.unwrap();
    let closed = async {
        loop {
            if c.reader.recv().await.is_err() {
                return;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), closed)
        .await
        .expect("link closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn push_arrives_under_two_seconds() {
    let mesh = start_mesh(5, fast_cover()).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[0], &roots, 5).await;
    let cands: Vec<Candidate> = nodes.iter().map(Candidate::from).collect();
    let (gw_a, gw_b) = (mesh[0].id, mesh[1].id);
    let k = MailboxKeys::derive(&random_bytes(), epoch_of(now()));
    let replicas = path::mailbox_nodes(&k.mailbox_id(), &cands, MAILBOX_REPLICAS);

    // B subscribes on every replica that is not its gateway (spec §7.5).
    let mut bob = Client::connect(mesh[1].addr, hop_of(&cands, &gw_b))
        .await
        .unwrap();
    let mut recoveries: Vec<([u8; 16], SurbRecovery)> = Vec::new();
    for r in replicas.iter().filter(|r| **r != gw_b) {
        let mut surbs = Vec::new();
        for _ in 0..3 {
            let route = reply(&cands, &gw_b, r);
            let id = random_bytes();
            let (surb, rec) =
                sphinx::create_surb(&route.hops, bob.inbox, id, &route.delays_ms).unwrap();
            surbs.push(surb);
            recoveries.push((id, rec));
        }
        let until = now() + 600;
        let unsigned = Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Subscribe, b"", now(), [0; 16]),
            surbs: surbs.clone(),
            until,
        };
        let (op, bound) = envelope::read_bound(&unsigned).unwrap();
        let sub = Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, op, &bound, now(), random_bytes()),
            surbs,
            until,
        };
        send(&mut bob, &forward(&cands, &gw_b, r), &sub).await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // A writes; B is pushed without asking.
    let mut alice = Client::connect(mesh[0].addr, hop_of(&cands, &gw_a))
        .await
        .unwrap();
    let start = Instant::now();
    for r in replicas.iter().filter(|r| **r != gw_a) {
        let msg = Message::Put {
            mailbox_id: k.mailbox_id(),
            write_auth: sign_put(&k, b"right now", random_bytes()),
            blob: b"right now".to_vec(),
        };
        send(&mut alice, &forward(&cands, &gw_a, r), &msg).await;
    }
    let (id, payload) = next_deliver(&mut bob, Duration::from_secs(5))
        .await
        .expect("a push");
    let latency = start.elapsed();
    let (_, rec) = recoveries.iter().find(|(i, _)| *i == id).expect("our SURB");
    let plain = sphinx::recover_reply(rec, &payload).unwrap();
    let Message::Push { mailbox_id, blobs } = envelope::decode(&plain).unwrap() else {
        panic!("expected PUSH")
    };
    assert_eq!(mailbox_id, k.mailbox_id());
    assert_eq!(blobs[0].blob, b"right now");
    assert!(latency < Duration::from_secs(2), "push took {latency:?}");
    let pushes: u64 = mesh
        .iter()
        .map(|m| m.router.counters.pushes.load(Ordering::Relaxed))
        .sum();
    assert!(pushes >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loops_return_in_healthy_mesh() {
    let mesh = start_mesh(5, fast_cover()).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    directory(&mesh[0], &roots, 5).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    for m in &mesh {
        let c = &m.router.counters;
        assert!(c.loops_sent.load(Ordering::Relaxed) > 0);
        assert!(c.loops_returned.load(Ordering::Relaxed) > 0);
        assert!(c.drops_sent.load(Ordering::Relaxed) > 0);
        assert_eq!(c.loops_lost.load(Ordering::Relaxed), 0);
        assert!(m.router.loops.lock().unwrap().suspects().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_peer_becomes_suspect() {
    let mut cover = fast_cover();
    cover.loop_rate = 10.0;
    let mut mesh = start_mesh(5, cover).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    for m in &mesh[..4] {
        directory(m, &roots, 5).await;
    }
    let dead = mesh[4].id;
    mesh[4].stop();
    // Losses are known once a loop's deadline (delays + 10 s grace) passes.
    let start = Instant::now();
    loop {
        let flagged = mesh[..4]
            .iter()
            .filter(|m| m.router.loops.lock().unwrap().suspects() == vec![dead])
            .count();
        if flagged == 4 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "only {flagged}/4 nodes flagged the dead peer"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_loop_comes_back_across_the_mesh() {
    let mesh = start_mesh(5, fast_cover()).await;
    let roots: Vec<[u8; 32]> = mesh.iter().map(|m| m.id).collect();
    let nodes = directory(&mesh[2], &roots, 5).await;
    let cands: Vec<Candidate> = nodes.iter().map(Candidate::from).collect();
    let gw = mesh[2].id;
    let mut phone = Client::connect(mesh[2].addr, hop_of(&cands, &gw))
        .await
        .unwrap();
    let route = path::phone_loop_route(
        &cands,
        &gw,
        &mut |n| (u64::from_le_bytes(random_bytes()) % n as u64) as usize,
        &mut || 0.5,
        50,
    )
    .unwrap();
    assert_eq!(route.hops.len(), 4);
    let loop_id: [u8; 16] = random_bytes();
    let pkt = sphinx::build_forward_tagged(
        &envelope::encode(&Message::Loop),
        &route.hops,
        phone.inbox,
        loop_id,
        &route.delays_ms,
        SizeClass::Small,
    )
    .unwrap();
    phone
        .writer
        .send(
            &LinkFrame {
                kind: FrameKind::Sphinx,
                body: pkt,
            },
            SizeClass::Small,
        )
        .await
        .unwrap();
    let (id, payload) = next_deliver(&mut phone, Duration::from_secs(5))
        .await
        .expect("loop back");
    assert_eq!(id, loop_id);
    let plain = sphinx::open_forward_payload(&payload).unwrap();
    assert_eq!(envelope::decode(&plain).unwrap(), Message::Loop);
}
