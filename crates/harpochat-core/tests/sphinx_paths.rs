// SPDX-License-Identifier: Apache-2.0
//! End-to-end Sphinx paths through the public API of `harpochat-core`.

use harpochat_core::descriptor::node_address;
use harpochat_core::envelope::{self, Message, StoredBlob};
use harpochat_core::keys::X25519Secret;
use harpochat_core::link::SizeClass;
use harpochat_core::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::sphinx::{
    build_forward, create_surb, max_message_len, max_surbs_per_subscribe, open_forward_payload,
    packet_len, payload_len, process, recover_reply, surb_len, use_surb, Hop, Processed,
    LOCAL_DELIVERY, MAX_HOPS,
};
use harpochat_core::CoreError;

struct TestNode {
    id_pub: [u8; 32],
    sk: X25519Secret,
}

impl TestNode {
    fn new(n: u8) -> Self {
        Self {
            id_pub: [n; 32],
            sk: X25519Secret::from_bytes([n.wrapping_add(0x30); 32]),
        }
    }
    fn hop(&self) -> Hop {
        Hop {
            id_pub: self.id_pub,
            sphinx_pub: self.sk.public(),
        }
    }
    fn addr(&self) -> [u8; 32] {
        node_address(&self.id_pub)
    }
}

fn nodes(n: u8) -> Vec<TestNode> {
    (1..=n).map(TestNode::new).collect()
}

fn put_message(blob_len: usize) -> Message {
    let k = MailboxKeys::derive(&[0x11; 32], 20_000);
    let blob = vec![0xC3; blob_len];
    Message::Put {
        mailbox_id: k.mailbox_id(),
        write_auth: sign_put(&k, &blob, [2; 16]),
        blob,
    }
}

/// Process `packet` through `route`, checking every forward hop, and return
/// the final hop's output.
fn walk(mut packet: Vec<u8>, route: &[&TestNode], delays: &[u64], class: SizeClass) -> Processed {
    for (i, node) in route.iter().enumerate() {
        assert_eq!(packet.len(), packet_len(class), "hop {i} packet length");
        let (_, out) = process(&packet, &node.sk).unwrap();
        match out {
            Processed::Forward {
                next_hop,
                delay_ms,
                packet: next,
            } => {
                assert_eq!(next_hop, route[i + 1].addr(), "hop {i} next address");
                assert_eq!(delay_ms, delays[i], "hop {i} delay");
                packet = next;
            }
            fin @ Processed::Final { .. } => {
                assert_eq!(i, route.len() - 1, "final hop reached early");
                return fin;
            }
        }
    }
    unreachable!("route ended without a final hop")
}

#[test]
fn sizes_are_consistent() {
    for class in [SizeClass::Small, SizeClass::Large] {
        assert_eq!(packet_len(class), class.max_body_len());
        assert!(payload_len(class) < packet_len(class));
        assert!(max_message_len(class) < payload_len(class));
        assert!(max_message_len(class) <= envelope::MAX_ENVELOPE_LEN);
    }
}

#[test]
fn forward_three_hops_reaches_mailbox() {
    let n = nodes(3);
    let route: Vec<&TestNode> = n.iter().collect();
    let hops: Vec<Hop> = n.iter().map(TestNode::hop).collect();
    let delays = [0, 100, 0];
    let msg = put_message(100);
    let pkt = build_forward(
        &envelope::encode(&msg),
        &hops,
        LOCAL_DELIVERY,
        &delays,
        SizeClass::Small,
        None,
    )
    .unwrap();
    let Processed::Final {
        destination,
        payload,
        ..
    } = walk(pkt, &route, &delays, SizeClass::Small)
    else {
        unreachable!()
    };
    assert_eq!(destination, LOCAL_DELIVERY);
    let plain = open_forward_payload(&payload).unwrap();
    assert_eq!(envelope::decode(&plain), Ok(msg));
}

#[test]
fn forward_five_hops() {
    let n = nodes(5);
    let route: Vec<&TestNode> = n.iter().collect();
    let hops: Vec<Hop> = n.iter().map(TestNode::hop).collect();
    let delays = [0, 50, 60, 70, 0];
    let pkt = build_forward(b"x", &hops, LOCAL_DELIVERY, &delays, SizeClass::Large, None).unwrap();
    assert_eq!(pkt.len(), packet_len(SizeClass::Large));
    let Processed::Final { payload, .. } = walk(pkt, &route, &delays, SizeClass::Large) else {
        unreachable!()
    };
    assert_eq!(open_forward_payload(&payload).unwrap(), b"x");
}

#[test]
fn six_hops_rejected() {
    let hops: Vec<Hop> = nodes(6).iter().map(TestNode::hop).collect();
    assert_eq!(MAX_HOPS, 5);
    assert_eq!(
        build_forward(b"x", &hops, LOCAL_DELIVERY, &[0; 6], SizeClass::Small, None),
        Err(CoreError::Malformed)
    );
    assert_eq!(
        build_forward(b"x", &[], LOCAL_DELIVERY, &[], SizeClass::Small, None),
        Err(CoreError::Malformed)
    );
    let three: Vec<Hop> = nodes(3).iter().map(TestNode::hop).collect();
    assert_eq!(
        build_forward(
            b"x",
            &three,
            LOCAL_DELIVERY,
            &[0; 2],
            SizeClass::Small,
            None
        ),
        Err(CoreError::Malformed)
    );
}

#[test]
fn packets_have_constant_length() {
    let hops: Vec<Hop> = nodes(3).iter().map(TestNode::hop).collect();
    for len in [1, max_message_len(SizeClass::Small)] {
        let p = build_forward(
            &vec![1; len],
            &hops,
            LOCAL_DELIVERY,
            &[0; 3],
            SizeClass::Small,
            None,
        )
        .unwrap();
        assert_eq!(p.len(), packet_len(SizeClass::Small));
    }
}

#[test]
fn initial_secret_fixes_header_key() {
    // sphinx-packet adds internal randomness (routing padding), so only the
    // header's ephemeral public key (first 32 bytes) is fixed by the secret.
    let n = nodes(3);
    let hops: Vec<Hop> = n.iter().map(TestNode::hop).collect();
    let build = || {
        build_forward(
            b"m",
            &hops,
            LOCAL_DELIVERY,
            &[0; 3],
            SizeClass::Small,
            Some([0x44; 32]),
        )
        .unwrap()
    };
    let (a, b) = (build(), build());
    assert!(a[..32] == b[..32], "ephemeral key must be fixed");
    let route: Vec<&TestNode> = n.iter().collect();
    for p in [a, b] {
        let Processed::Final { payload, .. } = walk(p, &route, &[0; 3], SizeClass::Small) else {
            unreachable!()
        };
        assert_eq!(open_forward_payload(&payload).unwrap(), b"m");
    }
}

#[test]
fn replay_tag_is_stable() {
    let n = nodes(3);
    let hops: Vec<Hop> = n.iter().map(TestNode::hop).collect();
    let p = build_forward(b"m", &hops, LOCAL_DELIVERY, &[0; 3], SizeClass::Small, None).unwrap();
    let (t1, _) = process(&p, &n[0].sk).unwrap();
    let (t2, _) = process(&p, &n[0].sk).unwrap();
    assert_eq!(t1, t2);
    let q = build_forward(b"m", &hops, LOCAL_DELIVERY, &[0; 3], SizeClass::Small, None).unwrap();
    assert_ne!(process(&q, &n[0].sk).unwrap().0, t1);
}

#[test]
fn wrong_key_fails() {
    let n = nodes(3);
    let hops: Vec<Hop> = n.iter().map(TestNode::hop).collect();
    let p = build_forward(b"m", &hops, LOCAL_DELIVERY, &[0; 3], SizeClass::Small, None).unwrap();
    assert_eq!(process(&p, &n[1].sk).err(), Some(CoreError::Sphinx));
}

#[test]
fn garbage_packets_fail_cleanly() {
    let sk = X25519Secret::from_bytes([1; 32]);
    assert_eq!(process(&[0; 10], &sk).err(), Some(CoreError::Malformed));
    assert_eq!(
        process(&vec![0xAB; packet_len(SizeClass::Small)], &sk).err(),
        Some(CoreError::Sphinx)
    );
}

#[test]
fn surb_reply_roundtrip() {
    // Reply path: mailbox (sender of the reply) → mix → gateway; destination
    // is the phone's inbox token at the gateway.
    let n = nodes(3);
    let (mbx, mix, gw) = (&n[0], &n[1], &n[2]);
    let inbox = [0xAA; 32];
    let surb_id = [0x07; 16];
    let (surb, recovery) = create_surb(&[mix.hop(), gw.hop()], inbox, surb_id, &[100, 0]).unwrap();
    assert_eq!(surb.len(), surb_len());

    let reply = Message::FetchResponse {
        blobs: vec![StoredBlob {
            id: [1; 16],
            blob: b"ciphertext".to_vec(),
        }],
        more: false,
    };
    let (pkt, first_hop) = use_surb(&surb, &envelope::encode(&reply), SizeClass::Small).unwrap();
    assert_eq!(first_hop, mix.addr());
    let _ = mbx;
    let Processed::Final {
        destination,
        surb_id: got_id,
        payload,
    } = walk(pkt, &[mix, gw], &[100, 0], SizeClass::Small)
    else {
        unreachable!()
    };
    assert_eq!(destination, inbox);
    assert_eq!(got_id, surb_id);
    // Hops cannot read it…
    assert!(open_forward_payload(&payload).is_err());
    // …only the SURB creator can.
    let plain = recover_reply(&recovery, &payload).unwrap();
    assert_eq!(envelope::decode(&plain), Ok(reply));
}

#[test]
fn surb_bytes_and_recovery_survive_serialization() {
    let n = nodes(2);
    let (surb, rec) = create_surb(&[n[0].hop(), n[1].hop()], [1; 32], [2; 16], &[0, 0]).unwrap();
    let rec2 = harpochat_core::sphinx::SurbRecovery::from_bytes(&rec.to_bytes()).unwrap();
    let (pkt, _) = use_surb(&surb, b"hi", SizeClass::Small).unwrap();
    let Processed::Final { payload, .. } = walk(pkt, &[&n[0], &n[1]], &[0, 0], SizeClass::Small)
    else {
        unreachable!()
    };
    assert_eq!(recover_reply(&rec2, &payload).unwrap(), b"hi");
}

#[test]
fn put_at_max_blob_fits_small_class() {
    let hops: Vec<Hop> = nodes(3).iter().map(TestNode::hop).collect();
    let max = max_message_len(SizeClass::Small);
    // Find the largest blob whose encoded PUT fits.
    let mut blob_len = max;
    while envelope::encode(&put_message(blob_len)).len() > max {
        blob_len -= 1;
    }
    let fits = envelope::encode(&put_message(blob_len));
    assert!(build_forward(
        &fits,
        &hops,
        LOCAL_DELIVERY,
        &[0; 3],
        SizeClass::Small,
        None
    )
    .is_ok());
    let over = envelope::encode(&put_message(blob_len + 1));
    assert!(over.len() > max);
    assert_eq!(
        build_forward(
            &over,
            &hops,
            LOCAL_DELIVERY,
            &[0; 3],
            SizeClass::Small,
            None
        ),
        Err(CoreError::TooLarge)
    );
    println!("max PUT blob in Small class: {blob_len} bytes");
}

#[test]
fn subscribe_capacity() {
    let k = MailboxKeys::derive(&[0x11; 32], 20_000);
    let sub = |n: usize| {
        envelope::encode(&Message::Subscribe {
            mailbox_id: k.mailbox_id(),
            read_auth: sign_read(&k, ReadOp::Subscribe, b"", 1_800_000_000, [3; 16]),
            surbs: vec![vec![0x5C; surb_len()]; n],
            until: 1_800_086_400,
        })
    };
    for class in [SizeClass::Small, SizeClass::Large] {
        let cap = max_surbs_per_subscribe(class);
        assert!(sub(cap).len() <= max_message_len(class));
        if cap < envelope::MAX_SURBS {
            assert!(sub(cap + 1).len() > max_message_len(class));
        }
        println!("{class:?}: {cap} SURBs per SUBSCRIBE");
    }
    assert!(max_surbs_per_subscribe(SizeClass::Small) >= 2);
    assert!(max_surbs_per_subscribe(SizeClass::Large) >= 10);
}

#[test]
fn absurd_delay_rejected_without_panic() {
    let hops: Vec<Hop> = nodes(3).iter().map(TestNode::hop).collect();
    assert_eq!(
        build_forward(
            b"x",
            &hops,
            LOCAL_DELIVERY,
            &[0, u64::MAX, 0],
            SizeClass::Small,
            None
        ),
        Err(CoreError::Malformed)
    );
    let n = nodes(2);
    assert!(create_surb(&[n[0].hop(), n[1].hop()], [1; 32], [2; 16], &[u64::MAX, 0]).is_err());
    let max = harpochat_core::sphinx::MAX_DELAY_MS;
    assert!(build_forward(
        b"x",
        &hops,
        LOCAL_DELIVERY,
        &[0, max, 0],
        SizeClass::Small,
        None
    )
    .is_ok());
}
