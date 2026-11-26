// SPDX-License-Identifier: Apache-2.0
//! Shared by `examples/gen_vectors.rs` (writes `test-vectors/v1.json`) and
//! `tests/vectors.rs` (replays it). Each vector is `name → (inputs, output)`;
//! [`compute`] turns inputs into output bytes using only the public API, so
//! any change to a wire format breaks the frozen file.

use harpochat_core::bootstrap::{Bootstrap, RootEntry};
use harpochat_core::cbor;
use harpochat_core::descriptor::{node_address, NodeDescriptor, Role};
use harpochat_core::directory::Vouch;
use harpochat_core::envelope::{self, Message};
use harpochat_core::hash::h_domain;
use harpochat_core::invite::{encode_token, NodeInvite};
use harpochat_core::keys::{SigningKey, X25519Secret};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::mailbox::{sign_put, sign_read, MailboxKeys, ReadOp};
use harpochat_core::signed::Signed;
use harpochat_core::sphinx::{self, Processed, SurbRecovery};
use serde_json::{json, Map, Value};

pub fn hexs(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(
        v[k].as_str()
            .unwrap_or_else(|| panic!("missing hex input {k}")),
    )
    .expect("valid hex")
}

pub fn arr<const N: usize>(v: &Value, k: &str) -> [u8; N] {
    hexs(v, k).try_into().expect("wrong length")
}

fn num(v: &Value, k: &str) -> u64 {
    v[k].as_u64()
        .unwrap_or_else(|| panic!("missing number input {k}"))
}

fn text(v: &Value, k: &str) -> String {
    v[k].as_str()
        .unwrap_or_else(|| panic!("missing text input {k}"))
        .to_string()
}

fn mbx(i: &Value) -> MailboxKeys {
    MailboxKeys::derive(&arr(i, "pair_secret"), num(i, "epoch") as u32)
}

/// Walk a packet through `secrets` (hex list) and return the final payload.
fn walk(i: &Value, packet: Vec<u8>) -> Vec<u8> {
    let mut p = packet;
    for s in i["node_secrets"].as_array().expect("node_secrets") {
        let sk = X25519Secret::from_bytes(
            hex::decode(s.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        match sphinx::process(&p, &sk).expect("sphinx process").1 {
            Processed::Forward { packet, .. } => p = packet,
            Processed::Final { payload, .. } => return payload,
        }
    }
    panic!("no final hop")
}

/// Compute a vector's output from its inputs.
pub fn compute(name: &str, i: &Value) -> Vec<u8> {
    match name {
        "h_domain" => h_domain(&text(i, "label"), &[&hexs(i, "data")]).to_vec(),
        "node_address" => node_address(&arr(i, "id_pub")).to_vec(),
        "mailbox_keys" => {
            let k = mbx(i);
            [k.write.public(), k.read.public(), k.mailbox_id()].concat()
        }
        "put_auth" => cbor::to_vec(&sign_put(&mbx(i), &hexs(i, "blob"), arr(i, "nonce"))),
        "read_auth_fetch" => cbor::to_vec(&sign_read(
            &mbx(i),
            ReadOp::Fetch,
            &hexs(i, "bound"),
            num(i, "ts"),
            arr(i, "nonce"),
        )),
        "envelope_put" => {
            let k = mbx(i);
            let blob = hexs(i, "blob");
            envelope::encode(&Message::Put {
                mailbox_id: k.mailbox_id(),
                write_auth: sign_put(&k, &blob, arr(i, "nonce")),
                blob,
            })
        }
        "envelope_subscribe" => {
            let k = mbx(i);
            let surbs = vec![hexs(i, "surb")];
            let until = num(i, "until");
            let msg = Message::Subscribe {
                mailbox_id: k.mailbox_id(),
                read_auth: sign_read(&k, ReadOp::Subscribe, b"", 0, [0; 16]),
                surbs: surbs.clone(),
                until,
            };
            let (op, bound) = envelope::read_bound(&msg).unwrap();
            envelope::encode(&Message::Subscribe {
                mailbox_id: k.mailbox_id(),
                read_auth: sign_read(&k, op, &bound, num(i, "ts"), arr(i, "nonce")),
                surbs,
                until,
            })
        }
        "descriptor_signed" => {
            let k = SigningKey::from_seed(&arr(i, "seed"));
            cbor::to_vec(&Signed::sign(
                &k,
                &NodeDescriptor {
                    v: 1,
                    id_pub: k.public(),
                    noise_pub: arr(i, "noise_pub"),
                    sphinx_pub: arr(i, "sphinx_pub"),
                    sphinx_key_epoch: num(i, "sphinx_key_epoch") as u32,
                    roles: vec![Role::Gateway, Role::Mix, Role::Mailbox],
                    endpoints: vec![text(i, "endpoint")],
                    layer: 0,
                    valid_until: num(i, "valid_until"),
                },
            ))
        }
        "vouch_signed" => {
            let k = SigningKey::from_seed(&arr(i, "sponsor_seed"));
            cbor::to_vec(&Signed::sign(
                &k,
                &Vouch {
                    v: 1,
                    node_id: arr(i, "node_id"),
                    sponsor_id: k.public(),
                    issued: num(i, "issued"),
                },
            ))
        }
        "node_invite_token" => {
            let k = SigningKey::from_seed(&arr(i, "sponsor_seed"));
            encode_token(&Signed::sign(
                &k,
                &NodeInvite {
                    v: 1,
                    sponsor_id: k.public(),
                    sponsor_endpoints: vec![text(i, "endpoint")],
                    secret: arr(i, "secret"),
                    expires: num(i, "expires"),
                },
            ))
            .into_bytes()
        }
        "bootstrap" => Bootstrap {
            v: 1,
            roots: vec![
                RootEntry {
                    id_pub: arr(i, "root1"),
                    endpoints: vec![text(i, "root1_endpoint")],
                },
                RootEntry {
                    id_pub: arr(i, "root2"),
                    endpoints: vec![text(i, "root2_endpoint")],
                },
            ],
        }
        .encode(),
        "link_frame_small" => LinkFrame {
            kind: FrameKind::Sphinx,
            body: hexs(i, "body"),
        }
        .encode(SizeClass::Small)
        .unwrap(),
        "sphinx_forward_3hops" => {
            let payload = walk(i, hexs(i, "packet"));
            sphinx::open_forward_payload(&payload).unwrap()
        }
        "sphinx_surb_reply" => {
            let payload = walk(i, hexs(i, "packet"));
            let rec = SurbRecovery::from_bytes(&hexs(i, "recovery")).unwrap();
            sphinx::recover_reply(&rec, &payload).unwrap()
        }
        other => panic!("unknown vector {other}"),
    }
}

/// Fixed inputs of the deterministic vectors.
pub fn deterministic_inputs() -> Vec<(&'static str, Value)> {
    let mb = |extra: Value| {
        let mut m: Map<String, Value> = Map::new();
        m.insert("pair_secret".into(), json!(hex::encode([0x11; 32])));
        m.insert("epoch".into(), json!(20_000));
        for (k, v) in extra.as_object().unwrap() {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    };
    vec![
        (
            "h_domain",
            json!({"label": "harpo-mbx-id", "data": hex::encode(b"abc")}),
        ),
        ("node_address", json!({"id_pub": hex::encode([7; 32])})),
        ("mailbox_keys", mb(json!({}))),
        (
            "put_auth",
            mb(json!({"nonce": hex::encode([0x22; 16]), "blob": hex::encode(b"hello")})),
        ),
        (
            "read_auth_fetch",
            mb(
                json!({"nonce": hex::encode([0x23; 16]), "ts": 1_728_000_000u64, "bound": hex::encode([0, 5])}),
            ),
        ),
        (
            "envelope_put",
            mb(json!({"nonce": hex::encode([0x22; 16]), "blob": hex::encode(b"hello")})),
        ),
        (
            "envelope_subscribe",
            mb(
                json!({"nonce": hex::encode([0x24; 16]), "ts": 1_728_000_000u64, "until": 1_728_086_400u64, "surb": hex::encode([0x5C; 64])}),
            ),
        ),
        (
            "descriptor_signed",
            json!({"seed": hex::encode([1; 32]), "noise_pub": hex::encode([2; 32]), "sphinx_pub": hex::encode([3; 32]),
                   "sphinx_key_epoch": 1, "endpoint": "wss://node1.example:443", "valid_until": 1_800_000_000u64}),
        ),
        (
            "vouch_signed",
            json!({"sponsor_seed": hex::encode([1; 32]), "node_id": hex::encode([9; 32]), "issued": 1_728_000_000u64}),
        ),
        (
            "node_invite_token",
            json!({"sponsor_seed": hex::encode([1; 32]), "secret": hex::encode([0x5A; 32]),
                   "endpoint": "wss://sponsor.example:443", "expires": 1_728_172_800u64}),
        ),
        (
            "bootstrap",
            json!({"root1": hex::encode([1; 32]), "root1_endpoint": "wss://root1.example:443",
                   "root2": hex::encode([2; 32]), "root2_endpoint": "wss://203.0.113.7:443"}),
        ),
        ("link_frame_small", json!({"body": hex::encode([0xAB; 8])})),
    ]
}

/// Node keys used by the Sphinx vectors: id_pub = [n; 32], sphinx secret = [0x30 + n; 32].
pub fn sphinx_node(n: u8) -> (sphinx::Hop, String) {
    let sk = X25519Secret::from_bytes([0x30 + n; 32]);
    (
        sphinx::Hop {
            id_pub: [n; 32],
            sphinx_pub: sk.public(),
        },
        hex::encode([0x30 + n; 32]),
    )
}
