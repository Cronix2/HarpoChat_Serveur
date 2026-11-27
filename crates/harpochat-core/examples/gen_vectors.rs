// SPDX-License-Identifier: Apache-2.0
//! Writes `test-vectors/v1.json`.
//!
//! `cargo run -p harpochat-core --example gen_vectors`
//!
//! Deterministic vectors are recomputed from fixed inputs. Sphinx packets are
//! not byte-reproducible (sphinx-packet adds internal randomness), so the two
//! Sphinx vectors reuse the packet already frozen in the file when present;
//! running the generator twice yields the same file.

#[path = "../tests/common/vectors.rs"]
mod common;

use harpochat_core::envelope::{self, Message, StoredBlob};
use harpochat_core::link::SizeClass;
use harpochat_core::sphinx::{self, LOCAL_DELIVERY};
use serde_json::{json, Map, Value};

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/v1.json");

fn previous(name: &str) -> Option<Value> {
    let raw = std::fs::read_to_string(FILE).ok()?;
    let doc: Value = serde_json::from_str(&raw).ok()?;
    let v = doc["vectors"][name]["inputs"].clone();
    (!v.is_null()).then_some(v)
}

fn sphinx_forward_inputs() -> Value {
    if let Some(v) = previous("sphinx_forward_3hops") {
        return v;
    }
    let nodes: Vec<_> = (1..=3).map(common::sphinx_node).collect();
    let hops: Vec<_> = nodes.iter().map(|n| n.0).collect();
    let packet = sphinx::build_forward(
        b"harpochat sphinx vector",
        &hops,
        LOCAL_DELIVERY,
        &[0, 100, 0],
        SizeClass::Small,
        Some([0x44; 32]),
    )
    .unwrap();
    json!({
        "node_secrets": nodes.iter().map(|n| n.1.clone()).collect::<Vec<_>>(),
        "node_ids": hops.iter().map(|h| hex::encode(h.id_pub)).collect::<Vec<_>>(),
        "delays_ms": [0, 100, 0],
        "packet": hex::encode(packet),
    })
}

fn sphinx_surb_inputs() -> Value {
    if let Some(v) = previous("sphinx_surb_reply") {
        return v;
    }
    let nodes: Vec<_> = (4..=5).map(common::sphinx_node).collect();
    let hops: Vec<_> = nodes.iter().map(|n| n.0).collect();
    let (surb, recovery) = sphinx::create_surb(&hops, [0xAA; 32], [0x07; 16], &[100, 0]).unwrap();
    let reply = envelope::encode(&Message::FetchResponse {
        blobs: vec![StoredBlob {
            id: [1; 16],
            blob: b"ciphertext".to_vec(),
        }],
        more: false,
    });
    let (packet, _) = sphinx::use_surb(&surb, &reply, SizeClass::Small).unwrap();
    json!({
        "node_secrets": nodes.iter().map(|n| n.1.clone()).collect::<Vec<_>>(),
        "node_ids": hops.iter().map(|h| hex::encode(h.id_pub)).collect::<Vec<_>>(),
        "inbox_token": hex::encode([0xAA; 32]),
        "surb_id": hex::encode([0x07; 16]),
        "recovery": hex::encode(recovery.to_bytes()),
        "packet": hex::encode(packet),
    })
}

fn main() {
    let mut vectors = Map::new();
    let mut inputs = common::deterministic_inputs();
    inputs.push(("sphinx_forward_3hops", sphinx_forward_inputs()));
    inputs.push(("sphinx_surb_reply", sphinx_surb_inputs()));
    for (name, i) in inputs {
        let out = common::compute(name, &i);
        vectors.insert(
            name.into(),
            json!({ "inputs": i, "output": hex::encode(out) }),
        );
    }
    let sizes = json!({
        "small": {
            "noise_ciphertext": SizeClass::Small.ciphertext_len(),
            "link_plaintext": SizeClass::Small.plaintext_len(),
            "sphinx_packet": sphinx::packet_len(SizeClass::Small),
            "sphinx_payload": sphinx::payload_len(SizeClass::Small),
            "max_message": sphinx::max_message_len(SizeClass::Small),
            "max_surbs_per_subscribe": sphinx::max_surbs_per_subscribe(SizeClass::Small),
        },
        "large": {
            "noise_ciphertext": SizeClass::Large.ciphertext_len(),
            "link_plaintext": SizeClass::Large.plaintext_len(),
            "sphinx_packet": sphinx::packet_len(SizeClass::Large),
            "sphinx_payload": sphinx::payload_len(SizeClass::Large),
            "max_message": sphinx::max_message_len(SizeClass::Large),
            "max_surbs_per_subscribe": sphinx::max_surbs_per_subscribe(SizeClass::Large),
        },
        "sphinx_header": sphinx::HEADER_LEN,
        "surb": sphinx::surb_len(),
    });
    let doc = json!({ "version": 1, "sizes": sizes, "vectors": vectors });
    std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors")).unwrap();
    std::fs::write(FILE, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
    println!("wrote {FILE}");
}
