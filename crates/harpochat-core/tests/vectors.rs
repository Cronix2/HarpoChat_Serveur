// SPDX-License-Identifier: Apache-2.0
//! Replays the frozen test vectors in `test-vectors/v1.json`.
//! Regenerate (only for an intentional, versioned format change) with
//! `cargo run -p harpochat-core --example gen_vectors`.

#[path = "common/vectors.rs"]
#[allow(dead_code)] // generator-only helpers
mod common;

use serde_json::Value;

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/v1.json");

#[test]
fn vectors_match() {
    let raw = std::fs::read_to_string(FILE).expect("test-vectors/v1.json exists");
    let doc: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["version"], 1);
    let vectors = doc["vectors"].as_object().unwrap();
    assert!(vectors.len() >= 14, "expected the full vector set");
    for (name, v) in vectors {
        let expected = hex::decode(v["output"].as_str().unwrap()).unwrap();
        let got = common::compute(name, &v["inputs"]);
        assert!(got == expected, "vector {name} changed");
    }
}

#[test]
fn encoded_vectors_decode_and_reencode() {
    use harpochat_core::{bootstrap::Bootstrap, cbor, envelope, link::LinkFrame};
    let raw = std::fs::read_to_string(FILE).unwrap();
    let doc: Value = serde_json::from_str(&raw).unwrap();
    let out = |n: &str| hex::decode(doc["vectors"][n]["output"].as_str().unwrap()).unwrap();
    for n in ["envelope_put", "envelope_subscribe"] {
        let bytes = out(n);
        assert_eq!(envelope::encode(&envelope::decode(&bytes).unwrap()), bytes);
    }
    let b = out("bootstrap");
    assert_eq!(Bootstrap::decode(&b).unwrap().encode(), b);
    let f = out("link_frame_small");
    assert_eq!(
        LinkFrame::decode(&f)
            .unwrap()
            .1
            .encode(harpochat_core::link::SizeClass::Small)
            .unwrap(),
        f
    );
    let d = out("descriptor_signed");
    let s: harpochat_core::signed::Signed<harpochat_core::descriptor::NodeDescriptor> =
        cbor::from_slice(&d, 4096).unwrap();
    assert!(s.verify().is_ok());
    assert_eq!(cbor::to_vec(&s), d);
    let token = String::from_utf8(out("node_invite_token")).unwrap();
    assert!(harpochat_core::invite::decode_token(&token, 1_728_000_000).is_ok());
}
