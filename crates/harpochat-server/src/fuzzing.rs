// SPDX-License-Identifier: Apache-2.0
//! Fuzzing bodies (P8): every function takes arbitrary bytes, as an attacker
//! would send them, and must never panic, hang or allocate without bound.
//!
//! They are the targets of `fuzz/` (cargo-fuzz, nightly, run by CI) and are
//! also exercised on stable by `tests/fuzz_bodies.rs` with random and
//! mutated inputs, so the fuzzed code is tested on every build.
//!
//! Each covers one parser or state machine reachable from the network: link
//! frames, envelopes, Sphinx packets, the Noise handshake, directories,
//! tokens, join requests, the mailbox service and the configuration file.

use std::sync::OnceLock;

use harpochat_core::bootstrap::Bootstrap;
use harpochat_core::directory::{verify_directory, Directory};
use harpochat_core::envelope;
use harpochat_core::invite::decode_token;
use harpochat_core::keys::{SigningKey, X25519Secret};
use harpochat_core::link::{LinkFrame, SizeClass};
use harpochat_core::noise::Handshake;
use harpochat_core::signed::Signed;
use harpochat_core::{cbor, sphinx};

use crate::config::{Config, Limits};
use crate::keystore::NodeKeys;
use crate::membership::Membership;
use crate::node::Node;
use crate::service::MailboxService;
use crate::sponsor::Sponsor;

/// A fixed point in time for the bodies (deterministic runs).
pub const NOW: u64 = 1_800_000_000;

fn node() -> &'static Node {
    static NODE: OnceLock<Node> = OnceLock::new();
    NODE.get_or_init(|| {
        let mut c = Config::default();
        c.node.root = true;
        c.node.public_endpoints = vec!["wss://127.0.0.1:4430".into()];
        Node::new(c, NodeKeys::generate(), NOW).expect("valid fuzz node")
    })
}

fn sphinx_secret() -> &'static X25519Secret {
    static KEY: OnceLock<X25519Secret> = OnceLock::new();
    KEY.get_or_init(X25519Secret::generate)
}

/// A link frame as decrypted from the wire.
pub fn link_frame(data: &[u8]) {
    let _ = LinkFrame::decode(data);
}

/// A final Sphinx payload: decode, and re-encoding must round-trip.
pub fn envelope(data: &[u8]) {
    if let Ok(m) = envelope::decode(data) {
        let again = envelope::decode(&envelope::encode(&m)).expect("re-encoded envelope decodes");
        assert_eq!(again, m, "envelope round-trip");
        let _ = envelope::read_bound(&m);
    }
}

/// A Sphinx packet, padded or cut to a valid size so the header is parsed.
pub fn sphinx_packet(data: &[u8]) {
    let len = sphinx::packet_len(SizeClass::Small);
    let mut p = data.to_vec();
    p.resize(len, 0);
    let _ = sphinx::process(&p, sphinx_secret());
    let _ = sphinx::process(data, sphinx_secret());
}

/// The first Noise message a node reads from an unknown initiator.
pub fn noise_handshake(data: &[u8]) {
    static ID: OnceLock<SigningKey> = OnceLock::new();
    let id = ID.get_or_init(SigningKey::generate);
    if let Ok(mut hs) = Handshake::responder(sphinx_secret(), Some(id)) {
        let _ = hs.read_message(data);
    }
}

/// A signed directory received from a peer or served to a phone.
pub fn directory(data: &[u8]) {
    if let Ok(d) = cbor::from_slice::<Signed<Directory>>(data, 1 << 20) {
        let _ = verify_directory(&d, &[node().keys.identity.public()], NOW);
        let _ = Membership::new(node()).merge(&d, NOW);
    }
}

/// A pasted `hcn1-` token.
pub fn token(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = decode_token(s, NOW);
    }
}

/// The bootstrap block embedded in the app.
pub fn bootstrap(data: &[u8]) {
    let _ = Bootstrap::decode(data);
}

/// A `JoinRequest` body sent by a would-be node.
pub fn join_request(data: &[u8]) {
    let n = node();
    let (resp, entry) = Sponsor::new(n).handle_join(n, data, Some([7; 32]), NOW);
    assert!(entry.is_none() || resp.vouch.is_some());
}

/// Decoded envelopes reaching the mailbox service.
pub fn mailbox_service(data: &[u8]) {
    if let Ok(m) = envelope::decode(data) {
        let mut s = MailboxService::new(&Limits::default());
        let _ = s.handle(m.clone(), NOW);
        let _ = s.handle(m, NOW + 1);
        s.sweep(NOW + 10 * 86_400);
    }
}

/// The operator's configuration file.
pub fn config(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(c) = Config::parse(s) {
            let _ = c.validate();
        }
    }
}

/// All bodies by name (used by the stable test and the fuzz crate docs).
pub const BODIES: &[(&str, fn(&[u8]))] = &[
    ("link_frame", link_frame),
    ("envelope", envelope),
    ("sphinx_packet", sphinx_packet),
    ("noise_handshake", noise_handshake),
    ("directory", directory),
    ("token", token),
    ("bootstrap", bootstrap),
    ("join_request", join_request),
    ("mailbox_service", mailbox_service),
    ("config", config),
];
