// SPDX-License-Identifier: Apache-2.0
//! Domain-separation labels. Each signature, KDF and hash has its own label;
//! a label is never reused for another purpose.

/// Signature over a [`crate::descriptor::NodeDescriptor`].
pub const DESCRIPTOR: &str = "harpochat/v1/descriptor";
/// Signature over a sponsorship certificate (`Vouch`).
pub const VOUCH: &str = "harpochat/v1/vouch";
/// Signature over a revocation.
pub const REVOKE: &str = "harpochat/v1/revoke";
/// Signature over a directory snapshot.
pub const DIRECTORY: &str = "harpochat/v1/directory";
/// Signature over a node invite token.
pub const NODE_INVITE: &str = "harpochat/v1/node-invite";
/// Signature authorising a PUT into a mailbox.
pub const PUT: &str = "harpochat/v1/put";
/// Signature authorising FETCH / ACK / SUBSCRIBE on a mailbox.
pub const READ: &str = "harpochat/v1/read";

/// Signature binding a Noise static key to a node identity (design E4).
pub const NOISE_STATIC: &str = "harpochat/v1/noise-static";

/// HKDF info label for per-epoch mailbox keys.
pub const MBX_KEYS: &str = "harpo-mbx-keys";
/// Hash label for mailbox identifiers.
pub const MBX_ID: &str = "harpo-mbx-id";
/// Hash label for Sphinx node addresses.
pub const NODE_ADDR: &str = "harpo-node-addr";

/// Prefix `len(label) as u8 || label`, used by signatures and labelled hashes.
pub(crate) fn prefix(label: &str) -> Vec<u8> {
    let bytes = label.as_bytes();
    assert!(bytes.len() <= u8::MAX as usize, "domain label too long");
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out
}
