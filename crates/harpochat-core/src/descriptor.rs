// SPDX-License-Identifier: Apache-2.0
//! Signed node descriptors (spec §4.1).
//!
//! Adds `noise_pub` (long-term X25519 Noise static key) to the spec's field
//! list: design deviations E4/E5 — the Noise handshake carries a signature of
//! this key by `id_pub`, so peers authenticate the Ed25519 identity.

use serde::{Deserialize, Serialize};

use crate::hash::h_domain;
use crate::signed::SignedPayload;
use crate::{domain, CoreError, Result};

/// Descriptor format version.
pub const VERSION: u8 = 1;
/// A descriptor may not claim validity further than this into the future.
pub const MAX_VALIDITY_SECS: u64 = 30 * 86_400;
/// Maximum endpoints per node.
pub const MAX_ENDPOINTS: usize = 4;
/// Maximum length of one endpoint URL, in bytes.
pub const MAX_ENDPOINT_LEN: usize = 255;
/// Highest mix layer index (three layers: 0, 1, 2).
pub const MAX_LAYER: u8 = 2;

/// Role a node plays in the mesh (spec §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Entry point for phones.
    Gateway,
    /// Intermediate mix.
    Mix,
    /// RAM-only mailbox.
    Mailbox,
}

/// Public description of a node, self-signed by `id_pub`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeDescriptor {
    /// Format version.
    pub v: u8,
    /// Long-term Ed25519 identity.
    #[serde(with = "serde_bytes")]
    pub id_pub: [u8; 32],
    /// Long-term X25519 Noise static key (E5).
    #[serde(with = "serde_bytes")]
    pub noise_pub: [u8; 32],
    /// Current X25519 Sphinx key.
    #[serde(with = "serde_bytes")]
    pub sphinx_pub: [u8; 32],
    /// Rotation counter of `sphinx_pub`.
    pub sphinx_key_epoch: u32,
    /// Roles this node accepts.
    pub roles: Vec<Role>,
    /// `wss://` endpoints.
    pub endpoints: Vec<String>,
    /// Mix layer (stratified topology).
    pub layer: u8,
    /// Expiry, unix seconds.
    pub valid_until: u64,
}

impl SignedPayload for NodeDescriptor {
    const DOMAIN: &'static str = domain::DESCRIPTOR;
    fn signer(&self) -> [u8; 32] {
        self.id_pub
    }
}

/// Check that an endpoint is a bounded `wss://` URL.
pub fn validate_endpoint(e: &str) -> Result<()> {
    if e.len() > MAX_ENDPOINT_LEN || !e.starts_with("wss://") || e.len() <= "wss://".len() {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

/// Structural and temporal checks on a (signature-verified) descriptor.
pub fn validate(d: &NodeDescriptor, now_unix_secs: u64) -> Result<()> {
    if d.v != VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    let mut roles = d.roles.clone();
    roles.sort_by_key(|r| *r as u8);
    roles.dedup();
    if d.roles.is_empty() || roles.len() != d.roles.len() {
        return Err(CoreError::Malformed);
    }
    if d.endpoints.is_empty() || d.endpoints.len() > MAX_ENDPOINTS {
        return Err(CoreError::Malformed);
    }
    d.endpoints.iter().try_for_each(|e| validate_endpoint(e))?;
    if d.layer > MAX_LAYER {
        return Err(CoreError::Malformed);
    }
    if d.valid_until <= now_unix_secs {
        return Err(CoreError::Expired);
    }
    if d.valid_until > now_unix_secs.saturating_add(MAX_VALIDITY_SECS) {
        return Err(CoreError::Malformed);
    }
    Ok(())
}

/// 32-byte Sphinx address of a node (design §5.7).
pub fn node_address(id_pub: &[u8; 32]) -> [u8; 32] {
    h_domain(domain::NODE_ADDR, &[id_pub])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;
    use crate::signed::Signed;
    use crate::CoreError;

    const NOW: u64 = 1_800_000_000;

    fn desc(k: &SigningKey) -> NodeDescriptor {
        NodeDescriptor {
            v: 1,
            id_pub: k.public(),
            noise_pub: [2; 32],
            sphinx_pub: [3; 32],
            sphinx_key_epoch: 7,
            roles: vec![Role::Gateway, Role::Mix, Role::Mailbox],
            endpoints: vec!["wss://node.example:443".into()],
            layer: 0,
            valid_until: NOW + 86_400,
        }
    }

    #[test]
    fn descriptor_sign_verify() {
        let k = SigningKey::from_seed(&[1; 32]);
        let d = desc(&k);
        assert_eq!(Signed::sign(&k, &d).verify(), Ok(d));
    }

    #[test]
    fn descriptor_signed_by_other_key_rejected() {
        let k = SigningKey::from_seed(&[1; 32]);
        let other = SigningKey::from_seed(&[9; 32]);
        assert_eq!(
            Signed::sign(&other, &desc(&k)).verify(),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn validate_accepts_good() {
        let k = SigningKey::from_seed(&[1; 32]);
        assert_eq!(validate(&desc(&k), NOW), Ok(()));
    }

    #[test]
    fn validate_rejects_expired() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut d = desc(&k);
        d.valid_until = NOW;
        assert_eq!(validate(&d, NOW), Err(CoreError::Expired));
    }

    #[test]
    fn validate_rejects_far_future() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut d = desc(&k);
        d.valid_until = NOW + MAX_VALIDITY_SECS + 1;
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
    }

    #[test]
    fn validate_rejects_non_wss_endpoint() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut d = desc(&k);
        d.endpoints = vec!["http://node.example".into()];
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
        d.endpoints = vec![];
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
        d.endpoints = vec![format!("wss://{}", "a".repeat(260))];
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
    }

    #[test]
    fn validate_rejects_duplicate_roles() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut d = desc(&k);
        d.roles = vec![Role::Mix, Role::Mix];
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
        d.roles = vec![];
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
    }

    #[test]
    fn validate_rejects_bad_layer_and_version() {
        let k = SigningKey::from_seed(&[1; 32]);
        let mut d = desc(&k);
        d.layer = 3;
        assert_eq!(validate(&d, NOW), Err(CoreError::Malformed));
        let mut d = desc(&k);
        d.v = 2;
        assert_eq!(validate(&d, NOW), Err(CoreError::UnsupportedVersion));
    }

    #[test]
    fn roles_encode_lowercase() {
        let bytes = crate::cbor::to_vec(&vec![Role::Gateway, Role::Mailbox]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("gateway") && s.contains("mailbox"));
    }

    #[test]
    fn node_address_is_stable() {
        let a = node_address(&[7; 32]);
        assert_eq!(a, node_address(&[7; 32]));
        assert_ne!(a, node_address(&[8; 32]));
        assert_eq!(
            a,
            crate::hash::h_domain(crate::domain::NODE_ADDR, &[&[7; 32]])
        );
    }
}
