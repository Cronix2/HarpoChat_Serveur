// SPDX-License-Identifier: Apache-2.0
//! Bootstrap block embedded in the app (spec §4.4).
//!
//! Unsigned on purpose: its authenticity comes from being compiled into the
//! APK. The app obfuscates it; the core only defines the format. Roots are
//! authenticated by their key (`id_pub`) through Noise, never by DNS or TLS.

use serde::{Deserialize, Serialize};

use crate::descriptor::{validate_endpoint, MAX_ENDPOINTS};
use crate::{cbor, CoreError, Result};

/// Format version.
pub const VERSION: u8 = 1;
/// Maximum number of roots.
pub const MAX_ROOTS: usize = 8;
const MAX_BOOTSTRAP_LEN: usize = 8 * 1024;

/// One root node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootEntry {
    /// Ed25519 identity, the trust anchor.
    #[serde(with = "serde_bytes")]
    pub id_pub: [u8; 32],
    /// Domain name **and** direct-IP endpoints (`wss://`).
    pub endpoints: Vec<String>,
}

/// Bootstrap block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    /// Format version.
    pub v: u8,
    /// Root nodes.
    pub roots: Vec<RootEntry>,
}

impl Bootstrap {
    /// CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        cbor::to_vec(self)
    }

    /// Decode and validate (`1..=8` roots, each with `1..=4` `wss://` endpoints).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let b: Bootstrap = cbor::from_slice(bytes, MAX_BOOTSTRAP_LEN)?;
        if b.v != VERSION {
            return Err(CoreError::UnsupportedVersion);
        }
        if b.roots.is_empty() || b.roots.len() > MAX_ROOTS {
            return Err(CoreError::Malformed);
        }
        for r in &b.roots {
            if r.endpoints.is_empty() || r.endpoints.len() > MAX_ENDPOINTS {
                return Err(CoreError::Malformed);
            }
            r.endpoints.iter().try_for_each(|e| validate_endpoint(e))?;
        }
        Ok(b)
    }

    /// Root identities, the trust anchors for directory verification.
    pub fn root_ids(&self) -> Vec<[u8; 32]> {
        self.roots.iter().map(|r| r.id_pub).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreError;
    use proptest::prelude::*;

    fn sample() -> Bootstrap {
        Bootstrap {
            v: 1,
            roots: vec![
                RootEntry {
                    id_pub: [1; 32],
                    endpoints: vec!["wss://root1.example".into(), "wss://203.0.113.7:443".into()],
                },
                RootEntry {
                    id_pub: [2; 32],
                    endpoints: vec!["wss://root2.example".into()],
                },
            ],
        }
    }

    #[test]
    fn bootstrap_roundtrip() {
        let b = sample();
        assert_eq!(Bootstrap::decode(&b.encode()), Ok(b.clone()));
        assert_eq!(b.root_ids(), vec![[1; 32], [2; 32]]);
    }

    #[test]
    fn bootstrap_rejects_zero_roots() {
        let b = Bootstrap {
            v: 1,
            roots: vec![],
        };
        assert_eq!(Bootstrap::decode(&b.encode()), Err(CoreError::Malformed));
    }

    #[test]
    fn bootstrap_rejects_root_without_endpoint() {
        let mut b = sample();
        b.roots[1].endpoints.clear();
        assert_eq!(Bootstrap::decode(&b.encode()), Err(CoreError::Malformed));
    }

    #[test]
    fn bootstrap_rejects_bad_version() {
        let mut b = sample();
        b.v = 2;
        assert_eq!(
            Bootstrap::decode(&b.encode()),
            Err(CoreError::UnsupportedVersion)
        );
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = Bootstrap::decode(&bytes);
        }
    }
}
