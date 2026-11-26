// SPDX-License-Identifier: Apache-2.0
//! A loaded node: configuration, long-term keys, and the in-RAM Sphinx key.

use std::path::Path;

use harpochat_core::descriptor::{NodeDescriptor, VERSION};
use harpochat_core::keys::X25519Secret;
use harpochat_core::signed::Signed;

use crate::config::{Config, ConfigError, CONFIG_FILE};
use crate::keystore::{self, KeyStoreError, NodeKeys};

/// Lifetime of a published descriptor (re-signed well before expiry).
pub const DESCRIPTOR_TTL_SECS: u64 = 24 * 3600;
/// Sphinx key rotation period (spec §13: 7 days).
pub const SPHINX_KEY_PERIOD_SECS: u64 = 7 * 86_400;

/// Why a node could not be loaded.
#[derive(Debug)]
pub enum NodeError {
    /// Configuration problem (exit code 2).
    Config(ConfigError),
    /// Key file problem (exit code 1).
    Keys(KeyStoreError),
    /// Configuration file unreadable (exit code 1).
    Io(std::io::Error),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Config(e) => e.fmt(f),
            NodeError::Keys(e) => e.fmt(f),
            NodeError::Io(e) => write!(f, "lecture de {CONFIG_FILE} impossible : {e}"),
        }
    }
}

impl std::error::Error for NodeError {}

/// A node ready to run.
#[derive(Debug)]
pub struct Node {
    /// Validated configuration.
    pub config: Config,
    /// Long-term keys.
    pub keys: NodeKeys,
    /// Current Sphinx key, RAM only.
    pub sphinx: X25519Secret,
    /// Rotation counter of the Sphinx key.
    pub sphinx_epoch: u32,
}

impl Node {
    /// Assemble a node from parts, validating the configuration.
    pub fn new(config: Config, keys: NodeKeys, now_unix_secs: u64) -> Result<Self, NodeError> {
        config.validate().map_err(NodeError::Config)?;
        if !config.node.root && config.roots.is_empty() {
            return Err(NodeError::Config(ConfigError::Invalid {
                field: "roots",
                reason: "un nœud non racine doit connaître au moins une racine".into(),
            }));
        }
        Ok(Self {
            config,
            keys,
            sphinx: X25519Secret::generate(),
            sphinx_epoch: u32::try_from(now_unix_secs / SPHINX_KEY_PERIOD_SECS).unwrap_or(u32::MAX),
        })
    }

    /// Load configuration and keys from the data directory.
    pub fn load(dir: &Path, now_unix_secs: u64) -> Result<Self, NodeError> {
        let keys = keystore::load(dir).map_err(NodeError::Keys)?;
        let text = std::fs::read_to_string(dir.join(CONFIG_FILE)).map_err(NodeError::Io)?;
        let config = Config::parse(&text).map_err(NodeError::Config)?;
        Self::new(config, keys, now_unix_secs)
    }

    /// Root identities this node trusts (itself included when it is a root).
    pub fn trusted_roots(&self) -> Result<Vec<[u8; 32]>, ConfigError> {
        let mut roots = self.config.root_ids()?;
        if self.config.node.root {
            let me = self.keys.identity.public();
            if !roots.contains(&me) {
                roots.insert(0, me);
            }
        }
        Ok(roots)
    }

    /// Freshly signed descriptor.
    pub fn descriptor(&self, now_unix_secs: u64) -> Signed<NodeDescriptor> {
        let d = NodeDescriptor {
            v: VERSION,
            id_pub: self.keys.identity.public(),
            noise_pub: self.keys.noise.public(),
            sphinx_pub: self.sphinx.public(),
            sphinx_key_epoch: self.sphinx_epoch,
            roles: self.config.node.roles.clone(),
            endpoints: self.config.node.public_endpoints.clone(),
            layer: self.config.node.layer,
            valid_until: now_unix_secs + DESCRIPTOR_TTL_SECS,
        };
        Signed::sign(&self.keys.identity, &d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::keystore::NodeKeys;

    const NOW: u64 = 1_800_000_000;

    fn node(root: bool, roots: bool) -> Result<Node, NodeError> {
        let mut config = Config::default();
        config.node.root = root;
        config.node.public_endpoints = vec!["wss://n.example".into()];
        if roots {
            config.roots = vec![crate::config::RootConfig {
                id_pub: "01".repeat(32),
                endpoints: vec!["wss://r.example".into()],
            }];
        }
        Node::new(config, NodeKeys::generate(), NOW)
    }

    #[test]
    fn descriptor_is_valid() {
        let n = node(true, false).unwrap();
        let d = n.descriptor(NOW).verify().unwrap();
        assert_eq!(harpochat_core::descriptor::validate(&d, NOW), Ok(()));
        assert_eq!(d.id_pub, n.keys.identity.public());
        assert_eq!(d.noise_pub, n.keys.noise.public());
        assert_eq!(d.sphinx_pub, n.sphinx.public());
        assert_eq!(d.valid_until, NOW + DESCRIPTOR_TTL_SECS);
    }

    #[test]
    fn non_root_without_roots_rejected() {
        assert!(matches!(node(false, false), Err(NodeError::Config(_))));
        assert!(node(false, true).is_ok());
    }

    #[test]
    fn root_trusts_itself() {
        let n = node(true, false).unwrap();
        assert_eq!(n.trusted_roots().unwrap(), vec![n.keys.identity.public()]);
        let n = node(true, true).unwrap();
        assert_eq!(n.trusted_roots().unwrap().len(), 2);
    }

    #[test]
    fn sphinx_key_epoch_is_weekly() {
        let n = node(true, false).unwrap();
        assert_eq!(n.sphinx_epoch, (NOW / (7 * 86_400)) as u32);
    }
}
