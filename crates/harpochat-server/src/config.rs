// SPDX-License-Identifier: Apache-2.0
//! `harpochat-server.toml` (spec §12.2).

use core::fmt;

use harpochat_core::descriptor::{validate_endpoint, Role, MAX_ENDPOINTS, MAX_LAYER};
use serde::{Deserialize, Serialize};

/// Configuration file name inside the data directory.
pub const CONFIG_FILE: &str = "harpochat-server.toml";
/// Spec §7.3: blobs never outlive 7 days.
pub const MAX_BLOB_TTL_SECS: u64 = 7 * 86_400;

/// Whole configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// This node.
    pub node: NodeSection,
    /// Listening socket.
    pub listen: ListenSection,
    /// Root nodes (trust anchors). Empty only on a root node.
    pub roots: Vec<RootConfig>,
    /// Memory limits.
    pub limits: Limits,
}

/// `[node]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NodeSection {
    /// Roles this node plays.
    pub roles: Vec<Role>,
    /// Mix layer (0..=2).
    pub layer: u8,
    /// Public `wss://` endpoints announced in the descriptor.
    pub public_endpoints: Vec<String>,
    /// Whether this node is a root of the mesh.
    pub root: bool,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            roles: vec![Role::Gateway, Role::Mix, Role::Mailbox],
            layer: 0,
            public_endpoints: Vec::new(),
            root: false,
        }
    }
}

/// `[listen]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenSection {
    /// Socket address, e.g. `0.0.0.0:443`.
    pub addr: String,
}

impl Default for ListenSection {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:443".into(),
        }
    }
}

/// `[[roots]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootConfig {
    /// Ed25519 identity, 64 hex characters.
    pub id_pub: String,
    /// `wss://` endpoints.
    pub endpoints: Vec<String>,
}

/// `[limits]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum blobs per mailbox (spec §13: 1 000).
    pub mailbox_max_blobs: u32,
    /// Maximum bytes per mailbox (spec §13: 50 MiB).
    pub mailbox_max_bytes: u64,
    /// RAM cap for all mailboxes and SURBs (design §5.6).
    pub global_ram_bytes: u64,
    /// Blob lifetime (spec §7.3: 7 days, the maximum).
    pub blob_ttl_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            mailbox_max_blobs: 1000,
            mailbox_max_bytes: 50 * 1024 * 1024,
            global_ram_bytes: 512 * 1024 * 1024,
            blob_ttl_secs: MAX_BLOB_TTL_SECS,
        }
    }
}

/// Configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The file is not valid TOML for this schema.
    Parse(String),
    /// A field has an invalid value.
    Invalid {
        /// Dotted field path.
        field: &'static str,
        /// Human explanation.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(m) => write!(f, "configuration invalide : {m}"),
            ConfigError::Invalid { field, reason } => write!(f, "`{field}` invalide : {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

fn check_endpoints(
    field: &'static str,
    eps: &[String],
    allow_empty: bool,
) -> Result<(), ConfigError> {
    if (!allow_empty && eps.is_empty()) || eps.len() > MAX_ENDPOINTS {
        return Err(invalid(
            field,
            format!("1 à {MAX_ENDPOINTS} adresses attendues"),
        ));
    }
    for e in eps {
        validate_endpoint(e)
            .map_err(|_| invalid(field, format!("`{e}` n'est pas une URL wss:// valide")))?;
    }
    Ok(())
}

fn decode_id(hex_id: &str) -> Result<[u8; 32], ConfigError> {
    let bytes =
        hex::decode(hex_id).map_err(|_| invalid("roots", "id_pub doit être en hexadécimal"))?;
    bytes
        .try_into()
        .map_err(|_| invalid("roots", "id_pub doit faire 32 octets (64 caractères hex)"))
}

impl Config {
    /// Parse TOML (missing sections take defaults; unknown keys are errors).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Render as TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("configuration is always serializable")
    }

    /// Check every value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let n = &self.node;
        let mut roles = n.roles.clone();
        roles.sort_by_key(|r| *r as u8);
        roles.dedup();
        if n.roles.is_empty() || roles.len() != n.roles.len() {
            return Err(invalid("node.roles", "au moins un rôle, sans doublon"));
        }
        if n.layer > MAX_LAYER {
            return Err(invalid(
                "node.layer",
                format!("doit être entre 0 et {MAX_LAYER}"),
            ));
        }
        check_endpoints("node.public_endpoints", &n.public_endpoints, true)?;
        for r in &self.roots {
            decode_id(&r.id_pub)?;
            check_endpoints("roots", &r.endpoints, false)?;
        }
        let l = &self.limits;
        if l.mailbox_max_blobs == 0 || l.mailbox_max_bytes == 0 || l.global_ram_bytes == 0 {
            return Err(invalid("limits", "les limites doivent être non nulles"));
        }
        if l.blob_ttl_secs == 0 || l.blob_ttl_secs > MAX_BLOB_TTL_SECS {
            return Err(invalid(
                "limits.blob_ttl_secs",
                "entre 1 s et 7 jours (spec §7.3)",
            ));
        }
        Ok(())
    }

    /// Decoded root identities.
    pub fn root_ids(&self) -> Result<Vec<[u8; 32]>, ConfigError> {
        self.roots.iter().map(|r| decode_id(&r.id_pub)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        let c = Config::default();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.listen.addr, "0.0.0.0:443");
        assert_eq!(c.limits.mailbox_max_blobs, 1000);
        assert_eq!(c.limits.mailbox_max_bytes, 50 * 1024 * 1024);
        assert_eq!(c.limits.blob_ttl_secs, 7 * 86_400);
        assert_eq!(c.node.roles.len(), 3);
    }

    #[test]
    fn roundtrip_toml() {
        let mut c = Config::default();
        c.node.public_endpoints = vec!["wss://node.example:443".into()];
        c.roots = vec![RootConfig {
            id_pub: "ab".repeat(32),
            endpoints: vec!["wss://root.example".into()],
        }];
        let text = c.to_toml();
        assert_eq!(Config::parse(&text), Ok(c));
    }

    #[test]
    fn partial_file_uses_defaults() {
        let c = Config::parse("[node]\nroot = true\n").unwrap();
        assert!(c.node.root);
        assert_eq!(c.listen.addr, "0.0.0.0:443");
    }

    #[test]
    fn unknown_field_rejected() {
        let err = Config::parse("[node]\nrooot = true\n").unwrap_err();
        assert!(
            matches!(&err, ConfigError::Parse(m) if m.contains("rooot")),
            "{err}"
        );
    }

    #[test]
    fn bad_endpoint_rejected() {
        let mut c = Config::default();
        c.node.public_endpoints = vec!["http://node.example".into()];
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid {
                field: "node.public_endpoints",
                ..
            })
        ));
    }

    #[test]
    fn bad_root_hex_rejected() {
        let mut c = Config::default();
        c.roots = vec![RootConfig {
            id_pub: "zz".into(),
            endpoints: vec!["wss://root.example".into()],
        }];
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid { field: "roots", .. })
        ));
        assert!(c.root_ids().is_err());
    }

    #[test]
    fn ttl_above_spec_rejected() {
        let mut c = Config::default();
        c.limits.blob_ttl_secs = 8 * 86_400;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid {
                field: "limits.blob_ttl_secs",
                ..
            })
        ));
    }

    #[test]
    fn bad_layer_and_roles_rejected() {
        let mut c = Config::default();
        c.node.layer = 3;
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid {
                field: "node.layer",
                ..
            })
        ));
        let mut c = Config::default();
        c.node.roles = vec![];
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid {
                field: "node.roles",
                ..
            })
        ));
    }

    #[test]
    fn root_ids_decode() {
        let mut c = Config::default();
        c.roots = vec![RootConfig {
            id_pub: "01".repeat(32),
            endpoints: vec!["wss://r.example".into()],
        }];
        assert_eq!(c.root_ids(), Ok(vec![[1u8; 32]]));
    }
}
