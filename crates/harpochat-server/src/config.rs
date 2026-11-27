// SPDX-License-Identifier: Apache-2.0
//! `harpochat-server.toml` (spec §12.2).

use core::fmt;

use std::path::Path;

use harpochat_core::cbor;
use harpochat_core::descriptor::{validate_endpoint, Role, MAX_ENDPOINTS, MAX_LAYER};
use harpochat_core::directory::{Revoke, Vouch, MAX_CHAIN_DEPTH, SPONSOR_LIMIT};
use harpochat_core::signed::Signed;
use serde::{Deserialize, Serialize};

/// Configuration file name inside the data directory.
pub const CONFIG_FILE: &str = "harpochat-server.toml";
/// Spec §7.3: blobs never outlive 7 days.
pub const MAX_BLOB_TTL_SECS: u64 = 7 * 86_400;

/// Whole configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Revocations signed by this node (hex of CBOR `Signed<Revoke>`),
    /// published in its directory (`harpochat-server revoke`).
    pub revocations: Vec<String>,
    /// This node.
    pub node: NodeSection,
    /// Listening socket.
    pub listen: ListenSection,
    /// Root nodes (trust anchors). Empty only on a root node.
    pub roots: Vec<RootConfig>,
    /// Other nodes this node links to (static until gossip, P7).
    pub peers: Vec<PeerConfig>,
    /// Memory limits.
    pub limits: Limits,
    /// Cover traffic (spec §5, §6.3).
    pub cover: Cover,
    /// Nodes this node sponsored (written by the node itself).
    pub sponsor: SponsorSection,
}

/// `[sponsor]`: this node as a sponsor (spec §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SponsorSection {
    /// Nodes this node may vouch for per 30 days (at most 3, the limit every
    /// verifier enforces).
    pub limit: u8,
    /// Nodes vouched for, and the invites they used (never reusable).
    pub vouched: Vec<Vouched>,
}

impl Default for SponsorSection {
    fn default() -> Self {
        Self {
            limit: SPONSOR_LIMIT as u8,
            vouched: Vec::new(),
        }
    }
}

/// `[[sponsor.vouched]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vouched {
    /// Vouched node, 64 hex characters.
    pub node_id: String,
    /// Hash of the invite it used, 64 hex characters.
    pub invite: String,
    /// Vouch time, unix seconds.
    pub issued: u64,
}

/// Highest configurable rate (frames or packets per second).
pub const MAX_RATE: f64 = 1000.0;

/// `[cover]`: rates in frames (links) or packets (loops, drops) per second.
/// `0` disables the mechanism (development only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cover {
    /// Frames per second on each outbound node link (real or padding).
    pub node_link_rate: f64,
    /// Default frames per second sent to a phone.
    pub phone_link_rate: f64,
    /// Lowest rate a phone may request with `CoverRate`.
    pub phone_link_rate_min: f64,
    /// Highest rate a phone may request with `CoverRate`.
    pub phone_link_rate_max: f64,
    /// Loops emitted by this node per second.
    pub loop_rate: f64,
    /// Drops emitted by this node per second.
    pub drop_rate: f64,
    /// Mean mix delay of this node's own loops and drops (ms).
    pub mean_delay_ms: u64,
}

impl Default for Cover {
    fn default() -> Self {
        Self {
            node_link_rate: 10.0,
            phone_link_rate: 1.0,
            phone_link_rate_min: 0.05,
            phone_link_rate_max: 10.0,
            loop_rate: 0.2,
            drop_rate: 0.2,
            mean_delay_ms: 100,
        }
    }
}

impl Cover {
    /// Everything off (tests that need exact frame sequences).
    pub fn off() -> Self {
        Self {
            node_link_rate: 0.0,
            phone_link_rate: 0.0,
            phone_link_rate_min: 0.0,
            phone_link_rate_max: 0.0,
            loop_rate: 0.0,
            drop_rate: 0.0,
            mean_delay_ms: 100,
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let rates = [
            ("cover.node_link_rate", self.node_link_rate),
            ("cover.phone_link_rate", self.phone_link_rate),
            ("cover.phone_link_rate_min", self.phone_link_rate_min),
            ("cover.phone_link_rate_max", self.phone_link_rate_max),
            ("cover.loop_rate", self.loop_rate),
            ("cover.drop_rate", self.drop_rate),
        ];
        for (field, r) in rates {
            if !r.is_finite() || !(0.0..=MAX_RATE).contains(&r) {
                return Err(invalid(field, format!("entre 0 et {MAX_RATE} par seconde")));
            }
        }
        if !(self.phone_link_rate_min <= self.phone_link_rate
            && self.phone_link_rate <= self.phone_link_rate_max)
        {
            return Err(invalid(
                "cover.phone_link_rate",
                "doit être entre phone_link_rate_min et phone_link_rate_max",
            ));
        }
        if self.mean_delay_ms > harpochat_core::sphinx::MAX_DELAY_MS {
            return Err(invalid(
                "cover.mean_delay_ms",
                format!("au plus {} ms", harpochat_core::sphinx::MAX_DELAY_MS),
            ));
        }
        Ok(())
    }
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
    /// Sponsorship chain from this node up to a root, hex of CBOR
    /// `Signed<Vouch>`, this node's vouch first (written by `join`).
    pub chain: Vec<String>,
}

impl Default for NodeSection {
    fn default() -> Self {
        Self {
            roles: vec![Role::Gateway, Role::Mix, Role::Mailbox],
            layer: 0,
            public_endpoints: Vec::new(),
            root: false,
            chain: Vec::new(),
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

/// `[[peers]]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Ed25519 identity, 64 hex characters.
    pub id_pub: String,
    /// `wss://host:port` of the peer.
    pub endpoint: String,
}

/// `host:port` of a `wss://` endpoint (port 443 by default).
pub fn host_port(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("wss://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    Some(
        if authority
            .rsplit_once(':')
            .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
        {
            authority.to_string()
        } else {
            format!("{authority}:443")
        },
    )
}

impl PeerConfig {
    /// `host:port` part of the endpoint.
    pub fn host_port(&self) -> Option<String> {
        host_port(&self.endpoint)
    }
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

fn decode_signed<T>(field: &'static str, hex_value: &str) -> Result<Signed<T>, ConfigError>
where
    T: harpochat_core::signed::SignedPayload + serde::de::DeserializeOwned + Serialize,
{
    let bytes = hex::decode(hex_value).map_err(|_| invalid(field, "hexadécimal attendu"))?;
    let signed: Signed<T> =
        cbor::from_slice(&bytes, 4096).map_err(|_| invalid(field, "objet CBOR invalide"))?;
    signed
        .verify()
        .map_err(|_| invalid(field, "signature invalide"))?;
    Ok(signed)
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
        for p in &self.peers {
            decode_id(&p.id_pub)
                .map_err(|_| invalid("peers", "id_pub doit faire 64 caractères hex"))?;
            if p.host_port().is_none() {
                return Err(invalid(
                    "peers",
                    format!("`{}` n'est pas une URL wss://hôte:port", p.endpoint),
                ));
            }
        }
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
        self.cover.validate()?;
        if self.node.chain.len() > MAX_CHAIN_DEPTH {
            return Err(invalid("node.chain", "chaîne de parrainage trop longue"));
        }
        self.chain()?;
        self.revocation_list()?;
        if self.sponsor.limit == 0 || usize::from(self.sponsor.limit) > SPONSOR_LIMIT {
            return Err(invalid(
                "sponsor.limit",
                format!("entre 1 et {SPONSOR_LIMIT} (spec §4.3)"),
            ));
        }
        for v in &self.sponsor.vouched {
            decode_id(&v.node_id).map_err(|_| invalid("sponsor.vouched", "node_id invalide"))?;
            decode_id(&v.invite).map_err(|_| invalid("sponsor.vouched", "invite invalide"))?;
        }
        Ok(())
    }

    /// This node's sponsorship chain, decoded and signature-checked.
    pub fn chain(&self) -> Result<Vec<Signed<Vouch>>, ConfigError> {
        self.node
            .chain
            .iter()
            .map(|h| decode_signed("node.chain", h))
            .collect()
    }

    /// Revocations this node publishes, decoded and signature-checked.
    pub fn revocation_list(&self) -> Result<Vec<Signed<Revoke>>, ConfigError> {
        self.revocations
            .iter()
            .map(|h| decode_signed("revocations", h))
            .collect()
    }

    /// Write `harpochat-server.toml` in `dir` atomically (temporary file,
    /// then rename): a crash never leaves a truncated configuration.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let tmp = dir.join(format!("{CONFIG_FILE}.tmp"));
        std::fs::write(&tmp, self.to_toml())?;
        std::fs::rename(&tmp, dir.join(CONFIG_FILE))
    }

    /// Decoded peer identities and `host:port` endpoints.
    pub fn peer_list(&self) -> Result<Vec<([u8; 32], String)>, ConfigError> {
        self.peers
            .iter()
            .map(|p| {
                let id = decode_id(&p.id_pub)?;
                let hp = p
                    .host_port()
                    .ok_or_else(|| invalid("peers", "endpoint invalide"))?;
                Ok((id, hp))
            })
            .collect()
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
    fn cover_config_validated() {
        let c = Config::parse(
            "[cover]
node_link_rate = 50.0
loop_rate = 0
",
        )
        .unwrap();
        assert_eq!(c.cover.node_link_rate, 50.0);
        assert_eq!(c.validate(), Ok(()));
        for bad in [
            "[cover]
node_link_rate = -1.0
",
            "[cover]
node_link_rate = 5000.0
",
            "[cover]
node_link_rate = nan
",
            "[cover]
phone_link_rate = 20.0
",
            "[cover]
phone_link_rate_min = 2.0
",
            "[cover]
mean_delay_ms = 600000
",
        ] {
            let c = Config::parse(bad).unwrap();
            assert!(c.validate().is_err(), "{bad}");
        }
        let mut off = Config::default();
        off.cover = Cover::off();
        assert_eq!(off.validate(), Ok(()));
    }

    fn signed_vouch_hex() -> String {
        let k = harpochat_core::keys::SigningKey::from_seed(&[4; 32]);
        hex::encode(cbor::to_vec(&Signed::sign(
            &k,
            &Vouch {
                v: 1,
                node_id: [9; 32],
                sponsor_id: k.public(),
                issued: 1,
            },
        )))
    }

    #[test]
    fn chain_and_revocations_validated() {
        let mut c = Config::default();
        c.node.chain = vec![signed_vouch_hex()];
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(c.chain().unwrap().len(), 1);
        let mut bad = c.clone();
        bad.node.chain = vec!["zz".into()];
        assert!(bad.validate().is_err());
        let mut tampered = c.clone();
        let mut bytes = hex::decode(&c.node.chain[0]).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        tampered.node.chain = vec![hex::encode(bytes)];
        assert!(tampered.validate().is_err());
        let mut wrong_kind = c.clone();
        wrong_kind.revocations = vec![signed_vouch_hex()];
        assert!(wrong_kind.validate().is_err());
        let mut limit = Config::default();
        limit.sponsor.limit = 4;
        assert!(limit.validate().is_err());
    }

    #[test]
    fn save_is_atomic_and_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.node.chain = vec![signed_vouch_hex()];
        c.sponsor.vouched.push(Vouched {
            node_id: "ab".repeat(32),
            invite: "cd".repeat(32),
            issued: 5,
        });
        c.save(tmp.path()).unwrap();
        c.save(tmp.path()).unwrap(); // replaces the existing file
        let text = std::fs::read_to_string(tmp.path().join(CONFIG_FILE)).unwrap();
        assert_eq!(Config::parse(&text), Ok(c));
        assert!(!tmp.path().join(format!("{CONFIG_FILE}.tmp")).exists());
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
        let c = Config {
            roots: vec![RootConfig {
                id_pub: "zz".into(),
                endpoints: vec!["wss://root.example".into()],
            }],
            ..Config::default()
        };
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
    fn peers_config_validated() {
        let c = Config::parse(
            "[[peers]]
id_pub = \"0101010101010101010101010101010101010101010101010101010101010101\"
endpoint = \"wss://10.0.0.2:8443\"
",
        )
        .unwrap();
        assert_eq!(c.validate(), Ok(()));
        assert_eq!(
            c.peer_list().unwrap(),
            vec![([1u8; 32], "10.0.0.2:8443".to_string())]
        );
        let mut bad = c.clone();
        bad.peers[0].endpoint = "http://x".into();
        assert!(matches!(
            bad.validate(),
            Err(ConfigError::Invalid { field: "peers", .. })
        ));
        let mut noport = c;
        noport.peers[0].endpoint = "wss://node.example".into();
        assert_eq!(noport.peer_list().unwrap()[0].1, "node.example:443");
    }

    #[test]
    fn root_ids_decode() {
        let c = Config {
            roots: vec![RootConfig {
                id_pub: "01".repeat(32),
                endpoints: vec!["wss://r.example".into()],
            }],
            ..Config::default()
        };
        assert_eq!(c.root_ids(), Ok(vec![[1u8; 32]]));
    }
}
