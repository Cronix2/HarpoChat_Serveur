// SPDX-License-Identifier: Apache-2.0
//! The new node's side of `join` (spec §4.3): one copy-paste.
//!
//! 1. Decode the token (sponsor id, endpoints, one-time secret, expiry).
//! 2. Generate keys, sign a descriptor, prove possession of the secret
//!    bound to that descriptor (`HMAC(secret, descriptor)`).
//! 3. Open a Noise link to the sponsor, requiring its identity, and send the
//!    `JoinRequest` (our identity is proved by Noise too).
//! 4. Check the answer **before writing anything**: the vouch is for us,
//!    signed by the sponsor, and the whole chain reaches the roots received.
//! 5. Write `node.key` and a configuration with the roots, the sponsor as a
//!    first peer and the chain. `run` then joins the mesh by gossip.

use std::path::Path;
use std::time::Duration;

use harpochat_core::cbor;
use harpochat_core::directory::{verify_entry, DirectoryEntry};
use harpochat_core::invite::{decode_signed_token, join_proof, JoinRequest, JoinResponse};
use harpochat_core::link::{FrameKind, LinkFrame, SizeClass};
use harpochat_core::CoreError;

use crate::config::{host_port, Config, ConfigError, PeerConfig, RootConfig, CONFIG_FILE};
use crate::keystore::{self, NodeKeys, KEY_FILE};
use crate::net;
use crate::node::Node;

/// How long to wait for the sponsor's answer.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE: usize = 32 * 1024;

/// Result of a successful join.
#[derive(Debug)]
pub struct Joined {
    /// The new node's identity.
    pub id: [u8; 32],
    /// Its sponsor.
    pub sponsor: [u8; 32],
    /// Length of its sponsorship chain (1 = vouched by a root).
    pub chain_len: usize,
    /// Roots it now trusts.
    pub roots: usize,
}

/// Why joining failed. Nothing has been written in any case.
#[derive(Debug)]
pub enum JoinError {
    /// The token does not decode, is expired or badly signed (exit 2).
    Token(CoreError),
    /// The data directory already holds a node (exit 2).
    Exists,
    /// An endpoint or the configuration is invalid (exit 2).
    Config(ConfigError),
    /// No sponsor endpoint answered (exit 1).
    Unreachable,
    /// The sponsor refused (token used or expired, limit reached…) (exit 1).
    Refused,
    /// The sponsor's answer does not verify (exit 1).
    BadResponse,
    /// Writing the files failed (exit 1).
    Io(String),
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Token(CoreError::Expired) => f.write_str("jeton expiré"),
            JoinError::Token(_) => f.write_str("jeton invalide (copier-coller incomplet ?)"),
            JoinError::Exists => f.write_str("ce répertoire contient déjà un nœud"),
            JoinError::Config(e) => e.fmt(f),
            JoinError::Unreachable => f.write_str("parrain injoignable"),
            JoinError::Refused => f.write_str(
                "refusé par le parrain (jeton déjà utilisé ou expiré, ou limite de parrainage \
                 atteinte)",
            ),
            JoinError::BadResponse => {
                f.write_str("réponse du parrain invalide : chaîne de parrainage non vérifiable")
            }
            JoinError::Io(e) => write!(f, "écriture impossible : {e}"),
        }
    }
}

impl std::error::Error for JoinError {}

async fn ask(hp: &str, keys: &NodeKeys, sponsor: [u8; 32], req: &[u8]) -> Option<JoinResponse> {
    let addr = tokio::net::lookup_host(hp).await.ok()?.next()?;
    let (mut reader, mut writer, _) =
        net::connect_named(addr, hp, &keys.noise, Some(&keys.identity), Some(sponsor))
            .await
            .ok()?;
    let class = if req.len() <= SizeClass::Small.max_body_len() {
        SizeClass::Small
    } else {
        SizeClass::Large
    };
    writer
        .send(
            &LinkFrame {
                kind: FrameKind::JoinRequest,
                body: req.to_vec(),
            },
            class,
        )
        .await
        .ok()?;
    let wait = async {
        loop {
            let (_, f) = reader.recv().await.ok()?;
            if f.kind == FrameKind::JoinResponse {
                return cbor::from_slice::<JoinResponse>(&f.body, MAX_RESPONSE).ok();
            }
        }
    };
    tokio::time::timeout(JOIN_TIMEOUT, wait).await.ok()?
}

/// Join the mesh with `token`, announcing `endpoints`; writes the node into
/// `dir` only on success.
pub async fn join_mesh(
    dir: &Path,
    token: &str,
    endpoints: Vec<String>,
    now: u64,
) -> Result<Joined, JoinError> {
    if dir.join(KEY_FILE).exists() || dir.join(CONFIG_FILE).exists() {
        return Err(JoinError::Exists);
    }
    let signed = decode_signed_token(token, now).map_err(JoinError::Token)?;
    let invite = signed.verify().map_err(JoinError::Token)?;
    let sponsor = invite.sponsor_id;

    // Provisional configuration: the sponsor stands in as root until the
    // real roots arrive.
    let mut config = Config::default();
    config.node.public_endpoints = endpoints;
    config.roots = vec![RootConfig {
        id_pub: hex::encode(sponsor),
        endpoints: invite.sponsor_endpoints.clone(),
    }];
    let keys = NodeKeys::generate();
    let node = Node::new(config, keys.clone(), now).map_err(|e| match e {
        crate::node::NodeError::Config(c) => JoinError::Config(c),
        other => JoinError::Io(other.to_string()),
    })?;
    let descriptor = node.descriptor(now);
    let req = cbor::to_vec(&JoinRequest {
        invite: signed,
        proof: join_proof(&invite.secret, &descriptor),
        descriptor: descriptor.clone(),
    });

    let mut response = None;
    for hp in invite.sponsor_endpoints.iter().filter_map(|e| host_port(e)) {
        if let Some(r) = ask(&hp, &keys, sponsor, &req).await {
            response = Some(r);
            break;
        }
    }
    let resp = response.ok_or(JoinError::Unreachable)?;
    let vouch = resp.vouch.clone().ok_or(JoinError::Refused)?;
    let v = vouch.verify().map_err(|_| JoinError::BadResponse)?;
    if v.node_id != keys.identity.public() || v.sponsor_id != sponsor || resp.roots.is_empty() {
        return Err(JoinError::BadResponse);
    }
    let mut chain = vec![vouch];
    chain.extend(resp.chain.iter().cloned());
    let root_ids: Vec<[u8; 32]> = resp.roots.iter().map(|r| r.id_pub).collect();
    let entry = DirectoryEntry {
        descriptor,
        chain: chain.clone(),
    };
    verify_entry(&entry, &root_ids, &[], now).map_err(|_| JoinError::BadResponse)?;

    // Final configuration.
    let mut config = node.config.clone();
    config.roots = resp
        .roots
        .iter()
        .map(|r| RootConfig {
            id_pub: hex::encode(r.id_pub),
            endpoints: r.endpoints.clone(),
        })
        .collect();
    config.peers = vec![PeerConfig {
        id_pub: hex::encode(sponsor),
        endpoint: invite.sponsor_endpoints[0].clone(),
    }];
    config.node.chain = chain.iter().map(|v| hex::encode(cbor::to_vec(v))).collect();
    config.validate().map_err(JoinError::Config)?;

    std::fs::create_dir_all(dir).map_err(|e| JoinError::Io(e.to_string()))?;
    keystore::save(dir, &keys).map_err(|e| JoinError::Io(e.to_string()))?;
    config.save(dir).map_err(|e| JoinError::Io(e.to_string()))?;
    Ok(Joined {
        id: keys.identity.public(),
        sponsor,
        chain_len: chain.len(),
        roots: config.roots.len(),
    })
}
