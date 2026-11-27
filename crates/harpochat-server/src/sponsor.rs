// SPDX-License-Identifier: Apache-2.0
//! Sponsoring new nodes (spec §4.3): invites, and the sponsor's side of
//! `join`.
//!
//! An invite is a self-verifying token signed by this node: `invite-node`
//! can issue it offline, with nothing but `node.key`. When a new node
//! presents it back, the sponsor checks its own signature, the expiry, the
//! HMAC proof binding the token to the new node's descriptor, and that the
//! descriptor's identity is the one proved in Noise; then it burns the token,
//! records the vouch in its configuration (so a restart cannot revive the
//! token) and answers with the vouch, its own chain and its roots.
//!
//! Every refusal is the same `JoinResponse::refusal()`: the requester never
//! learns why (expired, reused, limit reached, bad proof…).

use std::path::Path;
use std::sync::Mutex;

use harpochat_core::bootstrap::RootEntry;
use harpochat_core::cbor;
use harpochat_core::descriptor::{validate, MAX_ENDPOINTS};
use harpochat_core::directory::{DirectoryEntry, Vouch, SPONSOR_PERIOD_SECS, VERSION};
use harpochat_core::hash::h;
use harpochat_core::invite::{
    verify_join_proof, JoinRequest, JoinResponse, NodeInvite, INVITE_TTL_SECS,
};
use harpochat_core::keys::random_bytes;
use harpochat_core::signed::Signed;

use crate::config::{Config, SponsorSection, Vouched, CONFIG_FILE};
use crate::node::Node;

/// Largest `JoinRequest` accepted.
const MAX_JOIN_REQUEST: usize = 8 * 1024;
/// Tolerated clock skew on invite expiry.
const SKEW_SECS: u64 = 600;

/// Why an invite cannot be issued.
#[derive(Debug, PartialEq, Eq)]
pub enum InviteError {
    /// The node announces no `wss://` endpoint to be reached at.
    NoEndpoint,
    /// The node is neither a root nor sponsored: its vouches would be void.
    NotMember,
    /// Validity longer than the spec's 48 h.
    TooLong,
}

impl std::fmt::Display for InviteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InviteError::NoEndpoint => {
                "ce nœud n'annonce aucune adresse publique (node.public_endpoints) : \
                 le nouveau nœud ne saurait pas où le joindre"
            }
            InviteError::NotMember => {
                "ce nœud n'est ni racine ni parrainé : il ne peut pas parrainer"
            }
            InviteError::TooLong => "un jeton est valable 48 h au plus (spec §4.3)",
        })
    }
}

/// Issue a one-time invite valid `ttl_secs` (≤ 48 h).
pub fn create_invite(
    node: &Node,
    now: u64,
    ttl_secs: u64,
) -> Result<Signed<NodeInvite>, InviteError> {
    if ttl_secs == 0 || ttl_secs > INVITE_TTL_SECS {
        return Err(InviteError::TooLong);
    }
    let endpoints: Vec<String> = node
        .config
        .node
        .public_endpoints
        .iter()
        .take(MAX_ENDPOINTS)
        .cloned()
        .collect();
    if endpoints.is_empty() {
        return Err(InviteError::NoEndpoint);
    }
    if !node.is_member(now) {
        return Err(InviteError::NotMember);
    }
    Ok(Signed::sign(
        &node.keys.identity,
        &NodeInvite {
            v: 1,
            sponsor_id: node.keys.identity.public(),
            sponsor_endpoints: endpoints,
            secret: random_bytes(),
            expires: now + ttl_secs,
        },
    ))
}

/// Roots this node trusts, as the new node will need them.
pub fn trusted_root_entries(node: &Node) -> Vec<RootEntry> {
    let mut roots: Vec<RootEntry> = node
        .config
        .roots
        .iter()
        .filter_map(|r| {
            let id: [u8; 32] = hex::decode(&r.id_pub).ok()?.try_into().ok()?;
            Some(RootEntry {
                id_pub: id,
                endpoints: r.endpoints.clone(),
            })
        })
        .collect();
    let me = node.keys.identity.public();
    if node.config.node.root && roots.iter().all(|r| r.id_pub != me) {
        roots.insert(
            0,
            RootEntry {
                id_pub: me,
                endpoints: node.config.node.public_endpoints.clone(),
            },
        );
    }
    roots
}

/// The sponsor role of a running node.
pub struct Sponsor {
    records: Mutex<SponsorSection>,
}

impl Sponsor {
    /// Sponsor state from the node's configuration.
    pub fn new(node: &Node) -> Self {
        Self {
            records: Mutex::new(node.config.sponsor.clone()),
        }
    }

    /// Nodes vouched for so far.
    pub fn vouched(&self) -> Vec<Vouched> {
        self.records.lock().expect("sponsor").vouched.clone()
    }

    /// Answer a `JoinRequest` received on a link whose peer proved
    /// `noise_id`. On success also returns the new node's directory entry.
    pub fn handle_join(
        &self,
        node: &Node,
        body: &[u8],
        noise_id: Option<[u8; 32]>,
        now: u64,
    ) -> (JoinResponse, Option<DirectoryEntry>) {
        match self.try_join(node, body, noise_id, now) {
            Some((resp, entry)) => (resp, Some(entry)),
            None => (JoinResponse::refusal(), None),
        }
    }

    fn try_join(
        &self,
        node: &Node,
        body: &[u8],
        noise_id: Option<[u8; 32]>,
        now: u64,
    ) -> Option<(JoinResponse, DirectoryEntry)> {
        let me = node.keys.identity.public();
        let req: JoinRequest = cbor::from_slice(body, MAX_JOIN_REQUEST).ok()?;
        let invite = req.invite.verify().ok()?;
        let fresh = invite.expires > now && invite.expires <= now + INVITE_TTL_SECS + SKEW_SECS;
        if invite.sponsor_id != me || invite.v != 1 || !fresh {
            return None;
        }
        verify_join_proof(&invite.secret, &req).ok()?;
        let d = req.descriptor.verify().ok()?;
        validate(&d, now).ok()?;
        if noise_id != Some(d.id_pub) || d.id_pub == me || !node.is_member(now) {
            return None;
        }
        let invite_hash = hex::encode(h(&[&req.invite.body]));
        let node_hex = hex::encode(d.id_pub);
        let mut records = self.records.lock().expect("sponsor");
        let used = records
            .vouched
            .iter()
            .any(|v| v.invite == invite_hash || v.node_id == node_hex);
        let recent = records
            .vouched
            .iter()
            .filter(|v| now.saturating_sub(v.issued) < SPONSOR_PERIOD_SECS)
            .count();
        if used || recent >= usize::from(records.limit) {
            return None;
        }
        records.vouched.push(Vouched {
            node_id: node_hex,
            invite: invite_hash,
            issued: now,
        });
        // Burn the token durably before handing out the vouch.
        if let Some(dir) = &node.dir {
            if persist(dir, node, &records).is_err() {
                records.vouched.pop();
                return None;
            }
        }
        drop(records);
        let vouch = Signed::sign(
            &node.keys.identity,
            &Vouch {
                v: VERSION,
                node_id: d.id_pub,
                sponsor_id: me,
                issued: now,
            },
        );
        let mut chain = vec![vouch.clone()];
        chain.extend(node.chain().iter().cloned());
        Some((
            JoinResponse {
                v: 1,
                vouch: Some(vouch),
                chain: node.chain().to_vec(),
                roots: trusted_root_entries(node),
            },
            DirectoryEntry {
                descriptor: req.descriptor,
                chain,
            },
        ))
    }
}

/// Write the sponsor records into the configuration on disk, keeping the
/// rest of the file as it is now (an operator may have edited it).
fn persist(dir: &Path, node: &Node, records: &SponsorSection) -> std::io::Result<()> {
    let mut config = std::fs::read_to_string(dir.join(CONFIG_FILE))
        .ok()
        .and_then(|t| Config::parse(&t).ok())
        .unwrap_or_else(|| node.config.clone());
    config.sponsor = records.clone();
    config.save(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::NodeKeys;
    use harpochat_core::invite::join_proof;

    const NOW: u64 = 1_800_000_000;

    fn root() -> Node {
        let mut c = Config::default();
        c.node.root = true;
        c.node.public_endpoints = vec!["wss://127.0.0.1:4430".into()];
        Node::new(c, NodeKeys::generate(), NOW).unwrap()
    }

    fn joiner(sponsor: &Node) -> Node {
        let mut c = Config::default();
        c.node.public_endpoints = vec!["wss://127.0.0.1:4431".into()];
        c.roots = vec![crate::config::RootConfig {
            id_pub: hex::encode(sponsor.keys.identity.public()),
            endpoints: vec!["wss://127.0.0.1:4430".into()],
        }];
        Node::new(c, NodeKeys::generate(), NOW).unwrap()
    }

    fn request(invite: &Signed<NodeInvite>, new: &Node) -> Vec<u8> {
        let secret = invite.verify().unwrap().secret;
        let descriptor = new.descriptor(NOW);
        cbor::to_vec(&JoinRequest {
            invite: invite.clone(),
            proof: join_proof(&secret, &descriptor),
            descriptor,
        })
    }

    fn id(n: &Node) -> Option<[u8; 32]> {
        Some(n.keys.identity.public())
    }

    #[test]
    fn join_succeeds_and_token_is_single_use() {
        let r = root();
        let s = Sponsor::new(&r);
        let inv = create_invite(&r, NOW, 3600).unwrap();
        let a = joiner(&r);
        let (resp, entry) = s.handle_join(&r, &request(&inv, &a), id(&a), NOW);
        let vouch = resp.vouch.unwrap().verify().unwrap();
        assert_eq!(vouch.node_id, a.keys.identity.public());
        assert_eq!(resp.roots[0].id_pub, r.keys.identity.public());
        let entry = entry.unwrap();
        let roots = [r.keys.identity.public()];
        assert!(harpochat_core::directory::verify_entry(&entry, &roots, &[], NOW).is_ok());
        // Same token, another node: refused.
        let b = joiner(&r);
        let (again, none) = s.handle_join(&r, &request(&inv, &b), id(&b), NOW);
        assert_eq!(again, JoinResponse::refusal());
        assert!(none.is_none());
    }

    #[test]
    fn expired_or_foreign_invite_refused() {
        let r = root();
        let other = root();
        let s = Sponsor::new(&r);
        let a = joiner(&r);
        let inv = create_invite(&r, NOW, 3600).unwrap();
        let (late, _) = s.handle_join(&r, &request(&inv, &a), id(&a), NOW + 3600);
        assert_eq!(late, JoinResponse::refusal());
        let foreign = create_invite(&other, NOW, 3600).unwrap();
        let (f, _) = s.handle_join(&r, &request(&foreign, &a), id(&a), NOW);
        assert_eq!(f, JoinResponse::refusal());
        assert_eq!(
            create_invite(&r, NOW, INVITE_TTL_SECS + 1).err(),
            Some(InviteError::TooLong)
        );
    }

    #[test]
    fn bad_proof_refused() {
        let r = root();
        let s = Sponsor::new(&r);
        let a = joiner(&r);
        let inv = create_invite(&r, NOW, 3600).unwrap();
        let descriptor = a.descriptor(NOW);
        let body = cbor::to_vec(&JoinRequest {
            invite: inv,
            proof: join_proof(&[0; 32], &descriptor),
            descriptor,
        });
        assert_eq!(
            s.handle_join(&r, &body, id(&a), NOW).0,
            JoinResponse::refusal()
        );
        assert_eq!(
            s.handle_join(&r, b"garbage", id(&a), NOW).0,
            JoinResponse::refusal()
        );
    }

    #[test]
    fn join_requires_noise_identity() {
        let r = root();
        let s = Sponsor::new(&r);
        let a = joiner(&r);
        let inv = create_invite(&r, NOW, 3600).unwrap();
        // The link proved another identity (or none): refused, token intact.
        let b = joiner(&r);
        assert_eq!(
            s.handle_join(&r, &request(&inv, &a), id(&b), NOW).0,
            JoinResponse::refusal()
        );
        assert_eq!(
            s.handle_join(&r, &request(&inv, &a), None, NOW).0,
            JoinResponse::refusal()
        );
        assert!(s
            .handle_join(&r, &request(&inv, &a), id(&a), NOW)
            .0
            .vouch
            .is_some());
    }

    #[test]
    fn local_limit_refused() {
        let r = root();
        let s = Sponsor::new(&r);
        for i in 0..3 {
            let a = joiner(&r);
            let inv = create_invite(&r, NOW, 3600).unwrap();
            assert!(s
                .handle_join(&r, &request(&inv, &a), id(&a), NOW + i)
                .0
                .vouch
                .is_some());
        }
        let a = joiner(&r);
        let inv = create_invite(&r, NOW, 3600).unwrap();
        assert_eq!(
            s.handle_join(&r, &request(&inv, &a), id(&a), NOW + 5).0,
            JoinResponse::refusal()
        );
        // 30 days later the window has moved.
        let later = NOW + SPONSOR_PERIOD_SECS + 10;
        let b = Node::new(joiner(&r).config, NodeKeys::generate(), later).unwrap();
        let inv = create_invite(&r, later, 3600).unwrap();
        let req = {
            let secret = inv.verify().unwrap().secret;
            let descriptor = b.descriptor(later);
            cbor::to_vec(&JoinRequest {
                invite: inv,
                proof: join_proof(&secret, &descriptor),
                descriptor,
            })
        };
        assert!(s.handle_join(&r, &req, id(&b), later).0.vouch.is_some());
    }

    #[test]
    fn burned_list_survives_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.node.root = true;
        c.node.public_endpoints = vec!["wss://127.0.0.1:4430".into()];
        let keys = NodeKeys::generate();
        crate::keystore::save(tmp.path(), &keys).unwrap();
        c.save(tmp.path()).unwrap();
        let r = Node::load(tmp.path(), NOW).unwrap();
        let inv = create_invite(&r, NOW, 3600).unwrap();
        let a = joiner(&r);
        assert!(Sponsor::new(&r)
            .handle_join(&r, &request(&inv, &a), id(&a), NOW)
            .0
            .vouch
            .is_some());
        // Restart: the same token is still burned.
        let r = Node::load(tmp.path(), NOW).unwrap();
        assert_eq!(r.config.sponsor.vouched.len(), 1);
        let b = joiner(&r);
        assert_eq!(
            Sponsor::new(&r)
                .handle_join(&r, &request(&inv, &b), id(&b), NOW)
                .0,
            JoinResponse::refusal()
        );
    }

    #[test]
    fn unsponsored_node_cannot_invite() {
        let r = root();
        let a = joiner(&r);
        assert_eq!(
            create_invite(&a, NOW, 3600).err(),
            Some(InviteError::NotMember)
        );
        let mut silent = root();
        silent.config.node.public_endpoints.clear();
        assert_eq!(
            create_invite(&silent, NOW, 3600).err(),
            Some(InviteError::NoEndpoint)
        );
    }
}
