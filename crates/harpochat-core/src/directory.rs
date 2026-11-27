// SPDX-License-Identifier: Apache-2.0
//! Sponsorship chains, revocations and signed directories (spec §4.2–4.3).
//!
//! A node is trusted only if a chain of `Vouch` certificates links it to one
//! of the root keys embedded in the app. Revocation follows the spec: a
//! revoked node is rejected, and so is every node it vouched for **at or
//! after** its revocation time; nodes it vouched for earlier stay valid.
//!
//! A `Revoke` only counts if signed by the revoked node's own sponsor (as seen
//! in the chain being checked) or by a root.
//!
//! **Sponsorship limit** (spec §4.3): a sponsor vouches for at most
//! [`SPONSOR_LIMIT`] nodes in any [`SPONSOR_PERIOD_SECS`] window of `issued`.
//! Every verifier enforces it over the vouches it sees, so a compromised
//! sponsor cannot flood the mesh: excess vouches (latest `issued` first, then
//! highest `node_id`) are void, and so is every entry whose chain uses one.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::descriptor::{validate, NodeDescriptor};
use crate::signed::{Signed, SignedPayload};
use crate::{domain, CoreError, Result};

/// Format version of vouches, revocations and directories.
pub const VERSION: u8 = 1;
/// Longest accepted sponsorship chain.
pub const MAX_CHAIN_DEPTH: usize = 8;
/// Largest accepted directory.
pub const MAX_DIRECTORY_ENTRIES: usize = 512;
/// Largest accepted revocation list in a directory.
pub const MAX_REVOCATIONS: usize = 1024;
/// Tolerated clock skew for `issued` timestamps.
pub const CLOCK_SKEW_SECS: u64 = 600;
/// Vouches a sponsor may issue per period (spec §4.3).
pub const SPONSOR_LIMIT: usize = 3;
/// Sponsorship period (spec §4.3: 30 days).
pub const SPONSOR_PERIOD_SECS: u64 = 30 * 86_400;

/// Sponsorship certificate: `sponsor_id` admits `node_id` into the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vouch {
    /// Format version.
    pub v: u8,
    /// Admitted node.
    #[serde(with = "serde_bytes")]
    pub node_id: [u8; 32],
    /// Sponsor (signer).
    #[serde(with = "serde_bytes")]
    pub sponsor_id: [u8; 32],
    /// Issue time, unix seconds.
    pub issued: u64,
}

impl SignedPayload for Vouch {
    const DOMAIN: &'static str = domain::VOUCH;
    fn signer(&self) -> [u8; 32] {
        self.sponsor_id
    }
}

/// Revocation of `node_id` by `sponsor_id` (its sponsor, or a root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    /// Format version.
    pub v: u8,
    /// Revoked node.
    #[serde(with = "serde_bytes")]
    pub node_id: [u8; 32],
    /// Revoker (signer).
    #[serde(with = "serde_bytes")]
    pub sponsor_id: [u8; 32],
    /// Effective time, unix seconds.
    pub revoked_at: u64,
}

impl SignedPayload for Revoke {
    const DOMAIN: &'static str = domain::REVOKE;
    fn signer(&self) -> [u8; 32] {
        self.sponsor_id
    }
}

/// A descriptor plus the chain linking it to a root.
///
/// `chain[0]` vouches for the node, `chain[i + 1]` vouches for
/// `chain[i].sponsor_id`, and the last sponsor is a root. An empty chain means
/// the node is itself a root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryEntry {
    /// Self-signed descriptor.
    pub descriptor: Signed<NodeDescriptor>,
    /// Sponsorship chain, node first.
    pub chain: Vec<Signed<Vouch>>,
}

/// A node's view of the mesh, signed by that node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    /// Format version.
    pub v: u8,
    /// Issuing node (signer).
    #[serde(with = "serde_bytes")]
    pub issuer: [u8; 32],
    /// Issue time, unix seconds.
    pub issued: u64,
    /// Known nodes.
    pub entries: Vec<DirectoryEntry>,
    /// Known revocations.
    pub revocations: Vec<Signed<Revoke>>,
}

impl SignedPayload for Directory {
    const DOMAIN: &'static str = domain::DIRECTORY;
    fn signer(&self) -> [u8; 32] {
        self.issuer
    }
}

/// A node that passed [`verify_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedNode {
    /// Its descriptor.
    pub descriptor: NodeDescriptor,
    /// Direct sponsor (`None` for roots); used for path diversity.
    pub sponsor: Option<[u8; 32]>,
}

/// Earliest effective revocation of `node` by `its_sponsor` or by a root.
fn revoked_at(
    revocations: &[Revoke],
    node: &[u8; 32],
    its_sponsor: Option<&[u8; 32]>,
    roots: &[[u8; 32]],
) -> Option<u64> {
    revocations
        .iter()
        .filter(|r| r.v == VERSION && r.node_id == *node)
        .filter(|r| Some(&r.sponsor_id) == its_sponsor || roots.contains(&r.sponsor_id))
        .map(|r| r.revoked_at)
        .min()
}

/// Verify a directory entry against the trusted `roots` and the known
/// (signature-checked) `revocations`.
pub fn verify_entry(
    entry: &DirectoryEntry,
    roots: &[[u8; 32]],
    revocations: &[Revoke],
    now_unix_secs: u64,
) -> Result<VerifiedNode> {
    let descriptor = entry.descriptor.verify()?;
    validate(&descriptor, now_unix_secs)?;
    let node = descriptor.id_pub;

    if entry.chain.is_empty() {
        if !roots.contains(&node) || revoked_at(revocations, &node, None, roots).is_some() {
            return Err(CoreError::Untrusted);
        }
        return Ok(VerifiedNode {
            descriptor,
            sponsor: None,
        });
    }
    if entry.chain.len() > MAX_CHAIN_DEPTH {
        return Err(CoreError::Untrusted);
    }

    let links = entry
        .chain
        .iter()
        .map(|v| v.verify())
        .collect::<Result<Vec<Vouch>>>()?;

    let mut seen = HashSet::from([node]);
    let mut current = node;
    for (i, link) in links.iter().enumerate() {
        let next_sponsor = links.get(i + 1).map(|l| &l.sponsor_id);
        let ok = link.v == VERSION
            && link.node_id == current
            && link.issued <= now_unix_secs.saturating_add(CLOCK_SKEW_SECS)
            && seen.insert(link.sponsor_id);
        if !ok {
            return Err(CoreError::Untrusted);
        }
        // The node itself must not be revoked.
        if i == 0 && revoked_at(revocations, &node, Some(&link.sponsor_id), roots).is_some() {
            return Err(CoreError::Untrusted);
        }
        // A vouch issued at or after the sponsor's revocation is void.
        if let Some(t) = revoked_at(revocations, &link.sponsor_id, next_sponsor, roots) {
            if link.issued >= t {
                return Err(CoreError::Untrusted);
            }
        }
        current = link.sponsor_id;
    }
    if !roots.contains(&current) {
        return Err(CoreError::Untrusted);
    }
    Ok(VerifiedNode {
        descriptor,
        sponsor: Some(links[0].sponsor_id),
    })
}

/// Vouches void under the sponsorship limit, as `(sponsor, node)` pairs.
fn over_limit(links: &[Vouch]) -> HashSet<([u8; 32], [u8; 32])> {
    // Earliest vouch of each (sponsor, node) pair, grouped by sponsor.
    let mut by_sponsor: BTreeMap<[u8; 32], HashMap<[u8; 32], u64>> = BTreeMap::new();
    for l in links {
        let issued = by_sponsor
            .entry(l.sponsor_id)
            .or_default()
            .entry(l.node_id)
            .or_insert(l.issued);
        *issued = (*issued).min(l.issued);
    }
    let mut void = HashSet::new();
    for (sponsor, nodes) in by_sponsor {
        let mut sorted: Vec<(u64, [u8; 32])> = nodes.into_iter().map(|(n, t)| (t, n)).collect();
        sorted.sort();
        let mut accepted: Vec<u64> = Vec::new();
        for (issued, node) in sorted {
            let in_window = accepted
                .iter()
                .filter(|t| issued.saturating_sub(**t) < SPONSOR_PERIOD_SECS)
                .count();
            if in_window < SPONSOR_LIMIT {
                accepted.push(issued);
            } else {
                void.insert((sponsor, node));
            }
        }
    }
    void
}

/// Verify entries against the roots and (already signature-checked)
/// revocations, then apply the sponsorship limit. Returns the entries that
/// pass, with their verified form, in input order.
pub fn verify_entries(
    entries: &[DirectoryEntry],
    revocations: &[Revoke],
    roots: &[[u8; 32]],
    now_unix_secs: u64,
) -> Vec<(DirectoryEntry, VerifiedNode)> {
    let ok: Vec<(DirectoryEntry, VerifiedNode)> = entries
        .iter()
        .filter_map(|e| {
            verify_entry(e, roots, revocations, now_unix_secs)
                .ok()
                .map(|v| (e.clone(), v))
        })
        .collect();
    let links: Vec<Vouch> = ok
        .iter()
        .flat_map(|(e, _)| e.chain.iter().filter_map(|v| v.peek().ok()))
        .collect();
    let void = over_limit(&links);
    if void.is_empty() {
        return ok;
    }
    ok.into_iter()
        .filter(|(e, _)| {
            e.chain
                .iter()
                .filter_map(|v| v.peek().ok())
                .all(|l| !void.contains(&(l.sponsor_id, l.node_id)))
        })
        .collect()
}

/// Verify a directory: issuer signature, then each entry and the
/// sponsorship limit. Invalid entries and revocations are dropped rather
/// than failing the whole directory.
pub fn verify_directory(
    d: &Signed<Directory>,
    roots: &[[u8; 32]],
    now_unix_secs: u64,
) -> Result<Vec<VerifiedNode>> {
    let dir = d.verify()?;
    if dir.v != VERSION {
        return Err(CoreError::UnsupportedVersion);
    }
    if dir.entries.len() > MAX_DIRECTORY_ENTRIES || dir.revocations.len() > MAX_REVOCATIONS {
        return Err(CoreError::TooLarge);
    }
    let revocations: Vec<Revoke> = dir
        .revocations
        .iter()
        .filter_map(|r| r.verify().ok())
        .collect();
    Ok(
        verify_entries(&dir.entries, &revocations, roots, now_unix_secs)
            .into_iter()
            .map(|(_, v)| v)
            .collect(),
    )
}

/// Nodes present, with the same identity **and** Sphinx key, in every view
/// (spec §4.2: one node cannot fake the topology). Order of the first view.
pub fn intersect(views: &[Vec<VerifiedNode>]) -> Vec<VerifiedNode> {
    let Some((first, rest)) = views.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .filter(|n| {
            rest.iter().all(|view| {
                view.iter().any(|m| {
                    m.descriptor.id_pub == n.descriptor.id_pub
                        && m.descriptor.sphinx_pub == n.descriptor.sphinx_pub
                })
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{NodeDescriptor, Role};
    use crate::keys::SigningKey;
    use crate::signed::Signed;
    use crate::CoreError;

    const NOW: u64 = 1_800_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_seed(&[n; 32])
    }

    fn desc(k: &SigningKey) -> Signed<NodeDescriptor> {
        Signed::sign(
            k,
            &NodeDescriptor {
                v: 1,
                id_pub: k.public(),
                noise_pub: [2; 32],
                sphinx_pub: [k.public()[0]; 32],
                sphinx_key_epoch: 1,
                roles: vec![Role::Mix],
                endpoints: vec!["wss://n.example".into()],
                layer: 0,
                valid_until: NOW + 3_600,
            },
        )
    }

    fn vouch(sponsor: &SigningKey, node: &SigningKey, issued: u64) -> Signed<Vouch> {
        Signed::sign(
            sponsor,
            &Vouch {
                v: 1,
                node_id: node.public(),
                sponsor_id: sponsor.public(),
                issued,
            },
        )
    }

    fn revoke(sponsor: &SigningKey, node: &SigningKey, at: u64) -> Revoke {
        Revoke {
            v: 1,
            node_id: node.public(),
            sponsor_id: sponsor.public(),
            revoked_at: at,
        }
    }

    fn entry(k: &SigningKey, chain: Vec<Signed<Vouch>>) -> DirectoryEntry {
        DirectoryEntry {
            descriptor: desc(k),
            chain,
        }
    }

    // R (root) → A → B
    fn setup() -> (SigningKey, SigningKey, SigningKey, Vec<[u8; 32]>) {
        let (r, a, b) = (key(1), key(2), key(3));
        let roots = vec![r.public()];
        (r, a, b, roots)
    }

    #[test]
    fn root_accepted_with_empty_chain() {
        let (r, _, _, roots) = setup();
        let v = verify_entry(&entry(&r, vec![]), &roots, &[], NOW).unwrap();
        assert_eq!(v.descriptor.id_pub, r.public());
        assert_eq!(v.sponsor, None);
    }

    #[test]
    fn non_root_with_empty_chain_rejected() {
        let (_, a, _, roots) = setup();
        assert_eq!(
            verify_entry(&entry(&a, vec![]), &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn two_level_chain_accepted() {
        let (r, a, b, roots) = setup();
        let e = entry(&b, vec![vouch(&a, &b, NOW - 10), vouch(&r, &a, NOW - 20)]);
        let v = verify_entry(&e, &roots, &[], NOW).unwrap();
        assert_eq!(v.sponsor, Some(a.public()));
    }

    #[test]
    fn unknown_root_rejected() {
        let (_, a, b, roots) = setup();
        let stranger = key(9);
        let e = entry(&b, vec![vouch(&a, &b, NOW), vouch(&stranger, &a, NOW)]);
        assert_eq!(
            verify_entry(&e, &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn broken_link_rejected() {
        let (r, a, b, roots) = setup();
        let c = key(4);
        // chain[1] vouches for C, but chain[0]'s sponsor is A.
        let e = entry(&b, vec![vouch(&a, &b, NOW), vouch(&r, &c, NOW)]);
        assert_eq!(
            verify_entry(&e, &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn forged_vouch_rejected() {
        let (r, a, b, roots) = setup();
        let mut v = vouch(&a, &b, NOW);
        v.sig[0] ^= 1;
        let e = entry(&b, vec![v, vouch(&r, &a, NOW)]);
        assert!(verify_entry(&e, &roots, &[], NOW).is_err());
    }

    #[test]
    fn chain_cycle_rejected() {
        let (_, a, b, roots) = setup();
        let e = entry(&b, vec![vouch(&a, &b, NOW), vouch(&b, &a, NOW)]);
        assert_eq!(
            verify_entry(&e, &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn chain_depth_capped() {
        let r = key(1);
        let roots = vec![r.public()];
        // keys 10..=19: node 10 vouched by 11, …, 18 vouched by 19, 19 by root.
        let ks: Vec<SigningKey> = (10..=19).map(key).collect();
        let mut chain: Vec<Signed<Vouch>> =
            ks.windows(2).map(|w| vouch(&w[1], &w[0], NOW)).collect();
        chain.push(vouch(&r, &ks[9], NOW));
        assert_eq!(chain.len(), MAX_CHAIN_DEPTH + 2);
        assert_eq!(
            verify_entry(&entry(&ks[0], chain.clone()), &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
        // A chain of exactly MAX_CHAIN_DEPTH is fine.
        let tail = &ks[2..];
        let mut ok: Vec<Signed<Vouch>> =
            tail.windows(2).map(|w| vouch(&w[1], &w[0], NOW)).collect();
        ok.push(vouch(&r, tail.last().unwrap(), NOW));
        assert_eq!(ok.len(), MAX_CHAIN_DEPTH);
        assert!(verify_entry(&entry(&tail[0], ok), &roots, &[], NOW).is_ok());
    }

    #[test]
    fn revoked_node_rejected() {
        let (r, a, b, roots) = setup();
        let e = entry(&b, vec![vouch(&a, &b, NOW - 10), vouch(&r, &a, NOW - 20)]);
        let revs = [revoke(&a, &b, NOW - 5)];
        assert_eq!(
            verify_entry(&e, &roots, &revs, NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn vouch_after_revocation_rejected() {
        let (r, a, b, roots) = setup();
        let c = key(4);
        let t = NOW - 100;
        let revs = [revoke(&r, &a, t)];
        let late = entry(&b, vec![vouch(&a, &b, t + 1), vouch(&r, &a, NOW - 1_000)]);
        assert_eq!(
            verify_entry(&late, &roots, &revs, NOW),
            Err(CoreError::Untrusted)
        );
        let at = entry(&b, vec![vouch(&a, &b, t), vouch(&r, &a, NOW - 1_000)]);
        assert_eq!(
            verify_entry(&at, &roots, &revs, NOW),
            Err(CoreError::Untrusted)
        );
        let early = entry(&c, vec![vouch(&a, &c, t - 1), vouch(&r, &a, NOW - 1_000)]);
        assert!(verify_entry(&early, &roots, &revs, NOW).is_ok());
    }

    #[test]
    fn revoke_by_stranger_ignored() {
        let (r, a, b, roots) = setup();
        let stranger = key(9);
        let e = entry(&b, vec![vouch(&a, &b, NOW - 10), vouch(&r, &a, NOW - 20)]);
        let revs = [revoke(&stranger, &b, NOW - 5)];
        assert!(verify_entry(&e, &roots, &revs, NOW).is_ok());
    }

    #[test]
    fn root_can_revoke_any_node() {
        let (r, a, b, roots) = setup();
        let e = entry(&b, vec![vouch(&a, &b, NOW - 10), vouch(&r, &a, NOW - 20)]);
        let revs = [revoke(&r, &b, NOW - 5)];
        assert_eq!(
            verify_entry(&e, &roots, &revs, NOW),
            Err(CoreError::Untrusted)
        );
    }

    #[test]
    fn future_vouch_rejected() {
        let (r, a, b, roots) = setup();
        let e = entry(&b, vec![vouch(&a, &b, NOW + 10_000), vouch(&r, &a, NOW)]);
        assert_eq!(
            verify_entry(&e, &roots, &[], NOW),
            Err(CoreError::Untrusted)
        );
    }

    fn directory(
        issuer: &SigningKey,
        entries: Vec<DirectoryEntry>,
        revs: Vec<Signed<Revoke>>,
    ) -> Signed<Directory> {
        Signed::sign(
            issuer,
            &Directory {
                v: 1,
                issuer: issuer.public(),
                issued: NOW,
                entries,
                revocations: revs,
            },
        )
    }

    #[test]
    fn directory_drops_bad_entries_keeps_good() {
        let (r, a, b, roots) = setup();
        let stranger = key(9);
        let d = directory(
            &a,
            vec![
                entry(&r, vec![]),
                entry(&a, vec![vouch(&r, &a, NOW)]),
                entry(&stranger, vec![]),
                entry(&b, vec![vouch(&a, &b, NOW), vouch(&r, &a, NOW)]),
            ],
            vec![],
        );
        let got = verify_directory(&d, &roots, NOW).unwrap();
        let ids: Vec<[u8; 32]> = got.iter().map(|n| n.descriptor.id_pub).collect();
        assert_eq!(ids, vec![r.public(), a.public(), b.public()]);
    }

    #[test]
    fn directory_applies_its_revocations() {
        let (r, a, b, roots) = setup();
        let d = directory(
            &r,
            vec![entry(
                &b,
                vec![vouch(&a, &b, NOW - 10), vouch(&r, &a, NOW - 20)],
            )],
            vec![Signed::sign(&a, &revoke(&a, &b, NOW - 5))],
        );
        assert!(verify_directory(&d, &roots, NOW).unwrap().is_empty());
    }

    #[test]
    fn directory_bad_issuer_signature_rejected() {
        let (r, _, _, roots) = setup();
        let mut d = directory(&r, vec![entry(&r, vec![])], vec![]);
        d.sig[3] ^= 1;
        assert_eq!(
            verify_directory(&d, &roots, NOW),
            Err(CoreError::BadSignature)
        );
    }

    #[test]
    fn directory_too_large_rejected() {
        let (r, _, _, roots) = setup();
        let e = entry(&r, vec![]);
        let d = directory(&r, vec![e; MAX_DIRECTORY_ENTRIES + 1], vec![]);
        assert_eq!(verify_directory(&d, &roots, NOW), Err(CoreError::TooLarge));
    }

    #[test]
    fn intersect_keeps_common_only() {
        let (r, a, b, roots) = setup();
        let ra = entry(&r, vec![]);
        let aa = entry(&a, vec![vouch(&r, &a, NOW)]);
        let bb = entry(&b, vec![vouch(&a, &b, NOW), vouch(&r, &a, NOW)]);
        let v1: Vec<VerifiedNode> = [&ra, &aa, &bb]
            .iter()
            .map(|e| verify_entry(e, &roots, &[], NOW).unwrap())
            .collect();
        let mut v2: Vec<VerifiedNode> = [&ra, &aa]
            .iter()
            .map(|e| verify_entry(e, &roots, &[], NOW).unwrap())
            .collect();
        // Same id, different Sphinx key in the second view: must be dropped.
        v2[1].descriptor.sphinx_pub = [0xEE; 32];
        let common = intersect(&[v1, v2]);
        let ids: Vec<[u8; 32]> = common.iter().map(|n| n.descriptor.id_pub).collect();
        assert_eq!(ids, vec![r.public()]);
        assert!(intersect(&[]).is_empty());
    }

    #[test]
    fn sponsor_limit_enforced_by_verifiers() {
        let r = key(1);
        let roots = vec![r.public()];
        // The root vouches 5 nodes on the same day: only the first 3 count.
        let kids: Vec<SigningKey> = (10..15).map(key).collect();
        let entries: Vec<DirectoryEntry> = kids
            .iter()
            .enumerate()
            .map(|(i, k)| entry(k, vec![vouch(&r, k, NOW - 100 + i as u64)]))
            .collect();
        let ok = verify_entries(&entries, &[], &roots, NOW);
        let ids: Vec<[u8; 32]> = ok.iter().map(|(_, v)| v.descriptor.id_pub).collect();
        assert_eq!(
            ids,
            kids[..3].iter().map(|k| k.public()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn limit_window_slides() {
        let r = key(1);
        let roots = vec![r.public()];
        let kids: Vec<SigningKey> = (10..14).map(key).collect();
        // Three vouches, then a fourth 30 days after the first: accepted.
        let t0 = NOW - SPONSOR_PERIOD_SECS - 10;
        let times = [t0, t0 + 1, t0 + 2, t0 + SPONSOR_PERIOD_SECS];
        let entries: Vec<DirectoryEntry> = kids
            .iter()
            .zip(times)
            .map(|(k, t)| entry(k, vec![vouch(&r, k, t)]))
            .collect();
        assert_eq!(verify_entries(&entries, &[], &roots, NOW).len(), 4);
        // One day earlier, the fourth is over the limit.
        let mut early = entries.clone();
        early[3] = entry(
            &kids[3],
            vec![vouch(&r, &kids[3], t0 + SPONSOR_PERIOD_SECS - 86_400)],
        );
        assert_eq!(verify_entries(&early, &[], &roots, NOW).len(), 3);
    }

    #[test]
    fn rejected_vouch_voids_descendants() {
        let r = key(1);
        let roots = vec![r.public()];
        let kids: Vec<SigningKey> = (10..14).map(key).collect();
        let mut entries: Vec<DirectoryEntry> = kids
            .iter()
            .enumerate()
            .map(|(i, k)| entry(k, vec![vouch(&r, k, NOW - 100 + i as u64)]))
            .collect();
        // kids[3] is over the limit; a node it sponsored is void too.
        let grandchild = key(20);
        entries.push(entry(
            &grandchild,
            vec![
                vouch(&kids[3], &grandchild, NOW - 10),
                vouch(&r, &kids[3], NOW - 97),
            ],
        ));
        let ok = verify_entries(&entries, &[], &roots, NOW);
        assert_eq!(ok.len(), 3);
        assert!(ok
            .iter()
            .all(|(_, v)| v.descriptor.id_pub != grandchild.public()));
    }
}
