// SPDX-License-Identifier: Apache-2.0
//! The node's view of the mesh (spec §4.2–4.3).
//!
//! Entries (descriptor + sponsorship chain) and revocations are learnt from
//! the directories of the node's peers — gossip by periodic pull — and from
//! the nodes it sponsors itself. Everything is re-verified against the
//! trusted roots on every change: a node is kept only while its chain reaches
//! a root, is not revoked, and respects the sponsorship limit. The view
//! decides which nodes this node links to, and is what it serves to phones.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration;

use harpochat_core::cbor;
use harpochat_core::directory::{
    verify_entries, Directory, DirectoryEntry, Revoke, VerifiedNode, MAX_DIRECTORY_ENTRIES,
    MAX_REVOCATIONS, VERSION,
};
use harpochat_core::link::SizeClass;
use harpochat_core::signed::Signed;

use crate::config::host_port;
use crate::node::Node;

/// How often a node pulls its peers' directories.
pub const GOSSIP_EVERY: Duration = Duration::from_secs(5);

/// What changed in the set of verified nodes (this node excluded).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// New nodes, with the `host:port` to dial (if they announce one).
    pub added: Vec<([u8; 32], Option<String>)>,
    /// Nodes no longer valid (revoked, expired, over the limit).
    pub removed: Vec<[u8; 32]>,
}

/// Sponsorship links remembered for judging revocations.
const MAX_SEEN_LINKS: usize = 16_384;

#[derive(Default)]
struct State {
    entries: HashMap<[u8; 32], DirectoryEntry>,
    revocations: Vec<Signed<Revoke>>,
    members: HashSet<[u8; 32]>,
    /// `(node, sponsor)` of every vouch seen in a chain, kept after the
    /// entry is gone so its sponsor's revocation stays relevant.
    seen_links: HashSet<([u8; 32], [u8; 32])>,
}

/// The node's view of the mesh.
pub struct Membership {
    own: [u8; 32],
    roots: Vec<[u8; 32]>,
    state: Mutex<State>,
}

fn valid_until(e: &DirectoryEntry) -> u64 {
    e.descriptor.peek().map(|d| d.valid_until).unwrap_or(0)
}

impl Membership {
    /// Empty view, trusting the node's roots, with its own revocations.
    pub fn new(node: &Node) -> Self {
        Self {
            own: node.keys.identity.public(),
            roots: node.trusted_roots().unwrap_or_default(),
            state: Mutex::new(State {
                revocations: node.revocations().to_vec(),
                ..State::default()
            }),
        }
    }

    fn add_revocation(st: &mut State, r: Signed<Revoke>) {
        if st.revocations.len() < MAX_REVOCATIONS
            && r.verify().is_ok()
            && !st.revocations.iter().any(|x| x.body == r.body)
        {
            st.revocations.push(r);
        }
    }

    fn add_entry(&self, st: &mut State, e: DirectoryEntry) {
        let Ok(d) = e.descriptor.peek() else { return };
        if d.id_pub == self.own {
            return;
        }
        for v in e.chain.iter().filter_map(|v| v.verify().ok()) {
            if st.seen_links.len() < MAX_SEEN_LINKS {
                st.seen_links.insert((v.node_id, v.sponsor_id));
            }
        }
        let newer = st
            .entries
            .get(&d.id_pub)
            .is_none_or(|old| valid_until(old) < d.valid_until);
        if newer && (st.entries.len() < MAX_DIRECTORY_ENTRIES || st.entries.contains_key(&d.id_pub))
        {
            st.entries.insert(d.id_pub, e);
        }
    }

    /// Keep only revocations that can take effect: signed by a root, or by
    /// a sponsor that vouched for the revoked node in a known chain. Others
    /// would only fill the bounded list (a member signing junk revocations).
    fn prune_revocations(&self, st: &mut State) {
        let (roots, links) = (&self.roots, &st.seen_links);
        st.revocations.retain(|r| {
            r.peek().is_ok_and(|r| {
                roots.contains(&r.sponsor_id) || links.contains(&(r.node_id, r.sponsor_id))
            })
        });
    }

    /// Re-verify everything; drop what no longer verifies.
    fn reverify(&self, st: &mut State, now: u64) -> Changes {
        let revs: Vec<Revoke> = st
            .revocations
            .iter()
            .filter_map(|r| r.verify().ok())
            .collect();
        let entries: Vec<DirectoryEntry> = st.entries.values().cloned().collect();
        let ok = verify_entries(&entries, &revs, &self.roots, now);
        let new: HashMap<[u8; 32], VerifiedNode> = ok
            .iter()
            .map(|(_, v)| (v.descriptor.id_pub, v.clone()))
            .collect();
        st.entries.retain(|id, _| new.contains_key(id));
        let mut changes = Changes::default();
        for (id, v) in &new {
            if !st.members.contains(id) {
                let hp = v.descriptor.endpoints.iter().find_map(|e| host_port(e));
                changes.added.push((*id, hp));
            }
        }
        for id in &st.members {
            if !new.contains_key(id) {
                changes.removed.push(*id);
            }
        }
        changes.added.sort();
        changes.removed.sort();
        st.members = new.into_keys().collect();
        changes
    }

    /// Merge a peer's (or any node's) signed directory.
    pub fn merge(&self, dir: &Signed<Directory>, now: u64) -> Changes {
        let Ok(d) = dir.verify() else {
            return Changes::default();
        };
        if d.v != VERSION
            || d.entries.len() > MAX_DIRECTORY_ENTRIES
            || d.revocations.len() > MAX_REVOCATIONS
        {
            return Changes::default();
        }
        let mut st = self.state.lock().expect("membership");
        for r in d.revocations {
            Self::add_revocation(&mut st, r);
        }
        for e in d.entries {
            self.add_entry(&mut st, e);
        }
        self.prune_revocations(&mut st);
        self.reverify(&mut st, now)
    }

    /// Add an entry this node vouched for itself.
    pub fn insert(&self, entry: DirectoryEntry, now: u64) -> Changes {
        let mut st = self.state.lock().expect("membership");
        self.add_entry(&mut st, entry);
        self.reverify(&mut st, now)
    }

    /// Record a revocation (signed by this node, or received).
    pub fn revoke(&self, r: Signed<Revoke>, now: u64) -> Changes {
        let mut st = self.state.lock().expect("membership");
        Self::add_revocation(&mut st, r);
        self.reverify(&mut st, now)
    }

    /// Re-verify (expiry of descriptors) without new input.
    pub fn refresh(&self, now: u64) -> Changes {
        let mut st = self.state.lock().expect("membership");
        self.reverify(&mut st, now)
    }

    /// Verified nodes known (this node excluded).
    pub fn len(&self) -> usize {
        self.state.lock().expect("membership").members.len()
    }

    /// No other verified node known.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `id` is a verified node of the mesh (this node excluded).
    pub fn is_member(&self, id: &[u8; 32]) -> bool {
        self.state.lock().expect("membership").members.contains(id)
    }

    /// Verified nodes, this node first when it is itself a member.
    pub fn nodes(&self, node: &Node, now: u64) -> Vec<VerifiedNode> {
        let st = self.state.lock().expect("membership");
        let revs: Vec<Revoke> = st
            .revocations
            .iter()
            .filter_map(|r| r.verify().ok())
            .collect();
        let mut entries = vec![node.own_entry(now)];
        let mut others: Vec<&DirectoryEntry> = st.entries.values().collect();
        others.sort_by_key(|e| e.descriptor.peek().map(|d| d.id_pub).unwrap_or_default());
        entries.extend(others.into_iter().cloned());
        verify_entries(&entries, &revs, &self.roots, now)
            .into_iter()
            .map(|(_, v)| v)
            .collect()
    }

    /// The directory this node signs and serves: itself (when a member),
    /// every verified node, every known revocation — trimmed from the end to
    /// fit a Large link frame (≈ 50 nodes; pagination is future work).
    pub fn directory(&self, node: &Node, now: u64) -> Signed<Directory> {
        let (mut entries, mut revocations) = {
            let st = self.state.lock().expect("membership");
            let mut others: Vec<DirectoryEntry> = st.entries.values().cloned().collect();
            others.sort_by_key(|e| e.descriptor.peek().map(|d| d.id_pub).unwrap_or_default());
            (others, st.revocations.clone())
        };
        if node.is_member(now) {
            entries.insert(0, node.own_entry(now));
        }
        let sign = |entries: &[DirectoryEntry], revocations: &[Signed<Revoke>]| {
            Signed::sign(
                &node.keys.identity,
                &Directory {
                    v: VERSION,
                    issuer: node.keys.identity.public(),
                    issued: now,
                    entries: entries.to_vec(),
                    revocations: revocations.to_vec(),
                },
            )
        };
        let max = SizeClass::Large.max_body_len();
        loop {
            let d = sign(&entries, &revocations);
            let len = cbor::to_vec(&d).len();
            if len <= max {
                return d;
            }
            if entries.len() > 1 {
                // Drop about as many entries as the excess represents.
                let per_entry = len / entries.len();
                let excess = (len - max).div_ceil(per_entry.max(1));
                entries.truncate(entries.len().saturating_sub(excess).max(1));
            } else if !revocations.is_empty() {
                revocations.pop();
            } else {
                return d;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RootConfig};
    use crate::keystore::NodeKeys;
    use harpochat_core::descriptor::{NodeDescriptor, Role};
    use harpochat_core::directory::{verify_directory, Vouch};
    use harpochat_core::keys::SigningKey;

    const NOW: u64 = 1_800_000_000;

    fn root_node(k: &NodeKeys) -> Node {
        let mut c = Config::default();
        c.node.root = true;
        c.node.public_endpoints = vec!["wss://127.0.0.1:4430".into()];
        Node::new(c, k.clone(), NOW).unwrap()
    }

    fn member_node(root: &SigningKey) -> Node {
        let c = Config {
            roots: vec![RootConfig {
                id_pub: hex::encode(root.public()),
                endpoints: vec!["wss://r.example".into()],
            }],
            ..Config::default()
        };
        Node::new(c, NodeKeys::generate(), NOW).unwrap()
    }

    fn desc(k: &SigningKey, valid_until: u64) -> Signed<NodeDescriptor> {
        Signed::sign(
            k,
            &NodeDescriptor {
                v: 1,
                id_pub: k.public(),
                noise_pub: [2; 32],
                sphinx_pub: [3; 32],
                sphinx_key_epoch: 1,
                roles: vec![Role::Mix],
                endpoints: vec!["wss://10.0.0.1:443".into()],
                layer: 0,
                valid_until,
            },
        )
    }

    fn vouch(sponsor: &SigningKey, node: &SigningKey) -> Signed<Vouch> {
        Signed::sign(
            sponsor,
            &Vouch {
                v: 1,
                node_id: node.public(),
                sponsor_id: sponsor.public(),
                issued: NOW - 100,
            },
        )
    }

    fn directory_of(
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
    fn merge_keeps_valid_newest() {
        let root_keys = NodeKeys::generate();
        let me = member_node(&root_keys.identity);
        let m = Membership::new(&me);
        let r = &root_keys.identity;
        let a = SigningKey::generate();
        let stranger = SigningKey::generate();
        let old = DirectoryEntry {
            descriptor: desc(&a, NOW + 100),
            chain: vec![vouch(r, &a)],
        };
        let new = DirectoryEntry {
            descriptor: desc(&a, NOW + 900),
            chain: vec![vouch(r, &a)],
        };
        let unanchored = DirectoryEntry {
            descriptor: desc(&stranger, NOW + 900),
            chain: vec![],
        };
        let root_entry = root_node(&root_keys).own_entry(NOW);
        let ch = m.merge(
            &directory_of(r, vec![root_entry, new.clone(), unanchored], vec![]),
            NOW,
        );
        assert_eq!(ch.added.len(), 2);
        assert!(ch
            .added
            .contains(&(a.public(), Some("10.0.0.1:443".into()))));
        // An older descriptor does not replace a newer one; nothing changes.
        let ch = m.merge(&directory_of(r, vec![old], vec![]), NOW);
        assert_eq!(ch, Changes::default());
        assert!(m.is_member(&a.public()));
        assert!(!m.is_member(&stranger.public()));
        // A directory with a bad issuer signature is ignored.
        let mut forged = directory_of(r, vec![], vec![]);
        forged.sig[0] ^= 1;
        assert_eq!(m.merge(&forged, NOW), Changes::default());
    }

    #[test]
    fn merge_drops_revoked() {
        let root_keys = NodeKeys::generate();
        let r = &root_keys.identity;
        let me = member_node(r);
        let m = Membership::new(&me);
        let a = SigningKey::generate();
        let e = DirectoryEntry {
            descriptor: desc(&a, NOW + 900),
            chain: vec![vouch(r, &a)],
        };
        m.insert(e, NOW);
        assert!(m.is_member(&a.public()));
        let rev = Signed::sign(
            r,
            &Revoke {
                v: 1,
                node_id: a.public(),
                sponsor_id: r.public(),
                revoked_at: NOW - 1,
            },
        );
        let ch = m.merge(&directory_of(r, vec![], vec![rev]), NOW);
        assert_eq!(ch.removed, vec![a.public()]);
        assert!(!m.is_member(&a.public()));
        // Expiry is noticed on refresh.
        let b = SigningKey::generate();
        m.insert(
            DirectoryEntry {
                descriptor: desc(&b, NOW + 10),
                chain: vec![vouch(r, &b)],
            },
            NOW,
        );
        assert_eq!(m.refresh(NOW + 20).removed, vec![b.public()]);
    }

    #[test]
    fn directory_fits_a_large_frame() {
        let root_keys = NodeKeys::generate();
        let node = root_node(&root_keys);
        let m = Membership::new(&node);
        // 200 nodes vouched by the root 40 days apart (within the limit),
        // merged in one directory.
        let r = &root_keys.identity;
        let entries: Vec<DirectoryEntry> = (0..200u64)
            .map(|i| {
                let k = SigningKey::generate();
                let v = Signed::sign(
                    r,
                    &Vouch {
                        v: 1,
                        node_id: k.public(),
                        sponsor_id: r.public(),
                        issued: NOW - 40 * 86_400 * (i + 1),
                    },
                );
                DirectoryEntry {
                    descriptor: desc(&k, NOW + 900),
                    chain: vec![v],
                }
            })
            .collect();
        assert_eq!(
            m.merge(&directory_of(r, entries, vec![]), NOW).added.len(),
            200
        );
        let d = m.directory(&node, NOW);
        assert!(cbor::to_vec(&d).len() <= SizeClass::Large.max_body_len());
        let nodes = verify_directory(&d, &[r.public()], NOW).unwrap();
        assert!(nodes.len() > 20, "{}", nodes.len());
        assert_eq!(
            nodes[0].descriptor.id_pub,
            r.public(),
            "own entry kept first"
        );
    }

    #[test]
    fn junk_revocations_are_not_kept() {
        let root_keys = NodeKeys::generate();
        let r = &root_keys.identity;
        let me = member_node(r);
        let m = Membership::new(&me);
        let a = SigningKey::generate();
        let mallory = SigningKey::generate();
        m.insert(
            DirectoryEntry {
                descriptor: desc(&a, NOW + 900),
                chain: vec![vouch(r, &a)],
            },
            NOW,
        );
        // Mallory (no standing over A) floods revocations: none is kept.
        let junk: Vec<Signed<Revoke>> = (0..50u8)
            .map(|i| {
                Signed::sign(
                    &mallory,
                    &Revoke {
                        v: 1,
                        node_id: [i; 32],
                        sponsor_id: mallory.public(),
                        revoked_at: NOW,
                    },
                )
            })
            .collect();
        m.merge(&directory_of(&mallory, vec![], junk), NOW);
        let d = m.directory(&me, NOW).verify().unwrap();
        assert!(d.revocations.is_empty());
        assert!(m.is_member(&a.public()));
    }

    #[test]
    fn sponsor_revocation_outlives_the_revoked_entry() {
        let root_keys = NodeKeys::generate();
        let r = &root_keys.identity;
        let me = member_node(r);
        let m = Membership::new(&me);
        let (a, b) = (SigningKey::generate(), SigningKey::generate());
        let b_entry = DirectoryEntry {
            descriptor: desc(&b, NOW + 900),
            chain: vec![
                Signed::sign(
                    &a,
                    &Vouch {
                        v: 1,
                        node_id: b.public(),
                        sponsor_id: a.public(),
                        issued: NOW - 50,
                    },
                ),
                vouch(r, &a),
            ],
        };
        m.merge(&directory_of(r, vec![b_entry.clone()], vec![]), NOW);
        assert!(m.is_member(&b.public()));
        // A (B's sponsor, not a root) revokes B.
        let rev = Signed::sign(
            &a,
            &Revoke {
                v: 1,
                node_id: b.public(),
                sponsor_id: a.public(),
                revoked_at: NOW - 1,
            },
        );
        m.merge(&directory_of(&a, vec![], vec![rev]), NOW);
        assert!(!m.is_member(&b.public()));
        // Another gossip round in which B is absent everywhere…
        m.merge(&directory_of(r, vec![], vec![]), NOW);
        // …then a stale peer still lists B: the revocation holds.
        m.merge(&directory_of(r, vec![b_entry], vec![]), NOW);
        assert!(!m.is_member(&b.public()));
    }
}
