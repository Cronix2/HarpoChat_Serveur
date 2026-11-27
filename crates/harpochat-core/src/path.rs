// SPDX-License-Identifier: Apache-2.0
//! Route selection, delays and mailbox placement (spec §4.3, §6.1–6.2).
//!
//! Pure functions: randomness comes from caller-supplied closures, so the
//! app and the tests decide where it comes from.
//!
//! * Forward route: `gateway → mix… → mailbox`; reply (SURB) route:
//!   `mix… → gateway`. One mix below [`SMALL_MESH_LIMIT`] nodes, three
//!   (one per layer) at or above it.
//! * A route never visits a node twice and never ends at its own gateway
//!   (the gateway would see both the phone and the mailbox).
//! * Diversity: avoid two nodes with the same direct sponsor, then two nodes
//!   in the same IPv4 /16; relaxed in that order when the mesh is too small.
//! * Mailbox placement (deviation E14): rendezvous hashing over nodes with
//!   the `mailbox` role, [`MAILBOX_REPLICAS`] replicas.

use std::net::Ipv4Addr;

use crate::descriptor::Role;
use crate::directory::VerifiedNode;
use crate::hash::h_domain;
use crate::sphinx::{Hop, MAX_DELAY_MS};
use crate::{domain, CoreError, Result};

/// From this many nodes on, routes use three mix layers.
pub const SMALL_MESH_LIMIT: usize = 12;
/// Default mean per-mix delay (spec §13).
pub const DEFAULT_MEAN_DELAY_MS: u64 = 100;
/// Mailbox replicas per mailbox id.
pub const MAILBOX_REPLICAS: usize = 3;

/// A node usable in a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Address and Sphinx key.
    pub hop: Hop,
    /// Roles it accepts.
    pub roles: Vec<Role>,
    /// Mix layer.
    pub layer: u8,
    /// Direct sponsor (`None` for roots).
    pub sponsor: Option<[u8; 32]>,
    /// First two octets of its IPv4 endpoint, when it has one.
    pub ipv4_16: Option<[u8; 2]>,
}

/// First two octets of a `wss://` endpoint whose host is an IPv4 literal.
pub fn ipv4_16_of(endpoint: &str) -> Option<[u8; 2]> {
    let rest = endpoint.strip_prefix("wss://")?;
    let authority = rest.split('/').next()?;
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    let ip: Ipv4Addr = host.parse().ok()?;
    let o = ip.octets();
    Some([o[0], o[1]])
}

impl From<&VerifiedNode> for Candidate {
    fn from(n: &VerifiedNode) -> Self {
        let d = &n.descriptor;
        Candidate {
            hop: Hop::from(d),
            roles: d.roles.clone(),
            layer: d.layer,
            sponsor: n.sponsor,
            ipv4_16: d.endpoints.iter().find_map(|e| ipv4_16_of(e)),
        }
    }
}

/// A route and its per-hop delays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Hops, in order.
    pub hops: Vec<Hop>,
    /// Delay applied by each hop (zero for gateway and final hop).
    pub delays_ms: Vec<u64>,
}

/// Exponential delay: `-mean · ln(1 − u)` for `u ∈ [0, 1)`, capped.
pub fn exponential_delay_ms(mean_ms: u64, uniform: f64) -> u64 {
    let u = if uniform.is_finite() {
        uniform.clamp(0.0, 1.0 - 1e-9)
    } else {
        0.0
    };
    let d = -(mean_ms as f64) * (1.0 - u).ln();
    (d.round() as u64).min(MAX_DELAY_MS)
}

fn find<'a>(nodes: &'a [Candidate], id: &[u8; 32]) -> Result<&'a Candidate> {
    nodes
        .iter()
        .find(|c| c.hop.id_pub == *id)
        .ok_or(CoreError::Untrusted)
}

/// Pick `count` mixes distinct from `fixed`, layered when `count == 3`,
/// applying the diversity rules with relaxation.
fn pick_mixes<'a>(
    nodes: &'a [Candidate],
    fixed: &[&'a Candidate],
    count: usize,
    pick: &mut dyn FnMut(usize) -> usize,
) -> Result<Vec<&'a Candidate>> {
    let mut chosen: Vec<&Candidate> = Vec::new();
    for i in 0..count {
        let taken: Vec<&Candidate> = fixed
            .iter()
            .copied()
            .chain(chosen.iter().copied())
            .collect();
        let base: Vec<&Candidate> = nodes
            .iter()
            .filter(|c| c.roles.contains(&Role::Mix))
            .filter(|c| taken.iter().all(|t| t.hop.id_pub != c.hop.id_pub))
            .collect();
        let layered: Vec<&Candidate> = if count == 3 {
            let l: Vec<_> = base
                .iter()
                .copied()
                .filter(|c| c.layer as usize == i)
                .collect();
            if l.is_empty() {
                base.clone()
            } else {
                l
            }
        } else {
            base.clone()
        };
        let sponsor_ok =
            |c: &&Candidate| c.sponsor.is_none() || taken.iter().all(|t| t.sponsor != c.sponsor);
        let net_ok =
            |c: &&Candidate| c.ipv4_16.is_none() || taken.iter().all(|t| t.ipv4_16 != c.ipv4_16);
        let levels: [Vec<&Candidate>; 3] = [
            layered
                .iter()
                .copied()
                .filter(sponsor_ok)
                .filter(net_ok)
                .collect(),
            layered.iter().copied().filter(net_ok).collect(),
            layered.clone(),
        ];
        let Some(set) = levels.into_iter().find(|s| !s.is_empty()) else {
            return Err(CoreError::Malformed);
        };
        chosen.push(set[pick(set.len()) % set.len()]);
    }
    Ok(chosen)
}

fn mix_count(nodes: &[Candidate]) -> usize {
    if nodes.len() >= SMALL_MESH_LIMIT {
        3
    } else {
        1
    }
}

/// `gateway → mix… → mailbox`.
pub fn forward_route(
    nodes: &[Candidate],
    gateway: &[u8; 32],
    mailbox: &[u8; 32],
    pick: &mut dyn FnMut(usize) -> usize,
    uniform: &mut dyn FnMut() -> f64,
    mean_ms: u64,
) -> Result<Route> {
    let gw = find(nodes, gateway)?;
    let mb = find(nodes, mailbox)?;
    if gateway == mailbox {
        // Only a single-node development mesh may deliver to its own gateway.
        return if nodes.len() == 1 {
            Ok(Route {
                hops: vec![gw.hop],
                delays_ms: vec![0],
            })
        } else {
            Err(CoreError::Malformed)
        };
    }
    if nodes.len() < 3 {
        return Ok(Route {
            hops: vec![gw.hop, mb.hop],
            delays_ms: vec![0, 0],
        });
    }
    let mixes = pick_mixes(nodes, &[gw, mb], mix_count(nodes), pick)?;
    let mut hops = vec![gw.hop];
    let mut delays_ms = vec![0];
    for m in mixes {
        hops.push(m.hop);
        delays_ms.push(exponential_delay_ms(mean_ms, uniform()));
    }
    hops.push(mb.hop);
    delays_ms.push(0);
    Ok(Route { hops, delays_ms })
}

/// SURB route `mix… → gateway` for replies sent by `mailbox`.
pub fn reply_route(
    nodes: &[Candidate],
    gateway: &[u8; 32],
    mailbox: &[u8; 32],
    pick: &mut dyn FnMut(usize) -> usize,
    uniform: &mut dyn FnMut() -> f64,
    mean_ms: u64,
) -> Result<Route> {
    let gw = find(nodes, gateway)?;
    let mb = find(nodes, mailbox)?;
    if gateway == mailbox {
        return if nodes.len() == 1 {
            Ok(Route {
                hops: vec![gw.hop],
                delays_ms: vec![0],
            })
        } else {
            Err(CoreError::Malformed)
        };
    }
    if nodes.len() < 3 {
        return Ok(Route {
            hops: vec![gw.hop],
            delays_ms: vec![0],
        });
    }
    let mixes = pick_mixes(nodes, &[gw, mb], mix_count(nodes), pick)?;
    let mut hops = Vec::new();
    let mut delays_ms = Vec::new();
    for m in mixes {
        hops.push(m.hop);
        delays_ms.push(exponential_delay_ms(mean_ms, uniform()));
    }
    hops.push(gw.hop);
    delays_ms.push(0);
    Ok(Route { hops, delays_ms })
}

/// Loop emitted by node `own` (spec §6.3): `mix… → other → own`. The mixes
/// and the other node delay; `own` does not. A 2-node mesh gives
/// `[other, own]`.
pub fn loop_route(
    nodes: &[Candidate],
    own: &[u8; 32],
    pick: &mut dyn FnMut(usize) -> usize,
    uniform: &mut dyn FnMut() -> f64,
    mean_ms: u64,
) -> Result<Route> {
    let me = find(nodes, own)?;
    let others: Vec<&Candidate> = nodes.iter().filter(|c| c.hop.id_pub != *own).collect();
    if others.is_empty() {
        return Err(CoreError::Malformed);
    }
    let mut hops = Vec::new();
    let mut delays_ms = Vec::new();
    let mixes = if others.len() >= 2 {
        pick_mixes(nodes, &[me], mix_count(nodes), pick)?
    } else {
        Vec::new()
    };
    for m in &mixes {
        hops.push(m.hop);
        delays_ms.push(exponential_delay_ms(mean_ms, uniform()));
    }
    let rest: Vec<&&Candidate> = others
        .iter()
        .filter(|c| mixes.iter().all(|m| m.hop.id_pub != c.hop.id_pub))
        .collect();
    let Some(other) = (!rest.is_empty()).then(|| rest[pick(rest.len()) % rest.len()]) else {
        return Err(CoreError::Malformed);
    };
    hops.push(other.hop);
    delays_ms.push(exponential_delay_ms(mean_ms, uniform()));
    hops.push(me.hop);
    delays_ms.push(0);
    Ok(Route { hops, delays_ms })
}

/// Drop emitted by node `own` (spec §6.3): `mix… → mailbox`, never `own`.
/// `avoid` (e.g. suspect nodes) is skipped while other choices exist.
pub fn drop_route(
    nodes: &[Candidate],
    own: &[u8; 32],
    avoid: &[[u8; 32]],
    pick: &mut dyn FnMut(usize) -> usize,
    uniform: &mut dyn FnMut() -> f64,
    mean_ms: u64,
) -> Result<Route> {
    let me = find(nodes, own)?;
    let boxes: Vec<&Candidate> = nodes
        .iter()
        .filter(|c| c.hop.id_pub != *own && c.roles.contains(&Role::Mailbox))
        .collect();
    let healthy: Vec<&Candidate> = boxes
        .iter()
        .copied()
        .filter(|c| !avoid.contains(&c.hop.id_pub))
        .collect();
    let set = if healthy.is_empty() { &boxes } else { &healthy };
    if set.is_empty() {
        return Err(CoreError::Malformed);
    }
    let mb = set[pick(set.len()) % set.len()];
    let mixes = if nodes.len() >= 3 {
        pick_mixes(nodes, &[me, mb], mix_count(nodes), pick)?
    } else {
        Vec::new()
    };
    let mut hops = Vec::new();
    let mut delays_ms = Vec::new();
    for m in mixes {
        hops.push(m.hop);
        delays_ms.push(exponential_delay_ms(mean_ms, uniform()));
    }
    hops.push(mb.hop);
    delays_ms.push(0);
    Ok(Route { hops, delays_ms })
}

/// Nodes holding `mailbox_id`: the `n` mailbox-role nodes with the highest
/// rendezvous score `H("harpo-mbx-place" ‖ mailbox_id ‖ id_pub)`.
pub fn mailbox_nodes(mailbox_id: &[u8; 32], nodes: &[Candidate], n: usize) -> Vec<[u8; 32]> {
    let mut scored: Vec<([u8; 32], [u8; 32])> = nodes
        .iter()
        .filter(|c| c.roles.contains(&Role::Mailbox))
        .map(|c| {
            (
                h_domain(domain::MBX_PLACE, &[mailbox_id, &c.hop.id_pub]),
                c.hop.id_pub,
            )
        })
        .collect();
    scored.sort_by(|a, b| b.cmp(a));
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(n).map(|(_, id)| id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::Role;
    use crate::sphinx::{Hop, MAX_DELAY_MS};
    use crate::CoreError;

    fn cand(n: u8, sponsor: Option<u8>, ip16: Option<[u8; 2]>, layer: u8) -> Candidate {
        Candidate {
            hop: Hop {
                id_pub: [n; 32],
                sphinx_pub: [n; 32],
            },
            roles: vec![Role::Gateway, Role::Mix, Role::Mailbox],
            layer,
            sponsor: sponsor.map(|s| [s; 32]),
            ipv4_16: ip16,
        }
    }

    fn mesh(n: u8) -> Vec<Candidate> {
        (1..=n).map(|i| cand(i, None, None, i % 3)).collect()
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn pick(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn uniform(&mut self) -> f64 {
            (self.next() >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    fn route(nodes: &[Candidate], gw: u8, mbx: u8, rng: &mut Rng) -> Result<Route> {
        let (mut p, mut u) = (Rng(rng.next()), Rng(rng.next()));
        forward_route(
            nodes,
            &[gw; 32],
            &[mbx; 32],
            &mut |n| p.pick(n),
            &mut || u.uniform(),
            DEFAULT_MEAN_DELAY_MS,
        )
    }

    fn ids(r: &Route) -> Vec<u8> {
        r.hops.iter().map(|h| h.id_pub[0]).collect()
    }

    #[test]
    fn three_node_route_shape() {
        let r = route(&mesh(3), 1, 3, &mut Rng(7)).unwrap();
        assert_eq!(ids(&r), vec![1, 2, 3]);
        assert_eq!(r.delays_ms.len(), 3);
        assert_eq!(r.delays_ms[0], 0);
        assert_eq!(r.delays_ms[2], 0);
    }

    #[test]
    fn twelve_nodes_use_three_layers() {
        let nodes = mesh(12);
        let r = route(&nodes, 1, 2, &mut Rng(9)).unwrap();
        assert_eq!(r.hops.len(), 5);
        let layer = |id: u8| nodes.iter().find(|c| c.hop.id_pub[0] == id).unwrap().layer;
        let ids = ids(&r);
        assert_eq!((layer(ids[1]), layer(ids[2]), layer(ids[3])), (0, 1, 2));
        assert!(route(&mesh(11), 1, 2, &mut Rng(9)).unwrap().hops.len() == 3);
    }

    #[test]
    fn never_repeats_a_node() {
        let nodes = mesh(5);
        let mut rng = Rng(12345);
        for _ in 0..200 {
            let gw = (rng.pick(5) + 1) as u8;
            let mbx = (rng.pick(5) + 1) as u8;
            if gw == mbx {
                continue;
            }
            let r = route(&nodes, gw, mbx, &mut rng).unwrap();
            let mut v = ids(&r);
            v.sort();
            v.dedup();
            assert_eq!(v.len(), r.hops.len());
        }
    }

    #[test]
    fn route_may_not_end_at_its_gateway() {
        assert_eq!(
            route(&mesh(5), 2, 2, &mut Rng(1)).err(),
            Some(CoreError::Malformed)
        );
        // A single-node mesh (development) is the only exception.
        assert_eq!(ids(&route(&mesh(1), 1, 1, &mut Rng(1)).unwrap()), vec![1]);
    }

    #[test]
    fn prefers_distinct_sponsors() {
        // gw 1 and mailbox 2 sponsored by A; mixes: 3 (A), 4 (B).
        let nodes = vec![
            cand(1, Some(0xA), None, 0),
            cand(2, Some(0xA), None, 0),
            cand(3, Some(0xA), None, 0),
            cand(4, Some(0xB), None, 0),
        ];
        for seed in 1..50 {
            assert_eq!(ids(&route(&nodes, 1, 2, &mut Rng(seed)).unwrap())[1], 4);
        }
    }

    #[test]
    fn small_mesh_relaxes_diversity() {
        let nodes: Vec<_> = (1..=3)
            .map(|i| cand(i, Some(0xA), Some([10, 0]), 0))
            .collect();
        assert_eq!(
            ids(&route(&nodes, 1, 3, &mut Rng(3)).unwrap()),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn avoids_shared_ipv4_16() {
        let nodes = vec![
            cand(1, None, Some([10, 0]), 0),
            cand(2, None, Some([20, 0]), 0),
            cand(3, None, Some([10, 0]), 0),
            cand(4, None, Some([30, 0]), 0),
        ];
        for seed in 1..50 {
            assert_eq!(ids(&route(&nodes, 1, 2, &mut Rng(seed)).unwrap())[1], 4);
        }
    }

    #[test]
    fn two_node_mesh_routes_directly() {
        assert_eq!(
            ids(&route(&mesh(2), 1, 2, &mut Rng(3)).unwrap()),
            vec![1, 2]
        );
    }

    #[test]
    fn unknown_mailbox_rejected() {
        assert_eq!(
            route(&mesh(3), 1, 9, &mut Rng(1)).err(),
            Some(CoreError::Untrusted)
        );
    }

    #[test]
    fn exponential_delays_bounded() {
        assert_eq!(exponential_delay_ms(100, 0.0), 0);
        assert!(exponential_delay_ms(100, 1.0) <= MAX_DELAY_MS);
        assert!(exponential_delay_ms(100, f64::NAN) <= MAX_DELAY_MS);
        let mut rng = Rng(42);
        let n = 10_000;
        let sum: u64 = (0..n)
            .map(|_| exponential_delay_ms(100, rng.uniform()))
            .sum();
        let mean = sum as f64 / n as f64;
        assert!((90.0..110.0).contains(&mean), "mean {mean}");
    }

    #[test]
    fn reply_route_shape() {
        let mut p = Rng(5);
        let mut u = Rng(6);
        let r = reply_route(
            &mesh(5),
            &[1; 32],
            &[4; 32],
            &mut |n| p.pick(n),
            &mut || u.uniform(),
            DEFAULT_MEAN_DELAY_MS,
        )
        .unwrap();
        let ids = ids(&r);
        assert_eq!(ids.len(), 2);
        assert_eq!(*ids.last().unwrap(), 1);
        assert!(ids[0] != 1 && ids[0] != 4);
        assert_eq!(*r.delays_ms.last().unwrap(), 0);
    }

    #[test]
    fn mailbox_placement_is_deterministic() {
        let nodes = mesh(6);
        let a = mailbox_nodes(&[7; 32], &nodes, MAILBOX_REPLICAS);
        let mut shuffled = nodes.clone();
        shuffled.reverse();
        assert_eq!(a, mailbox_nodes(&[7; 32], &shuffled, MAILBOX_REPLICAS));
        assert_eq!(a.len(), 3);
        assert_ne!(a, mailbox_nodes(&[8; 32], &nodes, MAILBOX_REPLICAS));
    }

    #[test]
    fn placement_changes_little_when_a_node_leaves() {
        let nodes = mesh(6);
        let a = mailbox_nodes(&[7; 32], &nodes, 3);
        let without_unselected: Vec<_> = nodes
            .iter()
            .filter(|c| !a.contains(&c.hop.id_pub))
            .skip(1)
            .cloned()
            .chain(nodes.iter().filter(|c| a.contains(&c.hop.id_pub)).cloned())
            .collect();
        assert_eq!(mailbox_nodes(&[7; 32], &without_unselected, 3), a);
        let without_first: Vec<_> = nodes
            .iter()
            .filter(|c| c.hop.id_pub != a[0])
            .cloned()
            .collect();
        let b = mailbox_nodes(&[7; 32], &without_first, 3);
        assert_eq!(&b[..2], &a[1..]);
    }

    #[test]
    fn placement_ignores_non_mailbox_nodes() {
        let mut nodes = mesh(4);
        nodes[0].roles = vec![Role::Mix];
        let a = mailbox_nodes(&[7; 32], &nodes, 4);
        assert_eq!(a.len(), 3);
        assert!(!a.contains(&[1; 32]));
    }

    #[test]
    fn sender_and_recipient_replicas_intersect() {
        let nodes = mesh(5);
        let reps = mailbox_nodes(&[3; 32], &nodes, MAILBOX_REPLICAS);
        for gw_a in 1..=5u8 {
            for gw_b in 1..=5u8 {
                let a: Vec<_> = reps.iter().filter(|r| **r != [gw_a; 32]).collect();
                let b: Vec<_> = reps.iter().filter(|r| **r != [gw_b; 32]).collect();
                assert!(a.iter().any(|x| b.contains(x)));
            }
        }
    }

    #[test]
    fn loop_route_returns_home_without_repeats() {
        let nodes = mesh(5);
        let mut rng = Rng(77);
        for _ in 0..200 {
            let own = (rng.pick(5) + 1) as u8;
            let (mut p, mut u) = (Rng(rng.next()), Rng(rng.next()));
            let r = loop_route(
                &nodes,
                &[own; 32],
                &mut |n| p.pick(n),
                &mut || u.uniform(),
                DEFAULT_MEAN_DELAY_MS,
            )
            .unwrap();
            let v = ids(&r);
            assert_eq!(v.len(), 3);
            assert_eq!(*v.last().unwrap(), own);
            assert!(v[..2].iter().all(|i| *i != own));
            assert_ne!(v[0], v[1]);
            assert_eq!(*r.delays_ms.last().unwrap(), 0);
        }
    }

    #[test]
    fn loop_route_small_mesh() {
        let mut p = Rng(1);
        let mut u = Rng(2);
        let mut go = |n: u8| {
            loop_route(
                &mesh(n),
                &[1; 32],
                &mut |k| p.pick(k),
                &mut || u.uniform(),
                DEFAULT_MEAN_DELAY_MS,
            )
        };
        assert_eq!(ids(&go(2).unwrap()), vec![2, 1]);
        assert_eq!(go(1).err(), Some(CoreError::Malformed));
        assert_eq!(go(12).unwrap().hops.len(), 5);
    }

    #[test]
    fn drop_route_never_targets_self() {
        let nodes = mesh(5);
        let mut rng = Rng(99);
        for _ in 0..200 {
            let own = (rng.pick(5) + 1) as u8;
            let (mut p, mut u) = (Rng(rng.next()), Rng(rng.next()));
            let r = drop_route(
                &nodes,
                &[own; 32],
                &[],
                &mut |n| p.pick(n),
                &mut || u.uniform(),
                DEFAULT_MEAN_DELAY_MS,
            )
            .unwrap();
            let mut v = ids(&r);
            assert!(!v.contains(&own));
            assert_eq!(v.len(), 2);
            v.dedup();
            assert_eq!(v.len(), 2);
        }
    }

    #[test]
    fn drop_route_avoids_suspects_while_possible() {
        let nodes = mesh(4);
        let avoid = [[2; 32], [3; 32]];
        for seed in 1..30 {
            let (mut p, mut u) = (Rng(seed), Rng(seed + 100));
            let r = drop_route(
                &nodes,
                &[1; 32],
                &avoid,
                &mut |n| p.pick(n),
                &mut || u.uniform(),
                DEFAULT_MEAN_DELAY_MS,
            )
            .unwrap();
            assert_eq!(*ids(&r).last().unwrap(), 4);
        }
    }
}
