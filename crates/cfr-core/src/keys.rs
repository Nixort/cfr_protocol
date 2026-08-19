// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Group-key derivation from causal frontier state.
use crate::dag::Dag;
use crate::op::{Kind, Oid};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use cfr_crypto::{hash, kdf, Secret, KEY_LEN};

/// Retained node-key overlap window.
///
/// Increasing this value improves short-term lag tolerance and widens the
/// snapshot exposure window.
pub const OVERLAP: usize = 64;

/// The set of contribution nodes at the tip of the graph.
pub fn frontier(dag: &Dag) -> BTreeSet<Oid> {
    let nodes: Vec<Oid> = dag
        .iter()
        .filter(|(_, op)| op.kind() == Kind::Contrib)
        .map(|(oid, _)| *oid)
        .collect();
    if nodes.is_empty() {
        return BTreeSet::new();
    }
    let mut covered: BTreeSet<Oid> = BTreeSet::new();
    for oid in &nodes {
        covered.extend(dag.ancestors(oid));
    }
    nodes.into_iter().filter(|n| !covered.contains(n)).collect()
}

/// Eight-byte version hint over the frontier and membership root.
///
/// Membership must be included because roster changes do not alter the
/// contribution frontier. The beacon MAC confirms key agreement.
pub fn version_of(nodes: &BTreeSet<Oid>, membership_root: &[u8; 32]) -> [u8; 8] {
    let mut refs: Vec<&[u8]> = Vec::with_capacity(nodes.len() + 1);
    refs.push(membership_root.as_slice());
    refs.extend(nodes.iter().map(<[u8; 32]>::as_slice));
    let full = hash(b"cfr/version", &refs);
    let mut v = [0u8; 8];
    v.copy_from_slice(&full[..8]);
    v
}

/// Node keys retained for a bounded overlap window.
///
/// Eviction erases the key material and ends local derivability of that version.
pub struct NodeKeys {
    keys: BTreeMap<Oid, Secret<KEY_LEN>>,
    order: Vec<Oid>,
    capacity: usize,
}

impl Default for NodeKeys {
    fn default() -> Self {
        Self::with_capacity(OVERLAP)
    }
}

impl NodeKeys {
    /// A store holding `capacity` versions.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: BTreeMap::new(),
            order: Vec::new(),
            capacity: capacity.max(1),
        }
    }

    /// Number of retained node keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether a node key is retained.
    pub fn contains(&self, oid: &Oid) -> bool {
        self.keys.contains_key(oid)
    }

    /// Borrows a node key without changing its recency.
    pub fn peek(&self, oid: &Oid) -> Option<&Secret<KEY_LEN>> {
        self.keys.get(oid)
    }

    /// Inserts a node key, evicting the least recently inserted if full.
    pub fn insert(&mut self, node_id: Oid, node_key: Secret<KEY_LEN>) {
        if self.keys.insert(node_id, node_key).is_none() {
            self.order.push(node_id);
        } else {
            self.touch(&node_id);
        }
        while self.order.len() > self.capacity {
            let evicted_id = self.order.remove(0);
            if let Some(mut evicted_key) = self.keys.remove(&evicted_id) {
                evicted_key.wipe();
            }
        }
    }

    /// Marks a node key as recently used.
    pub fn touch(&mut self, oid: &Oid) {
        if let Some(pos) = self.order.iter().position(|o| o == oid) {
            let v = self.order.remove(pos);
            self.order.push(v);
        }
    }

    /// Which of `nodes` are absent.
    pub fn missing<'a>(&self, nodes: impl Iterator<Item = &'a Oid>) -> BTreeSet<Oid> {
        nodes
            .filter(|n| !self.keys.contains_key(*n))
            .copied()
            .collect()
    }

    /// XOR-combines node keys, returning `None` when any input is absent.
    pub fn combine(&self, nodes: &BTreeSet<Oid>) -> Option<Secret<KEY_LEN>> {
        let mut acc = Secret::<KEY_LEN>::zero();
        for n in nodes {
            acc.xor_in_place(self.keys.get(n)?);
        }
        Some(acc)
    }

    /// Erases every retained node key.
    pub fn wipe(&mut self) {
        for k in self.keys.values_mut() {
            k.wipe();
        }
        self.keys.clear();
        self.order.clear();
    }
}

/// Derives a node key from a contribution secret and its parents.
pub fn node_key(
    secret: &Secret<KEY_LEN>,
    parent_combined: &Secret<KEY_LEN>,
    oid: &Oid,
) -> Secret<KEY_LEN> {
    kdf(
        secret,
        b"cfr/node",
        &[parent_combined.as_bytes(), oid.as_slice()],
    )
}

/// Derives the group key of a specific frontier.
pub fn group_key(
    seed0: &Secret<KEY_LEN>,
    nodes: &BTreeSet<Oid>,
    membership_root: &[u8; 32],
    store: &NodeKeys,
) -> Option<Secret<KEY_LEN>> {
    let combined = if nodes.is_empty() {
        Secret::<KEY_LEN>::zero()
    } else {
        store.combine(nodes)?
    };
    let refs: Vec<&[u8]> = nodes.iter().map(<[u8; 32]>::as_slice).collect();
    let digest = hash(b"cfr/frontier", &refs);
    Some(kdf(
        seed0,
        b"cfr/group",
        &[combined.as_bytes(), membership_root, &digest],
    ))
}

/// The commitment published with a contribution.
pub fn commitment(secret: &Secret<KEY_LEN>) -> [u8; 32] {
    hash(b"cfr/cid", &[secret.as_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::{Body, Op};
    use cfr_crypto::{DhPublic, SigSecret};

    fn contrib(sk: &SigSecret, deps: BTreeSet<Oid>, cparents: BTreeSet<Oid>, tag: u8) -> Op {
        Op::create(
            sk,
            &[0x11u8; 32],
            deps,
            Body::Contrib {
                cid: [tag; 32],
                cparents,
                recips: Vec::new(),
                slices: Vec::new(),
                view: [0u8; 32],
            },
        )
    }

    #[test]
    fn frontier_is_the_uncovered_tip() {
        let sk = SigSecret::from_seed(&[1u8; 32]);
        let mut dag = Dag::new();
        let a = dag
            .add(contrib(&sk, BTreeSet::new(), BTreeSet::new(), 1))
            .unwrap();
        let b = dag
            .add(contrib(
                &sk,
                [a].into_iter().collect(),
                [a].into_iter().collect(),
                2,
            ))
            .unwrap();
        assert_eq!(frontier(&dag), [b].into_iter().collect());
    }

    #[test]
    fn concurrent_contributions_both_stay_in_the_frontier() {
        let sk = SigSecret::from_seed(&[1u8; 32]);
        let mut dag = Dag::new();
        let root = dag
            .add(contrib(&sk, BTreeSet::new(), BTreeSet::new(), 1))
            .unwrap();
        let l = dag
            .add(contrib(
                &sk,
                [root].into_iter().collect(),
                [root].into_iter().collect(),
                2,
            ))
            .unwrap();
        let r = dag
            .add(contrib(
                &sk,
                [root].into_iter().collect(),
                [root].into_iter().collect(),
                3,
            ))
            .unwrap();
        assert_eq!(frontier(&dag), [l, r].into_iter().collect());
    }

    #[test]
    fn frontier_ignores_non_contribution_operations() {
        let sk = SigSecret::from_seed(&[1u8; 32]);
        let mut dag = Dag::new();
        let c = dag
            .add(contrib(&sk, BTreeSet::new(), BTreeSet::new(), 1))
            .unwrap();
        dag.add(Op::create(
            &sk,
            &[0x11u8; 32],
            [c].into_iter().collect(),
            Body::Prekeys {
                gen: 1,
                pk: DhPublic::from_bytes([0u8; 32]),
            },
        ))
        .unwrap();
        assert_eq!(frontier(&dag), [c].into_iter().collect());
    }

    #[test]
    fn frontier_survives_compaction() {
        // The invariant that Theorem 7.1 rests on: contracting the graph must
        // not change the frontier.
        let sk = SigSecret::from_seed(&[1u8; 32]);
        let mut dag = Dag::new();
        let mut prev: BTreeSet<Oid> = BTreeSet::new();
        let mut last = None;
        for i in 0..6u8 {
            let op = contrib(&sk, prev.clone(), prev.clone(), i);
            let oid = dag.add(op).unwrap();
            prev = [oid].into_iter().collect();
            last = Some(oid);
        }
        let before = frontier(&dag);
        let keep: BTreeSet<Oid> = [last.unwrap()].into_iter().collect();
        dag.compact(&keep);
        assert_eq!(frontier(&dag), before);
    }

    #[test]
    fn combine_fails_closed_on_a_missing_node() {
        let mut store = NodeKeys::default();
        store.insert([1u8; 32], Secret::from([9u8; 32]));
        let want: BTreeSet<Oid> = [[1u8; 32], [2u8; 32]].into_iter().collect();
        assert!(store.combine(&want).is_none());
    }

    #[test]
    fn combine_is_order_independent() {
        let mut store = NodeKeys::default();
        store.insert([1u8; 32], Secret::from([0xAAu8; 32]));
        store.insert([2u8; 32], Secret::from([0x55u8; 32]));
        let s: BTreeSet<Oid> = [[1u8; 32], [2u8; 32]].into_iter().collect();
        assert_eq!(store.combine(&s).unwrap().as_bytes(), &[0xFFu8; 32]);
    }

    #[test]
    fn overlap_window_evicts_and_erases() {
        let mut store = NodeKeys::with_capacity(4);
        for i in 0..8u8 {
            store.insert([i; 32], Secret::from([i; 32]));
        }
        assert_eq!(store.len(), 4);
        assert!(!store.contains(&[0u8; 32]), "old versions leave the window");
        assert!(store.contains(&[7u8; 32]));
    }

    #[test]
    fn group_key_binds_membership_and_frontier() {
        let seed = Secret::from([1u8; 32]);
        let mut store = NodeKeys::default();
        store.insert([1u8; 32], Secret::from([2u8; 32]));
        let f: BTreeSet<Oid> = [[1u8; 32]].into_iter().collect();
        let base = group_key(&seed, &f, &[0u8; 32], &store).unwrap();
        assert_ne!(base, group_key(&seed, &f, &[1u8; 32], &store).unwrap());

        store.insert([2u8; 32], Secret::from([3u8; 32]));
        let f2: BTreeSet<Oid> = [[1u8; 32], [2u8; 32]].into_iter().collect();
        assert_ne!(base, group_key(&seed, &f2, &[0u8; 32], &store).unwrap());
    }

    #[test]
    fn version_label_tracks_the_frontier() {
        let a: BTreeSet<Oid> = [[1u8; 32]].into_iter().collect();
        let b: BTreeSet<Oid> = [[2u8; 32]].into_iter().collect();
        let m = [0u8; 32];
        assert_ne!(version_of(&a, &m), version_of(&b, &m));
        assert_eq!(version_of(&a, &m), version_of(&a.clone(), &m));
    }

    #[test]
    fn version_label_tracks_the_roster() {
        // A membership change that adds no contribution leaves the frontier
        // untouched. If the label ignored the roster, the two states below
        // would be indistinguishable while deriving different keys.
        let f: BTreeSet<Oid> = [[1u8; 32]].into_iter().collect();
        assert_ne!(version_of(&f, &[0u8; 32]), version_of(&f, &[1u8; 32]));
    }

    #[test]
    fn label_covers_every_input_to_the_key() {
        let seed = Secret::from([5u8; 32]);
        let mut store = NodeKeys::default();
        store.insert([1u8; 32], Secret::from([2u8; 32]));
        let f: BTreeSet<Oid> = [[1u8; 32]].into_iter().collect();
        for m in [[0u8; 32], [1u8; 32], [9u8; 32]] {
            let k1 = group_key(&seed, &f, &m, &store).unwrap();
            for n in [[0u8; 32], [1u8; 32], [9u8; 32]] {
                let k2 = group_key(&seed, &f, &n, &store).unwrap();
                assert_eq!(
                    k1 == k2,
                    version_of(&f, &m) == version_of(&f, &n),
                    "equal labels must mean equal keys"
                );
            }
        }
    }
}
