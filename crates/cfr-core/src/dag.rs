// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Causal operation graph.
use crate::error::{Error, Result};
use crate::op::{Oid, Op};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cell::RefCell;

/// Upper bound on stored operations before compaction is forced.
pub const MAX_OPS: usize = 4096;

/// A causally ordered set of operations.
#[derive(Default)]
pub struct Dag {
    /// Increments on mutation to invalidate derived caches.
    pub(crate) epoch: u64,
    pub(crate) ops: BTreeMap<Oid, Op>,
    pub(crate) parents: BTreeMap<Oid, BTreeSet<Oid>>,
    /// Cached transitive ancestor sets, cleared on mutation.
    pub(crate) cache: RefCell<BTreeMap<Oid, BTreeSet<Oid>>>,
}

impl Dag {
    /// An empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// A counter that changes whenever the graph changes.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of stored operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the graph is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Whether an operation is present.
    pub fn contains(&self, oid: &Oid) -> bool {
        self.ops.contains_key(oid)
    }

    /// Looks up an operation.
    pub fn get(&self, oid: &Oid) -> Option<&Op> {
        self.ops.get(oid)
    }

    /// Iterates over all operations.
    pub fn iter(&self) -> impl Iterator<Item = (&Oid, &Op)> {
        self.ops.iter()
    }

    /// All stored identifiers.
    pub fn oids(&self) -> impl Iterator<Item = &Oid> {
        self.ops.keys()
    }

    /// The recorded parents of an operation.
    pub fn parents_of(&self, oid: &Oid) -> Option<&BTreeSet<Oid>> {
        self.parents.get(oid)
    }

    /// Inserts an operation; existing identifiers are idempotent no-ops.
    pub fn add(&mut self, op: Op) -> Result<Oid> {
        if self.ops.len() >= MAX_OPS {
            return Err(Error::LimitExceeded("operation graph full"));
        }
        let oid = op.oid();
        if self.ops.contains_key(&oid) {
            return Ok(oid);
        }
        // Keep known dependencies only to bound attacker-controlled storage.
        let deps: BTreeSet<Oid> = op
            .deps
            .iter()
            .filter(|d| self.ops.contains_key(*d))
            .copied()
            .collect();
        self.parents.insert(oid, deps);
        self.ops.insert(oid, op);
        self.cache.borrow_mut().clear();
        self.epoch += 1;
        Ok(oid)
    }

    /// Whether every dependency of `op` is present.
    pub fn deps_satisfied(&self, op: &Op) -> bool {
        op.deps.iter().all(|d| self.ops.contains_key(d))
    }

    /// The transitive causal past of `oid`, excluding `oid` itself.
    pub fn ancestors(&self, oid: &Oid) -> BTreeSet<Oid> {
        if let Some(hit) = self.cache.borrow().get(oid) {
            return hit.clone();
        }
        let mut seen = BTreeSet::new();
        let mut stack: Vec<Oid> = self
            .parents
            .get(oid)
            .map(|p| p.iter().copied().collect())
            .unwrap_or_default();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur) {
                continue;
            }
            if let Some(ps) = self.parents.get(&cur) {
                stack.extend(ps.iter().copied());
            }
        }
        self.cache.borrow_mut().insert(*oid, seen.clone());
        seen
    }

    /// Returns every locally known operation implied by `heads`.
    ///
    /// A participant that holds a head also holds its complete signed causal
    /// past. Unknown heads are ignored so an untrusted repair advertisement can
    /// reduce only its own completeness, never authorise or reveal new state.
    pub fn causal_closure(&self, heads: impl IntoIterator<Item = Oid>) -> BTreeSet<Oid> {
        let mut known = BTreeSet::new();
        for head in heads {
            if !self.contains(&head) {
                continue;
            }
            known.insert(head);
            known.extend(self.ancestors(&head));
        }
        known
    }

    /// Whether `a` lies in the causal past of `b`.
    pub fn precedes(&self, a: &Oid, b: &Oid) -> bool {
        a != b && self.ancestors(b).contains(a)
    }

    /// Operations that no other operation depends on.
    pub fn heads(&self) -> BTreeSet<Oid> {
        let mut referenced = BTreeSet::new();
        for ps in self.parents.values() {
            referenced.extend(ps.iter().copied());
        }
        self.ops
            .keys()
            .filter(|o| !referenced.contains(*o))
            .copied()
            .collect()
    }

    /// Contracts the graph down to `keep`.
    ///
    /// Every dropped node is replaced, in each of its children's dependency
    /// sets, by that node's own parents. Repeating this to a fixpoint means the
    /// transitive relation restricted to `keep` is exactly what it was before.
    pub fn compact(&mut self, keep: &BTreeSet<Oid>) {
        let drop: Vec<Oid> = self
            .ops
            .keys()
            .filter(|o| !keep.contains(*o))
            .copied()
            .collect();
        if drop.is_empty() {
            return;
        }
        let dropped: BTreeSet<Oid> = drop.iter().copied().collect();

        // Resolve each surviving node's parents to the nearest surviving
        // ancestors.
        let mut rewired: BTreeMap<Oid, BTreeSet<Oid>> = BTreeMap::new();
        for oid in self.ops.keys().filter(|o| keep.contains(*o)) {
            let mut out = BTreeSet::new();
            let mut stack: Vec<Oid> = self
                .parents
                .get(oid)
                .map(|p| p.iter().copied().collect())
                .unwrap_or_default();
            let mut seen = BTreeSet::new();
            while let Some(cur) = stack.pop() {
                if !seen.insert(cur) {
                    continue;
                }
                if dropped.contains(&cur) {
                    if let Some(ps) = self.parents.get(&cur) {
                        stack.extend(ps.iter().copied());
                    }
                } else {
                    out.insert(cur);
                }
            }
            rewired.insert(*oid, out);
        }

        for oid in &drop {
            self.ops.remove(oid);
            self.parents.remove(oid);
        }
        self.parents = rewired;
        self.cache.borrow_mut().clear();
        self.epoch += 1;
    }

    /// Returns identifiers in an order where every operation follows its
    /// dependencies. Used when handing a newcomer a history.
    pub fn topological(&self) -> Vec<Oid> {
        let mut indeg: BTreeMap<Oid, usize> = self
            .ops
            .keys()
            .map(|o| (*o, self.parents.get(o).map_or(0, BTreeSet::len)))
            .collect();
        let mut children: BTreeMap<Oid, Vec<Oid>> = BTreeMap::new();
        for (oid, ps) in &self.parents {
            for p in ps {
                children.entry(*p).or_default().push(*oid);
            }
        }
        let mut ready: Vec<Oid> = indeg
            .iter()
            .filter(|(_, d)| **d == 0)
            .map(|(o, _)| *o)
            .collect();
        let mut out = Vec::with_capacity(self.ops.len());
        while let Some(cur) = ready.pop() {
            out.push(cur);
            if let Some(cs) = children.get(&cur) {
                for c in cs {
                    if let Some(d) = indeg.get_mut(c) {
                        *d -= 1;
                        if *d == 0 {
                            ready.push(*c);
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Body;
    use cfr_crypto::SigSecret;

    fn chain(n: usize) -> (Dag, Vec<Oid>) {
        let sk = SigSecret::from_seed(&[1u8; 32]);
        let mut dag = Dag::new();
        let mut ids = Vec::new();
        let mut deps = BTreeSet::new();
        for i in 0..n {
            let mut who = [0u8; 32];
            who[0] = u8::try_from(i).unwrap();
            let op = Op::create(
                &sk,
                &[0x11u8; 32],
                deps.clone(),
                Body::Prekeys {
                    gen: u32::try_from(i).unwrap(),
                    pk: cfr_crypto::DhPublic::from_bytes(who),
                },
            );
            let oid = dag.add(op).unwrap();
            ids.push(oid);
            deps.clear();
            deps.insert(oid);
        }
        (dag, ids)
    }

    #[test]
    fn precedence_is_transitive() {
        let (dag, ids) = chain(5);
        assert!(dag.precedes(&ids[0], &ids[4]));
        assert!(!dag.precedes(&ids[4], &ids[0]));
        assert!(!dag.precedes(&ids[2], &ids[2]));
    }

    #[test]
    fn compaction_preserves_transitive_precedence() {
        let (mut dag, ids) = chain(6);
        // Keep only the endpoints; everything between is contracted away.
        let keep: BTreeSet<Oid> = [ids[0], ids[5]].into_iter().collect();
        dag.compact(&keep);
        assert_eq!(dag.len(), 2);
        assert!(
            dag.precedes(&ids[0], &ids[5]),
            "contraction must not lose the relation"
        );
    }

    #[test]
    fn compaction_of_a_diamond_keeps_both_paths() {
        let sk = SigSecret::from_seed(&[2u8; 32]);
        let mut dag = Dag::new();
        let mk = |i: u8| Body::Prekeys {
            gen: u32::from(i),
            pk: cfr_crypto::DhPublic::from_bytes([i; 32]),
        };
        let root = dag
            .add(Op::create(&sk, &[0x11u8; 32], BTreeSet::new(), mk(0)))
            .unwrap();
        let l = dag
            .add(Op::create(
                &sk,
                &[0x11u8; 32],
                [root].into_iter().collect(),
                mk(1),
            ))
            .unwrap();
        let r = dag
            .add(Op::create(
                &sk,
                &[0x11u8; 32],
                [root].into_iter().collect(),
                mk(2),
            ))
            .unwrap();
        let tip = dag
            .add(Op::create(
                &sk,
                &[0x11u8; 32],
                [l, r].into_iter().collect(),
                mk(3),
            ))
            .unwrap();

        dag.compact(&[root, tip].into_iter().collect());
        assert!(dag.precedes(&root, &tip));
        assert_eq!(dag.parents_of(&tip).unwrap().len(), 1);
    }

    #[test]
    fn heads_are_the_unreferenced_nodes() {
        let (dag, ids) = chain(3);
        assert_eq!(dag.heads(), [ids[2]].into_iter().collect());
    }

    #[test]
    fn insertion_is_idempotent() {
        let sk = SigSecret::from_seed(&[3u8; 32]);
        let op = Op::create(
            &sk,
            &[0x11u8; 32],
            BTreeSet::new(),
            Body::Prekeys {
                gen: 0,
                pk: cfr_crypto::DhPublic::from_bytes([0u8; 32]),
            },
        );
        let mut dag = Dag::new();
        let a = dag.add(op.clone()).unwrap();
        let b = dag.add(op).unwrap();
        assert_eq!(a, b);
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn topological_order_respects_dependencies() {
        let (dag, ids) = chain(5);
        let order = dag.topological();
        assert_eq!(order.len(), 5);
        let pos = |x: &Oid| order.iter().position(|o| o == x).unwrap();
        for w in ids.windows(2) {
            assert!(pos(&w[0]) < pos(&w[1]));
        }
    }

    #[test]
    fn unknown_dependencies_are_not_retained() {
        let sk = SigSecret::from_seed(&[4u8; 32]);
        let op = Op::create(
            &sk,
            &[0x11u8; 32],
            [[0xAAu8; 32]].into_iter().collect(),
            Body::Prekeys {
                gen: 0,
                pk: cfr_crypto::DhPublic::from_bytes([0u8; 32]),
            },
        );
        let mut dag = Dag::new();
        let oid = dag.add(op).unwrap();
        assert!(dag.parents_of(&oid).unwrap().is_empty());
    }
}
