// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Causal membership evaluation.
use crate::dag::Dag;
use crate::op::{Body, Kind, Oid, Op};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use cfr_crypto::{hash, SigPublic};

/// Removal policy fixed for the lifetime of a conference.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Identities whose eviction operations count on their own.
    pub admins: BTreeSet<SigPublic>,
    /// How many independent evictions are needed without an administrator.
    pub quorum: usize,
    /// Ceiling on operations retained per author, to bound a flooding peer.
    pub max_ops_per_author: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            admins: BTreeSet::new(),
            quorum: 2,
            max_ops_per_author: 200,
        }
    }
}

impl Policy {
    /// Returns a policy with no administrators and a removal quorum.
    pub fn leaderless(quorum: usize) -> Self {
        Self {
            admins: BTreeSet::new(),
            quorum: quorum.max(1),
            max_ops_per_author: 200,
        }
    }
}

/// Evaluates membership over a graph.
pub struct Membership<'a> {
    dag: &'a Dag,
    policy: &'a Policy,
    guilty: &'a BTreeSet<SigPublic>,
}

impl<'a> Membership<'a> {
    /// Binds an evaluator to graph, policy, and verified equivocation state.
    pub fn new(dag: &'a Dag, policy: &'a Policy, guilty: &'a BTreeSet<SigPublic>) -> Self {
        Self {
            dag,
            policy,
            guilty,
        }
    }

    /// Returns counted removals by self-removal, administrator, quorum, or
    /// locally verified equivocation.
    fn counted_removes_in(&self, target: &SigPublic, keep: Option<&BTreeSet<Oid>>) -> Vec<Oid> {
        let mut votes: BTreeMap<SigPublic, Oid> = BTreeMap::new();
        let mut proven: Vec<Oid> = Vec::new();
        for (oid, op) in self.dag.iter() {
            if let Some(keep) = keep {
                if !keep.contains(oid) {
                    continue;
                }
            }
            match &op.body {
                Body::Remove { who } if who == target => {
                    if &op.author == target || self.policy.admins.contains(&op.author) {
                        proven.push(*oid);
                    } else {
                        votes.entry(op.author).or_insert(*oid);
                    }
                }
                Body::Accuse { who, .. } if who == target && self.guilty.contains(target) => {
                    proven.push(*oid);
                }
                _ => {}
            }
        }
        if votes.len() >= self.policy.quorum {
            proven.extend(votes.into_values());
        }
        proven
    }

    /// The current membership.
    pub fn members(&self) -> BTreeSet<SigPublic> {
        self.members_in(None)
    }

    /// Evaluates membership over a causally closed subset of the bound graph.
    ///
    /// `keep` contains an operation and all of its dependencies. Evaluating the
    /// source graph directly avoids cloning an induced [`Dag`] for every
    /// authorization decision while preserving its causal ordering.
    fn members_in(&self, keep: Option<&BTreeSet<Oid>>) -> BTreeSet<SigPublic> {
        let mut adds: BTreeMap<SigPublic, Vec<Oid>> = BTreeMap::new();
        for (oid, op) in self.dag.iter() {
            if let Some(keep) = keep {
                if !keep.contains(oid) {
                    continue;
                }
            }
            if let Body::Add { who } = &op.body {
                adds.entry(*who).or_default().push(*oid);
            }
        }
        let mut live = BTreeSet::new();
        for (who, admissions) in adds {
            let removes = self.counted_removes_in(&who, keep);
            let alive = admissions.iter().any(|admission| {
                removes
                    .iter()
                    .all(|removal| self.dag.precedes(removal, admission))
            });
            if alive {
                live.insert(who);
            }
        }
        live
    }

    /// Membership as it stood in the causal past of `op`.
    ///
    /// This is the authorisation basis. Judging an operation against the
    /// *current* view would make the verdict depend on what else has arrived,
    /// so two participants could disagree about the same operation. Judging it
    /// against its own declared past cannot: the past is inside the signed
    /// image.
    pub fn members_before(&self, op: &Op) -> BTreeSet<SigPublic> {
        let mut past: BTreeSet<Oid> = BTreeSet::new();
        let oid = op.oid();
        if self.dag.contains(&oid) {
            past.extend(self.dag.ancestors(&oid));
        }
        for d in &op.deps {
            if self.dag.contains(d) {
                past.insert(*d);
                past.extend(self.dag.ancestors(d));
            }
        }
        self.members_in(Some(&past))
    }

    #[cfg(test)]
    fn members_before_reference(&self, op: &Op) -> BTreeSet<SigPublic> {
        let mut past: BTreeSet<Oid> = BTreeSet::new();
        let oid = op.oid();
        if self.dag.contains(&oid) {
            past.extend(self.dag.ancestors(&oid));
        }
        for dependency in &op.deps {
            if self.dag.contains(dependency) {
                past.insert(*dependency);
                past.extend(self.dag.ancestors(dependency));
            }
        }
        let mut sub = Dag::new();
        for oid in self.dag.topological() {
            if !past.contains(&oid) {
                continue;
            }
            if let Some(operation) = self.dag.get(&oid) {
                let _ = sub.add(operation.clone());
            }
        }
        Membership::new(&sub, self.policy, self.guilty).members()
    }

    /// A digest of the membership, bound into every group key derivation so a
    /// participant who disagrees about the roster derives a different key
    /// instead of silently sharing one.
    pub fn root(&self) -> [u8; 32] {
        Self::root_for_members(&self.members())
    }

    /// Derives the canonical membership root for an already evaluated roster.
    ///
    /// State derivation computes both the roster and its root at every graph
    /// epoch. Reusing that roster avoids a second full causal membership pass.
    pub(crate) fn root_for_members(members: &BTreeSet<SigPublic>) -> [u8; 32] {
        let fields: Vec<&[u8]> = members
            .iter()
            .map(|member| member.as_bytes().as_slice())
            .collect();
        hash(b"cfr/members", &fields)
    }

    /// Whether `op` is authorised.
    ///
    /// Prekey publication, contribution and accusation require membership in
    /// the operation's own past. Admission requires the inviter to be a member,
    /// except for the founding self-admission, which has no past to appeal to.
    pub fn authorised(&self, op: &Op) -> bool {
        let past = self.members_before(op);
        self.decide(op, &past)
    }

    fn decide(&self, op: &Op, past: &BTreeSet<SigPublic>) -> bool {
        match op.kind() {
            // Only the unique dependency-free self-admission may found a conference.
            Kind::Add => {
                if past.contains(&op.author) {
                    return true;
                }
                let Body::Add { who } = &op.body else {
                    return false;
                };
                // Compare founders by author to keep replay-order independence.
                who == &op.author
                    && op.deps.is_empty()
                    && !self.dag.iter().any(|(_, o)| {
                        matches!(o.kind(), Kind::Add)
                            && o.deps.is_empty()
                            && matches!(&o.body, Body::Add { who: w } if w == &o.author)
                            && o.author != op.author
                    })
            }
            Kind::Remove | Kind::Prekeys | Kind::Contrib | Kind::Accuse | Kind::PrekeyRequest => {
                // A participant may always publish its own eviction, even if a
                // concurrent operation has already removed it.
                if let Body::Remove { who } = &op.body {
                    if who == &op.author {
                        return true;
                    }
                }
                past.contains(&op.author)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::Body;
    use cfr_crypto::{DhPublic, SigSecret};

    struct Fixture {
        dag: Dag,
        policy: Policy,
        guilty: BTreeSet<SigPublic>,
    }

    impl Fixture {
        fn new(quorum: usize) -> Self {
            Self {
                dag: Dag::new(),
                policy: Policy::leaderless(quorum),
                guilty: BTreeSet::new(),
            }
        }
        fn mem(&self) -> Membership<'_> {
            Membership::new(&self.dag, &self.policy, &self.guilty)
        }
        fn push(&mut self, sk: &SigSecret, deps: BTreeSet<Oid>, body: Body) -> Oid {
            self.dag.add(Op::create(sk, &SID, deps, body)).unwrap()
        }
    }

    const SID: crate::op::SessionId = [0xCDu8; 32];

    fn ids(n: u8) -> Vec<SigSecret> {
        (0..n).map(|i| SigSecret::from_seed(&[i + 1; 32])).collect()
    }

    #[test]
    fn admission_then_eviction_by_quorum() {
        let k = ids(3);
        let mut f = Fixture::new(2);
        let mut deps = BTreeSet::new();
        for s in &k {
            let o = f.push(&k[0], deps.clone(), Body::Add { who: s.public() });
            deps = [o].into_iter().collect();
        }
        assert_eq!(f.mem().members().len(), 3);

        // One eviction is not enough under quorum 2.
        let r1 = f.push(&k[0], deps.clone(), Body::Remove { who: k[2].public() });
        assert!(f.mem().members().contains(&k[2].public()));

        // A second, independent one completes the quorum.
        f.push(
            &k[1],
            [r1].into_iter().collect(),
            Body::Remove { who: k[2].public() },
        );
        assert!(!f.mem().members().contains(&k[2].public()));
        assert_eq!(f.mem().members().len(), 2);
    }

    #[test]
    fn two_evictions_from_the_same_author_do_not_form_a_quorum() {
        let k = ids(2);
        let mut f = Fixture::new(2);
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        let b = f.push(
            &k[0],
            [a].into_iter().collect(),
            Body::Add { who: k[1].public() },
        );
        let r1 = f.push(
            &k[0],
            [b].into_iter().collect(),
            Body::Remove { who: k[1].public() },
        );
        f.push(
            &k[0],
            [r1].into_iter().collect(),
            Body::Remove { who: k[1].public() },
        );
        assert!(f.mem().members().contains(&k[1].public()));
    }

    #[test]
    fn self_eviction_needs_no_quorum() {
        let k = ids(2);
        let mut f = Fixture::new(2);
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        let b = f.push(
            &k[0],
            [a].into_iter().collect(),
            Body::Add { who: k[1].public() },
        );
        f.push(
            &k[1],
            [b].into_iter().collect(),
            Body::Remove { who: k[1].public() },
        );
        assert!(!f.mem().members().contains(&k[1].public()));
    }

    #[test]
    fn admin_eviction_needs_no_quorum() {
        let k = ids(2);
        let mut f = Fixture::new(2);
        f.policy.admins.insert(k[0].public());
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        let b = f.push(
            &k[0],
            [a].into_iter().collect(),
            Body::Add { who: k[1].public() },
        );
        f.push(
            &k[0],
            [b].into_iter().collect(),
            Body::Remove { who: k[1].public() },
        );
        assert!(!f.mem().members().contains(&k[1].public()));
    }

    #[test]
    fn readmission_after_eviction_is_causally_later_and_wins() {
        let identities = ids(3);
        let mut fixture = Fixture::new(1);
        let founder_admission = fixture.push(
            &identities[0],
            BTreeSet::new(),
            Body::Add {
                who: identities[0].public(),
            },
        );
        let member_admission = fixture.push(
            &identities[0],
            [founder_admission].into_iter().collect(),
            Body::Add {
                who: identities[1].public(),
            },
        );
        let eviction = fixture.push(
            &identities[0],
            [member_admission].into_iter().collect(),
            Body::Remove {
                who: identities[1].public(),
            },
        );
        assert!(!fixture.mem().members().contains(&identities[1].public()));
        fixture.push(
            &identities[0],
            [eviction].into_iter().collect(),
            Body::Add {
                who: identities[1].public(),
            },
        );
        assert!(fixture.mem().members().contains(&identities[1].public()));
    }

    #[test]
    fn replaying_a_stale_admission_does_not_resurrect() {
        // The old admission is still preceded by the eviction, so remove-wins
        // holds no matter how many times it is re-delivered.
        let k = ids(2);
        let mut f = Fixture::new(1);
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        let stale = Op::create(
            &k[0],
            &SID,
            [a].into_iter().collect(),
            Body::Add { who: k[1].public() },
        );
        let b = f.dag.add(stale.clone()).unwrap();
        f.push(
            &k[0],
            [b].into_iter().collect(),
            Body::Remove { who: k[1].public() },
        );
        assert!(!f.mem().members().contains(&k[1].public()));
        f.dag.add(stale).unwrap();
        assert!(!f.mem().members().contains(&k[1].public()));
    }

    #[test]
    fn authorisation_uses_the_operations_own_past() {
        let k = ids(2);
        let mut f = Fixture::new(2);
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        // An outsider's contribution names a past in which it is not a member.
        let outsider = Op::create(
            &k[1],
            &SID,
            [a].into_iter().collect(),
            Body::PrekeyRequest {
                targets: Vec::new(),
            },
        );
        assert!(!f.mem().authorised(&outsider));
    }

    #[test]
    fn filtered_past_evaluation_matches_induced_subgraph_reference() {
        let identities = ids(3);
        let mut fixture = Fixture::new(2);
        let founder = fixture.push(
            &identities[0],
            BTreeSet::new(),
            Body::Add {
                who: identities[0].public(),
            },
        );
        let second = fixture.push(
            &identities[0],
            [founder].into_iter().collect(),
            Body::Add {
                who: identities[1].public(),
            },
        );
        let third = fixture.push(
            &identities[0],
            [second].into_iter().collect(),
            Body::Add {
                who: identities[2].public(),
            },
        );
        let first_vote = fixture.push(
            &identities[0],
            [third].into_iter().collect(),
            Body::Remove {
                who: identities[2].public(),
            },
        );
        fixture.push(
            &identities[1],
            [first_vote].into_iter().collect(),
            Body::Remove {
                who: identities[2].public(),
            },
        );

        let operations: Vec<Op> = fixture
            .dag
            .iter()
            .map(|(_, operation)| operation.clone())
            .collect();
        for operation in operations {
            assert_eq!(
                fixture.mem().members_before(&operation),
                fixture.mem().members_before_reference(&operation),
                "causal-past roster differs for {:?}",
                operation.oid(),
            );
        }
    }

    #[test]
    fn membership_root_changes_with_the_roster() {
        let k = ids(2);
        let mut f = Fixture::new(2);
        let a = f.push(&k[0], BTreeSet::new(), Body::Add { who: k[0].public() });
        let r1 = f.mem().root();
        f.push(
            &k[0],
            [a].into_iter().collect(),
            Body::Add { who: k[1].public() },
        );
        assert_ne!(r1, f.mem().root());
    }

    #[test]
    #[ignore = "reference timing; run with --release --ignored --nocapture"]
    fn profile_filtered_causal_membership() {
        use std::time::Instant;

        let identities = ids(16);
        let mut fixture = Fixture::new(2);
        let mut tail = fixture.push(
            &identities[0],
            BTreeSet::new(),
            Body::Add {
                who: identities[0].public(),
            },
        );
        for identity in identities.iter().skip(1) {
            tail = fixture.push(
                &identities[0],
                [tail].into_iter().collect(),
                Body::Add {
                    who: identity.public(),
                },
            );
        }
        for generation in 0..384u32 {
            let author = &identities[usize::try_from(generation % 16).expect("bounded index")];
            tail = fixture.push(
                author,
                [tail].into_iter().collect(),
                Body::Prekeys {
                    gen: generation,
                    pk: DhPublic::from_bytes([7u8; 32]),
                },
            );
        }
        let operation = fixture
            .dag
            .get(&tail)
            .expect("tail operation retained")
            .clone();
        let iterations = 200;

        let direct_started = Instant::now();
        let mut direct = BTreeSet::new();
        for _ in 0..iterations {
            direct = fixture.mem().members_before(&operation);
        }
        let direct_elapsed = direct_started.elapsed();

        let reference_started = Instant::now();
        let mut reference = BTreeSet::new();
        for _ in 0..iterations {
            reference = fixture.mem().members_before_reference(&operation);
        }
        let reference_elapsed = reference_started.elapsed();

        assert_eq!(direct, reference);
        println!(
            "filtered_membership,operations={},iterations={},direct_ns={},reference_ns={}",
            fixture.dag.len(),
            iterations,
            direct_elapsed.as_nanos(),
            reference_elapsed.as_nanos(),
        );
    }

    #[test]
    fn verified_accusation_evicts_without_a_vote() {
        let k = ids(3);
        let mut f = Fixture::new(2);
        let mut deps = BTreeSet::new();
        for s in &k {
            let o = f.push(&k[0], deps.clone(), Body::Add { who: s.public() });
            deps = [o].into_iter().collect();
        }
        f.push(
            &k[0],
            deps,
            Body::Accuse {
                who: k[2].public(),
                coid: [0u8; 32],
                mk: [0u8; 32],
                seq: 0,
            },
        );
        // Unverified: the accusation alone does nothing.
        assert!(f.mem().members().contains(&k[2].public()));
        // Verified locally: it counts.
        f.guilty.insert(k[2].public());
        assert!(!f.mem().members().contains(&k[2].public()));
    }
}
