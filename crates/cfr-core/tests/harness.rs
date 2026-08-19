// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! An in-memory conference used by the integration tests.
//!
//! The harness is deliberately hostile: it can drop, duplicate, reorder,
//! partition and censor, because every one of those is in the threat model.
//! It never reaches inside a participant's state; everything goes through the
//! public API, so a test that passes here is a statement about the library and
//! not about its internals.

#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::match_single_binding,
    clippy::range_plus_one,
    clippy::single_match,
    clippy::single_match_else,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::should_implement_trait,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

use cfr_core::{Destination, Event, Outbound, Participant, PendingJoin, Policy};
use cfr_crypto::SigPublic;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub struct Net {
    pub members: BTreeMap<SigPublic, Participant>,
    queue: VecDeque<(SigPublic, Vec<u8>)>,
    /// Identities that receive nothing (offline or partitioned away).
    pub offline: BTreeSet<SigPublic>,
    /// Disjoint groups; delivery only happens inside a group. Empty means one
    /// connected network.
    pub partitions: Vec<BTreeSet<SigPublic>>,
    /// Identities whose inbound traffic is selectively dropped.
    pub censored: BTreeSet<SigPublic>,
    pub delivered: usize,
    pub dropped: usize,
    pub events: Vec<(SigPublic, Event)>,
}

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

impl Net {
    pub fn new() -> Self {
        Self {
            members: BTreeMap::new(),
            queue: VecDeque::new(),
            offline: BTreeSet::new(),
            partitions: Vec::new(),
            censored: BTreeSet::new(),
            delivered: 0,
            dropped: 0,
            events: Vec::new(),
        }
    }

    pub fn founder(policy: Policy) -> (Self, SigPublic) {
        let mut net = Self::new();
        let (p, out) = Participant::create(policy).expect("conference created");
        let id = p.identity();
        net.members.insert(id, p);
        net.enqueue(id, out);
        net.settle();
        (net, id)
    }

    fn group_of(&self, who: &SigPublic) -> Option<&BTreeSet<SigPublic>> {
        self.partitions.iter().find(|g| g.contains(who))
    }

    fn reachable(&self, from: &SigPublic, to: &SigPublic) -> bool {
        if self.offline.contains(to) || self.censored.contains(to) {
            return false;
        }
        if self.partitions.is_empty() {
            return true;
        }
        match (self.group_of(from), self.group_of(to)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    pub fn enqueue(&mut self, from: SigPublic, out: Vec<Outbound>) {
        for o in out {
            match o.to {
                Destination::Everyone => {
                    let targets: Vec<SigPublic> = self
                        .members
                        .keys()
                        .filter(|m| **m != from)
                        .copied()
                        .collect();
                    for t in targets {
                        if self.reachable(&from, &t) {
                            self.queue.push_back((t, o.payload.clone()));
                        } else {
                            self.dropped += 1;
                        }
                    }
                }
                Destination::Peer(p) => {
                    if self.members.contains_key(&p) && self.reachable(&from, &p) {
                        self.queue.push_back((p, o.payload));
                    } else {
                        self.dropped += 1;
                    }
                }
            }
        }
    }

    /// Delivers until the queue drains, up to a bound.
    pub fn settle(&mut self) {
        for _ in 0..20_000 {
            let Some((to, payload)) = self.queue.pop_front() else {
                return;
            };
            let Some(p) = self.members.get_mut(&to) else {
                continue;
            };
            self.delivered += 1;
            match p.handle(&payload) {
                Ok((events, out)) => {
                    for e in events {
                        self.events.push((to, e));
                    }
                    self.enqueue(to, out);
                }
                Err(_) => {
                    // Rejections are expected in adversarial tests; the caller
                    // asserts on state, not on individual rejections.
                }
            }
        }
        panic!("network did not settle: possible message avalanche");
    }

    pub fn join(&mut self, inviter: SigPublic, policy: Policy) -> SigPublic {
        let pending = PendingJoin::new(policy).expect("identity generated");
        let kp = pending.key_package();
        let id = pending.identity();

        let out = self
            .members
            .get_mut(&inviter)
            .expect("inviter present")
            .invite(&kp)
            .expect("invitation issued");

        let welcome = out
            .iter()
            .find(|o| o.to == Destination::Peer(id))
            .expect("welcome produced")
            .payload
            .clone();

        let (newcomer, newcomer_out) = pending.accept(&welcome).expect("welcome accepted");
        self.members.insert(id, newcomer);
        self.enqueue(inviter, out);
        self.enqueue(id, newcomer_out);
        self.settle();
        // A newcomer contributes on the cycle after admission, once the
        // rotations triggered by its arrival have landed.
        self.contribute(id);
        id
    }

    pub fn act<F>(&mut self, who: SigPublic, f: F)
    where
        F: FnOnce(&mut Participant) -> Vec<Outbound>,
    {
        let out = f(self.members.get_mut(&who).expect("member present"));
        self.enqueue(who, out);
        self.settle();
    }

    pub fn contribute(&mut self, who: SigPublic) {
        self.act(who, |p| p.contribute().unwrap_or_default());
    }

    pub fn rotate(&mut self, who: SigPublic) {
        self.act(who, |p| {
            p.rotate_prekeys().map(|o| vec![o]).unwrap_or_default()
        });
    }

    pub fn remove(&mut self, by: SigPublic, target: SigPublic) {
        self.act(by, |p| p.remove(&target).unwrap_or_default());
    }

    pub fn repair(&mut self, who: SigPublic) {
        let req = self.members[&who].sync_request();
        self.enqueue(who, vec![req]);
        self.settle();
        if let Some(req) = self.members.get_mut(&who).unwrap().repair_request() {
            self.enqueue(who, req);
            self.settle();
        }
    }

    pub fn get(&self, who: &SigPublic) -> &Participant {
        &self.members[who]
    }

    /// Every online member's key, as an opaque digest for comparison.
    pub fn keys(&self) -> BTreeMap<SigPublic, Option<[u8; 32]>> {
        self.members
            .iter()
            .filter(|(id, _)| !self.offline.contains(id))
            .map(|(id, p)| (*id, p.group_key().map(|k| *k.as_bytes())))
            .collect()
    }

    /// Asserts that every online member derives the same non-empty key.
    pub fn assert_agreement(&self, ctx: &str) {
        let keys = self.keys();
        let mut it = keys.iter();
        let (first_id, first) = it.next().expect("at least one member");
        assert!(first.is_some(), "{ctx}: {first_id:?} cannot derive a key");
        for (id, k) in it {
            assert_eq!(
                k, first,
                "{ctx}: {id:?} disagrees with {first_id:?} on the group key"
            );
        }
        let versions: BTreeSet<[u8; 8]> = self
            .members
            .iter()
            .filter(|(id, _)| !self.offline.contains(id))
            .map(|(_, p)| p.version())
            .collect();
        assert_eq!(versions.len(), 1, "{ctx}: version labels diverged");
    }
}
