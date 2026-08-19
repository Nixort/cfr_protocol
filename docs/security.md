# Security

## Threat model

Servers are **untrusted and may be actively hostile**. They see every message
and may drop, duplicate, reorder, partition, censor and inject arbitrary bytes.
They never hold key material.

Participants may be **malicious, not merely curious**, and may collude. A
compromised client yields its **entire memory** to the attacker: conference
seed, node keys within the overlap window, unretired prekey secrets, channel
state, the operation graph, buffers.

Participants go offline and return. The network may partition and heal.

## What is provided

**Forward secrecy.** Prekey secrets are destroyed once channels are open;
channel chain keys are overwritten on every step; node keys leave the overlap
window and are erased. A snapshot does not open earlier traffic. The horizon is
the channel establishment window — roughly one round trip — not the rotation
period.

**Post-compromise security.** Rotating a prekey and contributing once restores
secrecy against an attacker holding an earlier snapshot. Both steps are
necessary: rotation removes the attacker's read access to new channels, the
contribution puts entropy into the key that the attacker never saw.

**Leaderless operation.** No coordinator, no tree root, no distinguished
participant. Every participant can contribute, admit, evict and repair. The
founder has no residual authority and can leave.

**Agreement.** The key version is a pure function of the operations received.
Participants holding the same operations hold the same key regardless of arrival
order, loss history or repair path.

**Authenticity.** Every operation is signed over a canonical, injective image
that includes the conference identifier, the author, the dependency set and the
payload. Verification precedes every other action.

**Membership soundness.** Operations are authorised against the roster in their
own causal past, so every participant reaches the same verdict.

**Equivocation is punished.** A participant that commits to one secret and
delivers another produces transferable proof against itself, and is evicted
without a vote.

**Replay and rollback resistance.** Operations deduplicate by identifier; the
graph only grows; a consumed channel position cannot be replayed; media frames
pass a per-sender sliding window.

**Split-brain resistance.** Partitions produce different versions rather than a
silent shared key, and anti-entropy merges them. The key confirmation beacon
makes a divergence visible in twelve bytes.

## What is not provided

Stated plainly, because a library that lists only its strengths is not one you
can deploy against.

**Metadata.** Who is present, when they speak, how much they send, and the shape
of the conversation are all visible to the server. CFR hides content.

**Availability.** A server that drops everything stops the call. There is no
defence against a network that refuses to carry traffic; the construction
ensures that such a server learns nothing and cannot forge, not that it cannot
disrupt.

**Identity binding.** The library cannot tell one stranger from another. A key
package must arrive over a channel that authenticates the identity, or the
inviter admits whoever produced it. Verify fingerprints out of band.

**History compaction.** Not offered. An operation names its dependencies inside
its signed image, so those identifiers are permanent; a participant that
discards an operation locally still forwards successors that name it, and a
receiver that never held it cannot rebuild the edge — after which membership
verdicts differ and the two diverge for good. Retaining every named dependency
forces the entire ancestor closure; shipping contracted edges asks the receiver
to trust the sender's contraction; re-signing needs an authority, and the
construction is leaderless by requirement. A sound scheme needs a global
watermark, which is itself a consensus problem. **Consequence: retained history
grows with the number of operations** — roughly one contribution per participant
per rotation, about 1 MB after 300 operations in a hundred-participant call. Key
material does not grow; the overlap window bounds it.

**Parent-set discipline.** A contribution declares which frontier nodes it
chains onto. An honest participant chains onto everything it can; a dishonest
one could declare a narrower set and discard another member's entropy from the
current version. This is narrow — available only to a current member, who
already holds the key; lasting one version, since the next honest contribution
folds the entropy back in; and visible after the fact, since the parent set is
inside the signed operation. Rejecting such contributions was implemented and
removed: the acceptance test must be evaluated identically by every participant,
and it is not, so enforcing it caused certain divergence in exchange for
preventing a marginal and self-repairing attack.

**Constant-time execution.** Comparison of secrets goes through `subtle`, and
the primitive crates make their own constant-time claims. The surrounding
control flow in this library has not been audited for timing behaviour.

**Physical erasure.** `zeroize` clears the object. It does not promise that no
copy was left by an optimiser, an allocator, a swap file or a hypervisor.
Forward secrecy is a statement about the whole system, not about one type.

**Formal verification of this code.** The construction has a separate written
analysis with reductions and an exhaustive symbolic check. That analysis is about
the construction. This crate is the construction *implemented*, and the bridge
between them is tests, not proof.

**Denial of service by a member.** A member can flood the graph with operations.
Per-author limits exist in the policy, and enforcing them is left to the
application, which knows its own rate budget.

## Obligations the implementation must keep

These are the properties the analysis assumes. Where the crate enforces one, the
enforcement point is named.

| # | obligation | where |
|---|---|---|
| O1 | secrets erased when declared destroyed | `Secret` zeroizes on drop; `wipe` at each declared point |
| O2 | no nonce repeats under one key | nonce covers version and counter; counter is per version |
| O3 | every hash and derivation domain-separated and length-prefixed | `cfr-crypto::{hash, kdf, mac}` |
| O4 | signature verified before any other action | first statement of `Participant::ingest` |
| O5 | membership judged on the operation's own causal past | `Membership::members_before` |
| O6 | frontier is a function of the graph, not of absorption history | `keys::frontier` |
| O7 | version label covers every input to the key | `keys::version_of` |
| O8 | encoding injective; decoder rejects non-canonical input | `codec::Reader`, fuzz target `codec_canonical` |
| O9 | overlap window finite | `keys::OVERLAP`, `NodeKeys` eviction erases |
| O10 | one entropy source | `cfr_crypto::fill_random` |
| O11 | secret comparison in constant time | `subtle` via `ct_eq` |
| O12 | every length bounded before allocation | `codec::MAX_FIELD`, `MAX_ITEMS`, `MAX_BATCH`, `MAX_PENDING` |
| O13 | no unbounded growth from remote input | buffer, pending and pruned caps |

O1 and O11 are enforced as far as Rust allows and are **not** claimed beyond
that; see the two entries above.

## Reporting

Security reports should go to the repository's private disclosure channel rather
than a public issue.
