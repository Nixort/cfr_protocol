# The Causal Frontier Ratchet (CFR) Protocol

> **Compatibility note.** Causal Frontier Ratchet is the public project and protocol name. The historical `"cfr/"` KDF and hash domain-separation labels are deliberately retained as immutable protocol parameters; changing them would create a cryptographically incompatible protocol variant.

## 1. Shape

Participants publish **operations** into a causal graph. Every operation is
signed and names the operations it follows. There is no coordinator: any
participant may publish any operation at any time, and concurrent operations
become concurrent nodes rather than conflicts.

Six kinds of operation:

| kind | meaning |
|---|---|
| `Add` | admit an identity |
| `Remove` | evict an identity |
| `Prekeys` | publish a prekey generation |
| `Contrib` | contribute entropy to the group key |
| `Accuse` | accuse an identity of equivocation, with proof |
| `PrekeyRequest` | ask named identities to publish a fresh prekey |

## 2. Keys

A contribution carries a fresh secret `x`, sealed individually to each
recipient. It becomes a **node key** chained onto the contributions it follows:

```
nodekey(c) = KDF(x_c; "cfr/node"; XOR nodekey(parents(c)); oid(c))
```

The **frontier** `F` is the set of contribution nodes that no other
contribution descends from. The group key is

```
K(F) = KDF(seed0; "cfr/group"; XOR nodekey(F); root(M); H(F))
```

where `root(M)` is a digest of the membership.

Chaining is what carries freshness forward: one honest contribution makes every
later version unpredictable, because its node key is folded into all of its
descendants.

### The frontier is a function of the graph

This is the load-bearing invariant. The frontier is computed by **transitive**
ancestry over the operations received — never from the local record of which
contributions this participant managed to absorb.

If it were derived from absorption history, two participants holding exactly the
same operations would compute different versions whenever their loss or repair
histories differed, and they would never converge again. Being *able to compute*
a version's key is a separate question from *what the version is*: a participant
missing node keys still knows the correct version and recovers the key by
repair.

### The version label covers everything the key covers

```
version = H("cfr/version", root(M) ‖ F)[..8]
```

The membership root is inside the label, not only inside the key. Admissions and
evictions are not contributions, so they do not change the frontier; a label over
the frontier alone would let two participants with different rosters publish the
same label while holding different keys. That is silent divergence, and it is
exactly what the label exists to prevent.

## 3. Channels

Each ordered pair of participants has a channel, rooted once in a prekey
agreement:

```
root  = KDF(dh(eph, prekey); "cfr/root"; sid, from, to, generation)
chain = KDF(root; "cfr/chan/data")
```

The chain steps per message and the previous chain key is overwritten, so a
snapshot cannot reach earlier messages. Out-of-order arrivals are **buffered,
not key-cached**: a skipped-key cache would keep message keys alive for the
duration of a gap, and a snapshot during that window would expose every buffered
position.

### Prekey lifecycle

One prekey per generation. The private half is destroyed once channels have been
opened with every current member — tracked as a **set of peers served**, not a
count. A count is wrong the moment the roster grows: the generation would be
destroyed while a member admitted a moment later still needed it.

A generation is also destroyed on a deadline, so a silent participant cannot
extend the forward-secrecy window for everyone else.

When a participant sees an admission and its own generation is already sealed, it
publishes a fresh one, so the newcomer always has something to reach it with.

## 4. Membership

A causal, authorised, remove-wins observed-remove set, evaluated as a pure
function of the graph. An admission survives only if every *counted* eviction of
that identity strictly precedes it.

An eviction counts when it comes from the target itself, from an administrator,
from a quorum of distinct authors, or from a verified accusation.

Operations are authorised against the roster **in their own causal past**, which
is inside the signed image. Judging against the current view would make the
verdict depend on what else has arrived, and two participants could disagree
about the same operation.

The founding operation is a dependency-free self-admission. At most one identity
may hold that position; the check is stated over *other authors* so that
replaying a history in any order reaches the same verdict.

## 5. Equivocation

A contribution commits to `cid = H(x)`. A recipient that opens its slice and
finds a different secret publishes an `Accuse` carrying the **one-time message
key** of its own slice. Any third party can then open the same slice and check
the mismatch for itself.

Revealing that key is safe: it is one-time and the contribution is being
discarded anyway. A false accusation costs the accuser its own key and proves
nothing.

## 6. Repair

Two mechanisms, both leaderless.

**Anti-entropy.** A participant broadcasts the identifiers it holds; members
reply directly with what it lacks. The exchange is bidirectional — a responder
that notices the requester holds operations *it* lacks sends its own request
back. A one-directional exchange only teaches the requester, and the two would
never converge.

**Node key repair.** A participant missing node keys for its frontier asks for
them. A responder serves the request only if the requester is a **current
member** and only for nodes in the **current frontier**. Ancestors are refused
even when held: a recently admitted participant must not be able to walk
backwards and decrypt media from before it joined.

## 7. Wire format

Canonical TLV. Every value carries a type tag; every variable-length value
carries a length; integers are fixed width; sets are stored sorted by encoded
image with duplicates rejected.

The decoder rejects anything its own encoder would not have produced, which
makes injectivity testable in the hard direction: for every accepted byte
string, re-encoding must reproduce it exactly. The fuzz target
`codec_canonical` checks precisely this.

Injectivity is not a nicety. Signatures cover the encoded image, not the
structure, so two structures with one image would let a signature be moved to a
different meaning without breaking Ed25519.

The conference identifier is inside every signed image, so an operation lifted
from one conference cannot be replayed into another.

## 8. Media

```
[ frame, content encrypted in place ][ tag: 32 or 16 ][ trailer: 13 ]

trailer := sender_tag(4) ‖ counter(4) ‖ version_hint(4) ‖ flags(1)
```

AEGIS-256 is length preserving, so content is encrypted in place and the frame
keeps its geometry. The trailer and every readable range are authenticated as
associated data: a forwarder may read them and route on them, and cannot change
them.

Readable ranges per codec:

| codec | readable | why |
|---|---|---|
| H.264 | start codes and the 1-byte NAL header of each unit | unit type, reference status |
| H.265 | start codes and the 2-byte NAL header | plus temporal layer identification |
| AV1 | OBU header, extension byte, LEB128 size | OBU type, layer identifiers |
| VP8 | 3 bytes, or 10 on a key frame | frame type, first partition size |
| VP9 | nothing | the uncompressed header is bit packed; scalability data rides in RTP |
| Opus | 1 byte | the TOC byte |
| other | nothing | fail closed |

A parser that does not recognise its input protects the whole frame. Failing
closed matters more than routability: guessing a header length on malformed
input could expose content.

Frame keys come from a per-sender ratchet:

```
base     = KDF(K_group; "cfr/media"; sender)
chain(i) = KDF(chain(i-1); "cfr/media/epoch")
frame(c) = KDF(chain(c >> 8); "cfr/media/frame"; c)
```

Per-sender separation means a participant cannot forge a frame that appears to
come from someone else even though everyone holds the same group key. The epoch
of 256 frames means a receiver that has advanced cannot decrypt older epochs —
about eight seconds at thirty frames per second — while still being able to
reach an arbitrary counter after loss.

The frame counter belongs to the **version**, not to the protector. A counter
shared across versions would restart whenever a version was re-selected, and
since the nonce is a function of version and counter, that would repeat a nonce
under a key already used.

## 9. Key confirmation

Twelve bytes: the version label and a tag over it computed under the group key.
It fits alongside media, so divergence is detected rather than assumed absent. A
participant fed a different history produces a tag that does not check.
