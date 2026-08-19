# Integration

CFR owns no sockets. It consumes byte slices and returns messages with a
destination; delivering them is the application's job.

## 1. Admission

A newcomer generates its own material and hands over a self-signed package:

```rust
let joining = cfr::Joining::new(Policy::leaderless(2))?;
let package = joining.key_package();   // send to the inviter out of band
```

The package is self-signed, so an inviter cannot substitute a prekey it controls
and read the welcome. **The library cannot authenticate the identity** — deliver
the package over a channel that does, or verify fingerprints separately.

The inviter admits:

```rust
let out = conference.invite(&package)?;
```

One of the returned messages is addressed to the newcomer; the rest are for
everyone. Deliver them.

```rust
let (mut newcomer, out) = joining.accept(&welcome_payload)?;
```

A newcomer does not contribute immediately. Existing members rotate their
prekeys when they see the admission, and until those rotations land the
newcomer's view of them is one message stale. Call `rekey()` on the next cycle.

## 2. The message loop

```rust
for msg in outbound {
    match msg.to {
        Recipient::Everyone => transport.broadcast(&msg.payload),
        Recipient::Peer(id) => transport.send_to(id, &msg.payload),
    }
}

// inbound
let (events, more) = conference.handle(&payload)?;
```

Handle the events:

| event | action |
|---|---|
| `KeyChanged` | nothing required; media keys refresh themselves |
| `Joined` / `Left` | update the roster in the user interface |
| `Equivocation` | surface it; the participant is being evicted |
| `RepairNeeded` | call `resync()` and deliver the result |

Call `tick()` about once per rotation interval so prekey deadlines advance.

## 3. Media

```rust
let sealed = conference.protect(Codec::H264, &frame, is_keyframe)?;
// … send over SRTP as usual …
let (from, plain) = conference.open(&packet)?;
```

Protect **encoded frames**, before packetisation, and open after
reassembly. The transport's own encryption stays in place: CFR protects
against the server, SRTP against the network.

Frame overhead is 45 bytes for video and 29 for audio. If you are packetising
close to the MTU, reduce the payload budget by that much.

### WebRTC

In libwebrtc terms this is a frame encryptor and decryptor pair. Register
`protect` as the encryptor and `open` as the decryptor. The keyframe flag comes
from the encoded image; passing it wrongly is safe — for VP8 the bitstream is
consulted and overrides a false claim.

## 4. Selective forwarding units

A forwarding unit needs no key:

```rust
let t = Conference::inspect(&packet)?;
t.sender; t.counter; t.codec; t.keyframe;
```

and the codec structure is still in the frame: NAL headers, OBU headers and the
VP8 uncompressed chunk are byte-identical to the original and sit at the same
offsets. Parse and route as before.

What a forwarder **cannot** do is change any of it. The trailer and every
readable range are authenticated; a single altered bit makes the frame fail to
open at every receiver.

## 5. Key confirmation

Attach `conference.beacon()` — twelve bytes — to outgoing media, and check what
arrives:

```rust
match conference.check_beacon(&peer, &beacon) {
    Beacon::Agreed   => {}
    Beacon::Diverged => alert("someone is being fed a different history"),
    Beacon::Unknown  => { /* usually lag; resync before concluding */ }
}
```

`Diverged` means same version, different key. That is not a network problem.

## 6. Recovery

```rust
if conference.needs_repair() {
    for m in conference.resync() { transport.send(m); }
}
```

`resync` is safe to call at any time and is the single recovery path: it covers
missed operations and missing node keys.

An inviter that cannot currently derive the key will refuse to admit — it cannot
hand over material it does not have. Resync, then retry.

## 7. Post-compromise

After any suspicion that a device was compromised:

```rust
for m in conference.heal()? { transport.send(m); }
```

This rotates the prekey and contributes. Both are needed. Rotation alone leaves
the attacker holding the current key; a contribution alone leaves it able to
read the channels.

## 8. Choosing a policy

`Policy::leaderless(quorum)` is the configuration the analysis assumes. A quorum
of two means two distinct participants must agree to evict, which stops a single
malicious member from ejecting people.

Naming administrators is supported and weakens the leaderless property: a named
identity can evict unilaterally. Use it only when the deployment already has an
authority worth trusting with that.

## 9. Post-quantum

Enable the `pq` feature to use X25519 + ML-KEM-768 hybrid key encapsulation.
Every reduction in the analysis goes through unchanged; the assumption becomes
"Gap-CDH **or** ML-KEM-768 IND-CCA" rather than Gap-CDH alone. Key packages grow
by about 1.2 kB.
