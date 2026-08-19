// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Signed CFR operations.
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use cfr_crypto::{hash, DhPublic, SigPublic, SigSecret, Signature};

/// Identifier of an operation: a hash of its signed image and its signature.
pub type Oid = [u8; 32];

/// Identifier of a contribution secret: a hash of the secret itself.
pub type Cid = [u8; 32];

/// Conference identifier, fixed at creation and bound into every derivation.
pub type SessionId = [u8; 32];

/// Maximum number of recipients addressed by one contribution. Conferences are
/// bounded at 100 participants; the margin absorbs churn without letting a
/// hostile operation allocate without limit (obligation O13).
pub const MAX_RECIPIENTS: usize = 256;

/// Maximum number of direct dependencies an operation may declare.
pub const MAX_DEPS: usize = 256;

/// The kinds of operation. Encoded as a fixed integer, never as a string, so
/// the tag cannot be confused with a length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum Kind {
    /// Admit a participant.
    Add = 1,
    /// Evict a participant.
    Remove = 2,
    /// Publish a prekey generation.
    Prekeys = 3,
    /// Contribute fresh entropy to the group key.
    Contrib = 4,
    /// Accuse a participant of equivocation, with transferable proof.
    Accuse = 5,
    /// Ask named participants to publish a fresh prekey generation.
    PrekeyRequest = 6,
}

impl Kind {
    fn from_u32(v: u32) -> Result<Self> {
        Ok(match v {
            1 => Self::Add,
            2 => Self::Remove,
            3 => Self::Prekeys,
            4 => Self::Contrib,
            5 => Self::Accuse,
            6 => Self::PrekeyRequest,
            _ => return Err(Error::Encoding("unknown operation kind")),
        })
    }
}

/// One recipient's share of a contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slice {
    /// Identity of the recipient.
    pub to: SigPublic,
    /// When present, this slice opens a new channel: it names the recipient's
    /// prekey generation and carries the sender's ephemeral public key. When
    /// absent, an established channel is advanced instead.
    pub establish: Option<(u32, DhPublic)>,
    /// Position in the sender-to-recipient channel. Out-of-order slices are
    /// buffered against this, never key-cached.
    pub seq: u64,
    /// The sealed contribution secret.
    pub ct: Vec<u8>,
}

impl Slice {
    fn encode(&self, w: &mut Writer) {
        w.bytes(self.to.as_bytes());
        match &self.establish {
            Some((gen, eph)) => {
                w.u32(1).u32(*gen).bytes(eph.as_bytes());
            }
            None => {
                w.u32(0);
            }
        }
        w.u64(self.seq).bytes(&self.ct);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let to = SigPublic::from_bytes(r.array::<32>()?);
        let establish = match r.u32()? {
            0 => None,
            1 => {
                let gen = r.u32()?;
                Some((gen, DhPublic::from_bytes(r.array::<32>()?)))
            }
            _ => return Err(Error::Encoding("invalid slice discriminant")),
        };
        let seq = r.u64()?;
        let ct = r.bytes()?.to_vec();
        Ok(Self {
            to,
            establish,
            seq,
            ct,
        })
    }
}

/// The payload of an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// Admit `who`.
    Add {
        /// Identity being admitted.
        who: SigPublic,
    },
    /// Evict `who`.
    Remove {
        /// Identity being evicted.
        who: SigPublic,
    },
    /// Publish prekey generation `gen`.
    Prekeys {
        /// Monotonic generation counter, scoped to the author.
        gen: u32,
        /// The public prekey of that generation.
        pk: DhPublic,
    },
    /// Contribute entropy.
    Contrib {
        /// Commitment to the contributed secret.
        cid: Cid,
        /// The frontier this contribution chains onto.
        cparents: BTreeSet<Oid>,
        /// Members addressed by this contribution.
        recips: Vec<SigPublic>,
        /// Per-recipient sealed shares.
        slices: Vec<Slice>,
        /// The membership root the author saw, binding the contribution to a
        /// view of the group.
        view: [u8; 32],
    },
    /// Accuse `who` of equivocating in contribution `coid`, revealing the
    /// one-time message key so any third party can check the claim.
    Accuse {
        /// The accused.
        who: SigPublic,
        /// The offending contribution.
        coid: Oid,
        /// The revealed one-time message key of the accuser's own slice.
        mk: [u8; 32],
        /// The channel index that key belongs to.
        seq: u64,
    },
    /// Ask `targets` to publish a fresh prekey generation.
    PrekeyRequest {
        /// Identities being asked.
        targets: Vec<SigPublic>,
    },
}

impl Body {
    /// The kind tag of this payload.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Add { .. } => Kind::Add,
            Self::Remove { .. } => Kind::Remove,
            Self::Prekeys { .. } => Kind::Prekeys,
            Self::Contrib { .. } => Kind::Contrib,
            Self::Accuse { .. } => Kind::Accuse,
            Self::PrekeyRequest { .. } => Kind::PrekeyRequest,
        }
    }

    fn encode(&self, w: &mut Writer) {
        match self {
            Self::Add { who } | Self::Remove { who } => {
                w.bytes(who.as_bytes());
            }
            Self::Prekeys { gen, pk } => {
                w.u32(*gen).bytes(pk.as_bytes());
            }
            Self::Contrib {
                cid,
                cparents,
                recips,
                slices,
                view,
            } => {
                w.bytes(cid);
                let parents: Vec<Oid> = cparents.iter().copied().collect();
                w.set(&parents, |w, p| {
                    w.bytes(p);
                });
                w.list(recips, |w, p| {
                    w.bytes(p.as_bytes());
                });
                w.list(slices, |w, s| s.encode(w));
                w.bytes(view);
            }
            Self::Accuse { who, coid, mk, seq } => {
                w.bytes(who.as_bytes()).bytes(coid).bytes(mk).u64(*seq);
            }
            Self::PrekeyRequest { targets } => {
                w.list(targets, |w, p| {
                    w.bytes(p.as_bytes());
                });
            }
        }
    }

    fn decode(kind: Kind, r: &mut Reader<'_>) -> Result<Self> {
        Ok(match kind {
            Kind::Add => Self::Add {
                who: SigPublic::from_bytes(r.array::<32>()?),
            },
            Kind::Remove => Self::Remove {
                who: SigPublic::from_bytes(r.array::<32>()?),
            },
            Kind::Prekeys => Self::Prekeys {
                gen: r.u32()?,
                pk: DhPublic::from_bytes(r.array::<32>()?),
            },
            Kind::Contrib => {
                let cid = r.array::<32>()?;
                let parents: Vec<Oid> = r.set(super::codec::Reader::array::<32>)?;
                if parents.len() > MAX_DEPS {
                    return Err(Error::Encoding("too many contribution parents"));
                }
                let recips: Vec<SigPublic> =
                    r.list(|r| Ok(SigPublic::from_bytes(r.array::<32>()?)))?;
                if recips.len() > MAX_RECIPIENTS {
                    return Err(Error::Encoding("too many recipients"));
                }
                let slices: Vec<Slice> = r.list(Slice::decode)?;
                if slices.len() > MAX_RECIPIENTS {
                    return Err(Error::Encoding("too many slices"));
                }
                let view = r.array::<32>()?;
                Self::Contrib {
                    cid,
                    cparents: parents.into_iter().collect(),
                    recips,
                    slices,
                    view,
                }
            }
            Kind::Accuse => Self::Accuse {
                who: SigPublic::from_bytes(r.array::<32>()?),
                coid: r.array::<32>()?,
                mk: r.array::<32>()?,
                seq: r.u64()?,
            },
            Kind::PrekeyRequest => {
                let targets: Vec<SigPublic> =
                    r.list(|r| Ok(SigPublic::from_bytes(r.array::<32>()?)))?;
                if targets.len() > MAX_RECIPIENTS {
                    return Err(Error::Encoding("too many targets"));
                }
                Self::PrekeyRequest { targets }
            }
        })
    }
}

/// A signed causal operation with cached image and identifier.
///
/// The caches are derived from the public fields and are excluded from equality.
#[derive(Debug, Clone)]
pub struct Op {
    /// Which conference it belongs to.
    pub sid: SessionId,
    /// Who published it.
    pub author: SigPublic,
    /// The operations it causally follows.
    pub deps: BTreeSet<Oid>,
    /// The payload.
    pub body: Body,
    /// The author's signature over [`Op::signed_image`].
    pub sig: Signature,
    image: [u8; 32],
    oid: Oid,
}

impl PartialEq for Op {
    fn eq(&self, other: &Self) -> bool {
        self.sid == other.sid
            && self.author == other.author
            && self.deps == other.deps
            && self.body == other.body
            && self.sig == other.sig
    }
}

impl Eq for Op {}

impl Op {
    /// Returns the canonical image whose signature binds operation semantics.
    pub fn signed_image(
        sid: &SessionId,
        author: &SigPublic,
        deps: &BTreeSet<Oid>,
        body: &Body,
    ) -> [u8; 32] {
        let mut w = Writer::new();
        w.bytes(sid)
            .u32(body.kind() as u32)
            .bytes(author.as_bytes());
        let d: Vec<Oid> = deps.iter().copied().collect();
        w.set(&d, |w, x| {
            w.bytes(x);
        });
        body.encode(&mut w);
        hash(b"cfr/op", &[&w.finish()])
    }

    /// Builds and signs an operation.
    pub fn create(
        signing_key: &SigSecret,
        session_id: &SessionId,
        deps: BTreeSet<Oid>,
        body: Body,
    ) -> Self {
        let author = signing_key.public();
        let image = Self::signed_image(session_id, &author, &deps, &body);
        let signature = signing_key.sign(&image);
        let oid = hash(b"cfr/oid", &[&image, signature.as_bytes()]);
        Self {
            sid: *session_id,
            author,
            deps,
            body,
            sig: signature,
            image,
            oid,
        }
    }

    /// Returns the cached identifier over the image and signature.
    pub fn oid(&self) -> Oid {
        self.oid
    }

    /// Verifies the author signature over the conference-bound image.
    pub fn verify(&self) -> Result<()> {
        self.author
            .verify(&self.image, &self.sig)
            .map_err(|_| Error::BadSignature)
    }

    /// The kind tag.
    pub fn kind(&self) -> Kind {
        self.body.kind()
    }

    /// Serializes the canonical operation image and signature.
    ///
    /// Public fields are inspection-only; reconstruct after mutation to refresh
    /// the cached image and identifier.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.sid)
            .u32(self.body.kind() as u32)
            .bytes(self.author.as_bytes());
        let d: Vec<Oid> = self.deps.iter().copied().collect();
        w.set(&d, |w, x| {
            w.bytes(x);
        });
        self.body.encode(&mut w);
        w.bytes(self.sig.as_bytes());
        w.finish()
    }

    /// Parses a canonical operation without authenticating its signature.
    pub fn from_wire(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let op = Self::read(&mut r)?;
        r.finish()?;
        Ok(op)
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let session_id = reader.array::<32>()?;
        let kind = Kind::from_u32(reader.u32()?)?;
        let author = SigPublic::from_bytes(reader.array::<32>()?);
        let dependency_list: Vec<Oid> = reader.set(super::codec::Reader::array::<32>)?;
        if dependency_list.len() > MAX_DEPS {
            return Err(Error::Encoding("too many dependencies"));
        }
        let body = Body::decode(kind, reader)?;
        let signature = Signature::from_bytes(reader.array::<64>()?);
        let deps: BTreeSet<Oid> = dependency_list.into_iter().collect();
        let image = Self::signed_image(&session_id, &author, &deps, &body);
        let oid = hash(b"cfr/oid", &[&image, signature.as_bytes()]);
        Ok(Self {
            sid: session_id,
            author,
            deps,
            body,
            sig: signature,
            image,
            oid,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        w.bytes(&self.to_wire());
    }

    /// Approximate encoded size, used by the cost accounting in the test suite.
    pub fn wire_len(&self) -> usize {
        self.to_wire().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> SigSecret {
        SigSecret::from_seed(&[1u8; 32])
    }

    const SID: SessionId = [0xABu8; 32];

    #[test]
    fn sign_verify_roundtrip() {
        let sk = ident();
        let op = Op::create(&sk, &SID, BTreeSet::new(), Body::Add { who: sk.public() });
        op.verify().unwrap();
        let wire = op.to_wire();
        let back = Op::from_wire(&wire).unwrap();
        assert_eq!(back, op);
        assert_eq!(back.oid(), op.oid());
        back.verify().unwrap();
    }

    #[test]
    fn wire_encoding_is_canonical() {
        let sk = ident();
        let mut deps = BTreeSet::new();
        deps.insert([9u8; 32]);
        deps.insert([3u8; 32]);
        let op = Op::create(&sk, &SID, deps, Body::Remove { who: sk.public() });
        let wire = op.to_wire();
        assert_eq!(Op::from_wire(&wire).unwrap().to_wire(), wire);
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        // Tampering happens on the wire and the result is re-parsed, which is
        // how an attacker would actually do it. A parsed operation recomputes
        // its own signed image, so a rewritten field cannot ride on the
        // original image.
        let sk = ident();
        let other = SigSecret::from_seed(&[2u8; 32]);
        let base = Op::create(&sk, &SID, BTreeSet::new(), Body::Add { who: sk.public() });
        let good = base.to_wire();

        let mutate = |f: &dyn Fn(&mut Op)| {
            let mut t = Op::from_wire(&good).unwrap();
            f(&mut t);
            Op::from_wire(&t.to_wire()).unwrap()
        };

        // changed payload
        assert!(mutate(&|t| {
            t.body = Body::Add {
                who: other.public(),
            };
        })
        .verify()
        .is_err());

        // changed kind
        assert!(mutate(&|t| {
            t.body = Body::Remove { who: sk.public() };
        })
        .verify()
        .is_err());

        // changed author
        assert!(mutate(&|t| {
            t.author = other.public();
        })
        .verify()
        .is_err());

        // added dependency
        assert!(mutate(&|t| {
            t.deps.insert([1u8; 32]);
        })
        .verify()
        .is_err());

        // changed conference
        assert!(mutate(&|t| {
            t.sid = [0xFFu8; 32];
        })
        .verify()
        .is_err());

        assert!(Op::from_wire(&good).unwrap().verify().is_ok());
    }

    #[test]
    fn dependency_set_order_does_not_affect_identity() {
        let sk = ident();
        let a: Oid = [1u8; 32];
        let b: Oid = [2u8; 32];
        let mut d1 = BTreeSet::new();
        d1.insert(a);
        d1.insert(b);
        let mut d2 = BTreeSet::new();
        d2.insert(b);
        d2.insert(a);
        assert_eq!(
            Op::signed_image(&SID, &sk.public(), &d1, &Body::Add { who: sk.public() }),
            Op::signed_image(&SID, &sk.public(), &d2, &Body::Add { who: sk.public() })
        );
    }

    #[test]
    fn truncated_wire_is_rejected() {
        let sk = ident();
        let op = Op::create(&sk, &SID, BTreeSet::new(), Body::Add { who: sk.public() });
        let wire = op.to_wire();
        for cut in [0, 1, wire.len() / 2, wire.len() - 1] {
            assert!(Op::from_wire(&wire[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let mut w = Writer::new();
        w.bytes(&SID).u32(99).bytes(&[0u8; 32]);
        assert!(Op::from_wire(&w.finish()).is_err());
    }
}
