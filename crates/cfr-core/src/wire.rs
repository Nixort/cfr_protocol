// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Canonical control-plane messages.
use crate::checkpoint::{CheckpointCertificate, PROTOCOL_ID};
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::op::{Oid, Op, SessionId};
use alloc::vec::Vec;
use cfr_crypto::{DhPublic, SigPublic, Signature};

/// A newcomer's signed identity and prekey material.
///
/// The self-signature prevents inviter substitution of the offered prekey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackage {
    /// The newcomer's long-term identity.
    pub ipk: SigPublic,
    /// Generation of the offered prekey.
    pub gen: u32,
    /// The offered prekey.
    pub prekey: DhPublic,
    /// Signature by `ipk` over the other three fields.
    pub sig: Signature,
}

impl KeyPackage {
    pub(crate) fn image(ipk: &SigPublic, gen: u32, prekey: &DhPublic) -> [u8; 32] {
        let mut w = Writer::new();
        w.bytes(ipk.as_bytes()).u32(gen).bytes(prekey.as_bytes());
        cfr_crypto::hash(b"cfr/keypackage", &[&w.finish()])
    }

    /// Verifies the self-signature.
    pub fn verify(&self) -> Result<()> {
        let img = Self::image(&self.ipk, self.gen, &self.prekey);
        self.ipk
            .verify(&img, &self.sig)
            .map_err(|_| Error::BadSignature)
    }

    fn encode(&self, w: &mut Writer) {
        w.bytes(self.ipk.as_bytes())
            .u32(self.gen)
            .bytes(self.prekey.as_bytes())
            .bytes(self.sig.as_bytes());
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            ipk: SigPublic::from_bytes(r.array::<32>()?),
            gen: r.u32()?,
            prekey: DhPublic::from_bytes(r.array::<32>()?),
            sig: Signature::from_bytes(r.array::<64>()?),
        })
    }

    /// Serialises to bytes for out-of-band delivery to an inviter.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode(&mut w);
        w.finish()
    }

    /// Parses an out-of-band key package.
    pub fn from_wire(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let kp = Self::decode(&mut r)?;
        r.finish()?;
        Ok(kp)
    }
}

/// A sealed point-to-point envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The sender's ephemeral public key.
    pub eph: DhPublic,
    /// Which of the recipient's prekey generations it is addressed to.
    pub gen: u32,
    /// The sealed payload.
    pub ct: Vec<u8>,
}

/// Everything a participant can send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A signed history operation, broadcast to the conference.
    Op(Op),
    /// A sealed admission bundle for a newcomer.
    Welcome {
        /// The conference identifier.
        sid: SessionId,
        /// The inviter.
        from: SigPublic,
        /// Sealed conference seed and node keys.
        sealed: Envelope,
        /// The history, in an order where dependencies come first.
        history: Vec<Op>,
        /// Dependency identifiers the sender no longer retains.
        pruned: Vec<Oid>,
    },
    /// Anti-entropy: "these heads imply the operations I hold".
    Sync {
        /// The requester. Responses are addressed to it, and only current
        /// members are served.
        from: SigPublic,
        /// Causal heads retained by the sender.
        ///
        /// Every ancestor of a known head is also known to the sender, allowing
        /// the responder to derive an exact shared causal closure without a
        /// full-history identifier list.
        heads: Vec<Oid>,
    },
    /// Anti-entropy response carrying operations the peer lacked.
    Deliver {
        /// Operations, in dependency-first order.
        ops: Vec<Op>,
        /// Operations the sender has compacted away.
        pruned: Vec<Oid>,
    },
    /// Requests missing node keys for the named requester.
    ///
    /// Responses are sealed to the requester's published prekey.
    NodeKeyRequest {
        /// The requester.
        from: SigPublic,
        /// The nodes whose keys are missing.
        nodes: Vec<Oid>,
    },
    /// A sealed response to [`Message::NodeKeyRequest`].
    NodeKeyResponse {
        /// The responder.
        from: SigPublic,
        /// Sealed `(oid, key)` pairs.
        sealed: Envelope,
    },
    /// A unanimously signed offer to reinitialize into a fresh session.
    Checkpoint(CheckpointCertificate),
}

/// Canonical control-plane marker required by every CFR message.
///
/// It is intentionally outside the valid message-tag range, so a decoder that
/// does not implement the CFR format fails before interpreting any payload field.
pub const CFR_WIRE_MARKER: u64 = 0x4346_5221;

const M_OP: u32 = 1;
const M_WELCOME: u32 = 2;
const M_SYNC: u32 = 3;
const M_DELIVER: u32 = 4;
const M_NKREQ: u32 = 5;
const M_NKRESP: u32 = 6;
const M_CHECKPOINT: u32 = 7;

/// Ceiling on operations carried by one message (obligation O13).
pub const MAX_BATCH: usize = 4096;

fn env_encode(e: &Envelope, w: &mut Writer) {
    w.bytes(e.eph.as_bytes()).u32(e.gen).bytes(&e.ct);
}

fn env_decode(r: &mut Reader<'_>) -> Result<Envelope> {
    Ok(Envelope {
        eph: DhPublic::from_bytes(r.array::<32>()?),
        gen: r.u32()?,
        ct: r.bytes()?.to_vec(),
    })
}

impl Message {
    /// Serialises the message.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64(CFR_WIRE_MARKER).u64(u64::from(PROTOCOL_ID));
        match self {
            Self::Op(op) => {
                w.u32(M_OP);
                op.write(&mut w);
            }
            Self::Welcome {
                sid,
                from,
                sealed,
                history,
                pruned,
            } => {
                w.u32(M_WELCOME).bytes(sid).bytes(from.as_bytes());
                env_encode(sealed, &mut w);
                w.list(history, |w, op| op.write(w));
                w.set(pruned, |w, o| {
                    w.bytes(o);
                });
            }
            Self::Sync { from, heads } => {
                w.u32(M_SYNC).bytes(from.as_bytes());
                w.set(heads, |w, o| {
                    w.bytes(o);
                });
            }
            Self::Deliver { ops, pruned } => {
                w.u32(M_DELIVER);
                w.list(ops, |w, op| op.write(w));
                w.set(pruned, |w, o| {
                    w.bytes(o);
                });
            }
            Self::NodeKeyRequest { from, nodes } => {
                w.u32(M_NKREQ).bytes(from.as_bytes());
                w.set(nodes, |w, o| {
                    w.bytes(o);
                });
            }
            Self::NodeKeyResponse { from, sealed } => {
                w.u32(M_NKRESP).bytes(from.as_bytes());
                env_encode(sealed, &mut w);
            }
            Self::Checkpoint(certificate) => {
                w.u32(M_CHECKPOINT);
                certificate.write(&mut w);
            }
        }
        w.finish()
    }

    /// Parses a message, enforcing every length bound.
    pub fn from_wire(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        if r.u64()? != CFR_WIRE_MARKER {
            return Err(Error::Encoding("not a CFR wire message"));
        }
        if r.u64()? != u64::from(PROTOCOL_ID) {
            return Err(Error::Encoding("unsupported CFR protocol identifier"));
        }
        let tag = r.u32()?;
        let msg = match tag {
            M_OP => Self::Op(Op::from_wire(r.bytes()?)?),
            M_WELCOME => {
                let sid = r.array::<32>()?;
                let from = SigPublic::from_bytes(r.array::<32>()?);
                let sealed = env_decode(&mut r)?;
                let history = r.list(|r| Op::from_wire(r.bytes()?))?;
                if history.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("welcome history too large"));
                }
                let pruned: Vec<Oid> = r.set(super::codec::Reader::array::<32>)?;
                if pruned.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("pruned set too large"));
                }
                Self::Welcome {
                    sid,
                    from,
                    sealed,
                    history,
                    pruned,
                }
            }
            M_SYNC => {
                let from = SigPublic::from_bytes(r.array::<32>()?);
                let heads: Vec<Oid> = r.set(super::codec::Reader::array::<32>)?;
                if heads.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("sync head set too large"));
                }
                Self::Sync { from, heads }
            }
            M_DELIVER => {
                let ops = r.list(|r| Op::from_wire(r.bytes()?))?;
                if ops.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("delivery batch too large"));
                }
                let pruned: Vec<Oid> = r.set(super::codec::Reader::array::<32>)?;
                if pruned.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("pruned set too large"));
                }
                Self::Deliver { ops, pruned }
            }
            M_NKREQ => {
                let from = SigPublic::from_bytes(r.array::<32>()?);
                let nodes: Vec<Oid> = r.set(super::codec::Reader::array::<32>)?;
                if nodes.len() > MAX_BATCH {
                    return Err(Error::LimitExceeded("node key request too large"));
                }
                Self::NodeKeyRequest { from, nodes }
            }
            M_NKRESP => Self::NodeKeyResponse {
                from: SigPublic::from_bytes(r.array::<32>()?),
                sealed: env_decode(&mut r)?,
            },
            M_CHECKPOINT => Self::Checkpoint(CheckpointCertificate::read(&mut r)?),
            _ => return Err(Error::Encoding("unknown message tag")),
        };
        r.finish()?;
        Ok(msg)
    }
}

/// Where an outbound message should go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Every current member.
    Everyone,
    /// One named identity.
    Peer(SigPublic),
}

/// An instruction to the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// Who should receive it.
    pub to: Destination,
    /// The serialised message.
    pub payload: Vec<u8>,
}

impl Outbound {
    /// Addresses a message to everyone.
    pub fn broadcast(m: &Message) -> Self {
        Self {
            to: Destination::Everyone,
            payload: m.to_wire(),
        }
    }

    /// Addresses a message to one peer.
    pub fn direct(to: SigPublic, m: &Message) -> Self {
        Self {
            to: Destination::Peer(to),
            payload: m.to_wire(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{Capabilities, CheckpointSignature, ProtocolProfile, ResumptionRecord};
    use crate::op::Body;
    use alloc::collections::BTreeSet;
    use cfr_crypto::SigSecret;

    fn sample_checkpoint() -> CheckpointCertificate {
        let signer = SigSecret::from_seed(&[6u8; 32]);
        let record = ResumptionRecord::new(
            [1u8; 32],
            [2u8; 16],
            [[3u8; 32]].into_iter().collect(),
            [4u8; 32],
            1,
            [5u8; 32],
            ProtocolProfile::DecentralizedMerkle,
            Capabilities::CORE_SECURITY,
        )
        .expect("valid checkpoint record");
        let mut certificate = CheckpointCertificate::new(record.clone());
        certificate
            .add_signature(CheckpointSignature {
                signer: signer.public(),
                signature: signer.sign(&record.signing_bytes()),
            })
            .expect("valid checkpoint approval");
        certificate
    }

    fn sample_op() -> Op {
        let sk = SigSecret::from_seed(&[1u8; 32]);
        Op::create(
            &sk,
            &[0xEFu8; 32],
            BTreeSet::new(),
            Body::Add { who: sk.public() },
        )
    }

    #[test]
    fn every_variant_roundtrips() {
        let op = sample_op();
        let env = Envelope {
            eph: DhPublic::from_bytes([1u8; 32]),
            gen: 3,
            ct: alloc::vec![9u8; 40],
        };
        let msgs = alloc::vec![
            Message::Op(op.clone()),
            Message::Welcome {
                sid: [2u8; 32],
                from: op.author,
                sealed: env.clone(),
                history: alloc::vec![op.clone()],
                pruned: alloc::vec![[7u8; 32]],
            },
            Message::Sync {
                from: op.author,
                heads: alloc::vec![[3u8; 32], [4u8; 32]],
            },
            Message::Deliver {
                ops: alloc::vec![op.clone()],
                pruned: alloc::vec![],
            },
            Message::NodeKeyRequest {
                from: op.author,
                nodes: alloc::vec![[5u8; 32]],
            },
            Message::NodeKeyResponse {
                from: op.author,
                sealed: env,
            },
            Message::Checkpoint(sample_checkpoint()),
        ];
        for m in msgs {
            let wire = m.to_wire();
            let back = Message::from_wire(&wire).unwrap();
            assert_eq!(back, m);
            assert_eq!(back.to_wire(), wire, "encoding must be canonical");
        }
    }

    #[test]
    fn unframed_or_unsupported_protocol_is_rejected() {
        let mut unframed = Writer::new();
        unframed.u32(M_OP);
        assert!(Message::from_wire(&unframed.finish()).is_err());

        let mut foreign = Writer::new();
        foreign.u64(CFR_WIRE_MARKER).u64(u64::from(PROTOCOL_ID) + 1);
        assert!(Message::from_wire(&foreign.finish()).is_err());
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let mut w = Writer::new();
        w.u64(CFR_WIRE_MARKER).u64(u64::from(PROTOCOL_ID)).u32(99);
        assert!(Message::from_wire(&w.finish()).is_err());
    }

    #[test]
    fn truncation_is_rejected_at_every_length() {
        let wire = Message::Op(sample_op()).to_wire();
        for cut in 0..wire.len() {
            assert!(Message::from_wire(&wire[..cut]).is_err(), "cut {cut}");
        }
        assert!(Message::from_wire(&wire).is_ok());
    }

    #[test]
    fn key_package_signature_is_checked() {
        let sk = SigSecret::from_seed(&[7u8; 32]);
        let prekey = DhPublic::from_bytes([8u8; 32]);
        let img = KeyPackage::image(&sk.public(), 0, &prekey);
        let kp = KeyPackage {
            ipk: sk.public(),
            gen: 0,
            prekey,
            sig: sk.sign(&img),
        };
        kp.verify().unwrap();
        assert_eq!(KeyPackage::from_wire(&kp.to_wire()).unwrap(), kp);

        // Substituting the prekey invalidates the package: an inviter cannot
        // swap in a key it controls.
        let mut forged = kp;
        forged.prekey = DhPublic::from_bytes([9u8; 32]);
        assert!(forged.verify().is_err());
    }
}
