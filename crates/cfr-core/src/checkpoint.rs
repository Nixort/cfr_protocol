// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Signed state-bound session transition certificates.
use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::op::{Oid, SessionId};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use cfr_crypto::{hash, SigPublic, Signature};

/// The CFR protocol generation implemented by this checkpoint format.
pub const PROTOCOL_ID: u16 = 1;

/// The maximum number of frontier identifiers in a checkpoint record.
pub const MAX_CHECKPOINT_FRONTIER: usize = 256;

/// The maximum number of signatures retained in one checkpoint certificate.
pub const MAX_CHECKPOINT_SIGNERS: usize = 256;

/// Derives the full current media context identifier from a group-key version label.
pub fn media_context_id(version: [u8; 8]) -> [u8; 16] {
    let digest = hash(b"cfr/media/context", &[&version]);
    digest[..16]
        .try_into()
        .expect("hash has at least sixteen bytes")
}

/// The deployment profile used to distribute signed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolProfile {
    /// A delivery service sequences and relays client-signed records.
    CentralizedSequenced,
    /// Peers reconcile Merkle heads over an untrusted transport.
    DecentralizedMerkle,
}

impl ProtocolProfile {
    fn code(self) -> u64 {
        match self {
            Self::CentralizedSequenced => 1,
            Self::DecentralizedMerkle => 2,
        }
    }

    fn decode(code: u64) -> Result<Self> {
        match code {
            1 => Ok(Self::CentralizedSequenced),
            2 => Ok(Self::DecentralizedMerkle),
            _ => Err(Error::Encoding("unknown protocol profile")),
        }
    }
}

/// Capabilities required to enter a CFR session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u64);

impl Capabilities {
    /// Requires the current media context identifier, channel index, and checkpoint format.
    pub const CORE_SECURITY: Self = Self(0b111);

    /// Returns the raw capability bits for a signed manifest.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns true when all bits in `required` are available.
    pub const fn supports(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Parses a raw capability set.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

/// A cryptographic link from an old CFR session to a fresh session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumptionRecord {
    /// The protocol generation selected by the active roster.
    pub protocol_id: u16,
    /// The old session identifier.
    pub previous_session: SessionId,
    /// The full context identifier for the old media key.
    pub previous_context: [u8; 16],
    /// The committed causal frontier of the old session.
    pub previous_frontier: BTreeSet<Oid>,
    /// The membership root bound to that frontier.
    pub membership_root: [u8; 32],
    /// A monotonically increasing checkpoint number for the old session.
    pub checkpoint_epoch: u64,
    /// The new random session identifier.
    pub next_session: SessionId,
    /// The selected delivery and reconciliation profile.
    pub profile: ProtocolProfile,
    /// The capabilities every new-session participant must support.
    pub required_capabilities: Capabilities,
}

impl ResumptionRecord {
    /// Creates a resumption record after validating its resource and session bounds.
    ///
    /// The eight parameters map one-to-one to the signed canonical record fields;
    /// grouping them would obscure their wire order and review surface.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        previous_session: SessionId,
        previous_context: [u8; 16],
        previous_frontier: BTreeSet<Oid>,
        membership_root: [u8; 32],
        checkpoint_epoch: u64,
        next_session: SessionId,
        profile: ProtocolProfile,
        required_capabilities: Capabilities,
    ) -> Result<Self> {
        let record = Self {
            protocol_id: PROTOCOL_ID,
            previous_session,
            previous_context,
            previous_frontier,
            membership_root,
            checkpoint_epoch,
            next_session,
            profile,
            required_capabilities,
        };
        record.validate()?;
        Ok(record)
    }

    /// Returns the canonical bytes that members sign.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write(&mut writer);
        writer.finish()
    }

    /// Returns a fixed identifier for this resumption record.
    pub fn id(&self) -> [u8; 32] {
        hash(b"cfr/resumption", &[&self.signing_bytes()])
    }

    fn validate(&self) -> Result<()> {
        if self.protocol_id != PROTOCOL_ID {
            return Err(Error::Encoding("unsupported protocol generation"));
        }
        if self.previous_session == self.next_session {
            return Err(Error::Encoding("checkpoint must create a fresh session"));
        }
        if self.previous_frontier.is_empty() {
            return Err(Error::Encoding("checkpoint frontier is empty"));
        }
        if self.previous_frontier.len() > MAX_CHECKPOINT_FRONTIER {
            return Err(Error::LimitExceeded("checkpoint frontier too large"));
        }
        if self.checkpoint_epoch == 0 {
            return Err(Error::Encoding("checkpoint epoch is zero"));
        }
        if !self
            .required_capabilities
            .supports(Capabilities::CORE_SECURITY)
        {
            return Err(Error::Unauthorised(
                "checkpoint lacks required required capabilities",
            ));
        }
        Ok(())
    }

    pub(crate) fn write(&self, writer: &mut Writer) {
        writer
            .u64(u64::from(self.protocol_id))
            .bytes(&self.previous_session)
            .bytes(&self.previous_context);
        let frontier: Vec<Oid> = self.previous_frontier.iter().copied().collect();
        writer.set(&frontier, |writer, oid| {
            writer.bytes(oid);
        });
        writer
            .bytes(&self.membership_root)
            .u64(self.checkpoint_epoch)
            .bytes(&self.next_session)
            .u64(self.profile.code())
            .u64(self.required_capabilities.bits());
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let protocol_id = u16::try_from(reader.u64()?)
            .map_err(|_| Error::Encoding("protocol generation exceeds u16"))?;
        let previous_session = reader.array::<32>()?;
        let previous_context = reader.array::<16>()?;
        let frontier: Vec<Oid> = reader.set(Reader::array::<32>)?;
        let membership_root = reader.array::<32>()?;
        let checkpoint_epoch = reader.u64()?;
        let next_session = reader.array::<32>()?;
        let profile = ProtocolProfile::decode(reader.u64()?)?;
        let required_capabilities = Capabilities::from_bits(reader.u64()?);
        let record = Self {
            protocol_id,
            previous_session,
            previous_context,
            previous_frontier: frontier.into_iter().collect(),
            membership_root,
            checkpoint_epoch,
            next_session,
            profile,
            required_capabilities,
        };
        record.validate()?;
        Ok(record)
    }
}

/// A roster member's signature over a [`ResumptionRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointSignature {
    /// The identity that approved the resumption record.
    pub signer: SigPublic,
    /// A strict Ed25519 signature over the canonical record bytes.
    pub signature: Signature,
}

/// An all-active-member certificate authorizing a fresh CFR session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointCertificate {
    record: ResumptionRecord,
    signatures: BTreeMap<SigPublic, Signature>,
}

impl CheckpointCertificate {
    /// Starts an unsigned certificate for `record`.
    pub fn new(record: ResumptionRecord) -> Self {
        Self {
            record,
            signatures: BTreeMap::new(),
        }
    }

    /// Returns the resumption record.
    pub fn record(&self) -> &ResumptionRecord {
        &self.record
    }

    /// Returns the certificate identifier.
    pub fn id(&self) -> [u8; 32] {
        self.record.id()
    }

    /// Adds one active member's signature.
    ///
    /// A duplicate signer is rejected even if the signature bytes match.
    pub fn add_signature(&mut self, approval: CheckpointSignature) -> Result<()> {
        if self.signatures.len() >= MAX_CHECKPOINT_SIGNERS {
            return Err(Error::LimitExceeded("checkpoint signer set too large"));
        }
        approval
            .signer
            .verify(&self.record.signing_bytes(), &approval.signature)
            .map_err(Error::Crypto)?;
        if self
            .signatures
            .insert(approval.signer, approval.signature)
            .is_some()
        {
            return Err(Error::Encoding("duplicate checkpoint signer"));
        }
        Ok(())
    }

    /// Verifies that exactly the active roster approved this record.
    pub fn verify(&self, active_roster: &BTreeSet<SigPublic>) -> Result<()> {
        self.record.validate()?;
        if active_roster.is_empty() || self.signatures.len() != active_roster.len() {
            return Err(Error::Unauthorised(
                "checkpoint lacks unanimous active roster",
            ));
        }
        let signed: BTreeSet<SigPublic> = self.signatures.keys().copied().collect();
        if &signed != active_roster {
            return Err(Error::Unauthorised(
                "checkpoint signer set differs from active roster",
            ));
        }
        let bytes = self.record.signing_bytes();
        for (signer, signature) in &self.signatures {
            signer.verify(&bytes, signature).map_err(Error::Crypto)?;
        }
        Ok(())
    }

    pub(crate) fn write(&self, writer: &mut Writer) {
        self.record.write(writer);
        let approvals: Vec<CheckpointSignature> = self
            .signatures
            .iter()
            .map(|(signer, signature)| CheckpointSignature {
                signer: *signer,
                signature: *signature,
            })
            .collect();
        writer.list(&approvals, |writer, approval| {
            writer
                .bytes(approval.signer.as_bytes())
                .bytes(approval.signature.as_bytes());
        });
    }

    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let record = ResumptionRecord::read(reader)?;
        let approvals: Vec<CheckpointSignature> = reader.list(|reader| {
            Ok(CheckpointSignature {
                signer: SigPublic::from_bytes(reader.array::<32>()?),
                signature: Signature::from_bytes(reader.array::<64>()?),
            })
        })?;
        if approvals.len() > MAX_CHECKPOINT_SIGNERS {
            return Err(Error::LimitExceeded("checkpoint signer set too large"));
        }
        let mut certificate = Self::new(record);
        for approval in approvals {
            certificate.add_signature(approval)?;
        }
        Ok(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cfr_crypto::SigSecret;

    fn certificate() -> (CheckpointCertificate, BTreeSet<SigPublic>, Vec<SigSecret>) {
        let secrets = vec![
            SigSecret::from_seed(&[1; 32]),
            SigSecret::from_seed(&[2; 32]),
            SigSecret::from_seed(&[3; 32]),
        ];
        let roster: BTreeSet<SigPublic> = secrets.iter().map(SigSecret::public).collect();
        let record = ResumptionRecord::new(
            [1; 32],
            [2; 16],
            BTreeSet::from([[3; 32], [4; 32]]),
            [5; 32],
            1,
            [6; 32],
            ProtocolProfile::DecentralizedMerkle,
            Capabilities::CORE_SECURITY,
        )
        .expect("valid record");
        (CheckpointCertificate::new(record), roster, secrets)
    }

    #[test]
    fn unanimous_certificate_verifies() {
        let (mut certificate, roster, secrets) = certificate();
        let bytes = certificate.record().signing_bytes();
        for secret in secrets {
            certificate
                .add_signature(CheckpointSignature {
                    signer: secret.public(),
                    signature: secret.sign(&bytes),
                })
                .expect("valid approval");
        }
        assert!(certificate.verify(&roster).is_ok());
    }

    #[test]
    fn missing_or_unrelated_signer_is_rejected() {
        let (mut certificate, roster, secrets) = certificate();
        let bytes = certificate.record().signing_bytes();
        certificate
            .add_signature(CheckpointSignature {
                signer: secrets[0].public(),
                signature: secrets[0].sign(&bytes),
            })
            .expect("valid approval");
        assert!(certificate.verify(&roster).is_err());

        let outsider = SigSecret::from_seed(&[9; 32]);
        certificate
            .add_signature(CheckpointSignature {
                signer: outsider.public(),
                signature: outsider.sign(&bytes),
            })
            .expect("signature itself is valid");
        assert!(certificate.verify(&roster).is_err());
    }

    #[test]
    fn mutated_record_invalidates_approval() {
        let (mut certificate, roster, secrets) = certificate();
        let bytes = certificate.record().signing_bytes();
        for secret in secrets {
            certificate
                .add_signature(CheckpointSignature {
                    signer: secret.public(),
                    signature: secret.sign(&bytes),
                })
                .expect("valid approval");
        }
        certificate.record.checkpoint_epoch = 2;
        assert!(certificate.verify(&roster).is_err());
    }
}
