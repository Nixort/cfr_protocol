// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Application-facing CFR conference API.
//!
//! Applications transport authenticated payloads and use [`Conference`] for
//! membership, key management, and media protection.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

extern crate alloc;

mod conference;

pub use conference::{Conference, Error, Joining, Message, Recipient, Result};

pub use cfr_core::{
    Beacon, Capabilities, CheckpointCertificate, CheckpointSignature, Event, KeyPackage, Oid,
    Policy, ProtocolProfile, ResumptionRecord, SessionId, CFR_WIRE_MARKER, PROTOCOL_ID,
};
pub use cfr_crypto::{SigPublic, SigSecret};
pub use cfr_media::{Codec, ContextId, Trailer};

/// Re-exported layers, for applications that need one without the other.
pub mod layers {
    pub use cfr_core as core;
    pub use cfr_crypto as crypto;
    pub use cfr_media as media;
}
