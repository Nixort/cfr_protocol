// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Causal group key-management state machine for CFR.
//!
//! The application transports signed operations; this crate derives membership,
//! causal state, and group-key material from them.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions
)]

extern crate alloc;

pub mod channel;
pub mod checkpoint;
pub mod codec;
pub mod dag;
pub mod error;
pub mod keys;
pub mod member;
pub mod membership;
pub mod op;
pub mod prekey;
pub mod wire;

pub use checkpoint::{
    media_context_id, Capabilities, CheckpointCertificate, CheckpointSignature, ProtocolProfile,
    ResumptionRecord, PROTOCOL_ID,
};
pub use error::{Error, Result};
pub use keys::{frontier, version_of, OVERLAP};
pub use member::{Beacon, Event, Participant, PendingJoin, BEACON_LEN, REINIT_RECOMMENDED_AT};
pub use membership::Policy;
pub use op::{Body, Kind, Oid, Op, SessionId};
pub use wire::{Destination, KeyPackage, Message, Outbound, CFR_WIRE_MARKER};
