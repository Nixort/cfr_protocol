// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Codec-aware authenticated frame protection for CFR.
//!
//! It protects codec payload bytes while preserving authenticated forwarding
//! metadata required by media routing.

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

pub mod codec;
pub mod error;
pub mod frame;
pub mod ratchet;
pub mod replay;

#[cfg(feature = "persistence")]
mod state;

pub use codec::{layout, Codec, Layout};
pub use error::{Error, Result};
pub use frame::{sender_tag, ContextId, Protector, SenderTag, Trailer, TRAILER_LEN};
pub use ratchet::EPOCH;
pub use replay::WINDOW;
