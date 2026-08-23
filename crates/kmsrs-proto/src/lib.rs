//! Sans-io KMS wire protocol: v4/v5/v6 payloads plus the DCE/RPC codec and
//! connection state machine (`ARCH-001`, #1; `ARCH-002`, #2).
//!
//! Nothing in this crate touches a socket, reads a clock or draws entropy.
//! Time and randomness are *inputs*: a reading of type [`time::Instant`] and a
//! borrowed [`entropy::Entropy`] are handed to [`sansio::SansIo::handle_input`]
//! by the platform driver. That is what makes the same code fuzzable,
//! differentially testable against vlmcsd and py-kms, and usable unchanged on a
//! bare-metal target (axiom A7).
//!
//! The crate is `no_std`, so the absence of I/O is enforced by the compiler
//! rather than by review.

#![no_std]
// Wire handling uses `TryFrom` and `checked_*`, never `as`. A silent truncation
// in a length field is precisely the defect class this crate exists to avoid,
// and `as` is the operator that produces it (`ARCH-007`, #7; `SEC-003`, #195).
#![deny(clippy::as_conversions)]

pub mod entropy;
pub mod sansio;
pub mod time;
