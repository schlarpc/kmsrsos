//! Sans-io KMS wire protocol: v4/v5/v6 payloads plus the DCE/RPC codec and
//! connection state machine (`ARCH-001`, #1; `ARCH-002`, #2).
//!
//! Nothing in this crate touches a socket, reads a clock or draws entropy.
//! Time and randomness are *inputs*, supplied by the caller through the traits
//! in [`kmsrs_proto`]'s sibling crates. That is what makes the same code
//! fuzzable, differentially testable against vlmcsd and py-kms, and usable
//! unchanged on a bare-metal target (axiom A7).
//!
//! [`kmsrs_proto`]: crate

#![no_std]
// Wire handling uses `TryFrom` and `checked_*`, never `as`. A silent truncation
// in a length field is precisely the defect class this crate exists to avoid,
// and `as` is the operator that produces it (`ARCH-007`, #7; `SEC-003`, #195).
#![deny(clippy::as_conversions)]
