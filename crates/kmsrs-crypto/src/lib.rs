//! Cryptographic primitives for the KMS activation protocol (`ARCH-001`, #1).
//!
//! # This crate is not a general-purpose cryptography library
//!
//! It exists because the KMS protocol uses two constructions that no maintained
//! Rust crate provides (`CRY-017`, #56):
//!
//! * **Rijndael with a 160-bit block**, which AES standardised away. The v4
//!   message authentication code is a CBC-MAC over this cipher.
//! * **AES-128 with a tweaked key schedule**, in which one round-constant byte
//!   differs from the standard. The v6 protocol uses it.
//!
//! Those two are the entirety of axiom A8's exception list (`CRY-002`, #41).
//! Everything else here — SHA-256, HMAC — is a thin re-export of RustCrypto.
//!
//! The keys these primitives use are published by Microsoft and are identical in
//! every KMS host and every emulator (`CRY-001`, #40). Nothing in this crate
//! protects a secret, and none of it is written to resist side-channel analysis.
//! Do not reuse it.

#![no_std]
