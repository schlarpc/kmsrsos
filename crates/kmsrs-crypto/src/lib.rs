//! Cryptographic primitives for the KMS activation protocol (`ARCH-001`, #1).
//!
//! # This crate is not a general-purpose cryptography library
//!
//! It exists because the KMS protocol uses two constructions that no maintained
//! Rust crate provides (`CRY-017`, #56):
//!
//! * **Rijndael with a 160-bit key**, which AES standardised away. The v4
//!   message authentication code is a CBC-MAC over that cipher.
//! * **AES-128 with a tampered key schedule**, in which three bytes of the
//!   expanded key are XORed after a standard expansion. The v6 protocol uses it.
//!
//! Those two are the entirety of axiom A8's exception list (`CRY-002`, #41).
//! Everything else — SHA-256, HMAC — comes from RustCrypto (`CRY-018`, #57).
//!
//! # Do not reuse this crate
//!
//! The keys these primitives use are published by Microsoft and are compiled
//! into every KMS host, every KMS client and both open-source emulators
//! (`CRY-001`, #40). Nothing here protects a secret, and consequently:
//!
//! * **Nothing is written to run in constant time.** Table lookups are
//!   data-dependent and the code makes no attempt to hide timing. That is a
//!   deliberate, stated trade-off rather than an oversight (`CRY-017`, #56) —
//!   with a published key there is no secret for a timing side channel to
//!   recover.
//! * **There is no key management, no zeroisation and no nonce discipline.**
//!
//! If a use for these primitives arises where a key *is* secret, none of this
//! code is suitable and none of it should be adapted.

#![no_std]

#[cfg(test)]
extern crate alloc;

pub mod keys;
pub mod rijndael;
