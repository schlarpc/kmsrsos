//! The three Microsoft key constants (`CRY-001`, #40).
//!
//! These are not secrets and never were. They are compiled into every genuine
//! KMS host, every KMS client, and both open-source emulators; recovering them
//! requires a disassembler and an afternoon. The protocol uses them for framing
//! and for proof-of-decryption, not for confidentiality — a KMS activation
//! exchange protects nothing, because there is nothing in it worth protecting.
//!
//! Treating them as published constants rather than as key material is what
//! lets this crate skip constant-time discipline entirely (`CRY-017`, #56).

/// The 160-bit Rijndael key used by the v4 message authentication code.
///
/// Twenty bytes, which is a key size AES standardised away — hence
/// [`crate::rijndael::KeySchedule::rijndael160`] and the whole A8 exception.
pub const V4: [u8; 20] = [
    0x05, 0x3D, 0x83, 0x07, 0xF9, 0xE5, 0xF0, 0x88, 0xEB, 0x5E, 0xA6, 0x68, 0x6C, 0xF0, 0x37, 0xC7,
    0xE4, 0xEF, 0xD2, 0xD6,
];

/// The AES-128 key used by the v5 protocol, with a standard key schedule.
pub const V5: [u8; 16] = [
    0xCD, 0x7E, 0x79, 0x6F, 0x2A, 0xB2, 0x5D, 0xCB, 0x55, 0xFF, 0xC8, 0xEF, 0x83, 0x64, 0xC4, 0x70,
];

/// The AES-128 key used by the v6 protocol.
///
/// The key itself is ordinary; what is not is the schedule expanded from it.
/// See [`crate::rijndael::KeySchedule::aes128_tweaked_for_v6`].
pub const V6: [u8; 16] = [
    0xA9, 0x4A, 0x41, 0x95, 0xE2, 0x01, 0x43, 0x2D, 0x9B, 0xCB, 0x46, 0x04, 0x05, 0xD8, 0x4A, 0x21,
];
