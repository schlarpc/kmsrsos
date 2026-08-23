//! Decoding a response, as a client does (`CLI-001`, #207; `CLI-003`, #209).
//!
//! The server's half of this lives in [`crate::kms::framing`]. This is the
//! mirror image, and it lives in the protocol crate for the same reason
//! [`crate::kms::framing::encode_request`] does: a diagnostic client that
//! framed and parsed with its own copy of the logic would be testing itself.
//!
//! # Decoding and checking are separate
//!
//! [`decode`] returns everything a response *claims*, with every field it
//! carries, and reports only the failures that make further reading
//! impossible — a truncated buffer, a padding length that would run off the
//! end. It does **not** decide whether the response is correct.
//!
//! That split matters. py-kms's client verifies the v4 CMAC and logs only on
//! *success*, so a wrong MAC produces silence; for v5 and v6 it verifies
//! nothing at all. A decoder that refuses a bad response gives a caller one bit
//! where it wanted twelve. Deciding is [`crate::kms::validate`]'s job, and it
//! reports every property separately.

use crate::kms::layout::{
    IV_LEN, MAC_LEN, RESPONSE_HEAD_LEN, RESPONSE_TAIL_LEN, ResponseHead, ResponseTail,
    SALT_PROOF_LEN, SaltProof, UNENCRYPTED_PREFIX_LEN, V6_TRAILER_LEN, V6Trailer,
};
use crate::kms::version::{ProtocolVersion, Version};
use crate::types::HardwareId;

/// Bytes of HMAC a v6 response carries — the last 16 of the SHA-256 tag.
const HMAC_TAG_LEN: usize = 16;
use kmsrs_crypto::cbc::{self, Iv};
use kmsrs_crypto::rijndael::KeySchedule;
use zerocopy::FromBytes;

/// Why a response could not be read at all.
///
/// Deliberately short. Anything a caller could want to *report* rather than
/// give up on is a validation result, not an error here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// The buffer is shorter than the fixed fields require.
    TooShort {
        /// Bytes needed to read this far.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The declared ePID length runs past the end of the response.
    PidSizeOutOfRange {
        /// What the response declared, in bytes.
        declared: u32,
    },
    /// The ciphertext is not a whole number of blocks.
    NotBlockAligned {
        /// The length that is not a multiple of the block size.
        len: usize,
    },
    /// The padding byte is zero, above the block size, or disagrees with the
    /// bytes it claims to cover.
    BadPadding,
}

impl core::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { needed, available } => {
                write!(f, "a response needs {needed} bytes, got {available}")
            }
            Self::PidSizeOutOfRange { declared } => {
                write!(f, "the declared ePID length {declared} runs past the end")
            }
            Self::NotBlockAligned { len } => {
                write!(f, "{len} ciphertext bytes is not a whole number of blocks")
            }
            Self::BadPadding => f.write_str("the padding is malformed"),
        }
    }
}

impl core::error::Error for ResponseError {}

/// Everything a response carries.
///
/// Every field is what the response *said*, not what it should have said.
///
/// Borrows rather than allocates, because this crate is `no_std` without
/// `alloc` in shipped code — the same reason [`kmsrs_crypto::cbc::decrypt`]
/// writes into a caller's buffer (`ARCH-013`). The variable-length fields point
/// either into the response itself, for v4, or into the scratch buffer the
/// caller supplied, for v5 and v6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedResponse<'a> {
    /// The version in the unencrypted prefix, for v5 and v6. `None` for v4,
    /// which has no such prefix.
    pub outer_version: Option<ProtocolVersion>,
    /// The version inside the response body.
    pub inner_version: ProtocolVersion,
    /// The IV block as it appeared **on the wire**, for v5 and v6.
    ///
    /// This is what a client compares, and the two versions differ: v5's is
    /// byte-identical to the request IV, v6's must not be. Taken from the
    /// ciphertext rather than the plaintext, because the server encrypts with a
    /// null IV — so wire block zero is `E_k(plaintext block zero)`, and for v5
    /// the server puts `D_k(IV_request)` there precisely so that the wire block
    /// comes back out as `IV_request` itself.
    pub response_iv: Option<[u8; IV_LEN]>,
    /// The first *plaintext* block, which is what the wire IV encrypts.
    ///
    /// For v5 this is `D_k(IV_request)`, the shared secret. For v6 it is the
    /// fresh IV the host drew. Kept separately because conflating it with the
    /// wire block is exactly the mistake that makes a v5/v6 IV check wrong.
    pub plaintext_iv_block: Option<[u8; IV_LEN]>,
    /// The ePID's declared length in bytes, including the terminator.
    pub pid_size: u32,
    /// The ePID's bytes, exactly as sent — including any terminator and
    /// anything after it (`CLI-004`, #210).
    ///
    /// Left as bytes rather than decoded to UTF-16 because the buffer they come
    /// from has no alignment guarantee, and because an odd length is itself
    /// something the validator should be able to report.
    pub pid_bytes: &'a [u8],
    /// The echoed client machine ID.
    pub client_machine_id: [u8; 16],
    /// The echoed client timestamp.
    pub client_time: u64,
    /// The count the host reported.
    pub count: u32,
    /// Minutes before a failed client retries.
    pub activation_interval: u32,
    /// Minutes before a successful client renews.
    pub renewal_interval: u32,
    /// The salt proof, for v5 and v6.
    pub salt_proof: Option<SaltProofBytes>,
    /// The hardware ID, for v6.
    pub hardware_id: Option<HardwareId>,
    /// The host's copy of `D_k(IV_request)`, for v6.
    pub decrypted_request_iv: Option<[u8; IV_LEN]>,
    /// The HMAC, for v6.
    pub hmac: Option<[u8; 16]>,
    /// The plaintext the HMAC covers, for v6 — from the response IV up to but
    /// not including the HMAC itself.
    pub hmac_message: &'a [u8],
    /// The MAC, for v4.
    pub mac: Option<[u8; MAC_LEN]>,
    /// The bytes the v4 MAC covers.
    pub mac_message: &'a [u8],
    /// The padding byte count the ciphertext ended with, for v5 and v6.
    pub padding_len: Option<usize>,
    /// The padding bytes themselves, so a caller can check they all agree.
    pub padding: &'a [u8],
    /// How many bytes the response actually occupied on the wire.
    pub wire_len: usize,
}

/// The two halves of the salt proof, kept apart so a caller can check them
/// independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaltProofBytes {
    /// The salt, XORed with the shared secret.
    pub random_xored_ivs: [u8; 16],
    /// SHA-256 of the salt before the XOR.
    pub hash: [u8; 32],
}

/// Read a response.
///
/// `scratch` receives the decrypted plaintext for v5 and v6, and the decoded
/// fields borrow from it. It must be at least as long as the response. For v4
/// it is unused, since a v4 response is already plaintext.
///
/// # Errors
///
/// Returns [`ResponseError`] only when the bytes cannot be read at all. A
/// response that is well-formed but wrong decodes successfully and fails
/// validation, which is the distinction the module documentation describes.
pub fn decode<'a>(
    version: Version,
    stub: &'a [u8],
    schedule: Option<&KeySchedule>,
    scratch: &'a mut [u8],
) -> Result<DecodedResponse<'a>, ResponseError> {
    match version {
        Version::V4 => decode_v4(stub),
        Version::V5 | Version::V6 => {
            let schedule = schedule.ok_or(ResponseError::TooShort {
                needed: 0,
                available: 0,
            })?;
            decode_encrypted(version, stub, schedule, scratch)
        }
    }
}

/// How many trailing bytes the padding claims.
///
/// Only the *length* is checked here — that it is 1..=16 and fits. Whether all
/// the padding bytes agree is a validation question, not a decoding one, and
/// belongs to the caller so it can be reported rather than swallowed
/// (`CLI-003`, #209).
fn padding_length(plaintext: &[u8]) -> Option<usize> {
    let last = *plaintext.last()?;
    let len = usize::from(last);
    if len == 0 || len > 16 || len > plaintext.len() {
        return None;
    }
    Some(len)
}

/// Read the head, ePID and tail from a plaintext body.
///
/// Returns the decoded fields plus whatever follows the tail — the salt proof
/// and trailer for the encrypted versions, the MAC for v4 — which the caller
/// slices according to the version.
fn read_body(body: &[u8], wire_len: usize) -> Result<(DecodedResponse<'_>, &[u8]), ResponseError> {
    let too_short = |needed: usize| ResponseError::TooShort {
        needed,
        available: body.len(),
    };

    let (head, rest) =
        ResponseHead::read_from_prefix(body).map_err(|_| too_short(RESPONSE_HEAD_LEN))?;
    let declared = head.pid_size.get();

    let pid_len = usize::try_from(declared)
        .ok()
        .filter(|len| *len <= rest.len())
        .ok_or(ResponseError::PidSizeOutOfRange { declared })?;
    let pid_bytes = rest
        .get(..pid_len)
        .ok_or(ResponseError::PidSizeOutOfRange { declared })?;

    let after_pid = rest.get(pid_len..).unwrap_or(&[]);
    let (tail, remainder) =
        ResponseTail::read_from_prefix(after_pid).map_err(|_| too_short(RESPONSE_TAIL_LEN))?;

    Ok((
        DecodedResponse {
            outer_version: None,
            inner_version: ProtocolVersion::from_wire(head.version.get()),
            response_iv: None,
            plaintext_iv_block: None,
            pid_size: declared,
            pid_bytes,
            client_machine_id: tail.client_machine_id.to_guid().to_bytes(),
            client_time: tail.client_time.get(),
            count: tail.count.get(),
            activation_interval: tail.activation_interval.get(),
            renewal_interval: tail.renewal_interval.get(),
            salt_proof: None,
            hardware_id: None,
            decrypted_request_iv: None,
            hmac: None,
            hmac_message: &[],
            mac: None,
            mac_message: &[],
            padding_len: None,
            padding: &[],
            wire_len,
        },
        remainder,
    ))
}

/// Read a v4 response: plaintext body followed by a 16-byte MAC.
fn decode_v4(stub: &[u8]) -> Result<DecodedResponse<'_>, ResponseError> {
    let (mut decoded, trailing) = read_body(stub, stub.len())?;
    let mac: [u8; MAC_LEN] = trailing
        .get(..MAC_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ResponseError::TooShort {
            needed: MAC_LEN,
            available: trailing.len(),
        })?;

    // The MAC covers everything before it (`KMS-005`, #21).
    let covered = stub.len().saturating_sub(MAC_LEN);
    decoded.mac = Some(mac);
    decoded.mac_message = stub.get(..covered).unwrap_or(&[]);
    Ok(decoded)
}

/// Read a v5 or v6 response: version word, IV, then one CBC-encrypted region.
fn decode_encrypted<'a>(
    version: Version,
    stub: &'a [u8],
    schedule: &KeySchedule,
    scratch: &'a mut [u8],
) -> Result<DecodedResponse<'a>, ResponseError> {
    let stub_len = stub.len();
    let too_short = |needed: usize| ResponseError::TooShort {
        needed,
        available: stub_len,
    };

    let outer = stub
        .get(..UNENCRYPTED_PREFIX_LEN)
        .and_then(|bytes| <[u8; UNENCRYPTED_PREFIX_LEN]>::try_from(bytes).ok())
        .ok_or(too_short(UNENCRYPTED_PREFIX_LEN))?;
    let outer_version = ProtocolVersion::from_wire(u32::from_le_bytes(outer));

    let ciphertext = stub
        .get(UNENCRYPTED_PREFIX_LEN..)
        .ok_or(too_short(UNENCRYPTED_PREFIX_LEN))?;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(ResponseError::NotBlockAligned {
            len: ciphertext.len(),
        });
    }

    // The server encrypts with a null IV, treating the response IV as
    // ciphertext block zero, so decrypting the same way recovers it
    // (`KMS-006`, #22).
    let plaintext = scratch
        .get_mut(..ciphertext.len())
        .ok_or(ResponseError::TooShort {
            needed: ciphertext.len(),
            available: 0,
        })?;
    cbc::decrypt(schedule, Iv::Null, ciphertext, plaintext).map_err(|_| {
        ResponseError::NotBlockAligned {
            len: ciphertext.len(),
        }
    })?;

    // Reborrow as shared for the rest of the function, which is what lets the
    // decoded fields point into the caller's buffer.
    let plaintext: &'a [u8] = plaintext;

    let padding_len = padding_length(plaintext).ok_or(ResponseError::BadPadding)?;
    let content_end = plaintext
        .len()
        .checked_sub(padding_len)
        .ok_or(ResponseError::BadPadding)?;

    // What a client compares is the block on the wire.
    let wire_iv: [u8; IV_LEN] = ciphertext
        .get(..IV_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(too_short(IV_LEN))?;
    let plaintext_iv_block: [u8; IV_LEN] = plaintext
        .get(..IV_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(too_short(IV_LEN))?;

    let body = plaintext
        .get(IV_LEN..content_end)
        .ok_or(too_short(IV_LEN))?;
    let (mut decoded, trailing) = read_body(body, stub_len)?;
    decoded.outer_version = Some(outer_version);
    decoded.response_iv = Some(wire_iv);
    decoded.plaintext_iv_block = Some(plaintext_iv_block);
    decoded.padding_len = Some(padding_len);
    decoded.padding = plaintext.get(content_end..).unwrap_or(&[]);

    let proof = SaltProof::read_from_prefix(trailing)
        .map(|(proof, _)| proof)
        .map_err(|_| ResponseError::TooShort {
            needed: SALT_PROOF_LEN,
            available: trailing.len(),
        })?;
    decoded.salt_proof = Some(SaltProofBytes {
        random_xored_ivs: proof.random_xored_ivs,
        hash: proof.hash,
    });

    if version.uses_tweaked_cipher() {
        let after_proof = trailing.get(SALT_PROOF_LEN..).unwrap_or(&[]);
        let trailer = V6Trailer::read_from_prefix(after_proof)
            .map(|(trailer, _)| trailer)
            .map_err(|_| ResponseError::TooShort {
                needed: V6_TRAILER_LEN,
                available: after_proof.len(),
            })?;
        decoded.hardware_id = Some(HardwareId(trailer.hardware_id));
        decoded.decrypted_request_iv = Some(trailer.xored_ivs);
        decoded.hmac = Some(trailer.hmac);

        // The HMAC covers the plaintext from the response IV up to but not
        // including the HMAC itself, and is computed before encryption
        // (`CRY-010`, #49).
        let hmac_end = content_end
            .checked_sub(HMAC_TAG_LEN)
            .ok_or(ResponseError::BadPadding)?;
        decoded.hmac_message = plaintext.get(..hmac_end).unwrap_or(&[]);
    }

    Ok(decoded)
}
