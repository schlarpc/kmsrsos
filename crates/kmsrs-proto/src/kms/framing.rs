//! v4, v5 and v6 framing: turning a stub into a request and a decision into a
//! stub (`KMS-005`, #21; `KMS-006`, #22; `KMS-007`, #23).
//!
//! # The three versions differ in exactly three ways
//!
//! * **v4** is plaintext with a trailing Rijndael-160 CBC-MAC.
//! * **v5** encrypts, and the response IV must be **byte-identical** to the
//!   request IV. A genuine Microsoft client checks this.
//! * **v6** encrypts with the tampered key schedule, draws a **fresh** response
//!   IV, and adds a hardware ID and an HMAC.
//!
//! Reusing the v5 IV rule in v6 is the loudest emulator tell in the class:
//! `vlmcs` prints *"WARNING: The KMS server is an emulator because the response
//! uses an IV following KMSv5 rules in KMSv6 protocol"* when it sees it. There
//! is a test asserting the two IVs differ.
//!
//! # No artificial delay (`KMS-022`, #38)
//!
//! Nothing here sleeps, and nothing downstream of here may. py-kms's `time.sleep(1)`
//! in its v4 path is both a deterministic timing fingerprint — a host that
//! always takes exactly one second is not a host — and a per-thread throughput
//! cap.

use crate::entropy::{Entropy, EntropyExt as _};
use crate::kms::epid::EPid;
use crate::kms::layout::{
    IV_LEN, MAC_LEN, REQUEST_BODY_LEN, REQUEST_PAD_LEN, RESPONSE_HEAD_LEN, RESPONSE_TAIL_LEN,
    RequestBody, ResponseHead, ResponseTail, UNENCRYPTED_PREFIX_LEN, V4_POST_EPID_LEN,
    V5_POST_EPID_LEN, V6_POST_EPID_LEN, WireGuid,
};
use crate::kms::request::{Request, RequestError, dispatch};
use crate::kms::version::{ProtocolVersion, Version};
use crate::types::{ClientMachineId, ClientTime, HardwareId, Intervals};
use kmsrs_crypto::cbc::{self, CipherError, Iv};
use kmsrs_crypto::mac::CbcMacV4;
use kmsrs_crypto::rijndael::KeySchedule;
use kmsrs_crypto::{keys, v6};
use zerocopy::{FromBytes, IntoBytes};

/// The cipher state a host needs, expanded once (`CRY-016`, #55).
///
/// Held by the connection rather than rebuilt per request, and immutable, so
/// there is no shared cipher state for a concurrent request to corrupt
/// (`CRY-015`, #54).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphers {
    v4: CbcMacV4,
    v5: KeySchedule,
    v6: KeySchedule,
}

impl Default for Ciphers {
    fn default() -> Self {
        Self::new()
    }
}

impl Ciphers {
    /// Expand all three keys.
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4: CbcMacV4::new(),
            v5: KeySchedule::aes128(&keys::V5),
            v6: KeySchedule::aes128_tweaked_for_v6(&keys::V6),
        }
    }

    /// The block cipher a version uses, if it encrypts at all.
    #[must_use]
    pub const fn schedule(&self, version: Version) -> Option<&KeySchedule> {
        match version {
            Version::V4 => None,
            Version::V5 => Some(&self.v5),
            Version::V6 => Some(&self.v6),
        }
    }

    /// The v4 message authentication code.
    #[must_use]
    pub const fn mac(&self) -> &CbcMacV4 {
        &self.v4
    }
}

/// A request, decoded and decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRequest {
    /// Which version this host will answer as.
    pub version: Version,
    /// Exactly what the client declared, for echoing back.
    pub declared: ProtocolVersion,
    /// The parsed body.
    pub request: Request,

    /// `D_k(IV_req)` — the value both sides can compute and nobody else can
    /// (`CRY-005`, #44). `None` for v4, which does not encrypt.
    ///
    /// This is the shared secret the salt proof and the response IV are built
    /// from. Recovering it is what proves to the client that the responder
    /// could decrypt the request.
    pub shared_secret: Option<[u8; IV_LEN]>,

    /// Whether the v4 MAC matched. `None` for v5 and v6, which have no MAC.
    ///
    /// **Recorded, not enforced.** vlmcsd's server does not check it either,
    /// and the key is published, so the MAC authenticates nothing — refusing on
    /// a mismatch would be a difference from a genuine host with no security
    /// benefit. A mismatch is worth a log line, because it means something
    /// upstream is corrupting traffic.
    pub mac_verified: Option<bool>,
}

/// Why a stub could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The version or the length was wrong.
    Request(RequestError),
    /// The ciphertext could not be processed.
    Cipher(CipherError),
    /// The decrypted body was not the size the version requires.
    ///
    /// Only reachable if the padding validated and still left the wrong number
    /// of bytes, which a fixed-size request makes impossible — but "cannot
    /// happen" is not something this codebase asserts at runtime.
    BodyLength {
        /// Bytes recovered.
        actual: usize,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Request(error) => write!(f, "{error}"),
            Self::Cipher(error) => write!(f, "{error}"),
            Self::BodyLength { actual } => {
                write!(f, "decryption produced {actual} bytes of body")
            }
        }
    }
}

impl From<RequestError> for DecodeError {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<CipherError> for DecodeError {
    fn from(error: CipherError) -> Self {
        Self::Cipher(error)
    }
}

/// Decode a KMS request stub.
///
/// The input is never modified (`ARCH-013`, #13): decryption writes to a local
/// buffer, so the caller still has the bytes that arrived for its log line and
/// for a golden-vector comparison.
///
/// # Errors
///
/// Returns [`DecodeError`] if the version is unsupported, the length is not
/// exactly right for that version, or the ciphertext is malformed.
pub fn decode(stub: &[u8], ciphers: &Ciphers) -> Result<DecodedRequest, DecodeError> {
    let (version, declared) = dispatch(stub)?;

    let Some(schedule) = ciphers.schedule(version) else {
        return decode_v4(stub, declared, ciphers);
    };

    // The encrypted region starts at the IV, immediately after the version
    // word, and runs to the end. Decrypting from there with a null IV makes
    // block 1 come out as `D_k(IV_req)` and the rest as the plaintext body.
    let ciphertext = stub
        .get(UNENCRYPTED_PREFIX_LEN..)
        .ok_or(DecodeError::BodyLength { actual: 0 })?;

    let mut plaintext = [0_u8; IV_LEN + REQUEST_BODY_LEN + REQUEST_PAD_LEN];
    cbc::decrypt(schedule, Iv::Null, ciphertext, &mut plaintext)?;

    let (secret, padded_body) = plaintext.split_at(IV_LEN);
    let body_bytes = cbc::strip_padding(padded_body)?;

    let body = RequestBody::read_from_bytes(body_bytes).map_err(|_| DecodeError::BodyLength {
        actual: body_bytes.len(),
    })?;

    let mut shared_secret = [0_u8; IV_LEN];
    if let Some(bytes) = secret.first_chunk::<IV_LEN>() {
        shared_secret = *bytes;
    }

    Ok(DecodedRequest {
        version,
        declared,
        request: Request::from_body(&body),
        shared_secret: Some(shared_secret),
        mac_verified: None,
    })
}

/// Decode a v4 stub: a plaintext body followed by its MAC (`KMS-005`, #21).
fn decode_v4(
    stub: &[u8],
    declared: ProtocolVersion,
    ciphers: &Ciphers,
) -> Result<DecodedRequest, DecodeError> {
    let (body_bytes, mac_bytes) = stub
        .split_at_checked(REQUEST_BODY_LEN)
        .ok_or(DecodeError::BodyLength { actual: stub.len() })?;

    let body = RequestBody::read_from_bytes(body_bytes).map_err(|_| DecodeError::BodyLength {
        actual: body_bytes.len(),
    })?;

    let expected = ciphers.mac().tag(body_bytes);
    let mac_verified = mac_bytes
        .first_chunk::<MAC_LEN>()
        .is_some_and(|received| *received == expected);

    Ok(DecodedRequest {
        version: Version::V4,
        declared,
        request: Request::from_body(&body),
        shared_secret: None,
        mac_verified: Some(mac_verified),
    })
}

/// Everything a response needs that this module does not decide.
///
/// The count, the ePID and the hardware ID are policy and identity outputs.
/// Keeping them as inputs is what makes this module testable against a golden
/// vector: with a fixed plan and a fixed entropy stream, the bytes are a
/// function of the request.
#[derive(Debug, Clone, Copy)]
pub struct ResponsePlan<'a> {
    /// The client's own ePID for this host key (`ID-001`, #106).
    pub epid: &'a EPid,
    /// Echoed from the request verbatim (`KMS-012`, #28).
    pub client_machine_id: ClientMachineId,
    /// Echoed from the request verbatim.
    pub client_time: ClientTime,
    /// The count this host reports (`POL-001`, #89).
    pub count: u32,
    /// What to tell the client about retrying and renewing (`KMS-021`, #37).
    pub intervals: Intervals,
    /// The host's hardware ID. Emitted for v6 only (`ID-018`, #123).
    pub hardware_id: HardwareId,
}

/// Why a response could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer was too small.
    ///
    /// Unreachable when the caller sizes its buffer at
    /// [`crate::kms::layout::MAX_RESPONSE_LEN`], which is the point of that
    /// constant (`KMS-023`, #39).
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The entropy source failed, so the response would have carried
    /// predictable values (`OS-012`, #263).
    EntropyUnavailable,
    /// A v5 or v6 response was requested without the shared secret that only a
    /// decrypted request can supply.
    MissingSharedSecret,
    /// The cipher refused the buffer.
    Cipher(CipherError),
}

impl core::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooSmall { needed, available } => {
                write!(
                    f,
                    "a response needs {needed} bytes, buffer holds {available}"
                )
            }
            Self::EntropyUnavailable => f.write_str("the entropy source failed"),
            Self::MissingSharedSecret => {
                f.write_str("an encrypted response needs the decrypted request IV")
            }
            Self::Cipher(error) => write!(f, "{error}"),
        }
    }
}

impl From<CipherError> for EncodeError {
    fn from(error: CipherError) -> Self {
        Self::Cipher(error)
    }
}

/// Build the response to a decoded request.
///
/// Returns the number of bytes written to the front of `out`.
///
/// # Errors
///
/// Returns [`EncodeError`] if the buffer is too small, the entropy source
/// failed, or the request carried no shared secret for an encrypted version.
pub fn encode(
    decoded: &DecodedRequest,
    plan: &ResponsePlan<'_>,
    ciphers: &Ciphers,
    entropy: &mut dyn Entropy,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    match decoded.version {
        Version::V4 => encode_v4(decoded, plan, ciphers, out),
        Version::V5 | Version::V6 => encode_encrypted(decoded, plan, ciphers, entropy, out),
    }
}

/// The head-and-tail every version shares, written at `offset`.
fn write_body(
    out: &mut [u8],
    offset: usize,
    declared: ProtocolVersion,
    plan: &ResponsePlan<'_>,
) -> Option<usize> {
    let head = ResponseHead {
        version: declared.to_wire().into(),
        pid_size: plan.epid.pid_size().get().into(),
    };
    let tail = ResponseTail {
        client_machine_id: WireGuid::from_guid(plan.client_machine_id.0),
        client_time: plan.client_time.0.as_ticks().into(),
        count: plan.count.into(),
        activation_interval: plan.intervals.activation.into(),
        renewal_interval: plan.intervals.renewal.into(),
    };

    let mut cursor = offset;
    cursor = put(out, cursor, head.as_bytes())?;
    let epid_len = plan.epid.encode(out.get_mut(cursor..)?)?;
    cursor = cursor.checked_add(epid_len)?;
    cursor = put(out, cursor, tail.as_bytes())?;
    Some(cursor)
}

/// Copy `bytes` into `out` at `offset`, returning the new offset.
fn put(out: &mut [u8], offset: usize, bytes: &[u8]) -> Option<usize> {
    let end = offset.checked_add(bytes.len())?;
    out.get_mut(offset..end)?.copy_from_slice(bytes);
    Some(end)
}

/// Build a v4 response: head, ePID, tail, then a MAC over all of it
/// (`KMS-005`, #21).
fn encode_v4(
    decoded: &DecodedRequest,
    plan: &ResponsePlan<'_>,
    ciphers: &Ciphers,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let needed = RESPONSE_HEAD_LEN
        .saturating_add(plan.epid.encoded_len())
        .saturating_add(V4_POST_EPID_LEN)
        .saturating_add(MAC_LEN);
    let available = out.len();
    let too_small = EncodeError::BufferTooSmall { needed, available };

    let body_end = write_body(out, 0, decoded.declared, plan).ok_or(too_small)?;
    let tag = ciphers.mac().tag(out.get(..body_end).ok_or(too_small)?);
    let end = put(out, body_end, &tag).ok_or(too_small)?;
    Ok(end)
}

/// Build a v5 or v6 response (`KMS-006`, #22; `KMS-007`, #23).
fn encode_encrypted(
    decoded: &DecodedRequest,
    plan: &ResponsePlan<'_>,
    ciphers: &Ciphers,
    entropy: &mut dyn Entropy,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let secret = decoded
        .shared_secret
        .ok_or(EncodeError::MissingSharedSecret)?;
    let schedule = ciphers
        .schedule(decoded.version)
        .ok_or(EncodeError::MissingSharedSecret)?;

    let post_epid_len = if decoded.version.uses_tweaked_cipher() {
        V6_POST_EPID_LEN
    } else {
        V5_POST_EPID_LEN
    };
    let plaintext_len = IV_LEN
        .saturating_add(RESPONSE_HEAD_LEN)
        .saturating_add(plan.epid.encoded_len())
        .saturating_add(post_epid_len);
    let needed =
        UNENCRYPTED_PREFIX_LEN.saturating_add(cbc::padded_len(plaintext_len).unwrap_or(usize::MAX));
    let available = out.len();
    let too_small = EncodeError::BufferTooSmall { needed, available };
    if available < needed {
        return Err(too_small);
    }

    // The outer version word, which is not encrypted.
    let mut cursor = put(out, 0, &decoded.declared.to_wire().to_le_bytes()).ok_or(too_small)?;
    let encrypt_start = cursor;

    // The response IV. This is the difference between v5 and v6, and getting it
    // wrong is the loudest emulator tell there is.
    let response_iv: [u8; IV_LEN] = if decoded.version.uses_tweaked_cipher() {
        entropy
            .array::<IV_LEN>()
            .map_err(|_| EncodeError::EntropyUnavailable)?
    } else {
        // v5: after the null-IV encryption below, the first ciphertext block is
        // `E_k(D_k(IV_req))`, which is `IV_req` itself — so the wire response IV
        // is byte-identical to the request's, which is what a genuine client
        // checks.
        secret
    };
    cursor = put(out, cursor, &response_iv).ok_or(too_small)?;

    cursor = write_body(out, cursor, decoded.declared, plan).ok_or(too_small)?;

    // The salt proof, in the order it is computed: draw the salt, hash it, then
    // XOR the shared secret into the salt in place (`CRY-008`, #47).
    let salt = entropy
        .array::<16>()
        .map_err(|_| EncodeError::EntropyUnavailable)?;
    let hash = kmsrs_crypto::hash::sha256(&salt);
    let mut random_xored_ivs = salt;
    for (byte, mask) in random_xored_ivs.iter_mut().zip(secret.iter()) {
        *byte ^= *mask;
    }
    cursor = put(out, cursor, &random_xored_ivs).ok_or(too_small)?;
    cursor = put(out, cursor, &hash).ok_or(too_small)?;

    if decoded.version.uses_tweaked_cipher() {
        cursor = put(out, cursor, &plan.hardware_id.0).ok_or(too_small)?;
        // The client recomputes `D_k(IV_req)` and compares.
        cursor = put(out, cursor, &secret).ok_or(too_small)?;
        // The HMAC goes over everything written so far, from the response IV up
        // to but not including the HMAC itself, and is computed on the
        // *plaintext* — before encryption (`CRY-010`, #49).
        let hmac_start = cursor;
        let message = out.get(encrypt_start..hmac_start).ok_or(too_small)?;
        let tag = v6::tag(
            plan.client_time.0.as_ticks(),
            v6::SlotOffset::Current,
            message,
        );
        cursor = put(out, hmac_start, &tag).ok_or(too_small)?;
    }

    debug_assert_eq!(cursor, encrypt_start.saturating_add(plaintext_len));

    let region = out.get_mut(encrypt_start..).ok_or(too_small)?;
    let ciphertext_len = cbc::encrypt_in_place(schedule, Iv::Null, region, plaintext_len)?;
    Ok(encrypt_start.saturating_add(ciphertext_len))
}

/// Build a request stub, as a client does.
///
/// Here rather than in `kmsrs-client` because a diagnostic client that framed
/// requests with its own copy of this logic would be testing itself
/// (`CLI-001`, #207). It is also what lets the round-trip tests in this module
/// exercise the server's decode path against something other than a fixture.
///
/// The client uses its IV as a *genuine* CBC initialisation vector, which is
/// what makes the server's null-IV trick work: treating the IV as ciphertext
/// block zero, the chaining recovers `D_k(IV)` from the first block and the
/// correct plaintext from every block after it.
///
/// # Errors
///
/// Returns [`EncodeError`] if the buffer is too small or the entropy source
/// failed.
pub fn encode_request(
    version: Version,
    body: &RequestBody,
    ciphers: &Ciphers,
    entropy: &mut dyn Entropy,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let available = out.len();
    let needed = crate::kms::request::framed_request_len(version);
    let too_small = EncodeError::BufferTooSmall { needed, available };
    if available < needed {
        return Err(too_small);
    }

    let Some(schedule) = ciphers.schedule(version) else {
        let end = put(out, 0, body.as_bytes()).ok_or(too_small)?;
        let tag = ciphers.mac().tag(out.get(..end).ok_or(too_small)?);
        return put(out, end, &tag).ok_or(too_small);
    };

    let version_word = version.to_protocol_version().to_wire();
    let mut cursor = put(out, 0, &version_word.to_le_bytes()).ok_or(too_small)?;

    let iv: [u8; IV_LEN] = entropy
        .array::<IV_LEN>()
        .map_err(|_| EncodeError::EntropyUnavailable)?;
    cursor = put(out, cursor, &iv).ok_or(too_small)?;

    let body_start = cursor;
    put(out, cursor, body.as_bytes()).ok_or(too_small)?;
    let region = out.get_mut(body_start..).ok_or(too_small)?;
    let ciphertext_len = cbc::encrypt_in_place(schedule, Iv::Block(&iv), region, REQUEST_BODY_LEN)?;
    Ok(body_start.saturating_add(ciphertext_len))
}

/// The exact wire size of a response, before it is built (`KMS-011`, #27).
///
/// A client computes this the same way and compares: `vlmcs` prints
/// *"Size of RPC payload should be %u but is %u"* when it disagrees, which
/// reads like a framing bug rather than the padding bug it usually is.
#[must_use]
pub fn response_len(version: Version, epid: &EPid) -> usize {
    let epid_len = epid.encoded_len();
    match version {
        Version::V4 => RESPONSE_HEAD_LEN
            .saturating_add(epid_len)
            .saturating_add(V4_POST_EPID_LEN)
            .saturating_add(MAC_LEN),
        Version::V5 | Version::V6 => {
            let post = if version.uses_tweaked_cipher() {
                V6_POST_EPID_LEN
            } else {
                V5_POST_EPID_LEN
            };
            let plaintext = IV_LEN
                .saturating_add(RESPONSE_HEAD_LEN)
                .saturating_add(epid_len)
                .saturating_add(post);
            UNENCRYPTED_PREFIX_LEN.saturating_add(cbc::padded_len(plaintext).unwrap_or(0))
        }
    }
}

/// The bytes of a decoded response body, for a client checking one.
///
/// Exposed so `kmsrs-client` can verify a response without reimplementing the
/// layout (`CLI-001`, #207).
#[must_use]
pub const fn response_tail_len(version: Version) -> usize {
    match version {
        Version::V4 => RESPONSE_TAIL_LEN,
        Version::V5 => V5_POST_EPID_LEN,
        Version::V6 => V6_POST_EPID_LEN,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        Ciphers, DecodeError, DecodedRequest, EncodeError, ResponsePlan, decode, encode,
        encode_request, response_len,
    };
    use crate::entropy::testing::{DeterministicEntropy, FailingEntropy};
    use crate::kms::epid::EPid;
    use crate::kms::layout::{
        IV_LEN, MAC_LEN, MAX_RESPONSE_LEN, REQUEST_BODY_LEN, RESPONSE_HEAD_LEN, RequestBody,
        UNENCRYPTED_PREFIX_LEN,
    };
    use crate::kms::version::Version;
    use crate::time::FileTime;
    use crate::types::{ClientMachineId, ClientTime, HardwareId, Intervals};
    use alloc::vec;
    use kmsrs_crypto::v6;
    use kmsrs_db::Guid;
    use zerocopy::{FromBytes, IntoBytes};

    const EPID_TEXT: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";

    fn sample_body(version: Version) -> RequestBody {
        let mut bytes = [0_u8; REQUEST_BODY_LEN];
        let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
        body.version.set(version.to_protocol_version().to_wire());
        body.license_status.set(2);
        body.required_clients.set(25);
        body.client_time.set(133_000_000_000_000_000);
        body.application_id.data1.set(0x55c9_2734);
        body.kms_counted_id.data1.set(0x907f_1f65);
        body.client_machine_id.data1.set(0xDEAD_BEEF);
        for (slot, unit) in body
            .workstation_name
            .iter_mut()
            .zip("client".encode_utf16())
        {
            slot.set(unit);
        }
        bytes.copy_from_slice(body.as_bytes());
        RequestBody::read_from_bytes(&bytes).unwrap()
    }

    fn plan(epid: &EPid) -> ResponsePlan<'_> {
        ResponsePlan {
            epid,
            client_machine_id: ClientMachineId(Guid::from_bytes([0x11; 16])),
            client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
            count: 50,
            intervals: Intervals::DEFAULT,
            hardware_id: HardwareId([0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18]),
        }
    }

    /// Frame a request, decode it, and build a response — the whole exchange.
    fn exchange(
        version: Version,
        seed: u64,
    ) -> (alloc::vec::Vec<u8>, DecodedRequest, alloc::vec::Vec<u8>) {
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(seed);

        let mut stub = vec![0_u8; 512];
        let stub_len = encode_request(
            version,
            &sample_body(version),
            &ciphers,
            &mut entropy,
            &mut stub,
        )
        .unwrap();
        stub.truncate(stub_len);

        let decoded = decode(&stub, &ciphers).unwrap();

        let epid = EPid::parse(EPID_TEXT).unwrap();
        let mut response = vec![0_u8; MAX_RESPONSE_LEN];
        let response_len_actual = encode(
            &decoded,
            &plan(&epid),
            &ciphers,
            &mut entropy,
            &mut response,
        )
        .unwrap();
        response.truncate(response_len_actual);

        (stub, decoded, response)
    }

    #[test]
    fn every_version_round_trips_a_request() {
        for version in Version::ALL {
            let (stub, decoded, _) = exchange(version, 1);
            assert_eq!(
                stub.len(),
                crate::kms::request::framed_request_len(version),
                "{version:?}"
            );
            assert_eq!(decoded.version, version);
            assert_eq!(decoded.request.required_clients.0, 25);
            assert_eq!(decoded.request.workstation_name.as_str(), "client");
            assert_eq!(
                decoded.request.client_time.0.as_ticks(),
                133_000_000_000_000_000
            );
        }
    }

    /// `KMS-005` (#21): v4 is plaintext with a trailing MAC, and the MAC over a
    /// request a client actually built must verify.
    #[test]
    fn a_v4_request_carries_a_verifiable_mac() {
        let (stub, decoded, _) = exchange(Version::V4, 2);
        assert_eq!(decoded.mac_verified, Some(true));
        assert_eq!(decoded.shared_secret, None, "v4 does not encrypt");
        assert_eq!(stub.len(), REQUEST_BODY_LEN + MAC_LEN);
        // Plaintext: the body is readable in the stub as it stands.
        assert_eq!(
            &stub[..REQUEST_BODY_LEN],
            sample_body(Version::V4).as_bytes()
        );
    }

    /// A corrupted v4 MAC is recorded, not refused. vlmcsd's server does not
    /// check it either, the key is published so it authenticates nothing, and
    /// refusing would be a difference from a genuine host for no benefit.
    #[test]
    fn a_corrupted_v4_mac_is_reported_rather_than_refused() {
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(3);
        let mut stub = vec![0_u8; 512];
        let len = encode_request(
            Version::V4,
            &sample_body(Version::V4),
            &ciphers,
            &mut entropy,
            &mut stub,
        )
        .unwrap();
        stub.truncate(len);
        stub[REQUEST_BODY_LEN] ^= 0xFF;

        let decoded = decode(&stub, &ciphers).unwrap();
        assert_eq!(decoded.mac_verified, Some(false));
        // ...and the request is still fully parsed.
        assert_eq!(decoded.request.required_clients.0, 25);
    }

    /// `KMS-006` (#22). This is what a genuine Microsoft v5 client checks, and
    /// it is the reason the server decrypts with a null IV: after encrypting
    /// `D_k(IV_req)` with a null IV, the first ciphertext block is `IV_req`.
    #[test]
    fn a_v5_response_iv_is_byte_identical_to_the_request_iv() {
        let (stub, _, response) = exchange(Version::V5, 4);
        let request_iv = &stub[UNENCRYPTED_PREFIX_LEN..UNENCRYPTED_PREFIX_LEN + IV_LEN];
        let response_iv = &response[UNENCRYPTED_PREFIX_LEN..UNENCRYPTED_PREFIX_LEN + IV_LEN];
        assert_eq!(response_iv, request_iv);
    }

    /// `KMS-007` (#23). Reusing the v5 rule here is the loudest emulator tell
    /// in the class: `vlmcs` prints an explicit "the KMS server is an emulator"
    /// warning when the two IVs match under v6.
    #[test]
    fn a_v6_response_iv_differs_from_the_request_iv() {
        for seed in 0..8_u64 {
            let (stub, _, response) = exchange(Version::V6, seed);
            let request_iv = &stub[UNENCRYPTED_PREFIX_LEN..UNENCRYPTED_PREFIX_LEN + IV_LEN];
            let response_iv = &response[UNENCRYPTED_PREFIX_LEN..UNENCRYPTED_PREFIX_LEN + IV_LEN];
            assert_ne!(response_iv, request_iv, "seed {seed}");
        }
    }

    /// A client decrypts the response and checks four things. This test is that
    /// client: it verifies the salt proof, the echoed fields, the hardware ID
    /// and the HMAC, which between them cover `CRY-006` (#45), `CRY-007` (#46),
    /// `CRY-008` (#47) and `CRY-010` (#49).
    #[test]
    fn a_client_can_verify_everything_a_v6_response_claims() {
        let ciphers = Ciphers::new();
        let (stub, decoded, response) = exchange(Version::V6, 9);
        let secret = decoded.shared_secret.unwrap();

        // Decrypt the response the way a client does: the response IV is a
        // genuine CBC IV for the blocks after it, so decrypting from the IV
        // with a null IV recovers everything.
        let schedule = ciphers.schedule(Version::V6).unwrap();
        let ciphertext = &response[UNENCRYPTED_PREFIX_LEN..];
        let mut plain = vec![0_u8; ciphertext.len()];
        kmsrs_crypto::cbc::decrypt(
            schedule,
            kmsrs_crypto::cbc::Iv::Null,
            ciphertext,
            &mut plain,
        )
        .unwrap();

        // Block 1 is `D_k(IV_resp)`; the body starts after it.
        let body = &plain[IV_LEN..];
        let epid = EPid::parse(EPID_TEXT).unwrap();
        let epid_len = epid.encoded_len();

        // The echoed fields (`KMS-012`, #28).
        let tail_start = RESPONSE_HEAD_LEN + epid_len;
        assert_eq!(
            &body[tail_start + 16..tail_start + 24],
            &133_000_000_000_000_000_u64.to_le_bytes(),
            "the client time is echoed verbatim"
        );

        // The salt proof: recover the salt and check its hash.
        let proof_start = tail_start + 36;
        let mut salt = [0_u8; 16];
        salt.copy_from_slice(&body[proof_start..proof_start + 16]);
        for (byte, mask) in salt.iter_mut().zip(secret.iter()) {
            *byte ^= *mask;
        }
        assert_eq!(
            &body[proof_start + 16..proof_start + 48],
            kmsrs_crypto::hash::sha256(&salt).as_slice(),
            "SHA-256 of the recovered salt must match the transmitted hash"
        );

        // The hardware ID, and the decrypted request IV the client recomputes.
        let trailer = proof_start + 48;
        assert_eq!(
            &body[trailer..trailer + 8],
            &[0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18]
        );
        assert_eq!(&body[trailer + 8..trailer + 24], secret.as_slice());

        // The HMAC, over the plaintext from the response IV to just before it.
        let plaintext_len = IV_LEN + tail_start + 36 + 48 + 40;
        let message = &plain[..plaintext_len - 16];
        let expected = v6::tag(133_000_000_000_000_000, v6::SlotOffset::Current, message);
        assert_eq!(
            &plain[plaintext_len - 16..plaintext_len],
            expected.as_slice()
        );
        assert_eq!(
            v6::verify(
                133_000_000_000_000_000,
                message,
                &plain[plaintext_len - 16..plaintext_len]
                    .first_chunk::<16>()
                    .copied()
                    .unwrap()
            ),
            Some(v6::SlotOffset::Current)
        );

        // And the request the client sent is untouched.
        assert_eq!(stub.len(), 260);
    }

    /// `KMS-011` (#27): the size a client computes must be the size we send.
    /// A disagreement makes `vlmcs` print "Size of RPC payload should be %u but
    /// is %u", which reads like a framing bug rather than a padding one.
    #[test]
    fn the_response_length_matches_what_a_client_would_compute() {
        let epid = EPid::parse(EPID_TEXT).unwrap();
        for version in Version::ALL {
            let (_, _, response) = exchange(version, 5);
            assert_eq!(response.len(), response_len(version, &epid), "{version:?}");
        }

        // The formulae from the issue, stated independently of the code above.
        let pid_size = epid.encoded_len();
        let round_up = |value: usize| value + ((!value & 15) + 1);
        assert_eq!(
            response_len(Version::V5, &epid),
            4 + round_up(108 + pid_size)
        );
        assert_eq!(
            response_len(Version::V6, &epid),
            4 + round_up(148 + pid_size)
        );
    }

    /// Every response fits the fixed buffer, at every ePID length
    /// (`KMS-023`, #39).
    #[test]
    fn every_response_fits_the_fixed_buffer() {
        for units in [0_usize, 1, 40, 62, 63] {
            let text: alloc::string::String = core::iter::repeat_n('9', units).collect();
            let epid = EPid::parse(&text).unwrap();
            for version in Version::ALL {
                assert!(
                    response_len(version, &epid) <= MAX_RESPONSE_LEN,
                    "{version:?} with {units} units"
                );
            }
        }
    }

    /// `OS-012` (#263): a failing entropy source must stop a response being
    /// built rather than produce one with predictable values in it.
    #[test]
    fn a_failing_entropy_source_refuses_to_build_an_encrypted_response() {
        let ciphers = Ciphers::new();
        let epid = EPid::parse(EPID_TEXT).unwrap();
        let mut out = vec![0_u8; MAX_RESPONSE_LEN];

        for version in [Version::V5, Version::V6] {
            let (_, decoded, _) = exchange(version, 6);
            assert_eq!(
                encode(
                    &decoded,
                    &plan(&epid),
                    &ciphers,
                    &mut FailingEntropy,
                    &mut out
                ),
                Err(EncodeError::EntropyUnavailable),
                "{version:?}"
            );
        }
    }

    /// v4 draws no randomness, so it must still work when the source fails —
    /// stating that deliberately, because the alternative reading is that the
    /// test above is incomplete.
    #[test]
    fn a_v4_response_needs_no_entropy() {
        let ciphers = Ciphers::new();
        let epid = EPid::parse(EPID_TEXT).unwrap();
        let mut out = vec![0_u8; MAX_RESPONSE_LEN];
        let (_, decoded, _) = exchange(Version::V4, 7);
        assert!(
            encode(
                &decoded,
                &plan(&epid),
                &ciphers,
                &mut FailingEntropy,
                &mut out
            )
            .is_ok()
        );
    }

    /// `CRY-012` (#51) on the inbound path: a request whose padding is wrong
    /// must be refused, not decrypted into whatever the bytes happen to be.
    #[test]
    fn a_request_with_corrupt_ciphertext_is_refused() {
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(8);
        let mut stub = vec![0_u8; 512];
        let len = encode_request(
            Version::V6,
            &sample_body(Version::V6),
            &ciphers,
            &mut entropy,
            &mut stub,
        )
        .unwrap();
        stub.truncate(len);

        // Corrupting the final block changes the padding bytes, which the
        // padding check catches. Both existing implementations perform no
        // integrity check on inbound ciphertext at all.
        let last = stub.len() - 1;
        stub[last] ^= 0xFF;
        assert!(matches!(
            decode(&stub, &ciphers),
            Err(DecodeError::Cipher(_))
        ));
    }

    /// The response buffer must be refused rather than truncated when it is too
    /// small — the caller sizes it at `MAX_RESPONSE_LEN`, so this is the
    /// programming-error path rather than a wire one.
    #[test]
    fn an_undersized_response_buffer_is_refused() {
        let ciphers = Ciphers::new();
        let epid = EPid::parse(EPID_TEXT).unwrap();
        let mut entropy = DeterministicEntropy::from_seed(10);
        for version in Version::ALL {
            let (_, decoded, _) = exchange(version, 10);
            let needed = response_len(version, &epid);
            let mut out = vec![0_u8; needed - 1];
            assert!(
                matches!(
                    encode(&decoded, &plan(&epid), &ciphers, &mut entropy, &mut out),
                    Err(EncodeError::BufferTooSmall { .. })
                ),
                "{version:?}"
            );
        }
    }

    /// The same request with the same entropy stream must produce the same
    /// response bytes — the property differential testing rests on
    /// (`TEST-004`, #225).
    #[test]
    fn the_exchange_is_reproducible() {
        for version in Version::ALL {
            let first = exchange(version, 11);
            let second = exchange(version, 11);
            assert_eq!(first.0, second.0, "{version:?} request");
            assert_eq!(first.2, second.2, "{version:?} response");
        }
    }

    /// Two exchanges with *different* entropy must differ, or something is
    /// drawing from a constant.
    #[test]
    fn different_entropy_produces_different_bytes() {
        for version in [Version::V5, Version::V6] {
            let (first_stub, _, first_response) = exchange(version, 12);
            let (second_stub, _, second_response) = exchange(version, 13);
            assert_ne!(
                first_stub, second_stub,
                "{version:?} request IV is constant"
            );
            assert_ne!(first_response, second_response, "{version:?} response");
        }
    }
}
