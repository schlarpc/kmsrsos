//! Checking a response, property by property (`CLI-001`, #207;
//! `CLI-003`, #209; `CLI-004`, #210).
//!
//! # Why this is not a boolean
//!
//! A single pass/fail verdict throws away exactly the information that makes a
//! diagnostic client worth having: *which* property failed. [`Checks`] mirrors
//! `vlmcs`'s `RESPONSE_RESULT` bitfield, and every bit is computed and reported
//! whether or not an earlier one failed.
//!
//! The counter-example is py-kms's client, which verifies the v4 CMAC and logs
//! **only on success** — so a wrong MAC produces silence, indistinguishable
//! from not checking — and verifies nothing at all for v5 and v6.
//!
//! # Every check is a fact about a genuine host
//!
//! Nothing here is a preference. Each bit corresponds to something a real KMS
//! host's response has, so a response failing one is either a broken host or an
//! emulator — which is the same statement viewed from either end, and is why
//! this module is also the regression suite for our own server
//! (`CLI-002`, #208).

use crate::kms::epid::MAX_EPID_UNITS;
use crate::kms::response::DecodedResponse;
use crate::kms::version::Version;
use crate::types::{ClientMachineId, ClientTime};
use kmsrs_crypto::v6;

/// One property of a response.
///
/// Named after `vlmcs`'s bits where one corresponds, so a report can be
/// compared against `vlmcs` output directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Check {
    /// The v4 MAC over the response body is correct.
    HashOk,
    /// The echoed timestamp matches the one sent.
    TimeStampOk,
    /// The echoed client machine ID matches the one sent.
    ClientMachineIdOk,
    /// Every version field agrees — request base, request header, response
    /// base, response header (`CLI-003`, #209).
    VersionOk,
    /// The response IV follows the version's rule.
    ///
    /// v5 echoes the request IV; v6 must **not**. A v6 response carrying a v5
    /// IV is the loudest emulator tell there is.
    IvsOk,
    /// The response decrypted and its padding is well-formed: a final byte in
    /// `1..=16`, and every padding byte equal to it (`CLI-003`, #209).
    DecryptSuccess,
    /// The v6 HMAC over the response plaintext is correct.
    HmacSha256Ok,
    /// The declared ePID length is within bounds, ends in a NUL, and has no
    /// interior NUL (`CLI-004`, #210).
    PidLengthOk,
    /// The response occupied exactly the number of bytes its contents imply.
    SizeOk,
    /// The response IV is not one of the values that betray a lazy emulator —
    /// all zeros, or equal to the request IV where the version forbids it.
    IvNotSuspicious,
    /// The salt proof verifies: SHA-256 of the recovered salt matches the hash
    /// the response carried.
    SaltProofOk,
    /// The v6 trailer's copy of `D_k(IV_request)` matches what the client
    /// derived (`CLI-003`, #209).
    ///
    /// This is the deepest v6 check there is: it can only hold if the host
    /// genuinely decrypted the request with the right key, and it is
    /// independent of the HMAC — a host that copied a captured HMAC would still
    /// fail this.
    DecryptedIvOk,
}

impl Check {
    /// Every check, in report order.
    pub const ALL: [Self; 12] = [
        Self::VersionOk,
        Self::ClientMachineIdOk,
        Self::TimeStampOk,
        Self::DecryptSuccess,
        Self::HashOk,
        Self::IvsOk,
        Self::IvNotSuspicious,
        Self::SaltProofOk,
        Self::HmacSha256Ok,
        Self::PidLengthOk,
        Self::SizeOk,
        Self::DecryptedIvOk,
    ];

    /// A short name for reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HashOk => "HashOK",
            Self::TimeStampOk => "TimeStampOK",
            Self::ClientMachineIdOk => "ClientMachineIDOK",
            Self::VersionOk => "VersionOK",
            Self::IvsOk => "IVsOK",
            Self::DecryptSuccess => "DecryptSuccess",
            Self::HmacSha256Ok => "HmacSha256OK",
            Self::PidLengthOk => "PidLengthOK",
            Self::SizeOk => "SizeOK",
            Self::IvNotSuspicious => "IVnotSuspicious",
            Self::SaltProofOk => "SaltProofOK",
            Self::DecryptedIvOk => "DecryptedIVOK",
        }
    }
}

/// What a check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The property holds.
    Pass,
    /// The property does not hold.
    ///
    /// A failure is always a real problem: either the host is broken or it is
    /// not a genuine KMS host.
    Fail,
    /// This version does not have this property.
    ///
    /// Distinct from [`Outcome::Pass`] on purpose. A v4 response has no HMAC,
    /// and reporting that as a pass would let "we did not look" read as "we
    /// looked and it was fine" — which is how py-kms's client ends up appearing
    /// to validate v5 and v6.
    NotApplicable,
}

impl Outcome {
    /// Whether this outcome means something is wrong.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// The full result of checking one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checks {
    outcomes: [Outcome; 12],
    /// The size the response should have been, for the report.
    pub expected_size: usize,
    /// The size it was.
    pub actual_size: usize,
}

impl Checks {
    /// What one check concluded.
    #[must_use]
    pub fn outcome(&self, check: Check) -> Outcome {
        Check::ALL
            .iter()
            .position(|candidate| *candidate == check)
            .and_then(|index| self.outcomes.get(index).copied())
            .unwrap_or(Outcome::NotApplicable)
    }

    /// Every check and its outcome, in report order.
    pub fn iter(&self) -> impl Iterator<Item = (Check, Outcome)> + '_ {
        Check::ALL
            .iter()
            .copied()
            .zip(self.outcomes.iter().copied())
    }

    /// Whether every applicable check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        !self.outcomes.iter().any(|outcome| outcome.is_failure())
    }

    /// Every check that failed.
    pub fn failures(&self) -> impl Iterator<Item = Check> + '_ {
        self.iter()
            .filter(|(_, outcome)| outcome.is_failure())
            .map(|(check, _)| check)
    }
}

/// What the client sent, so the response can be checked against it.
#[derive(Debug, Clone, Copy)]
pub struct Sent {
    /// The version the client asked for.
    pub version: Version,
    /// The machine ID it sent.
    pub client_machine_id: ClientMachineId,
    /// The timestamp it sent.
    pub client_time: ClientTime,
    /// The IV it sent, for v5 and v6.
    pub request_iv: Option<[u8; 16]>,
    /// `D_k(IV_request)` — the shared secret both sides derive.
    pub shared_secret: Option<[u8; 16]>,
    /// The version word in the RPC request header, for the four-way version
    /// cross-check (`CLI-003`, #209).
    pub header_version: u32,
    /// The version word in the RPC response header.
    pub response_header_version: u32,
}

/// Check a response against what was sent.
#[must_use]
pub fn check(sent: &Sent, response: &DecodedResponse<'_>, mac_key: Option<&MacCheck>) -> Checks {
    let mut outcomes = [Outcome::NotApplicable; 12];

    let expected_size = expected_size(sent.version, response);
    let set = |outcomes: &mut [Outcome; 12], check: Check, outcome: Outcome| {
        if let Some(index) = Check::ALL.iter().position(|candidate| *candidate == check)
            && let Some(slot) = outcomes.get_mut(index)
        {
            *slot = outcome;
        }
    };
    let verdict = |holds: bool| {
        if holds { Outcome::Pass } else { Outcome::Fail }
    };

    // `CLI-003` (#209): all four version fields must agree. Checking only the
    // response body would miss a host that framed the RPC header differently
    // from the payload.
    let wire = sent.version.to_protocol_version().to_wire();
    let versions_agree = response.inner_version.to_wire() == wire
        && sent.header_version == wire
        && sent.response_header_version == wire
        && response
            .outer_version
            .is_none_or(|outer| outer.to_wire() == wire);
    set(&mut outcomes, Check::VersionOk, verdict(versions_agree));

    set(
        &mut outcomes,
        Check::ClientMachineIdOk,
        verdict(response.client_machine_id == sent.client_machine_id.0.to_bytes()),
    );
    set(
        &mut outcomes,
        Check::TimeStampOk,
        verdict(response.client_time == sent.client_time.0.as_ticks()),
    );
    set(
        &mut outcomes,
        Check::SizeOk,
        verdict(response.wire_len == expected_size),
    );
    set(
        &mut outcomes,
        Check::PidLengthOk,
        verdict(pid_is_well_formed(response)),
    );

    // Decryption succeeded if we got here at all; what remains to check is the
    // padding, which the decoder deliberately did not judge.
    if sent.version == Version::V4 {
        set(&mut outcomes, Check::DecryptSuccess, Outcome::NotApplicable);
    } else {
        let padding_ok = response.padding_len.is_some_and(|len| {
            response.padding.len() == len
                && response
                    .padding
                    .iter()
                    .all(|byte| usize::from(*byte) == len)
        });
        set(&mut outcomes, Check::DecryptSuccess, verdict(padding_ok));
    }

    check_crypto(&mut outcomes, sent, response, mac_key, set, verdict);

    Checks {
        outcomes,
        expected_size,
        actual_size: response.wire_len,
    }
}

/// The version-specific cryptographic checks: the v4 MAC, the IV rules, the
/// salt proof, and v6's trailer and HMAC.
///
/// Split out of [`check`] only for length. The order is the order a reader
/// would want them in a report, not an evaluation order — every one is computed
/// regardless of what the others concluded.
fn check_crypto(
    outcomes: &mut [Outcome; 12],
    sent: &Sent,
    response: &DecodedResponse<'_>,
    mac_key: Option<&MacCheck>,
    set: impl Fn(&mut [Outcome; 12], Check, Outcome),
    verdict: impl Fn(bool) -> Outcome,
) {
    // v4's MAC.
    match (sent.version, response.mac, mac_key) {
        (Version::V4, Some(mac), Some(checker)) => {
            let expected = (checker.tag)(response.mac_message);
            set(outcomes, Check::HashOk, verdict(expected == mac));
        }
        (Version::V4, _, _) => set(outcomes, Check::HashOk, Outcome::Fail),
        _ => set(outcomes, Check::HashOk, Outcome::NotApplicable),
    }

    // The IV rule, which is the difference between v5 and v6 and the loudest
    // tell an emulator has (`FP` checklist, `CLI-002`, #208).
    match (sent.version, response.response_iv, sent.request_iv) {
        (Version::V5, Some(response_iv), Some(request_iv)) => {
            set(outcomes, Check::IvsOk, verdict(response_iv == request_iv));
            set(
                outcomes,
                Check::IvNotSuspicious,
                verdict(response_iv != [0_u8; 16]),
            );
        }
        (Version::V6, Some(response_iv), Some(request_iv)) => {
            // A v6 host draws a *fresh* IV. Echoing the request's is the v5
            // rule applied to v6, which is what several emulators do.
            let fresh = response_iv != request_iv;
            set(outcomes, Check::IvsOk, verdict(fresh));
            set(
                outcomes,
                Check::IvNotSuspicious,
                verdict(fresh && response_iv != [0_u8; 16]),
            );
        }
        (Version::V4, _, _) => {
            set(outcomes, Check::IvsOk, Outcome::NotApplicable);
            set(outcomes, Check::IvNotSuspicious, Outcome::NotApplicable);
        }
        _ => {
            set(outcomes, Check::IvsOk, Outcome::Fail);
            set(outcomes, Check::IvNotSuspicious, Outcome::Fail);
        }
    }

    // The salt proof: recover the salt by XORing the shared secret back out,
    // then check its hash (`CRY-008`, #47).
    match (response.salt_proof, sent.shared_secret) {
        (Some(proof), Some(secret)) => {
            let mut salt = proof.random_xored_ivs;
            for (byte, mask) in salt.iter_mut().zip(secret.iter()) {
                *byte ^= *mask;
            }
            let expected = kmsrs_crypto::hash::sha256(&salt);
            set(
                outcomes,
                Check::SaltProofOk,
                verdict(expected == proof.hash),
            );
        }
        (None, _) if sent.version == Version::V4 => {
            set(outcomes, Check::SaltProofOk, Outcome::NotApplicable);
        }
        _ => set(outcomes, Check::SaltProofOk, Outcome::Fail),
    }

    // `CLI-003` (#209): the v6 trailer carries the host's own `D_k(IV_request)`.
    // A host that did not decrypt the request cannot produce it, and unlike the
    // HMAC it cannot be replayed from a capture of a different request.
    match (
        sent.version,
        response.decrypted_request_iv,
        sent.shared_secret,
    ) {
        (Version::V6, Some(carried), Some(secret)) => {
            set(outcomes, Check::DecryptedIvOk, verdict(carried == secret));
        }
        (Version::V6, _, _) => set(outcomes, Check::DecryptedIvOk, Outcome::Fail),
        _ => set(outcomes, Check::DecryptedIvOk, Outcome::NotApplicable),
    }

    // v6's HMAC, computed over the plaintext before encryption.
    match (sent.version, response.hmac) {
        (Version::V6, Some(hmac)) => {
            let holds = [
                v6::SlotOffset::Current,
                v6::SlotOffset::Previous,
                v6::SlotOffset::Next,
            ]
            .into_iter()
            .any(|offset| {
                v6::tag(sent.client_time.0.as_ticks(), offset, response.hmac_message) == hmac
            });
            set(outcomes, Check::HmacSha256Ok, verdict(holds));
        }
        (Version::V6, None) => set(outcomes, Check::HmacSha256Ok, Outcome::Fail),
        _ => set(outcomes, Check::HmacSha256Ok, Outcome::NotApplicable),
    }
}

/// How the caller computes a v4 MAC.
///
/// A function pointer rather than the key, so this module does not have to own
/// a cipher and the caller cannot accidentally check against a different key
/// than it sent with.
pub struct MacCheck {
    /// Compute the tag over a message.
    pub tag: fn(&[u8]) -> [u8; 16],
}

impl core::fmt::Debug for MacCheck {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MacCheck")
    }
}

/// `CLI-004` (#210): the ePID must fit, end in a NUL, and contain no interior
/// NUL.
///
/// An interior NUL is the interesting one. A field that is NUL-terminated *and*
/// carries data past the terminator is a place to hide bytes, and a host that
/// sends one is not sending what a genuine host sends.
fn pid_is_well_formed(response: &DecodedResponse<'_>) -> bool {
    let bytes = response.pid_bytes;
    // Even length, since the field is UTF-16.
    if !bytes.len().is_multiple_of(2) || bytes.is_empty() {
        return false;
    }
    // Within the field a genuine host can fill.
    if bytes.len() > (MAX_EPID_UNITS.saturating_add(1)).saturating_mul(2) {
        return false;
    }
    // The declared size must match what was carried.
    if usize::try_from(response.pid_size).is_ok_and(|declared| declared != bytes.len()) {
        return false;
    }

    let unit_at = |pair: &[u8]| {
        u16::from_le_bytes([
            pair.first().copied().unwrap_or(0),
            pair.get(1).copied().unwrap_or(0),
        ])
    };
    let mut units = bytes.chunks_exact(2).map(unit_at);

    // The field must end in a NUL.
    let Some(last) = bytes.chunks_exact(2).next_back().map(unit_at) else {
        return false;
    };
    if last != 0 {
        return false;
    }

    // No interior NUL: every unit before the last must be non-zero.
    let count = bytes.len().checked_div(2).unwrap_or(0);
    let interior = count.saturating_sub(1);
    units.by_ref().take(interior).all(|unit| unit != 0)
}

/// The size a response of this shape should have had (`KMS-011`, #27).
///
/// `vlmcs` prints *"Size of RPC payload should be %u but is %u"* when this
/// disagrees, which reads like a framing bug and is usually a padding bug.
fn expected_size(version: Version, response: &DecodedResponse<'_>) -> usize {
    use crate::kms::layout::{
        MAC_LEN, RESPONSE_HEAD_LEN, UNENCRYPTED_PREFIX_LEN, V4_POST_EPID_LEN, V5_POST_EPID_LEN,
        V6_POST_EPID_LEN,
    };

    let pid_len = response.pid_bytes.len();
    match version {
        Version::V4 => RESPONSE_HEAD_LEN
            .saturating_add(pid_len)
            .saturating_add(V4_POST_EPID_LEN)
            .saturating_add(MAC_LEN),
        Version::V5 | Version::V6 => {
            let post = if version == Version::V6 {
                V6_POST_EPID_LEN
            } else {
                V5_POST_EPID_LEN
            };
            let plaintext = 16_usize
                .saturating_add(RESPONSE_HEAD_LEN)
                .saturating_add(pid_len)
                .saturating_add(post);
            let padded = kmsrs_crypto::cbc::padded_len(plaintext).unwrap_or(plaintext);
            UNENCRYPTED_PREFIX_LEN.saturating_add(padded)
        }
    }
}
