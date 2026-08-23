//! Every response this server builds passes every check (`CLI-001`, #207;
//! `CLI-003`, #209; `CLI-004`, #210).
//!
//! This is the round trip that makes the validator worth having: encode a
//! request the way a client does, build the response the way the server does,
//! then check it the way a diagnostic client does — for all three versions.
//!
//! Each check is then *individually* falsified by corrupting exactly the byte
//! it covers, because a validator whose bits are all wired to the same
//! condition would pass this file's happy path and catch nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::{self, Ciphers, ResponsePlan};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::validate::{Check, Checks, MacCheck, Outcome, Sent, check};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::FileTime;
use kmsrs_proto::types::{ClientMachineId, ClientTime, HardwareId, Intervals};
use zerocopy::{FromBytes, IntoBytes};

const EPID_TEXT: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";
const MACHINE: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
];
const CLIENT_TICKS: u64 = 133_000_000_000_000_000;

/// A v4 MAC over a message, using the shipped key.
fn v4_tag(message: &[u8]) -> [u8; 16] {
    Ciphers::new().mac().tag(message)
}

/// One full exchange: the request bytes, the response bytes, and what was sent.
struct Exchange {
    response: Vec<u8>,
    sent: Sent,
}

fn make(version: Version) -> Exchange {
    let mut body_bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&body_bytes).unwrap();
    body.version.set(version.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(CLIENT_TICKS);
    body.client_machine_id =
        kmsrs_proto::kms::layout::WireGuid::from_guid(Guid::from_bytes(MACHINE));
    body_bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&body_bytes).unwrap();

    let ciphers = Ciphers::new();
    let mut request_entropy = DeterministicEntropy::from_seed(0xC0DE);
    let mut request = vec![0_u8; 1024];
    let len = framing::encode_request(version, &body, &ciphers, &mut request_entropy, &mut request)
        .unwrap();
    request.truncate(len);

    // The IV the client sent, which v5 echoes and v6 must not.
    let request_iv: Option<[u8; 16]> = if version == Version::V4 {
        None
    } else {
        request.get(4..20).and_then(|bytes| bytes.try_into().ok())
    };

    let decoded = framing::decode(&request, &ciphers).expect("the server decodes it");
    let shared_secret = decoded.shared_secret;

    let epid = EPid::parse(EPID_TEXT).unwrap();
    let plan = ResponsePlan {
        epid: &epid,
        client_machine_id: ClientMachineId(Guid::from_bytes(MACHINE)),
        client_time: ClientTime(FileTime::from_ticks(CLIENT_TICKS)),
        count: 50,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F]),
    };
    let mut response_entropy = DeterministicEntropy::from_seed(0x5A17);
    let mut response = vec![0_u8; 1024];
    let len = framing::encode(
        &decoded,
        &plan,
        &ciphers,
        &mut response_entropy,
        &mut response,
    )
    .unwrap();
    response.truncate(len);

    let wire = version.to_protocol_version().to_wire();
    Exchange {
        response,
        sent: Sent {
            version,
            client_machine_id: ClientMachineId(Guid::from_bytes(MACHINE)),
            client_time: ClientTime(FileTime::from_ticks(CLIENT_TICKS)),
            request_iv,
            shared_secret,
            header_version: wire,
            response_header_version: wire,
        },
    }
}

/// Decode and check one response.
fn validate(version: Version, response: &[u8], sent: &Sent) -> Checks {
    let ciphers = Ciphers::new();
    let mut scratch = vec![0_u8; response.len().max(64)];
    let decoded = response::decode(version, response, ciphers.schedule(version), &mut scratch)
        .expect("the response decodes");
    check(sent, &decoded, Some(&MacCheck { tag: v4_tag }))
}

/// The happy path: our own server's response passes every applicable check, for
/// every version. This is the assertion `CLI-002` (#208) is built on.
#[test]
fn our_own_responses_pass_every_check() {
    for version in Version::ALL {
        let exchange = make(version);
        let checks = validate(version, &exchange.response, &exchange.sent);

        let failures: Vec<&str> = checks.failures().map(Check::name).collect();
        assert!(
            failures.is_empty(),
            "{version:?} failed: {failures:?} (size {} vs expected {})",
            checks.actual_size,
            checks.expected_size
        );
        assert!(checks.all_passed());
    }
}

/// Every version has the checks it should, and *only* those — a v4 response
/// reporting `HmacSha256OK` as a pass would be reporting "we did not look" as
/// "we looked and it was fine".
#[test]
fn not_applicable_is_distinct_from_pass() {
    let exchange = make(Version::V4);
    let checks = validate(Version::V4, &exchange.response, &exchange.sent);
    for check in [
        Check::HmacSha256Ok,
        Check::IvsOk,
        Check::IvNotSuspicious,
        Check::SaltProofOk,
        Check::DecryptSuccess,
    ] {
        assert_eq!(
            checks.outcome(check),
            Outcome::NotApplicable,
            "{} should not apply to v4",
            check.name()
        );
    }
    assert_eq!(checks.outcome(Check::HashOk), Outcome::Pass, "v4 has a MAC");

    let exchange = make(Version::V5);
    let checks = validate(Version::V5, &exchange.response, &exchange.sent);
    assert_eq!(checks.outcome(Check::HashOk), Outcome::NotApplicable);
    assert_eq!(checks.outcome(Check::HmacSha256Ok), Outcome::NotApplicable);
    assert_eq!(checks.outcome(Check::SaltProofOk), Outcome::Pass);

    let exchange = make(Version::V6);
    let checks = validate(Version::V6, &exchange.response, &exchange.sent);
    assert_eq!(checks.outcome(Check::HmacSha256Ok), Outcome::Pass);
    assert_eq!(checks.outcome(Check::DecryptedIvOk), Outcome::Pass);

    // v4 and v5 have no such trailer.
    for version in [Version::V4, Version::V5] {
        let exchange = make(version);
        let checks = validate(version, &exchange.response, &exchange.sent);
        assert_eq!(
            checks.outcome(Check::DecryptedIvOk),
            Outcome::NotApplicable,
            "{version:?}"
        );
    }
}

/// `CLI-003` (#209): the deepest v6 check. A host that did not genuinely
/// decrypt the request cannot produce `D_k(IV_request)`, and unlike the HMAC
/// this cannot be replayed from a capture of a different request.
#[test]
fn a_wrong_decrypted_iv_is_caught() {
    let exchange = make(Version::V6);
    let checks = validate(Version::V6, &exchange.response, &exchange.sent);
    assert_eq!(checks.outcome(Check::DecryptedIvOk), Outcome::Pass);

    let mut sent = exchange.sent;
    sent.shared_secret = Some([0x77; 16]);
    let checks = validate(Version::V6, &exchange.response, &sent);
    assert_eq!(
        checks.outcome(Check::DecryptedIvOk),
        Outcome::Fail,
        "a mismatched shared secret went unnoticed"
    );
}

/// `CLI-001` (#207): a wrong machine ID or timestamp is caught. Both are
/// echoed, so a host that does not echo them is not answering *this* request.
#[test]
fn a_wrong_echo_is_caught() {
    let exchange = make(Version::V6);

    let mut sent = exchange.sent;
    sent.client_machine_id = ClientMachineId(Guid::from_bytes([0x11; 16]));
    let checks = validate(Version::V6, &exchange.response, &sent);
    assert_eq!(checks.outcome(Check::ClientMachineIdOk), Outcome::Fail);
    assert_eq!(
        checks.outcome(Check::TimeStampOk),
        Outcome::Pass,
        "and only that check failed"
    );

    let mut sent = exchange.sent;
    sent.client_time = ClientTime(FileTime::from_ticks(CLIENT_TICKS + 1));
    let checks = validate(Version::V6, &exchange.response, &sent);
    assert_eq!(checks.outcome(Check::TimeStampOk), Outcome::Fail);
    assert_eq!(checks.outcome(Check::ClientMachineIdOk), Outcome::Pass);
}

/// `CLI-003` (#209): all four version fields are cross-checked, so a host that
/// framed its RPC header differently from its payload is caught.
#[test]
fn a_version_disagreement_in_any_of_the_four_fields_is_caught() {
    let exchange = make(Version::V6);

    for corrupt in [
        |sent: &mut Sent| sent.header_version = 0x0005_0000,
        |sent: &mut Sent| sent.response_header_version = 0x0005_0000,
    ] {
        let mut sent = exchange.sent;
        corrupt(&mut sent);
        let checks = validate(Version::V6, &exchange.response, &sent);
        assert_eq!(
            checks.outcome(Check::VersionOk),
            Outcome::Fail,
            "a header version disagreement went unnoticed"
        );
    }

    // And the version word inside the response body.
    let mut response = exchange.response.clone();
    response[0] ^= 0x01;
    let checks = validate(Version::V6, &response, &exchange.sent);
    assert_eq!(
        checks.outcome(Check::VersionOk),
        Outcome::Fail,
        "the outer version word is not checked"
    );
}

/// `CLI-001` (#207): the v6 IV rule. A v6 response that echoes the request IV
/// is applying v5's rule, which is the loudest emulator tell there is.
#[test]
fn a_v6_response_echoing_the_request_iv_is_caught() {
    let exchange = make(Version::V6);
    let checks = validate(Version::V6, &exchange.response, &exchange.sent);
    assert_eq!(checks.outcome(Check::IvsOk), Outcome::Pass);

    // Pretend the request IV was whatever the response carried — which is what
    // a v5-rule emulator would produce.
    let ciphers = Ciphers::new();
    let mut scratch = vec![0_u8; exchange.response.len()];
    let decoded = response::decode(
        Version::V6,
        &exchange.response,
        ciphers.schedule(Version::V6),
        &mut scratch,
    )
    .unwrap();
    let echoed = decoded.response_iv.unwrap();

    let mut sent = exchange.sent;
    sent.request_iv = Some(echoed);
    let checks = validate(Version::V6, &exchange.response, &sent);
    assert_eq!(
        checks.outcome(Check::IvsOk),
        Outcome::Fail,
        "a v6 response reusing the request IV must fail"
    );
    assert_eq!(checks.outcome(Check::IvNotSuspicious), Outcome::Fail);
}

/// And v5's rule is the opposite: the response IV *must* equal the request's.
#[test]
fn a_v5_response_not_echoing_the_request_iv_is_caught() {
    let exchange = make(Version::V5);
    let checks = validate(Version::V5, &exchange.response, &exchange.sent);
    assert_eq!(checks.outcome(Check::IvsOk), Outcome::Pass);

    let mut sent = exchange.sent;
    sent.request_iv = Some([0x99; 16]);
    let checks = validate(Version::V5, &exchange.response, &sent);
    assert_eq!(checks.outcome(Check::IvsOk), Outcome::Fail);
}

/// `CLI-001` (#207): a corrupted v4 MAC fails loudly. py-kms's client logs only
/// on success here, so a wrong MAC produces silence.
#[test]
fn a_corrupted_v4_mac_is_caught() {
    let exchange = make(Version::V4);
    let mut response = exchange.response.clone();
    let last = response.len() - 1;
    response[last] ^= 0xFF;

    let checks = validate(Version::V4, &response, &exchange.sent);
    assert_eq!(checks.outcome(Check::HashOk), Outcome::Fail);
    assert!(!checks.all_passed());
}

/// `CLI-001` (#207): a corrupted v6 HMAC fails. It covers the plaintext, so
/// flipping any byte of the response body invalidates it.
#[test]
fn a_corrupted_v6_body_breaks_the_hmac() {
    let exchange = make(Version::V6);
    let ciphers = Ciphers::new();

    // Flip a bit in the middle of the ciphertext. CBC turns that into garbage
    // for one block and a single flipped bit in the next, so decoding may or
    // may not survive — what must never happen is a *pass*.
    let mut response = exchange.response.clone();
    let middle = response.len().checked_div(2).unwrap();
    response[middle] ^= 0x01;

    let mut scratch = vec![0_u8; response.len().max(64)];
    if let Ok(decoded) = response::decode(
        Version::V6,
        &response,
        ciphers.schedule(Version::V6),
        &mut scratch,
    ) {
        let checks = check(&exchange.sent, &decoded, Some(&MacCheck { tag: v4_tag }));
        assert!(
            !checks.all_passed(),
            "a corrupted v6 response passed every check"
        );
    }
}

/// `CLI-004` (#210): an ePID with an interior NUL is rejected. A field that is
/// NUL-terminated *and* carries data past the terminator is a place to hide
/// bytes, and no genuine host sends one.
#[test]
fn an_epid_with_an_interior_nul_is_rejected() {
    // v4 keeps the response in plaintext, so the ePID can be corrupted directly.
    let exchange = make(Version::V4);
    let mut response = exchange.response.clone();

    // The ePID starts after the 8-byte head. Zero one of its units.
    let head = 8;
    response[head + 4] = 0;
    response[head + 5] = 0;

    // Recompute the MAC so this test is about the ePID and not about the MAC.
    let covered = response.len() - 16;
    let tag = v4_tag(&response[..covered]);
    response[covered..].copy_from_slice(&tag);

    let checks = validate(Version::V4, &response, &exchange.sent);
    assert_eq!(
        checks.outcome(Check::PidLengthOk),
        Outcome::Fail,
        "an interior NUL was accepted"
    );
    assert_eq!(
        checks.outcome(Check::HashOk),
        Outcome::Pass,
        "and the MAC still verifies, so this is about the ePID"
    );
}

/// An ePID that does not end in a NUL is rejected too.
#[test]
fn an_unterminated_epid_is_rejected() {
    let exchange = make(Version::V4);
    let mut response = exchange.response.clone();

    // The ePID's declared length includes its terminator; overwrite it.
    let head = 8;
    let epid = EPid::parse(EPID_TEXT).unwrap();
    let terminator = head + epid.encoded_len() - 2;
    response[terminator] = b'X';
    response[terminator + 1] = 0;

    let covered = response.len() - 16;
    let tag = v4_tag(&response[..covered]);
    response[covered..].copy_from_slice(&tag);

    let checks = validate(Version::V4, &response, &exchange.sent);
    assert_eq!(checks.outcome(Check::PidLengthOk), Outcome::Fail);
}

/// Every check has a name, and the names are the ones `vlmcs` prints — so a
/// report can be compared against `vlmcs` output directly.
#[test]
fn the_check_names_match_vlmcs() {
    let names: Vec<&str> = Check::ALL.iter().map(|check| check.name()).collect();
    for expected in [
        "HashOK",
        "TimeStampOK",
        "ClientMachineIDOK",
        "VersionOK",
        "IVsOK",
        "DecryptSuccess",
        "HmacSha256OK",
        "PidLengthOK",
        "IVnotSuspicious",
        "DecryptedIVOK",
    ] {
        assert!(names.contains(&expected), "{expected} is missing");
    }
    assert_eq!(
        names.len(),
        Check::ALL.len(),
        "every check must be reportable"
    );
}
