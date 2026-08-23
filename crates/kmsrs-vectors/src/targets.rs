//! The bodies of the six fuzz targets (`SEC-004`, #196).
//!
//! # Why these live here and not in `fuzz/fuzz_targets`
//!
//! `cargo fuzz` needs a nightly toolchain for `-Zsanitizer=address`, and this
//! workspace is pinned to stable (`ARCH-016`, #16). Code that only ever
//! compiles under a toolchain CI does not run is code nobody checks: it rots,
//! and the rot is invisible until the day someone actually reaches for the
//! fuzzer.
//!
//! So the interesting part of each target — which parsers to call, with what
//! arguments, and which invariants to assert — is an ordinary function in an
//! ordinary workspace crate. It is type-checked by `cargo check`, linted by
//! `cargo clippy --all-targets`, exercised on every commit by
//! `tests/fuzz_seeds.rs`, and measured by `cargo llvm-cov` (`TEST-006`, #227).
//! Each file under `fuzz/fuzz_targets/` is then a three-line shim that hands
//! `libFuzzer`'s bytes to the function here.
//!
//! # The contract these functions obey
//!
//! A target must not panic *on its own account*. Every `assert!` below is a
//! deliberate invariant of the code under test, so that the fuzzer finds wrong
//! answers and not just crashes; anything else is written to be total. That is
//! why the workspace deny list (`ARCH-008`, #8) is left switched on for this
//! module rather than blanket-allowed the way test files are.

// Every panic in this module is a deliberate invariant assertion, documented
// at its site — a `# Panics` section on each target would say the same thing
// six times and imply the panics were incidental.
#![expect(
    clippy::missing_panics_doc,
    reason = "a target panics exactly when it has found a bug; that is the interface"
)]

use alloc::vec;
use kmsrs_crypto::cbc::{self, Iv};
use kmsrs_crypto::rijndael::KeySchedule;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::time::Instant;
use kmsrs_proto::types::{HardwareId, Intervals};
use kmsrs_proto::wire::connection::{Connection, Decision, Grant, Step};
use kmsrs_proto::wire::header::RpcHeader;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_proto::wire::{bind, stub};
use zerocopy::FromBytes;

/// A target body: bytes in, nothing out, a panic if it found something.
pub type Target = fn(&[u8]);

/// Every target, by the name `cargo fuzz` knows it under.
///
/// The seed test walks this, so adding a target without a committed seed set
/// fails a test rather than being silently unfuzzed.
pub const TARGETS: &[(&str, Target)] = &[
    ("rpc_pdu", rpc_pdu),
    ("connection", connection),
    ("kms_payload", kms_payload),
    ("decrypt_unpad", decrypt_unpad),
    ("epid", epid),
    ("response", response),
];

/// Run one target by name.
///
/// Returns `false` if no such target exists.
pub fn run(name: &str, data: &[u8]) -> bool {
    for (target, body) in TARGETS {
        if *target == name {
            body(data);
            return true;
        }
    }
    false
}

/// The ePID the connection target grants, which is a real Server 2025 shape.
const GRANT_EPID: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";

/// The DCE/RPC common header and the bodies read straight off it
/// (`SEC-004`, #196; `WIRE-025`, #83).
///
/// The first parser a byte from a socket reaches. Neither vlmcsd nor py-kms has
/// ever fed a malformed PDU at its own decoder, which the cross-implementation
/// audit calls the single highest-value missing QA capability in the ecosystem.
pub fn rpc_pdu(data: &[u8]) {
    // The common header. Reading it must never depend on the bytes being
    // sensible — only on there being sixteen of them.
    if let Ok((header, rest)) = RpcHeader::read_from_prefix(data) {
        // Whatever the wire says, these are total.
        let _ = header.packet_type();
        let _ = header.flags();
        let _ = header.version_is_supported();

        // The bind body declares a count and then a variable-length array,
        // which is the shape where a length check in the wrong place is fatal.
        if let Ok(request) = bind::parse(rest) {
            // The item count is capped, and what the client *declared* is kept
            // separately from what was kept, so a client claiming thousands of
            // contexts is recorded rather than believed (`WIRE-007`, #65).
            assert!(request.items.len() <= request.declared_items);
            for item in &request.items {
                let _ = item.names_kms_interface();
                let _ = item.feature_bits();
                let _ = item.offer_for(TransferSyntax::Ndr32);
                let _ = item.offer_for(TransferSyntax::Ndr64);
            }
            // And the decision made from it, for both NDR64 settings.
            let _ = bind::decide(&request, true);
            let _ = bind::decide(&request, false);
        }

        // Both stub layouts, since the width of the NDR length fields differs
        // between them (`WIRE-029`, #87).
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            let _ = stub::parse_request(rest, syntax);
            let _ = stub::parse_response(rest, syntax);
        }
    }

    // And again treating the whole input as a body, so a corpus entry that is
    // already a stub is not wasted on a header parse that consumes it.
    let _ = bind::parse(data);
    for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
        let _ = stub::parse_request(data, syntax);
        let _ = stub::parse_response(data, syntax);
    }
}

/// The whole connection state machine, over a sequence of PDUs
/// (`SEC-004`, #196; `WIRE-022`, #80).
///
/// The most valuable of the six, because it fuzzes *state* rather than a single
/// parse. The first input byte chooses a chunk size and the rest is fed in
/// pieces of that size, so one corpus entry explores many fragmentations of the
/// same bytes: partial headers, PDUs split mid-body, several PDUs arriving in
/// one read, and a stream that stops in the middle.
///
/// It is three dozen lines only because the core is sans-io (axiom A7). There
/// is no socket to stand up, no clock to fake and no thread to join.
pub fn connection(data: &[u8]) {
    let Some((first, rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(*first).max(1);

    let Ok(granted) = EPid::parse(GRANT_EPID) else {
        return;
    };
    let decision = Decision::Grant(Grant {
        epid: granted,
        count: 50,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([1, 2, 3, 4, 5, 6, 7, 8]),
    });

    let mut connection = Connection::new(0x1234_5678, true);
    let mut entropy = DeterministicEntropy::from_seed(0xF0F0_F0F0);
    let mut out = vec![0_u8; OUTPUT_BUDGET];
    let mut tick = 0_u64;

    for piece in rest.chunks(chunk) {
        if connection.receive(piece).is_err() {
            // A client that overruns the receive buffer is refused, and the
            // machine is done. Continuing would fuzz a state no driver reaches.
            return;
        }
        // Drain everything the machine will produce from what it now has. The
        // bound is a runaway guard, not a protocol limit: `step` returning
        // `Send` forever without consuming input would be a bug, and hanging
        // the fuzzer is a worse way to report it than finishing quietly.
        for _ in 0..MAX_STEPS_PER_CHUNK {
            tick = tick.wrapping_add(1);
            let step = connection.step(
                Instant::from_nanos(tick),
                &mut entropy,
                &mut |_request| decision.clone(),
                &mut out,
            );
            match step {
                Step::NeedMore => break,
                Step::Close { .. } | Step::SendThenClose { .. } => return,
                Step::Send { len } => {
                    // Anything the machine claims to have written must be
                    // inside the buffer it was handed. This is the invariant
                    // that a driver trusts when it calls `write` (`WIRE-021`,
                    // #79), so it is worth asserting rather than assuming.
                    assert!(
                        len <= out.len(),
                        "step wrote {len} into {} bytes",
                        out.len()
                    );
                }
            }
        }
        // Events must be drainable at any point, in any state.
        while connection.next_event().is_some() {}
    }
}

/// Room for the largest reply, with slack so a too-small buffer is never what
/// the fuzzer finds.
const OUTPUT_BUDGET: usize = 8192;

/// How many replies one chunk may produce before the target gives up.
const MAX_STEPS_PER_CHUNK: usize = 16;

/// The KMS request payload, at every version (`SEC-004`, #196; `KMS-002`, #18).
///
/// Where a length field meets a cipher: v5 and v6 decrypt before they parse, so
/// a malformed length is reachable only *after* a block cipher has run over
/// attacker bytes. `decode` picks the version out of the bytes themselves, so
/// this covers all three plus every value that is not a version at all.
pub fn kms_payload(data: &[u8]) {
    let ciphers = Ciphers::new();
    if let Ok(request) = framing::decode(data, &ciphers) {
        // A decoded request must agree with itself: the version it reports is
        // one this host answers, and the length of the response it would
        // produce is something the encoder can state in advance
        // (`KMS-023`, #39) rather than discover while writing.
        assert!(Version::ALL.contains(&request.version));
        let granted = EPid::parse(GRANT_EPID);
        if let Ok(granted) = granted {
            assert!(framing::response_len(request.version, &granted) <= OUTPUT_BUDGET);
        }
    }
}

/// CBC decryption and padding removal (`SEC-004`, #196; `CRY-014`, #53).
///
/// Padding removal is the classic place to find an out-of-bounds read: the
/// length comes from the last byte of the plaintext, which after a decryption
/// of attacker-chosen ciphertext is a length field the attacker writes
/// directly. Both IV modes are exercised, because [`Iv::Null`] is not an absent
/// IV but a deliberate protocol trick with different reachable states.
pub fn decrypt_unpad(data: &[u8]) {
    let schedule = KeySchedule::aes128(&[0x2A; 16]);
    let iv = [0x11_u8; 16];

    for mode in [Iv::Null, Iv::Block(&iv)] {
        let mut plaintext = vec![0_u8; data.len()];
        if cbc::decrypt(&schedule, mode, data, &mut plaintext).is_ok() {
            // A successful decryption fills exactly as much as it was given.
            assert_eq!(plaintext.len(), data.len());
            if let Ok(stripped) = cbc::strip_padding(&plaintext) {
                assert!(stripped.len() <= plaintext.len());
            }
        }
    }

    // And directly, so the corpus does not have to find block-aligned inputs
    // before the unpadder is reached at all.
    if let Ok(stripped) = cbc::strip_padding(data) {
        assert!(stripped.len() <= data.len());
    }
}

/// The ePID parser and encoder (`SEC-004`, #196; `ID-008`, #113).
///
/// An ePID is the one place text meets the wire: UTF-16 on the wire, parsed
/// from a `str` here. Both directions run, and the round trip is asserted,
/// because an encoder that disagrees with its own declared length is how a
/// response ends up with a `PIDSize` that does not match its own bytes — the
/// defect a genuine client notices and an emulator does not.
pub fn epid(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(parsed) = EPid::parse(text) else {
        return;
    };

    let needed = parsed.encoded_len();
    assert_eq!(
        needed,
        parsed.units().len().saturating_add(1).saturating_mul(2)
    );

    let mut out = vec![0_u8; needed];
    assert_eq!(parsed.encode(&mut out), Some(needed));
    // The terminating NUL is part of what is written, and `PIDSize` counts it.
    // A `PIDSize` that disagrees with the bytes beside it is the defect a
    // genuine client notices and an emulator does not (`KMS-011`, #27).
    assert_eq!(out.get(needed.saturating_sub(2)..), Some(&[0, 0][..]));
    assert_eq!(usize::try_from(parsed.pid_size().get()), Ok(needed));

    // One byte short must fail rather than truncate.
    if let Some(short) = needed.checked_sub(1) {
        let mut small = vec![0_u8; short];
        assert_eq!(parsed.encode(&mut small), None);
    }
}

/// The response decoder, at every version (`SEC-004`, #196; `CLI-003`, #209).
///
/// The client's side of the wire. A diagnostic tool pointed at an unknown host
/// reads whatever that host sends, which is exactly as untrusted as what a
/// server receives — and this is the parser that takes a declared ePID length
/// out of freshly decrypted bytes.
pub fn response(data: &[u8]) {
    let ciphers = Ciphers::new();
    for version in Version::ALL {
        let mut scratch = vec![0_u8; data.len().saturating_add(64)];
        let _ = response::decode(version, data, ciphers.schedule(version), &mut scratch);
    }
}
