//! Every attacker-controlled length is checked against the buffer it indexes
//! (`SEC-003`, #195).
//!
//! # The bug class
//!
//! The KMD-loader defects the audit describes are all one shape: a length or a
//! pointer that came off the wire is compared against the wrong thing, or
//! against the right thing too late. Validation running *after* the loop that
//! already dereferenced; a bound checked with unchecked 64-bit addition, so it
//! wraps; a size check 160 bytes more permissive than the structure it guards.
//!
//! Compiling the product data in removes most of that class from this codebase,
//! and `#![deny(clippy::as_conversions)]` plus the `checked_*` discipline
//! removes the wrapping. What neither removes is the possibility of a parser
//! *believing* a declared length. That is what this file tests.
//!
//! # The invariant
//!
//! Every parser here returns borrowed slices. The invariant is therefore
//! checkable without knowing anything about the format: **whatever a parser
//! returns must lie inside the buffer it was given.** A parser that trusted a
//! declared length would either panic — caught — or hand back a slice reaching
//! past its input, which cannot happen in safe Rust and so shows up as a length
//! that exceeds the input instead.
//!
//! The inputs are the golden vectors (`TEST-002`, #223) with each length-shaped
//! field driven to its extremes, which is the systematic version of what the
//! fuzzer finds by search (`SEC-004`, #196).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::wire::header::HEADER_LEN;
use kmsrs_proto::wire::stub;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_proto::wire::{bind, connection};

/// Whether `part` is a subslice of `whole`.
///
/// By pointer range rather than by length, because a length comparison alone
/// would pass for a slice borrowed from somewhere else entirely — which is the
/// interesting failure if a parser ever starts returning owned or `'static`
/// data where the caller expects a view of its own buffer.
fn is_within(part: &[u8], whole: &[u8]) -> bool {
    if part.is_empty() {
        return true;
    }
    let outer = whole.as_ptr_range();
    let inner = part.as_ptr_range();
    inner.start >= outer.start && inner.end <= outer.end
}

/// The KMS payload inside a vector, which is what the framing layer sees.
///
/// `framing::decode` is handed the stub payload, not the PDU and not the RPC
/// stub. Feeding it the wrong slice would make every test below vacuous — every
/// variant would be refused for the same uninteresting reason — which is what
/// the "decoded nothing at all" assertions in each test are there to catch.
fn payload_of(pdu: &[u8]) -> Option<Vec<u8>> {
    let body = pdu.get(HEADER_LEN..)?;
    for syntax in [TransferSyntax::Ndr64, TransferSyntax::Ndr32] {
        if let Ok(parsed) = stub::parse_request(body, syntax) {
            return Some(parsed.data.to_vec());
        }
        if let Ok(parsed) = stub::parse_response(body, syntax) {
            return Some(parsed.payload.to_vec());
        }
    }
    None
}

/// Every value a length field is worth trying: zero, one, the extremes of each
/// width, and the value one past the buffer.
const EXTREMES: &[u32] = &[
    0,
    1,
    0x7F,
    0x80,
    0xFF,
    0x0100,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x0001_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
];

/// Every vector, with a 16- or 32-bit field at each even offset overwritten
/// with each extreme.
///
/// Blunt on purpose. Enumerating only the fields that are documented lengths
/// would test the parser against the format as understood by whoever wrote this
/// file, and the defect being looked for is precisely a field nobody realised
/// was a length.
fn hostile_variants(original: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for offset in (0..original.len()).step_by(2) {
        for value in EXTREMES {
            for width in [2_usize, 4] {
                if offset + width > original.len() {
                    continue;
                }
                let mut mutated = original.to_vec();
                let bytes = value.to_le_bytes();
                mutated[offset..offset + width].copy_from_slice(&bytes[..width]);
                out.push(mutated);
            }
        }
    }
    out
}

#[test]
fn no_stub_parse_returns_a_slice_outside_its_input() {
    let mut checked = 0_usize;
    for vector in kmsrs_vectors::VECTORS {
        for input in hostile_variants(vector.bytes) {
            let Some(body) = input.get(HEADER_LEN..) else {
                continue;
            };
            for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
                if let Ok(parsed) = stub::parse_request(body, syntax) {
                    assert!(
                        is_within(parsed.data, body),
                        "{}: request stub data escaped its body ({} bytes from a {} byte body)",
                        vector.name,
                        parsed.data.len(),
                        body.len()
                    );
                }
                if let Ok(parsed) = stub::parse_response(body, syntax) {
                    assert!(
                        is_within(parsed.payload, body),
                        "{}: response stub payload escaped its body",
                        vector.name
                    );
                    assert!(
                        is_within(parsed.padding, body),
                        "{}: response stub padding escaped its body",
                        vector.name
                    );
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 10_000, "only {checked} parses attempted");
}

#[test]
fn a_bind_body_never_reports_more_items_than_it_kept() {
    let mut accepted = 0_usize;
    for vector in kmsrs_vectors::VECTORS {
        for input in hostile_variants(vector.bytes) {
            let Some(body) = input.get(HEADER_LEN..) else {
                continue;
            };
            let Ok(request) = bind::parse(body) else {
                continue;
            };
            accepted += 1;

            // What the client declared is kept, but never believed: the array
            // is capped, and each item's syntax list is capped independently.
            // py-kms allocates from the declared count directly.
            assert!(request.items.len() <= request.declared_items);
            assert!(request.items.len() <= bind::MAX_CONTEXT_ITEMS);
            for item in &request.items {
                assert!(item.offered.len() <= bind::MAX_TRANSFER_SYNTAXES);
            }

            // And a decision can always be reached from whatever survived,
            // rather than the parser having handed on something undecidable.
            let _ = bind::decide(&request, true);
            let _ = bind::decide(&request, false);
        }
    }
    assert!(accepted > 0, "no hostile variant parsed as a bind at all");
}

#[test]
fn a_kms_payload_never_decodes_past_its_stub() {
    let ciphers = Ciphers::new();
    let mut decoded = 0_usize;
    for vector in kmsrs_vectors::VECTORS {
        let Some(payload) = payload_of(vector.bytes) else {
            continue;
        };
        for input in hostile_variants(&payload) {
            // The payload, and the payload minus a byte: the second is the case
            // where a length that was exactly right becomes one too long, which
            // is the off-by-one this file exists for.
            let truncated = input.get(..input.len().saturating_sub(1)).unwrap_or(&[]);
            for slice in [input.as_slice(), truncated] {
                if let Ok(request) = framing::decode(slice, &ciphers) {
                    assert!(Version::ALL.contains(&request.version));
                    decoded += 1;
                }
            }
        }
    }
    assert!(
        decoded > 0,
        "no hostile variant decoded as a request at all"
    );
}

#[test]
fn a_response_never_decodes_an_epid_past_its_scratch() {
    let ciphers = Ciphers::new();
    let mut decoded_any = 0_usize;
    for vector in kmsrs_vectors::VECTORS {
        let Some(payload) = payload_of(vector.bytes) else {
            continue;
        };
        for input in hostile_variants(&payload) {
            for version in Version::ALL {
                // Scratch exactly as long as the input, which is the smallest
                // the contract allows. A decoder that wrote a declared ePID
                // length into it without checking would run off the end.
                let mut scratch = vec![0_u8; input.len()];
                // Ranges taken before the call, since the decoded value borrows
                // both buffers for the rest of the scope.
                let input_range = input.as_ptr_range();
                let scratch_range = scratch.as_ptr_range();
                let Ok(decoded) =
                    response::decode(version, &input, ciphers.schedule(version), &mut scratch)
                else {
                    continue;
                };
                decoded_any += 1;

                // Every borrowed field points into one of the two buffers it
                // was given. `pid_size` is a *declared* length and the bytes
                // beside it are a real one; the decoder must never let the
                // first decide how much of the second to hand back.
                for (name, field) in [
                    ("pid_bytes", decoded.pid_bytes),
                    ("hmac_message", decoded.hmac_message),
                    ("mac_message", decoded.mac_message),
                    ("padding", decoded.padding),
                ] {
                    let start = field.as_ptr_range().start;
                    let end = field.as_ptr_range().end;
                    let inside_input =
                        field.is_empty() || (start >= input_range.start && end <= input_range.end);
                    let inside_scratch = field.is_empty()
                        || (start >= scratch_range.start && end <= scratch_range.end);
                    assert!(
                        inside_input || inside_scratch,
                        "{}: {name} ({} bytes) is in neither the response nor the scratch buffer",
                        vector.name,
                        field.len()
                    );
                }
                assert!(
                    decoded.wire_len <= input.len(),
                    "{}: claimed {} wire bytes from a {}-byte response",
                    vector.name,
                    decoded.wire_len,
                    input.len()
                );
            }
        }
    }
    assert!(
        decoded_any > 0,
        "no hostile variant decoded as a response at all"
    );
}

#[test]
fn the_connection_never_writes_more_than_its_output_buffer() {
    // A deliberately tight buffer. The machine must refuse to answer rather
    // than write past it, and must say so rather than truncating silently
    // (`SEC-012`, #204).
    for capacity in [0_usize, 1, HEADER_LEN, 64, 8192] {
        for vector in kmsrs_vectors::VECTORS {
            let mut machine = connection::Connection::new(0x1234_5678, true);
            let mut entropy =
                kmsrs_proto::entropy::testing::DeterministicEntropy::from_seed(0xABCD);
            let mut out = vec![0_u8; capacity];
            machine.receive(vector.bytes).unwrap();

            let step = machine.step(
                kmsrs_proto::time::Instant::from_nanos(1),
                &mut entropy,
                &mut |_request| {
                    connection::Decision::Refuse(kmsrs_proto::kms::hresult::HResult::from_wire(1))
                },
                &mut out,
            );
            match step {
                connection::Step::Send { len } | connection::Step::SendThenClose { len, .. } => {
                    assert!(
                        len <= capacity,
                        "{}: wrote {len} into a {capacity}-byte buffer",
                        vector.name
                    );
                }
                connection::Step::NeedMore | connection::Step::Close { .. } => {}
            }
        }
    }
}
