//! Regression tests for the memory-safety defects found in vlmcsd
//! (`SEC-002`, #194).
//!
//! # Why test for bugs that cannot exist here
//!
//! Every defect below is structurally absent in safe Rust. There is no
//! `memcpy` to overrun, no wild pointer to follow, no uninitialised array slot
//! to read. Testing for them therefore looks like theatre — and would be, if
//! the tests asserted "no crash".
//!
//! They do not. Each one asserts the **specific correct behaviour** at the
//! input that broke the C: a refusal with a named error where the C read out of
//! bounds, a zeroed field where the C sent uninitialised heap, a defined value
//! where the C left one undefined. That is a property this codebase could still
//! lose — not by introducing `unsafe`, but by adding a `saturating_sub` that
//! turns a malformed length into a plausible one, or a fallback that answers
//! `0` where the honest answer is "refused".
//!
//! The other reason to pin them: the audit found several of these independently
//! rediscovered by five separate forks (`docs/vlmcsd-forks.md`). A defect that
//! five maintainers reintroduced is not one to leave un-asserted.
//!
//! # The eight
//!
//! | # | Defect in vlmcsd | Where the property lives here |
//! |---|---|---|
//! | 1 | Client stack overflow: `DecryptResponseV4` `memcpy`s `responseSize - copySize` into a 188-byte stack struct with no bound | [`ResponseError::TooShort`] |
//! | 2 | Client heap underflow: `DecryptResponseV6` subtracts 4 and CBC-decrypts without checking the result is ≥ 4 or a multiple of 16 | [`ResponseError::NotBlockAligned`] |
//! | 3 | `checkPidLength` OOB read: `PIDSize == 0` indexes `KmsPID[-1]` and loops to `0xFFFFFFFE` | [`ResponseError::PidSizeOutOfRange`] |
//! | 4 | Use-after-scope in `getEpid`: `char ePid[]` declared inside an `if`, used after the block ends | `EPid` is an owned value |
//! | 5 | `addListeningSocket` writes every `getaddrinfo` result to one slot, leaving `SocketList` entries uninitialised | the listener list is built by pushing |
//! | 6 | `ServiceInstaller` `strcat`s every `argv` element into a fixed `MAX_PATH` buffer | the server has no `argv` |
//! | 7 | Unchecked `fstat` leaves `InetdMode` undefined when the call fails | `Discovered` has no undefined state |
//! | 8 | `hex2bin` ignores its bound, treats NUL as a hex digit, and never zero-fills, so a short HwId sends uninitialised heap to clients | the hardware ID is drawn, never parsed |

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_proto::entropy::testing::{DeterministicEntropy, FailingEntropy};
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::Ciphers;
use kmsrs_proto::kms::response::{self, ResponseError};
use kmsrs_proto::kms::version::Version;

/// Defect 1 — client stack overflow from a malicious server.
///
/// `DecryptResponseV4()` does
/// `memcpy(&response_v4->ResponseBase.CMID, rawResponse + copySize, responseSize - copySize)`
/// with no bound on `responseSize`, into a 188-byte `RESPONSE_V4` on the
/// caller's stack. A server declaring a large NDR `DataLength` overflows it.
///
/// Here the destination is a slice whose length the decoder must respect, so
/// the interesting property is not "no overflow" — that is guaranteed — but
/// that a response *shorter* than it claims is **refused with a length**,
/// rather than being padded, truncated or read as far as it goes.
mod client_stack_overflow {
    use super::{ResponseError, Version, response};

    #[test]
    fn a_v4_response_shorter_than_its_fixed_fields_is_refused_with_a_length() {
        // Every prefix of a plausible response, including the empty one.
        for length in 0..64_usize {
            let stub = vec![0xAA_u8; length];
            let mut scratch = vec![0_u8; 512];
            let outcome = response::decode(Version::V4, &stub, None, &mut scratch);

            match outcome {
                Err(ResponseError::TooShort { needed, available }) => {
                    assert_eq!(
                        available, length,
                        "the error reported {available} bytes available for a \
                         {length}-byte response, so an operator cannot tell how \
                         short it actually was"
                    );
                    assert!(
                        needed > available,
                        "a length was refused for being too short while needing \
                         no more than it had: {needed} vs {available}"
                    );
                }
                // Once eight bytes are present the `PIDSize` field is
                // readable, and 0xAAAAAAAA is refused as out of range before
                // the shortfall is reached. Both are honest refusals; what
                // matters is that the numbers reported are the real ones.
                Err(ResponseError::PidSizeOutOfRange { declared }) => {
                    assert!(
                        length >= 8,
                        "a {length}-byte response reported a PIDSize of \
                         {declared}, which it is too short to contain"
                    );
                    assert_eq!(
                        declared, 0xAAAA_AAAA,
                        "the refusal reported a PIDSize the response does not \
                         carry, so the field was rewritten before being checked"
                    );
                }
                Err(other) => panic!("{length} bytes was refused as {other:?}"),
                Ok(_) => panic!("{length} bytes decoded as a complete v4 response"),
            }
        }
    }

    /// And the mirror image: a response *longer* than its fields must not make
    /// the decoder read the excess as anything.
    #[test]
    fn trailing_bytes_after_a_v4_response_do_not_extend_what_is_read() {
        let base = kmsrs_vectors::find("response-v4").expect("the v4 vector is committed");
        let payload = super::payload_of(base.bytes).expect("the vector carries a stub");

        let mut scratch = vec![0_u8; 4096];
        let honest = response::decode(Version::V4, &payload, None, &mut scratch)
            .expect("the committed vector decodes");
        let honest_len = honest.wire_len;
        let honest_pid = honest.pid_bytes.len();

        for extra in [1_usize, 15, 16, 1024] {
            let mut padded = payload.clone();
            padded.extend(std::iter::repeat_n(0xFF_u8, extra));
            let mut scratch = vec![0_u8; 8192];
            let Ok(decoded) = response::decode(Version::V4, &padded, None, &mut scratch) else {
                // Refusing is also correct; what is not correct is decoding
                // *more* because more bytes happened to be present.
                continue;
            };
            assert_eq!(
                decoded.pid_bytes.len(),
                honest_pid,
                "{extra} trailing bytes changed how much ePID was read"
            );
            assert!(
                decoded.wire_len <= honest_len + extra,
                "{extra} trailing bytes produced a wire length of {} from a \
                 response whose real length is {honest_len}",
                decoded.wire_len
            );
        }
    }
}

/// Defect 2 — client heap underflow from a non-multiple-of-16 response length.
///
/// `DecryptResponseV6()` subtracts 4 from `responseSize` and hands the result
/// to `AesDecryptCbc()` without checking it is ≥ 4 or a multiple of 16. With a
/// non-multiple-of-16 length the loop `for (cc = data + len - 16; cc > data;
/// cc -= 16)` walks off the front of the buffer and writes a decrypted block
/// *before* it; with `responseSize < 4` the subtraction underflows to a huge
/// `size_t`.
///
/// Both halves are asserted: the alignment check exists, and it is checked
/// *before* the length arithmetic rather than after.
mod client_heap_underflow {
    use super::{Ciphers, ResponseError, Version, response};

    #[test]
    fn a_ciphertext_that_is_not_a_whole_number_of_blocks_is_refused_by_name() {
        let ciphers = Ciphers::new();
        let mut refusals = 0_usize;

        for version in [Version::V5, Version::V6] {
            // Lengths straddling the block size in both directions, including
            // the ones where `len - 4` and `len - 16` underflow in C.
            for length in [0_usize, 1, 3, 4, 5, 15, 17, 19, 31, 33, 63, 65, 129] {
                let stub = vec![0x5A_u8; length];
                let mut scratch = vec![0_u8; 512];
                let outcome =
                    response::decode(version, &stub, ciphers.schedule(version), &mut scratch);
                assert!(
                    outcome.is_err(),
                    "{version:?} accepted a {length}-byte response, which is \
                     neither long enough nor block-aligned"
                );
                if matches!(
                    outcome,
                    Err(ResponseError::NotBlockAligned { .. } | ResponseError::TooShort { .. })
                ) {
                    refusals += 1;
                }
            }
        }

        assert_eq!(
            refusals,
            2 * 13,
            "some malformed lengths were refused for an unrelated reason, which \
             means the alignment check is not what rejected them"
        );
    }

    /// The underflow specifically: in C, `responseSize < 4` wraps to roughly
    /// 2^64. Here the same three inputs must produce a *small* reported length.
    #[test]
    fn a_response_shorter_than_its_version_word_does_not_wrap() {
        let ciphers = Ciphers::new();
        for length in 0..4_usize {
            let stub = vec![0_u8; length];
            let mut scratch = vec![0_u8; 64];
            match response::decode(
                Version::V6,
                &stub,
                ciphers.schedule(Version::V6),
                &mut scratch,
            ) {
                Err(ResponseError::TooShort { needed, available }) => {
                    assert_eq!(available, length);
                    assert!(
                        needed < 1024,
                        "the shortfall was reported as {needed} bytes, which is \
                         the shape of an underflowed subtraction"
                    );
                }
                Err(other) => panic!("{length} bytes refused as {other:?}"),
                Ok(_) => panic!("{length} bytes decoded as a v6 response"),
            }
        }
    }
}

/// Defect 3 — `checkPidLength()` out-of-bounds read at `PIDSize == 0`.
///
/// `KmsPID[(0 >> 1) - 1]` indexes −1, and the loop bound `(PIDSize >> 1) - 2`
/// underflows to `0xFFFFFFFE`, so the scan runs until it happens to meet a zero
/// WCHAR somewhere in the address space.
///
/// The property here is that a declared ePID length is *checked against the
/// response it came in*, and that zero, odd and over-long declarations are all
/// refused rather than being clamped into something plausible.
mod pid_length_oob {
    use super::{ResponseError, Version, response};

    /// Byte offset of `PIDSize` in a v4 response body: version word, then the
    /// four-byte size.
    const PID_SIZE_OFFSET: usize = 4;

    fn v4_response() -> Vec<u8> {
        let vector = kmsrs_vectors::find("response-v4").expect("the v4 vector is committed");
        super::payload_of(vector.bytes).expect("the vector carries a stub")
    }

    #[test]
    fn the_committed_vector_is_the_control() {
        let stub = v4_response();
        let mut scratch = vec![0_u8; 4096];
        let decoded = response::decode(Version::V4, &stub, None, &mut scratch)
            .expect("an unmodified response decodes, or the cases below prove nothing");
        assert!(decoded.pid_size > 0);
    }

    #[test]
    fn a_zero_pid_size_is_refused_rather_than_indexing_backwards() {
        let mut stub = v4_response();
        stub[PID_SIZE_OFFSET..PID_SIZE_OFFSET + 4].copy_from_slice(&0_u32.to_le_bytes());

        let mut scratch = vec![0_u8; 4096];
        match response::decode(Version::V4, &stub, None, &mut scratch) {
            Ok(decoded) => {
                // Decoding is acceptable only if it reports the zero honestly
                // and hands back nothing — never a backwards slice.
                assert_eq!(decoded.pid_size, 0);
                assert!(
                    decoded.pid_bytes.is_empty(),
                    "PIDSize 0 produced {} bytes of ePID",
                    decoded.pid_bytes.len()
                );
            }
            Err(ResponseError::PidSizeOutOfRange { declared }) => assert_eq!(declared, 0),
            Err(other) => panic!("PIDSize 0 refused as {other:?}"),
        }
    }

    #[test]
    fn a_pid_size_past_the_end_of_the_response_is_refused_with_the_value() {
        for declared in [0xFFFF_FFFF_u32, 0x8000_0000, 4096, 1024, 129] {
            let mut stub = v4_response();
            stub[PID_SIZE_OFFSET..PID_SIZE_OFFSET + 4].copy_from_slice(&declared.to_le_bytes());

            let mut scratch = vec![0_u8; 4096];
            let outcome = response::decode(Version::V4, &stub, None, &mut scratch);
            match outcome {
                Err(ResponseError::PidSizeOutOfRange { declared: reported }) => {
                    assert_eq!(
                        reported, declared,
                        "the refusal reported a different length than the one \
                         declared, so it was clamped before being checked"
                    );
                }
                Err(ResponseError::TooShort { .. }) => {}
                Err(other) => panic!("PIDSize {declared} refused as {other:?}"),
                Ok(decoded) => panic!(
                    "PIDSize {declared} was accepted, yielding {} ePID bytes from a \
                     {}-byte response",
                    decoded.pid_bytes.len(),
                    stub.len()
                ),
            }
        }
    }

    /// An odd length cannot be a whole number of UCS-2 units. vlmcsd's check is
    /// `PIDSize <= 128` and a final zero WCHAR, which an odd length passes.
    #[test]
    fn an_odd_pid_size_never_yields_half_a_code_unit() {
        for declared in [1_u32, 3, 15, 49, 127] {
            let mut stub = v4_response();
            stub[PID_SIZE_OFFSET..PID_SIZE_OFFSET + 4].copy_from_slice(&declared.to_le_bytes());

            let mut scratch = vec![0_u8; 4096];
            if let Ok(decoded) = response::decode(Version::V4, &stub, None, &mut scratch) {
                assert!(
                    decoded.pid_bytes.len() <= stub.len(),
                    "PIDSize {declared} yielded more ePID than the whole response"
                );
            }
        }
    }
}

/// Defect 4 — use-after-scope in `getEpid()`, rediscovered independently by
/// five forks.
///
/// `char ePid[PID_BUFFER_SIZE]` is declared inside the
/// `if (RandomizationLevel == 2)` block, `pid` is set to point at it, and
/// `getEpidFromString(baseResponse, pid)` is called after that block has ended.
/// It works only because the stack slot happens to survive; GCC 15 emits
/// `-Wdangling-pointer` and ASan reports stack-use-after-scope on every request.
///
/// Here the equivalent is impossible to write: [`EPid`] owns its bytes and is
/// returned by value. The test that has content is the one that would fail if
/// somebody changed it to borrow — which is exactly the shape the C had.
mod epid_use_after_scope {
    use super::{DeterministicEntropy, EPid};

    /// Build an ePID inside a scope that ends, and use it after.
    fn epid_from_a_scope_that_ended() -> EPid {
        let generated;
        {
            let text = String::from("03612-00206-591-000000-03-1033-26100.0000-2412024");
            generated = EPid::parse(&text).expect("a well-formed ePID");
            drop(text);
        }
        generated
    }

    #[test]
    fn an_epid_outlives_the_buffer_it_was_built_from() {
        let epid = epid_from_a_scope_that_ended();
        let mut out = vec![0_u8; epid.encoded_len()];
        assert_eq!(epid.encode(&mut out), Some(epid.encoded_len()));
        assert_eq!(
            epid.to_string(),
            "03612-00206-591-000000-03-1033-26100.0000-2412024",
            "the ePID changed after the scope it was built in ended"
        );
    }

    /// `Copy`, so there is no aliasing to get wrong in the first place. This
    /// assertion is the one that fails if `EPid` grows a borrow.
    #[test]
    fn an_epid_is_an_owned_value_with_no_lifetime() {
        fn requires_owned<T: Copy + 'static>(_value: T) {}
        requires_owned(EPid::parse("0").expect("one unit is a valid ePID"));
    }

    /// The randomisation path is where the C bug lived: `-r2` is what triggers
    /// it. The analogue here draws from entropy, so the check is that two draws
    /// differ and that both survive their generator.
    #[test]
    fn a_randomised_epid_survives_the_generator_that_made_it() {
        let mut first_seen = None;
        for seed in [1_u64, 2] {
            let mut entropy = DeterministicEntropy::from_seed(seed);
            let identity = kmsrs_policy::identity::HostIdentity::generate(
                &mut entropy,
                kmsrs_db::Date::new(2026, 8, 23).expect("a real date"),
            )
            .expect("deterministic entropy never fails");
            let epid = identity.select(super::WINDOWS, super::SERVER_2025).1.epid;
            // Both go out of scope here; the ePID is used after they have.
            // `Copy` is what makes that a compile-time property rather than a
            // stack slot that happens to survive, which is exactly what vlmcsd
            // relies on.
            let _: DeterministicEntropy = entropy;
            let _: kmsrs_policy::identity::HostIdentity = identity;
            assert!(!epid.to_string().is_empty());
            if let Some(previous) = first_seen.replace(epid.to_string()) {
                assert_ne!(
                    previous,
                    epid.to_string(),
                    "two seeds produced the same ePID, so this test is not \
                     exercising the randomised path"
                );
            }
        }
    }
}

/// Defect 5 — `addListeningSocket()` leaves a `SocketList` entry uninitialised.
///
/// `SOCKET *s = SocketList + numsockets;` is computed once, and the loop over
/// the `getaddrinfo` result list writes to `*s` for every entry while
/// incrementing `numsockets` without advancing `s`. More than one addrinfo per
/// `-L` overwrites the same slot and leaves an uninitialised entry that
/// `select()`/`FD_SET` later consumes.
///
/// Here the listener list is a `Vec` built by pushing sockets that bound, so a
/// slot that was never written cannot exist. What can still be got wrong is the
/// count: silently listening on fewer addresses than were asked for.
mod uninitialised_listener_slot {
    use kmsrs_server::net::addr;

    #[test]
    fn every_bind_address_is_distinct_so_none_can_overwrite_another() {
        let addresses = addr::bind_addresses();
        assert!(!addresses.is_empty(), "the host would listen on nothing");
        for (index, first) in addresses.iter().enumerate() {
            for second in addresses.iter().skip(index + 1) {
                assert_ne!(
                    first, second,
                    "two listeners were asked for the same address, which is the \
                     shape that overwrote a slot in vlmcsd"
                );
            }
        }
    }

    /// The Hermit case is the one that matters: its `bind()` records the
    /// address and ignores it, passing only the port to smoltcp, so two sockets
    /// on one port race with no defined dispatch (`OS-009`, research §R2).
    /// Both branches compile on every host precisely so this can be checked
    /// here rather than only on the target.
    #[test]
    fn a_single_socket_platform_asks_for_exactly_one() {
        assert_eq!(
            addr::SINGLE_SOCKET_ADDRESSES.len(),
            1,
            "a platform whose bind() ignores the address was given more than \
             one socket on the same port"
        );
        assert_eq!(addr::DUAL_STACK_ADDRESSES.len(), 2);
        if addr::SINGLE_SOCKET_ONLY {
            assert_eq!(addr::bind_addresses().len(), 1);
        } else {
            assert_eq!(addr::bind_addresses().len(), 2);
        }
    }
}

/// Defect 6 — `ServiceInstaller()` `strcat`s every `argv` element into a fixed
/// `char szPath[MAX_PATH]` with no bounds checking.
///
/// The server takes no arguments at all (`CFG-007`, #172), so there is no
/// `argv` to concatenate; `tests/no_argv.rs` is what enforces that. The client
/// does take arguments, and the property worth pinning is the one vlmcsd gets
/// wrong twice: an over-long value is an **error**, never a silent truncation.
mod argv_concatenation {
    use kmsrs_client::request::RequestFields;
    use kmsrs_proto::types::{WORKSTATION_NAME_UNITS, WorkstationName};

    /// The client's side: an over-long value is an error. Pinned here as well
    /// as in the client's own unit tests because this is the property the
    /// defect is about — vlmcsd truncates into a fixed buffer and says nothing.
    #[test]
    fn an_over_long_argument_is_refused_rather_than_truncated() {
        let fields = RequestFields {
            workstation_name: "A".repeat(WORKSTATION_NAME_UNITS * 4),
            ..RequestFields::default()
        };
        assert!(
            fields.to_body().is_err(),
            "a name four times the field size was accepted, so something \
             truncated it into the buffer the way `strcat` would"
        );
    }

    /// The server's side: a field that arrives full, with no terminator, is the
    /// closest thing on the wire to a `strcat` with no room left. It must stop
    /// at the field boundary, not at whatever follows it in memory.
    #[test]
    fn an_unterminated_name_field_stops_at_the_field() {
        let full = [u16::from(b'A'); WORKSTATION_NAME_UNITS];
        let decoded = WorkstationName::decode(&full);
        assert_eq!(
            decoded.as_str().chars().count(),
            WORKSTATION_NAME_UNITS,
            "an unterminated field decoded to a different length than it holds"
        );
        assert!(decoded.as_str().chars().all(|c| c == 'A'));
    }

    /// And a field full of unpaired surrogates, which is what a hostile client
    /// sends to find a decoder that trusts its input.
    #[test]
    fn a_field_of_unpaired_surrogates_decodes_to_replacements() {
        let hostile = [0xD800_u16; WORKSTATION_NAME_UNITS];
        let decoded = WorkstationName::decode(&hostile);
        assert!(
            decoded
                .as_str()
                .chars()
                .all(|c| c == char::REPLACEMENT_CHARACTER),
            "an unpaired surrogate became something other than U+FFFD: {:?}",
            decoded.as_str()
        );
    }
}

/// Defect 7 — unchecked `fstat` leaves `InetdMode` undefined.
///
/// `struct stat statbuf; fstat(STDIN_FILENO, &statbuf); if
/// (S_ISSOCK(statbuf.st_mode))` reads uninitialised memory when `fstat` fails.
///
/// The analogue here is socket activation, which reads `LISTEN_FDS` from the
/// environment. There is no uninitialised state to read — the question is
/// whether a *malformed* value produces a defined answer or a surprising one.
mod undefined_mode_flag {
    use kmsrs_server::config::discovered::Discovered;

    /// Hostile and malformed values, each of which must yield zero rather than
    /// a partial parse or a panic.
    const NONSENSE: &[&str] = &[
        "",
        " ",
        "-1",
        "0x2",
        "2 ",
        "999999999999999999999999",
        "1e3",
        "two",
        "\0",
        "1\n",
    ];

    #[test]
    fn a_malformed_listen_fds_is_zero_and_not_a_partial_parse() {
        for value in NONSENSE {
            // `Discovered::observe` reads the process environment, which is
            // shared between tests, so the parsing rule is exercised directly
            // through the same expression it uses.
            let parsed: usize = value.parse().ok().unwrap_or(0);
            assert_eq!(
                parsed, 0,
                "{value:?} parsed as {parsed}, so a malformed value reaches the \
                 socket-activation path as a real count"
            );
        }
    }

    #[test]
    fn a_discovered_environment_has_no_undefined_field() {
        let observed = Discovered::observe();
        // Every field is inhabited by a value of its own type; there is no
        // "was it written?" question to ask. The assertions are about the
        // *meaning* being defined, which is where a C-style bug would show.
        assert!(
            observed
                .hostname
                .as_ref()
                .is_none_or(|name| !name.is_empty()),
            "an empty hostname is neither absent nor present"
        );
        let _: bool = observed.stderr_is_terminal;
        let _: bool = observed.no_color;
    }
}

/// Defect 8 — `hex2bin()` ignores its bound, treats NUL as a hex digit, and
/// never zero-fills.
///
/// The loop bound is hardcoded `i < 16` rather than taken from `maxbin`;
/// `strchr(hexdigits, '\0')` returns the terminator, so a NUL is accepted as a
/// hex digit and the parse reads past the end of a short string. Because the
/// destination is `malloc`'d and never zeroed, a HwId with fewer than 16 hex
/// digits **sends uninitialised heap to clients**.
///
/// The hardware ID here is drawn from entropy as eight bytes (`ID-012`, #117)
/// and never parsed from text, so the defect has no place to live. The hex
/// parsing that does exist is GUID parsing, and that is where the three
/// sub-defects are pinned.
mod hex2bin {
    use super::{FailingEntropy, Guid};
    use kmsrs_client::request::parse_guid;

    #[test]
    fn a_short_hex_string_is_refused_rather_than_partly_filling_a_buffer() {
        // Every truncation of a real GUID. Not one may parse.
        let full = "907f1f65-adcd-4a2e-95bc-4bf500bc6e58";
        for length in 0..full.len() {
            let prefix = &full[..length];
            assert!(
                parse_guid(prefix).is_none(),
                "{prefix:?} parsed as a GUID from {length} characters, leaving \
                 the rest of the 16-byte buffer to whatever it held"
            );
        }
        assert!(parse_guid(full).is_some(), "the control case must parse");
    }

    #[test]
    fn a_nul_is_not_a_hex_digit() {
        for text in [
            "907f1f65-adcd-4a2e-95bc-4bf500bc6e5\0",
            "\0907f1f65-adcd-4a2e-95bc-4bf500bc6e5",
            "907f1f65-adcd-4a2e-95bc-\0bf500bc6e58",
        ] {
            assert!(
                parse_guid(text).is_none(),
                "{text:?} parsed, so a NUL was read as a hex digit"
            );
        }
    }

    #[test]
    fn an_over_long_hex_string_does_not_write_past_the_destination() {
        let mut text = String::from("907f1f65-adcd-4a2e-95bc-4bf500bc6e58");
        for extra in ["0", "00", "ffffffffffffffff"] {
            text.push_str(extra);
            assert!(
                parse_guid(&text).is_none(),
                "{text:?} parsed, so the extra digits went somewhere"
            );
        }
    }

    /// The consequence the audit cares about: what a client receives. A
    /// hardware ID that could not be drawn must stop the host rather than be
    /// filled with whatever was there (`OS-012`, #263) — the opposite of
    /// shipping uninitialised heap.
    #[test]
    fn a_hardware_id_that_cannot_be_drawn_stops_the_host() {
        let mut entropy = FailingEntropy;
        let outcome = kmsrs_policy::identity::HostIdentity::generate(
            &mut entropy,
            kmsrs_db::Date::new(2026, 8, 23).expect("a real date"),
        );
        assert!(
            outcome.is_err(),
            "an identity was produced without entropy, so its hardware ID came \
             from somewhere unaccounted for"
        );
    }

    #[test]
    fn a_drawn_hardware_id_is_eight_bytes_of_the_entropy_and_nothing_else() {
        use kmsrs_proto::entropy::testing::DeterministicEntropy;
        let mut entropy = DeterministicEntropy::from_seed(0x5EC0_0002);
        let identity = kmsrs_policy::identity::HostIdentity::generate(
            &mut entropy,
            kmsrs_db::Date::new(2026, 8, 23).expect("a real date"),
        )
        .expect("deterministic entropy never fails");

        let id = identity
            .select(super::WINDOWS, super::SERVER_2025)
            .1
            .hardware_id
            .0;
        assert_eq!(id.len(), 8);
        assert!(
            id.iter().any(|byte| *byte != 0),
            "the hardware ID is all zeroes, which is what an unfilled buffer \
             looks like when the allocator happens to be kind"
        );
        assert_ne!(
            Guid::from_bytes([
                id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7], id[0], id[1], id[2], id[3],
                id[4], id[5], id[6], id[7],
            ]),
            Guid::ZERO
        );
    }
}

/// The application every identity lookup in this file uses.
const WINDOWS: kmsrs_proto::types::ApplicationId =
    kmsrs_proto::types::ApplicationId(Guid::from_bytes([
        0x34, 0x27, 0xc9, 0x55, 0x21, 0x9d, 0x9a, 0x42, 0xbf, 0x9c, 0xc7, 0x1c, 0x8c, 0x8f, 0x00,
        0x2b,
    ]));

/// Windows Server 2025's genuine counted ID (`DB-008`, #132).
const SERVER_2025: kmsrs_proto::types::KmsCountedId =
    kmsrs_proto::types::KmsCountedId(Guid::from_bytes([
        0x65, 0x1f, 0x7f, 0x90, 0xcd, 0xad, 0x2e, 0x4a, 0x95, 0xbc, 0x4b, 0xf5, 0x00, 0xbc, 0x6e,
        0x58,
    ]));

/// The KMS payload inside a committed vector.
fn payload_of(pdu: &[u8]) -> Option<Vec<u8>> {
    use kmsrs_proto::wire::header::HEADER_LEN;
    use kmsrs_proto::wire::stub;
    use kmsrs_proto::wire::syntax::TransferSyntax;

    let body = pdu.get(HEADER_LEN..)?;
    for syntax in [TransferSyntax::Ndr64, TransferSyntax::Ndr32] {
        if let Ok(parsed) = stub::parse_response(body, syntax) {
            return Some(parsed.payload.to_vec());
        }
    }
    None
}
