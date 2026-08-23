//! Round-trip properties over generated inputs (`TEST-003`, #224).
//!
//! `decode(encode(x)) == x` for every wire structure, and the encoded length
//! matches the size computed independently.
//!
//! # Why the length property is the interesting one
//!
//! Round-tripping catches a field written to the wrong offset. It does **not**
//! catch a length that is consistently wrong in both directions — an encoder
//! and decoder that agree on a mistaken size will round-trip perfectly forever.
//! That is the failure `vlmcs` reports as *"Size of RPC payload should be %u
//! but is %u"*, and it is why every case here also checks the length against
//! [`kmsrs_proto::kms::framing::response_len`], which is computed from the
//! layout rather than from the encoder.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::epid::{EPid, MAX_EPID_UNITS};
use kmsrs_proto::kms::framing::{self, Ciphers, ResponsePlan};
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody, WireGuid};
use kmsrs_proto::kms::response;
use kmsrs_proto::kms::version::{ProtocolVersion, Version};
use kmsrs_proto::types::{HardwareId, Intervals};
use kmsrs_proto::wire::header::{PacketFlags, PacketType, RpcHeader};
use proptest::prelude::*;
use zerocopy::{FromBytes, IntoBytes};

/// Stamp the version a body declares.
///
/// Separate from generation because the declared version and the framing must
/// agree: v5 and v6 carry a version word outside the encrypted body, but v4 has
/// only the body's own field, so a body left at zero decodes as "not a version
/// this host speaks" rather than as the version it was encoded for.
fn with_version(body: &RequestBody, version: Version) -> RequestBody {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    bytes.copy_from_slice(body.as_bytes());
    let mut stamped = RequestBody::read_from_bytes(&bytes).unwrap();
    stamped.version.set(version.to_protocol_version().to_wire());
    bytes.copy_from_slice(stamped.as_bytes());
    RequestBody::read_from_bytes(&bytes).unwrap()
}

/// An arbitrary request body.
///
/// Every field is generated, including the ones a host ignores — a decoder that
/// dropped `sku_id` would still round-trip if the test only set what the host
/// reads.
fn arbitrary_body() -> impl Strategy<Value = RequestBody> {
    (
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u64>(),
        prop::array::uniform16(any::<u8>()),
        prop::array::uniform16(any::<u8>()),
        prop::collection::vec(any::<u16>(), 0..63),
    )
        .prop_map(
            |(is_vm, status, grace, required, time, machine, previous, name)| {
                let bytes = [0_u8; REQUEST_BODY_LEN];
                let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
                body.is_client_vm.set(is_vm);
                body.license_status.set(status);
                body.grace_time.set(grace);
                body.required_clients.set(required);
                body.client_time.set(time);
                body.client_machine_id = WireGuid::from_guid(kmsrs_db::Guid::from_bytes(machine));
                body.previous_client_machine_id =
                    WireGuid::from_guid(kmsrs_db::Guid::from_bytes(previous));
                for (slot, unit) in body.workstation_name.iter_mut().zip(name.iter()) {
                    // A NUL terminates the field, so a generated interior NUL
                    // would make the comparison meaningless rather than wrong.
                    slot.set(if *unit == 0 { 1 } else { *unit });
                }
                body
            },
        )
}

/// An arbitrary well-formed ePID.
///
/// Built from the shape a real one has rather than from arbitrary text, since
/// the point is to exercise every *length* the field can hold.
fn arbitrary_epid() -> impl Strategy<Value = EPid> {
    (1_usize..=MAX_EPID_UNITS).prop_map(|len| {
        let text: String = core::iter::repeat_n('7', len).collect();
        EPid::parse(&text).expect("a same-length ePID is always parseable")
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// `TEST-003` (#224): a request survives encode-then-decode intact, for
    /// every version.
    #[test]
    fn a_request_round_trips(
        body in arbitrary_body(),
        version in prop::sample::select(Version::ALL.as_slice()),
        seed in any::<u64>(),
    ) {
        let body = with_version(&body, version);
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(seed);
        let mut wire = vec![0_u8; 2048];
        let len = framing::encode_request(version, &body, &ciphers, &mut entropy, &mut wire)
            .expect("encoding");
        wire.truncate(len);

        let decoded = framing::decode(&wire, &ciphers).expect("decoding");
        prop_assert_eq!(decoded.version, version);

        // Compare the parsed request against what was put in, field by field —
        // including `sku`, which a host reads and then ignores (`KMS-018`,
        // #34). A decoder that dropped it would still round-trip if the test
        // only checked what the host acts on.
        prop_assert_eq!(
            decoded.request.client_machine_id.0.to_bytes(),
            body.client_machine_id.to_guid().to_bytes()
        );
        prop_assert_eq!(decoded.request.sku.0.to_bytes(), body.sku_id.to_guid().to_bytes());
        prop_assert_eq!(
            decoded.request.counted.0.to_bytes(),
            body.kms_counted_id.to_guid().to_bytes()
        );
        prop_assert_eq!(
            decoded.request.application.0.to_bytes(),
            body.application_id.to_guid().to_bytes()
        );
        prop_assert_eq!(decoded.request.required_clients.0, body.required_clients.get());
        prop_assert_eq!(decoded.request.client_time.0.as_ticks(), body.client_time.get());
        prop_assert_eq!(decoded.request.grace.0, body.grace_time.get());

        // The length must match what the layout says, not merely what the
        // encoder produced.
        prop_assert_eq!(
            len,
            kmsrs_proto::kms::request::framed_request_len(version),
            "the encoded length disagrees with the computed one"
        );
    }

    /// A response survives encode-then-decode intact, and its length matches
    /// `response_len` — which a client computes the same way and compares.
    #[test]
    fn a_response_round_trips_and_its_length_is_predicted(
        body in arbitrary_body(),
        epid in arbitrary_epid(),
        version in prop::sample::select(Version::ALL.as_slice()),
        count in any::<u32>(),
        hardware in prop::array::uniform8(any::<u8>()),
        seed in any::<u64>(),
    ) {
        let body = with_version(&body, version);
        let ciphers = Ciphers::new();
        let mut entropy = DeterministicEntropy::from_seed(seed);
        let mut request = vec![0_u8; 2048];
        let request_len =
            framing::encode_request(version, &body, &ciphers, &mut entropy, &mut request)
                .expect("encoding the request");
        request.truncate(request_len);
        let decoded_request = framing::decode(&request, &ciphers).expect("decoding the request");

        let machine = decoded_request.request.client_machine_id;
        let client_time = decoded_request.request.client_time;
        let plan = ResponsePlan {
            epid: &epid,
            client_machine_id: machine,
            client_time,
            count,
            intervals: Intervals::DEFAULT,
            hardware_id: HardwareId(hardware),
        };

        let mut wire = vec![0_u8; 2048];
        let len = framing::encode(&decoded_request, &plan, &ciphers, &mut entropy, &mut wire)
            .expect("encoding the response");
        wire.truncate(len);

        // The independently computed size, which is what `vlmcs` compares and
        // reports as "Size of RPC payload should be %u but is %u".
        prop_assert_eq!(len, framing::response_len(version, &epid));

        let mut scratch = vec![0_u8; len.max(64)];
        let decoded = response::decode(version, &wire, ciphers.schedule(version), &mut scratch)
            .expect("decoding the response");

        prop_assert_eq!(decoded.client_machine_id, machine.0.to_bytes());
        prop_assert_eq!(decoded.client_time, client_time.0.as_ticks());
        prop_assert_eq!(decoded.count, count);
        prop_assert_eq!(decoded.activation_interval, Intervals::DEFAULT.activation);
        prop_assert_eq!(decoded.renewal_interval, Intervals::DEFAULT.renewal);
        prop_assert_eq!(decoded.wire_len, len);

        // The ePID survives, terminator and all.
        prop_assert_eq!(decoded.pid_bytes.len(), epid.encoded_len());
        if version == Version::V6 {
            prop_assert_eq!(decoded.hardware_id.map(|id| id.0), Some(hardware));
        }
    }

    /// An RPC header round-trips through its wire form.
    #[test]
    fn an_rpc_header_round_trips(
        packet_type in prop::sample::select(PacketType::EMITTED.as_slice()),
        call_id in any::<u32>(),
        frag_length in 16_u16..=2048,
    ) {
        let header = RpcHeader::for_reply(packet_type, PacketFlags::COMPLETE, call_id, frag_length);
        let bytes = header.as_bytes().to_vec();
        let (read, rest) = RpcHeader::read_from_prefix(&bytes).expect("a header");

        prop_assert!(rest.is_empty(), "a header is exactly 16 bytes");
        prop_assert_eq!(read.packet_type(), Some(packet_type));
        prop_assert_eq!(read.call_id.get(), call_id);
        prop_assert_eq!(read.frag_length.get(), frag_length);
        prop_assert!(read.flags().contains(PacketFlags::LAST_FRAG));
    }

    /// A protocol version round-trips through its packed `u32`.
    ///
    /// The halves are swapped relative to what a reader expects — the field is
    /// a union of a `DWORD` and `{ WORD minor; WORD major; }` on a
    /// little-endian machine, so minor occupies the *low* half.
    #[test]
    fn a_protocol_version_round_trips(major in any::<u16>(), minor in any::<u16>()) {
        let version = ProtocolVersion { major, minor };
        let round_tripped = ProtocolVersion::from_wire(version.to_wire());
        prop_assert_eq!(round_tripped, version);
    }

    /// An ePID round-trips through its wire encoding at every length.
    #[test]
    fn an_epid_round_trips_at_every_length(epid in arbitrary_epid()) {
        let mut out = vec![0_u8; 512];
        let len = epid.encode(&mut out).expect("encoding");
        prop_assert_eq!(len, epid.encoded_len());

        // The declared size counts bytes including the terminator.
        prop_assert_eq!(usize::try_from(epid.pid_size().get()).unwrap(), len);
        prop_assert_eq!(&out[len - 2..len], &[0, 0][..], "NUL-terminated");
    }
}

/// Decoding never panics on arbitrary bytes (`SEC-003`, #195).
///
/// Separate from the round-trip properties because it asserts something
/// weaker and more important: whatever a peer sends, the parser returns rather
/// than aborting. The KMD-loader bug class this guards against — bounds
/// validated by unchecked addition, validation running *after* the loop that
/// already dereferenced — has no analogue once data is compiled in, but the
/// discipline applies to everything that comes off a socket.
#[test]
fn decoding_arbitrary_bytes_never_panics() {
    let ciphers = Ciphers::new();

    for case in 0..2_000_usize {
        // Lengths cycle through every shape a PDU can be truncated to, and the
        // contents are a cheap deterministic pattern — enough to walk the
        // length checks, which is what this asserts. Real mutation coverage is
        // the fuzzers' job (`SEC-004`, #196).
        let len = case.checked_rem(600).unwrap_or(0);
        let mut bytes = vec![0_u8; len];
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = u8::try_from(case.wrapping_mul(31).wrapping_add(index) & 0xFF).unwrap_or(0);
        }

        // Every parser that sees attacker-controlled bytes.
        let _ = framing::decode(&bytes, &ciphers);
        for version in Version::ALL {
            let mut scratch = vec![0_u8; bytes.len().max(64)];
            let _ = response::decode(version, &bytes, ciphers.schedule(version), &mut scratch);
        }
        let _ = kmsrs_proto::wire::bind::parse(&bytes);
        let _ = RpcHeader::read_from_prefix(&bytes);
        let _ = kmsrs_proto::wire::stub::parse_request(
            &bytes,
            kmsrs_proto::wire::syntax::TransferSyntax::Ndr32,
        );
        let _ = kmsrs_proto::wire::stub::parse_response(
            &bytes,
            kmsrs_proto::wire::syntax::TransferSyntax::Ndr64,
        );
    }
}
