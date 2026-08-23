//! A complete DCE/RPC exchange, driven from outside the crate.
//!
//! These are integration tests rather than unit tests because the thing worth
//! checking is the whole conversation: bind, then a call, then another call on
//! the same association. A unit test of any one layer would pass while the
//! layers disagreed about an offset.
//!
//! The client half is built here from the crate's public API — the same
//! `encode_request` a diagnostic client uses (`CLI-001`, #207) — so an offset
//! that is wrong in both directions cannot cancel out and pass.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::kms::framing::{self, Ciphers};
use kmsrs_proto::kms::hresult::HResult;
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::sansio::CloseReason;
use kmsrs_proto::time::Instant;
use kmsrs_proto::types::{HardwareId, Intervals};
use kmsrs_proto::wire::connection::{
    AssociationGroups, ConnectionEvent, Decision, Grant, MAX_PDU_LEN, RejectReason, Step,
};
use kmsrs_proto::wire::header::{HEADER_LEN, PacketFlags, PacketType, RpcHeader};
use kmsrs_proto::wire::stub;
use kmsrs_proto::wire::syntax::TransferSyntax;
use kmsrs_proto::wire::{Connection, NcaStatus};
use zerocopy::{FromBytes, IntoBytes};

const NDR32_WIRE: [u8; 16] = [
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
];
const NDR64_WIRE: [u8; 16] = [
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
];
const INTERFACE_WIRE: [u8; 16] = [
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
];

const EPID_TEXT: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";

/// Wrap a body in a DCE/RPC PDU.
fn pdu(packet_type: PacketType, flags: PacketFlags, call_id: u32, body: &[u8]) -> Vec<u8> {
    let frag_length = u16::try_from(HEADER_LEN + body.len()).unwrap();
    let header = RpcHeader::for_reply(packet_type, flags, call_id, frag_length);
    let mut out = header.as_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// A bind body offering one transfer syntax per context.
fn bind_body(items: &[(u16, [u8; 16])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&5840_u16.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(u8::try_from(items.len()).unwrap());
    body.extend_from_slice(&[0, 0, 0]);
    for (context_id, transfer) in items {
        body.extend_from_slice(&context_id.to_le_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&INTERFACE_WIRE);
        body.extend_from_slice(&0x0000_0001_u32.to_le_bytes());
        body.extend_from_slice(transfer);
        body.extend_from_slice(&2_u32.to_le_bytes());
    }
    body
}

/// A request stub carrying a KMS payload.
fn request_body(syntax: TransferSyntax, context_id: u16, payload: &[u8]) -> Vec<u8> {
    let width = if syntax == TransferSyntax::Ndr64 {
        8
    } else {
        4
    };
    let mut body = Vec::new();
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&context_id.to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
    for _ in 0..2 {
        let value = u64::try_from(payload.len()).unwrap();
        if width == 8 {
            body.extend_from_slice(&value.to_le_bytes());
        } else {
            body.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
        }
    }
    body.extend_from_slice(payload);
    body
}

/// A KMS request payload, framed the way a client frames one.
fn kms_payload(version: Version, entropy: &mut DeterministicEntropy) -> Vec<u8> {
    let mut bytes = [0_u8; REQUEST_BODY_LEN];
    let mut body = RequestBody::read_from_bytes(&bytes).unwrap();
    body.version.set(version.to_protocol_version().to_wire());
    body.required_clients.set(25);
    body.client_time.set(133_000_000_000_000_000);
    body.application_id.data1.set(0x55c9_2734);
    body.kms_counted_id.data1.set(0x907f_1f65);
    body.client_machine_id.data1.set(0xDEAD_BEEF);
    bytes.copy_from_slice(body.as_bytes());
    let body = RequestBody::read_from_bytes(&bytes).unwrap();

    let ciphers = Ciphers::new();
    let mut stub = vec![0_u8; 512];
    let len = framing::encode_request(version, &body, &ciphers, entropy, &mut stub).unwrap();
    stub.truncate(len);
    stub
}

fn grant() -> Decision {
    Decision::Grant(Grant {
        epid: EPid::parse(EPID_TEXT).unwrap(),
        count: 50,
        intervals: Intervals::DEFAULT,
        hardware_id: HardwareId([1, 2, 3, 4, 5, 6, 7, 8]),
    })
}

/// Drive one PDU through the connection and return the reply bytes.
fn exchange(connection: &mut Connection, input: &[u8], decision: &Decision) -> (Step, Vec<u8>) {
    let mut entropy = DeterministicEntropy::from_seed(42);
    let mut out = vec![0_u8; MAX_PDU_LEN];
    connection.receive(input).unwrap();
    let step = connection.step(
        Instant::from_nanos(1_000),
        &mut entropy,
        &mut |_request| decision.clone(),
        &mut out,
    );
    let len = match step {
        Step::Send { len } | Step::SendThenClose { len, .. } => len,
        Step::NeedMore | Step::Close { .. } => 0,
    };
    out.truncate(len);
    (step, out)
}

/// The whole conversation: bind, then activate, then activate again.
#[test]
fn a_complete_exchange_binds_activates_and_stays_open() {
    let mut connection = Connection::new(0x1234_5678, false);
    let mut entropy = DeterministicEntropy::from_seed(1);

    // Bind.
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    let (step, reply) = exchange(&mut connection, &bind, &grant());
    assert!(matches!(step, Step::Send { .. }));

    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::BindAck));
    assert_eq!(
        header.call_id.get(),
        2,
        "`WIRE-027` (#85): clients start at 2"
    );
    assert_eq!(
        u32::from_le_bytes(reply[20..24].try_into().unwrap()),
        0x1234_5678,
        "the association group is ours, not the client's"
    );
    assert_eq!(
        connection.next_event(),
        Some(ConnectionEvent::Bound {
            syntax: TransferSyntax::Ndr32,
            context_id: 0
        })
    );

    // Two activations on the same association.
    for call_id in 3..5_u32 {
        let payload = kms_payload(Version::V6, &mut entropy);
        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            call_id,
            &request_body(TransferSyntax::Ndr32, 0, &payload),
        );
        let (step, reply) = exchange(&mut connection, &request, &grant());

        // `WIRE-021` (#79): the association survives an activation. py-kms
        // disconnects, which `vlmcs` reports as "probably non-multitasked KMS
        // emulator".
        assert!(
            matches!(step, Step::Send { .. }),
            "call {call_id} must not close the connection"
        );

        let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
        assert_eq!(header.packet_type(), Some(PacketType::Response));
        assert_eq!(header.call_id.get(), call_id);
        assert_eq!(usize::from(header.frag_length.get()), reply.len());

        // The KMS payload is where the stub layout says it is, and the RPC
        // return code after it is zero.
        let data_at = HEADER_LEN + stub::response_data_offset(TransferSyntax::Ndr32);
        let payload_len =
            u32::from_le_bytes(reply[HEADER_LEN + 8..HEADER_LEN + 12].try_into().unwrap()) as usize;
        let code_at = data_at + payload_len;
        assert_eq!(
            u32::from_le_bytes(reply[code_at..code_at + 4].try_into().unwrap()),
            0
        );

        assert_eq!(
            connection.next_event(),
            Some(ConnectionEvent::Activated {
                version: Version::V6,
                mac_verified: None
            })
        );
    }
}

/// `WIRE-029` (#87): a client binds NDR32, calls over it, then adds NDR64 by
/// `alter_context` and calls over that. Both must work on one association.
#[test]
fn both_syntaxes_work_on_one_association() {
    let mut connection = Connection::new(7, true);
    let mut entropy = DeterministicEntropy::from_seed(2);

    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    assert!(matches!(
        exchange(&mut connection, &bind, &grant()).0,
        Step::Send { .. }
    ));
    assert!(connection.next_event().is_some());

    // First call over NDR32.
    let payload = kms_payload(Version::V6, &mut entropy);
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        3,
        &request_body(TransferSyntax::Ndr32, 0, &payload),
    );
    assert!(matches!(
        exchange(&mut connection, &request, &grant()).0,
        Step::Send { .. }
    ));
    assert!(connection.next_event().is_some());

    // Add NDR64.
    let alter = pdu(
        PacketType::AlterContext,
        PacketFlags::COMPLETE,
        4,
        &bind_body(&[(1, NDR64_WIRE)]),
    );
    let (step, reply) = exchange(&mut connection, &alter, &grant());
    assert!(matches!(step, Step::Send { .. }));
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::AlterContextResponse));
    assert_eq!(
        connection.next_event(),
        Some(ConnectionEvent::ContextAdded {
            syntax: TransferSyntax::Ndr64,
            context_id: 1
        })
    );

    // Subsequent calls over NDR64, on the same association.
    let payload = kms_payload(Version::V6, &mut entropy);
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        5,
        &request_body(TransferSyntax::Ndr64, 1, &payload),
    );
    let (step, reply) = exchange(&mut connection, &request, &grant());
    assert!(matches!(step, Step::Send { .. }));
    // The KMS payload for this ePID is 260 bytes, not the 280 a full-width one
    // would give — computed rather than written down, so the assertion tracks
    // the ePID the test actually uses.
    let kms_len = framing::response_len(Version::V6, &EPid::parse(EPID_TEXT).unwrap());
    assert_eq!(kms_len, 260);
    assert_eq!(
        reply.len(),
        HEADER_LEN + stub::response_stub_len(TransferSyntax::Ndr64, kms_len)
    );

    // ...and the NDR32 context still works afterwards.
    let payload = kms_payload(Version::V6, &mut entropy);
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        6,
        &request_body(TransferSyntax::Ndr32, 0, &payload),
    );
    assert!(matches!(
        exchange(&mut connection, &request, &grant()).0,
        Step::Send { .. }
    ));
}

/// `ARCH-006` (#6) and `SEC-001` (#193): the pre-bind path. vlmcsd's `ContextId
/// = 0xffff` before any bind satisfies both its sentinels and reaches an
/// indirect call through a wild function pointer.
#[test]
fn a_request_before_any_bind_faults_rather_than_dispatching() {
    for context_id in [0_u16, 1, 0xFFFE, 0xFFFF] {
        let mut connection = Connection::new(1, false);
        let mut entropy = DeterministicEntropy::from_seed(3);
        let payload = kms_payload(Version::V6, &mut entropy);
        let request = pdu(
            PacketType::Request,
            PacketFlags::COMPLETE,
            2,
            &request_body(TransferSyntax::Ndr32, context_id, &payload),
        );
        let (step, reply) = exchange(&mut connection, &request, &grant());

        assert!(matches!(step, Step::Send { .. }), "context {context_id}");
        let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
        assert_eq!(header.packet_type(), Some(PacketType::Fault));
        assert_eq!(
            u32::from_le_bytes(reply[24..28].try_into().unwrap()),
            NcaStatus::UnknownInterface.to_wire()
        );
        assert_eq!(
            connection.next_event(),
            Some(ConnectionEvent::Faulted {
                status: NcaStatus::UnknownInterface
            })
        );
    }
}

/// A call on a context the bind refused must fault too — being bound is not
/// enough, the context has to be one that was accepted.
#[test]
fn a_request_on_an_unaccepted_context_faults() {
    let mut connection = Connection::new(1, false);
    let mut entropy = DeterministicEntropy::from_seed(4);
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    exchange(&mut connection, &bind, &grant());
    let _ = connection.next_event();

    let payload = kms_payload(Version::V6, &mut entropy);
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        3,
        &request_body(TransferSyntax::Ndr32, 99, &payload),
    );
    let (_, reply) = exchange(&mut connection, &request, &grant());
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::Fault));
}

/// `WIRE-023` (#81) and `WIRE-025` (#83): the length is bounded before anything
/// is buffered, and a PDU declaring itself shorter than its own header is
/// malformed rather than a partial read.
#[test]
fn hostile_fragment_lengths_are_refused_before_parsing() {
    for (declared, expected) in [
        (0_u16, RejectReason::FragmentTooShort { declared: 0 }),
        (15, RejectReason::FragmentTooShort { declared: 15 }),
        (
            u16::try_from(MAX_PDU_LEN + 1).unwrap(),
            RejectReason::FragmentTooLong {
                declared: MAX_PDU_LEN + 1,
            },
        ),
        (
            u16::MAX,
            RejectReason::FragmentTooLong {
                declared: usize::from(u16::MAX),
            },
        ),
    ] {
        let mut connection = Connection::new(1, false);
        let mut header = RpcHeader::for_reply(PacketType::Bind, PacketFlags::COMPLETE, 2, declared);
        header.frag_length = declared.into();
        let (step, _) = exchange(&mut connection, header.as_bytes(), &grant());

        assert_eq!(
            step,
            Step::Close {
                reason: CloseReason::Malformed
            },
            "frag_length {declared}"
        );
        assert_eq!(
            connection.next_event(),
            Some(ConnectionEvent::Rejected { reason: expected })
        );
    }
}

/// A partial read is *not* a malformed PDU: the answer is to wait
/// (`NET-007`, #156).
#[test]
fn a_partial_pdu_waits_rather_than_closing() {
    let mut connection = Connection::new(1, false);
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    let mut entropy = DeterministicEntropy::from_seed(5);
    let mut out = vec![0_u8; MAX_PDU_LEN];

    // Feed it one byte at a time; every step but the last must want more.
    for (index, byte) in bind.iter().enumerate() {
        connection.receive(&[*byte]).unwrap();
        let step = connection.step(
            Instant::from_nanos(u64::try_from(index).unwrap()),
            &mut entropy,
            &mut |_| grant(),
            &mut out,
        );
        if index + 1 < bind.len() {
            assert_eq!(step, Step::NeedMore, "after {} bytes", index + 1);
        } else {
            assert!(
                matches!(step, Step::Send { .. }),
                "the last byte completes it"
            );
        }
    }
}

/// `WIRE-022` (#80): fragments accumulate, and only the last one is answered.
#[test]
fn a_fragmented_request_is_reassembled() {
    let mut connection = Connection::new(1, false);
    let mut entropy = DeterministicEntropy::from_seed(6);
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    exchange(&mut connection, &bind, &grant());
    let _ = connection.next_event();

    let payload = kms_payload(Version::V6, &mut entropy);
    let body = request_body(TransferSyntax::Ndr32, 0, &payload);
    let split = 100;

    let first = pdu(
        PacketType::Request,
        PacketFlags::FIRST_FRAG,
        3,
        &body[..split],
    );
    let (step, _) = exchange(&mut connection, &first, &grant());
    assert_eq!(step, Step::NeedMore, "a first fragment is not an answer");

    let last = pdu(
        PacketType::Request,
        PacketFlags::LAST_FRAG,
        3,
        &body[split..],
    );
    let (step, reply) = exchange(&mut connection, &last, &grant());
    assert!(matches!(step, Step::Send { .. }));
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::Response));
}

/// `KMS-014` (#30): an unsupported protocol version is a well-formed response
/// carrying `0x8007000D` — not a fault, not `0xC004F042`, not a dropped
/// connection.
#[test]
fn an_unsupported_kms_version_gets_a_well_formed_refusal() {
    let mut connection = Connection::new(1, false);
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    exchange(&mut connection, &bind, &grant());
    let _ = connection.next_event();

    // A v6.1 payload: py-kms services this as v6.
    let mut payload = vec![0_u8; 260];
    payload[..4].copy_from_slice(&0x0006_0001_u32.to_le_bytes());
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        3,
        &request_body(TransferSyntax::Ndr32, 0, &payload),
    );
    let (step, reply) = exchange(&mut connection, &request, &grant());

    assert!(
        matches!(step, Step::Send { .. }),
        "not a dropped connection"
    );
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(
        header.packet_type(),
        Some(PacketType::Response),
        "a response, not a fault"
    );

    // The result code sits where `size_is` would be, because the error path
    // omits it (`KMS-013`, #29).
    let code_at = HEADER_LEN + 8 + 8;
    assert_eq!(
        u32::from_le_bytes(reply[code_at..code_at + 4].try_into().unwrap()),
        HResult::InvalidData.to_wire()
    );
    assert_eq!(
        connection.next_event(),
        Some(ConnectionEvent::Refused {
            result: HResult::InvalidData
        })
    );
}

/// A policy refusal is also a well-formed response, for the same reason.
#[test]
fn a_policy_refusal_is_a_response_rather_than_a_disconnect() {
    let mut connection = Connection::new(1, false);
    let mut entropy = DeterministicEntropy::from_seed(7);
    let bind = pdu(
        PacketType::Bind,
        PacketFlags::COMPLETE,
        2,
        &bind_body(&[(0, NDR32_WIRE)]),
    );
    exchange(&mut connection, &bind, &grant());
    let _ = connection.next_event();

    let payload = kms_payload(Version::V6, &mut entropy);
    let request = pdu(
        PacketType::Request,
        PacketFlags::COMPLETE,
        3,
        &request_body(TransferSyntax::Ndr32, 0, &payload),
    );
    let (step, reply) = exchange(
        &mut connection,
        &request,
        &Decision::Refuse(HResult::NotSupportedByKmsServer),
    );

    assert!(matches!(step, Step::Send { .. }));
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::Response));
    let code_at = HEADER_LEN + 8 + 8;
    assert_eq!(
        u32::from_le_bytes(reply[code_at..code_at + 4].try_into().unwrap()),
        HResult::NotSupportedByKmsServer.to_wire()
    );
}

/// Declined item D4: real KMS clients never authenticate. An inbound trailer is
/// faulted rather than being treated as stub data, which is what vlmcsd does.
#[test]
fn an_authenticated_bind_faults_rather_than_being_misread() {
    let mut connection = Connection::new(1, false);
    let body = bind_body(&[(0, NDR32_WIRE)]);
    let mut bind = pdu(PacketType::Bind, PacketFlags::COMPLETE, 2, &body);
    bind[10..12].copy_from_slice(&16_u16.to_le_bytes());

    let (step, reply) = exchange(&mut connection, &bind, &grant());
    assert!(matches!(step, Step::Send { .. }));
    let header = RpcHeader::read_from_bytes(&reply[..HEADER_LEN]).unwrap();
    assert_eq!(header.packet_type(), Some(PacketType::Fault));
    assert_eq!(
        connection.next_event(),
        Some(ConnectionEvent::Rejected {
            reason: RejectReason::AuthenticationAttempted
        })
    );
}

/// `WIRE-010` (#68): the association group is drawn once per process and
/// incremented per connection. py-kms hands out `0x1063BF3F` everywhere, so one
/// `bind_ack` identifies the software with no active probing.
#[test]
fn association_groups_are_random_per_process_and_sequential_per_connection() {
    let mut first = AssociationGroups::new(&mut DeterministicEntropy::from_seed(1)).unwrap();
    let mut second = AssociationGroups::new(&mut DeterministicEntropy::from_seed(2)).unwrap();

    let start = first.take();
    assert_ne!(start, second.take(), "two processes must not agree");

    for step in 1..8_u32 {
        assert_eq!(first.take(), start.wrapping_add(step));
    }

    // And it must not be the py-kms constant, which is the point of the issue.
    assert_ne!(start, 0x1063_BF3F);
}

/// A failing entropy source must stop the process before it serves, because a
/// predictable association group is exactly what this avoids (`OS-012`, #263).
#[test]
fn association_groups_refuse_a_failing_entropy_source() {
    use kmsrs_proto::entropy::testing::FailingEntropy;
    assert!(AssociationGroups::new(&mut FailingEntropy).is_none());
}

/// The deadline is rearmed on every PDU, so a slow client cannot extend it
/// indefinitely (`NET-004`, #153).
#[test]
fn the_deadline_advances_with_each_pdu() {
    let mut connection = Connection::new(1, false);
    assert_eq!(connection.deadline(), None);

    let mut entropy = DeterministicEntropy::from_seed(8);
    let mut out = vec![0_u8; MAX_PDU_LEN];
    let mut previous = None;
    for tick in [1_u64, 1_000_000_000, 2_000_000_000] {
        connection.step(
            Instant::from_nanos(tick),
            &mut entropy,
            &mut |_| grant(),
            &mut out,
        );
        let deadline = connection.deadline().unwrap();
        if let Some(previous) = previous {
            assert!(deadline > previous, "the deadline must move forward");
        }
        previous = Some(deadline);
    }
}

/// A PDU type this host does not accept is refused rather than misinterpreted.
#[test]
fn an_unexpected_packet_type_is_refused() {
    for packet_type in [
        PacketType::Response,
        PacketType::Fault,
        PacketType::BindAck,
        PacketType::BindNak,
        PacketType::AlterContextResponse,
    ] {
        let mut connection = Connection::new(1, false);
        let frame = pdu(packet_type, PacketFlags::COMPLETE, 2, &[0_u8; 8]);
        let (step, _) = exchange(&mut connection, &frame, &grant());
        assert_eq!(
            step,
            Step::Close {
                reason: CloseReason::Malformed
            },
            "{packet_type:?}"
        );
    }
}
