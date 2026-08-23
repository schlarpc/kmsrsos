//! Nothing that goes wrong goes unsaid (`SEC-012`, #204).
//!
//! # The defect this is named for
//!
//! vlmcsd's `handle_error()` is `-> pass`. A dozen distinct crash paths — a
//! malformed PDU, a refused context, an unparseable payload — all become the
//! same thing on the wire: a connection reset, with nothing logged at any
//! level. An operator watching a client fail cannot tell a bug from a network
//! fault from a deliberate refusal, and neither can the next person to read the
//! code.
//!
//! # What is checked here
//!
//! Two properties, and the second is the one that is easy to get wrong.
//!
//! 1. **Every refusal produces an event with a discriminant.** Not a log line,
//!    not a reset — a value the driver can match on. The connection state
//!    machine is sans-io, so this is checkable directly: drive it into each
//!    failure and look at what comes out.
//! 2. **The event ring cannot lose anything silently.** It is bounded, because
//!    an unbounded one is a memory-exhaustion vector reachable by anything that
//!    can open a socket. Bounded means something eventually gives — and what
//!    must not give is the reader's knowledge that it did.
//!
//! Property 2 is what makes property 1 worth having. An event log that answers
//! every question correctly except "did you tell me everything?" is a log that
//! reports a clean run during the incident.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::hresult::HResult;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::connection::{Connection, ConnectionEvent, Decision, RejectReason, Step};
use kmsrs_proto::wire::header::HEADER_LEN;

/// How many events the ring holds before it has to start losing them.
///
/// Not imported: the capacity is a private implementation detail, and a test
/// that reached in for it would pass by construction. This is the number the
/// test *assumes*, and `the_assumed_ring_capacity_is_not_larger_than_the_real_one`
/// is what fails if the real one shrinks below it.
const ASSUMED_RING_CAPACITY: usize = 8;

/// Drive a connection with the given bytes and collect everything it says.
fn events_from(inputs: &[&[u8]]) -> Vec<ConnectionEvent> {
    let mut connection = Connection::new(0x1234_5678, true);
    let mut entropy = DeterministicEntropy::from_seed(0x2004);
    let mut out = vec![0_u8; 8192];
    let mut collected = Vec::new();

    for (tick, input) in inputs.iter().enumerate() {
        if connection.receive(input).is_err() {
            break;
        }
        loop {
            let step = connection.step(
                Instant::from_nanos(tick as u64 + 1),
                &mut entropy,
                &mut |_request| Decision::Refuse(HResult::from_wire(0xC004_F042)),
                &mut out,
            );
            while let Some(event) = connection.next_event() {
                collected.push(event);
            }
            match step {
                Step::NeedMore => break,
                Step::Close { .. } | Step::SendThenClose { .. } => return collected,
                Step::Send { .. } => {}
            }
        }
    }
    while let Some(event) = connection.next_event() {
        collected.push(event);
    }
    collected
}

/// A PDU with a chosen type, flags and declared length, and nothing sensible
/// inside it.
fn pdu(packet_type: u8, frag_length: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; usize::from(frag_length).max(HEADER_LEN)];
    bytes[0] = 5;
    bytes[1] = 0;
    bytes[2] = packet_type;
    bytes[3] = 0x03;
    bytes[4] = 0x10;
    bytes[8..10].copy_from_slice(&frag_length.to_le_bytes());
    bytes[12..16].copy_from_slice(&1_u32.to_le_bytes());
    bytes
}

#[test]
fn an_unsupported_rpc_version_is_an_event_and_not_a_silent_reset() {
    let mut bytes = pdu(11, 72);
    bytes[0] = 4; // DCE/RPC 4.0, which this host does not speak.

    let events = events_from(&[&bytes]);
    assert!(
        events.iter().any(|event| matches!(
            event,
            ConnectionEvent::Rejected {
                reason: RejectReason::UnsupportedRpcVersion
            }
        )),
        "an unsupported version closed the connection without saying why: {events:?}"
    );
}

#[test]
fn an_authenticated_bind_is_an_event_and_not_a_silent_reset() {
    let mut bytes = pdu(11, 72);
    bytes[10..12].copy_from_slice(&16_u16.to_le_bytes()); // AuthLength

    let events = events_from(&[&bytes]);
    assert!(
        events.iter().any(|event| matches!(
            event,
            ConnectionEvent::Rejected {
                reason: RejectReason::AuthenticationAttempted
            }
        )),
        "an authentication attempt was refused with no event: {events:?}"
    );
}

#[test]
fn a_fragment_shorter_than_its_own_header_is_an_event() {
    let mut bytes = pdu(11, 72);
    bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());

    let events = events_from(&[&bytes]);
    assert!(
        events.iter().any(|event| matches!(
            event,
            ConnectionEvent::Rejected {
                reason: RejectReason::FragmentTooShort { .. }
            }
        )),
        "a PDU declaring itself shorter than its header was dropped silently: {events:?}"
    );
}

#[test]
fn an_unexpected_packet_type_is_an_event() {
    // 2 is `response`, which a client never sends to a host.
    let events = events_from(&[&pdu(2, 32)]);
    assert!(
        events.iter().any(|event| matches!(
            event,
            ConnectionEvent::Rejected {
                reason: RejectReason::UnexpectedPacketType
            }
        )),
        "a host-only PDU type was refused with no event: {events:?}"
    );
}

#[test]
fn every_refusal_carries_a_discriminant_a_driver_can_match_on() {
    // The point of a typed reason rather than a string: a driver can decide
    // what to do, and a new refusal reason is a compile error at every
    // exhaustive match rather than a new string nobody handles.
    let mut seen = Vec::new();
    for (name, bytes) in [
        ("bad version", {
            let mut bytes = pdu(11, 72);
            bytes[0] = 4;
            bytes
        }),
        ("authenticated", {
            let mut bytes = pdu(11, 72);
            bytes[10..12].copy_from_slice(&16_u16.to_le_bytes());
            bytes
        }),
        ("short fragment", {
            let mut bytes = pdu(11, 72);
            bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
            bytes
        }),
        ("wrong type", pdu(2, 32)),
    ] {
        let events = events_from(&[&bytes]);
        let reason = events.iter().find_map(|event| match event {
            ConnectionEvent::Rejected { reason } => Some(*reason),
            _ => None,
        });
        assert!(reason.is_some(), "{name}: refused with no reason at all");
        seen.push(reason);
    }

    // And the reasons are distinct, which is the whole complaint about
    // `handle_error() -> pass`: it is not that it fails to log, it is that it
    // makes four different failures indistinguishable.
    let mut distinct = seen.clone();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        seen.len(),
        "four different failures produced the same reason: {seen:?}"
    );
}

#[test]
fn a_full_event_ring_reports_what_it_lost_rather_than_dropping_it_quietly() {
    let mut connection = Connection::new(0x1234_5678, true);
    let mut entropy = DeterministicEntropy::from_seed(0x2004);
    let mut out = vec![0_u8; 8192];

    // Faults keep the association open, so this generates events without ever
    // being drained — which is exactly the shape of a driver that is busy.
    // Every one of these is a request on a context that was never bound.
    let overflow = ASSUMED_RING_CAPACITY * 3;
    for tick in 0..overflow {
        let request = pdu(0, 32);
        connection.receive(&request).unwrap();
        let _step = connection.step(
            Instant::from_nanos(tick as u64 + 1),
            &mut entropy,
            &mut |_request| Decision::Refuse(HResult::from_wire(1)),
            &mut out,
        );
    }

    let mut drained = Vec::new();
    while let Some(event) = connection.next_event() {
        drained.push(event);
    }

    let lost: u32 = drained
        .iter()
        .filter_map(|event| match event {
            ConnectionEvent::Lost { count } => Some(*count),
            _ => None,
        })
        .sum();

    assert!(
        lost > 0,
        "the ring held {} of {overflow} events and reported losing none of the rest: {drained:?}",
        drained.len()
    );
    // One of the drained entries is the loss report itself, not an event the
    // connection produced.
    let delivered = u32::try_from(drained.len() - 1).unwrap();
    assert_eq!(
        delivered + lost,
        u32::try_from(overflow).unwrap(),
        "every event is either delivered or counted as lost, and none is both"
    );

    // And the loss report comes last, so a driver that drains until `None`
    // cannot stop before it.
    assert!(
        matches!(drained.last(), Some(ConnectionEvent::Lost { .. })),
        "the loss report was not the final event: {drained:?}"
    );
}

#[test]
fn the_loss_count_resets_once_it_has_been_reported() {
    let mut connection = Connection::new(0x1234_5678, true);
    let mut entropy = DeterministicEntropy::from_seed(0x2004);
    let mut out = vec![0_u8; 8192];

    for tick in 0..(ASSUMED_RING_CAPACITY * 2) {
        connection.receive(&pdu(0, 32)).unwrap();
        let _step = connection.step(
            Instant::from_nanos(tick as u64 + 1),
            &mut entropy,
            &mut |_request| Decision::Refuse(HResult::from_wire(1)),
            &mut out,
        );
    }
    while connection.next_event().is_some() {}

    // Drained. A second drain must not re-report a loss that was already
    // reported, or a quiet connection accumulates a permanent phantom warning.
    assert_eq!(
        connection.next_event(),
        None,
        "a drained connection reported a loss it had already reported"
    );
}

#[test]
fn the_assumed_ring_capacity_is_not_larger_than_the_real_one() {
    // If the ring grows, the overflow tests above still overflow it and still
    // pass. If it shrinks below what they assume they would still pass, for
    // the wrong reason — so the assumption is checked directly: exactly
    // `ASSUMED_RING_CAPACITY` events must survive without any loss report.
    let mut connection = Connection::new(0x1234_5678, true);
    let mut entropy = DeterministicEntropy::from_seed(0x2004);
    let mut out = vec![0_u8; 8192];

    for tick in 0..ASSUMED_RING_CAPACITY {
        connection.receive(&pdu(0, 32)).unwrap();
        let _step = connection.step(
            Instant::from_nanos(tick as u64 + 1),
            &mut entropy,
            &mut |_request| Decision::Refuse(HResult::from_wire(1)),
            &mut out,
        );
    }

    let mut drained = Vec::new();
    while let Some(event) = connection.next_event() {
        drained.push(event);
    }
    assert_eq!(
        drained.len(),
        ASSUMED_RING_CAPACITY,
        "the ring no longer holds {ASSUMED_RING_CAPACITY} events, so the \
         overflow tests are measuring something else"
    );
    assert!(
        !drained
            .iter()
            .any(|event| matches!(event, ConnectionEvent::Lost { .. })),
        "a ring filled exactly to capacity reported a loss: {drained:?}"
    );
}
