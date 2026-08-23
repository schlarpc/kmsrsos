//! Per-request state is owned by the request (`ARCH-014`, #14).
//!
//! `kmsrs-policy`'s own concurrency test proves the event log carries the right
//! peer under load. This proves the same thing one layer up, through
//! [`Host::activate`] — the function the RPC state machine actually calls — and
//! adds the part that only makes sense here: that two requests handled
//! concurrently cannot see each other's answer.
//!
//! The bug being ruled out is py-kms's process-global `srv_config['raddr']`,
//! which a second connection can overwrite between the first connection's
//! accept and its request handling. The Organization fork made it durable by
//! persisting the racy value as `lastRequestIP`; MelroyB's is the only fork
//! surveyed that fixed it.
//!
//! [`Host`] has no field a per-request value could be written into. Everything
//! about a request arrives as [`kmsrs_server::RequestContext`] and is dropped
//! when `activate` returns, so the bug is unrepresentable rather than absent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_policy::events::{Outcome, Peer};
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::kms::status::LicenseStatus;
use kmsrs_proto::kms::version::ProtocolVersion;
use kmsrs_proto::time::{FileTime, Instant};
use kmsrs_proto::types::{
    ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
    RequiredClients, SkuId, WorkstationName,
};
use kmsrs_proto::wire::connection::Decision;
use kmsrs_server::{Host, RequestContext};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Barrier, Mutex};

const THREADS: usize = 16;
const PER_THREAD: usize = 64;

fn workstation(name: &str) -> WorkstationName {
    let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
    for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
        *slot = unit;
    }
    WorkstationName::decode(&field)
}

/// Every identifying field encodes the thread and index that produced it, so a
/// leak is detectable rather than merely improbable.
fn request(thread: usize, index: usize) -> Request {
    let machine = (u128::try_from(thread).unwrap() << 64) | u128::try_from(index).unwrap();
    Request {
        version: ProtocolVersion { major: 6, minor: 0 },
        client_kind: ClientKind::VirtualMachine,
        license_status: LicenseStatus::Unlicensed,
        grace: GraceMinutes(0),
        application: ApplicationId(kmsrs_db::APPLICATIONS[0].guid),
        sku: SkuId(Guid::from_bytes([0xAB; 16])),
        counted: KmsCountedId(Guid::from_bytes([0xAB; 16])),
        client_machine_id: ClientMachineId(Guid::from_bytes(machine.to_be_bytes())),
        required_clients: RequiredClients(25),
        client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
        previous_client_machine_id: None,
        workstation_name: workstation(&format!("host-{thread}-{index}")),
    }
}

fn peer(thread: usize, index: usize) -> Peer {
    Peer {
        address: IpAddr::V4(Ipv4Addr::new(
            10,
            u8::try_from(thread).unwrap(),
            u8::try_from(index >> 8).unwrap(),
            u8::try_from(index & 0xFF).unwrap(),
        )),
        port: 1024 + u16::try_from(index).unwrap(),
    }
}

/// The peer, machine ID and workstation name recorded for a request must all
/// come from that request and no other.
#[test]
fn concurrent_requests_do_not_leak_state_into_each_other() {
    let mut entropy = DeterministicEntropy::from_seed(0xFACE_FEED);
    let host = Arc::new(Mutex::new(
        Host::new(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap(),
    ));
    let barrier = Arc::new(Barrier::new(THREADS));

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let host = Arc::clone(&host);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for index in 0..PER_THREAD {
                    let request = request(thread, index);
                    let context = RequestContext {
                        peer: Some(peer(thread, index)),
                        now: Instant::from_nanos(u64::try_from(index).unwrap()),
                        host_time: None,
                    };
                    let decision = host.lock().unwrap().activate(&request, context);
                    // Every request here is for an unknown product, so every
                    // one must be granted (`POL-017`, #105).
                    let Decision::Grant(grant) = decision else {
                        panic!("thread {thread} index {index} was refused");
                    };
                    assert!(
                        (25..=50).contains(&grant.count),
                        "thread {thread} index {index} saw {}",
                        grant.count
                    );
                }
            });
        }
    });

    let host = host.lock().unwrap();
    let total = THREADS * PER_THREAD;
    assert_eq!(host.events().len(), total, "every request was recorded");

    let mut seen: HashSet<[u8; 16]> = HashSet::new();
    for event in host.events().iter() {
        let machine = u128::from_be_bytes(event.client_machine_id.0.to_bytes());
        let thread = usize::try_from(machine >> 64).unwrap();
        let index = usize::try_from(machine & u128::from(u64::MAX)).unwrap();

        assert_eq!(
            event.peer,
            Some(peer(thread, index)),
            "request {thread}-{index} was logged against another request's address"
        );
        assert_eq!(
            event.workstation_name.as_str(),
            format!("host-{thread}-{index}"),
            "request {thread}-{index} was logged against another request's name"
        );
        assert!(matches!(event.outcome, Outcome::Activated(_)));
        assert!(
            seen.insert(event.client_machine_id.0.to_bytes()),
            "request {thread}-{index} was recorded twice"
        );
    }
    assert_eq!(seen.len(), total);
}

/// Two hosts in the same process share nothing. If any per-request value lived
/// in a process-global — which is exactly where py-kms puts the peer address —
/// this would not hold.
#[test]
fn two_hosts_in_one_process_share_no_state() {
    let mut first_entropy = DeterministicEntropy::from_seed(1);
    let mut second_entropy = DeterministicEntropy::from_seed(2);
    let mut first =
        Host::new(&mut first_entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap();
    let mut second = Host::new(
        &mut second_entropy,
        kmsrs_db::Date::new(2026, 8, 1).unwrap(),
    )
    .unwrap();

    for index in 0..30 {
        first.activate(
            &request(1, index),
            RequestContext {
                peer: Some(peer(1, index)),
                now: Instant::from_nanos(0),
                host_time: None,
            },
        );
    }

    assert_eq!(first.events().len(), 30);
    assert_eq!(second.events().len(), 0, "the second host saw nothing");

    let decision = second.activate(
        &request(2, 0),
        RequestContext {
            peer: Some(peer(2, 0)),
            now: Instant::from_nanos(0),
            host_time: None,
        },
    );
    let Decision::Grant(grant) = decision else {
        panic!("{decision:?}");
    };
    assert_eq!(
        grant.count, 25,
        "the second host's world is its own, and still empty"
    );
}
