//! Cross-request leakage under concurrent load (`OBS-005`, #181;
//! `ARCH-014`, #14).
//!
//! The unit tests in `events.rs` interleave requests on one thread, which
//! proves the data structure carries a peer address but not that *concurrency*
//! cannot lose one. This runs the real thing: many threads, one shared log, one
//! shared count model, each request carrying its own peer.
//!
//! The bug being ruled out is specific. py-kms stores the peer address in the
//! process-global `srv_config['raddr']`, so a second connection can overwrite it
//! between the first connection's accept and its request handling — and the
//! Organization fork made it durable by persisting that racy value as
//! `lastRequestIP`. Of the forks surveyed, only MelroyB's fixed it.
//!
//! This crate makes the bug unrepresentable rather than merely absent: a peer
//! address is a parameter to [`EventLog::record`], and there is no shared slot
//! for it to be written into. The test is what keeps that true.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::unreadable_literal,
    clippy::unseparated_literal_suffix,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_policy::counting::ClientCounts;
use kmsrs_policy::events::{EventLog, Outcome, Peer};
use kmsrs_policy::gate::{Decision, evaluate};
use kmsrs_policy::identity::HostIdentity;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::kms::status::LicenseStatus;
use kmsrs_proto::kms::version::ProtocolVersion;
use kmsrs_proto::time::{FileTime, Instant};
use kmsrs_proto::types::{
    ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
    RequiredClients, SkuId, WorkstationName,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Barrier, Mutex};

const THREADS: usize = 16;
const REQUESTS_PER_THREAD: usize = 64;

fn workstation(name: &str) -> WorkstationName {
    let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
    for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
        *slot = unit;
    }
    WorkstationName::decode(&field)
}

/// A request whose every identifying field encodes the thread and index that
/// produced it, so any cross-request leak is detectable rather than plausible.
fn request_for(thread: usize, index: usize) -> Request {
    let machine = u128::try_from(thread)
        .unwrap_or(0)
        .wrapping_mul(1_000)
        .wrapping_add(u128::try_from(index).unwrap_or(0));
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

/// The peer that request must be recorded against.
fn peer_for(thread: usize, index: usize) -> Peer {
    Peer {
        address: IpAddr::V4(Ipv4Addr::new(
            10,
            u8::try_from(thread).unwrap_or(0),
            u8::try_from(index / 256).unwrap_or(0),
            u8::try_from(index % 256).unwrap_or(0),
        )),
        port: 1024_u16.wrapping_add(u16::try_from(index).unwrap_or(0)),
    }
}

/// `OBS-005` (#181): every event carries the address of the request that
/// produced it, under load, with no cross-request leakage.
#[test]
fn peer_addresses_do_not_leak_between_concurrent_requests() {
    let mut entropy = DeterministicEntropy::from_seed(0xC0FFEE);
    let identity = Arc::new(
        HostIdentity::generate(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap())
            .expect("deterministic entropy always yields an identity"),
    );

    let total = THREADS * REQUESTS_PER_THREAD;
    let log = Arc::new(Mutex::new(EventLog::new(
        total * 2,
        kmsrs_policy::counting::CMID_EXPIRY,
    )));
    let counts = Arc::new(Mutex::new(ClientCounts::new()));
    let barrier = Arc::new(Barrier::new(THREADS));

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let identity = Arc::clone(&identity);
            let log = Arc::clone(&log);
            let counts = Arc::clone(&counts);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                // Start together, so the threads genuinely contend.
                barrier.wait();
                for index in 0..REQUESTS_PER_THREAD {
                    let request = request_for(thread, index);
                    let peer = peer_for(thread, index);
                    let now = Instant::from_nanos(u64::try_from(index).unwrap_or(0));

                    // The decision and the log entry are taken under separate
                    // locks, which is the interleaving most likely to expose a
                    // shared slot if one existed.
                    let decision_outcome = {
                        let mut counts = counts.lock().expect("counts lock");
                        let (decision, observations) =
                            evaluate(&request, &identity, &mut counts, now, None);
                        match decision {
                            Decision::Grant(grant) => (
                                Outcome::Activated(kmsrs_policy::events::Activation {
                                    selection: grant.selection,
                                    reported_count: grant.counts.reported,
                                    cached_count: grant.counts.cached,
                                    outcome: grant.counts.outcome,
                                    expired: grant.counts.expired,
                                    anomalous_demand: grant.counts.anomalous_demand,
                                }),
                                observations,
                            ),
                            Decision::Refuse(refusal) => (Outcome::Refused(refusal), observations),
                        }
                    };

                    let mut log = log.lock().expect("log lock");
                    log.record(
                        &request,
                        Some(peer),
                        now,
                        decision_outcome.0,
                        decision_outcome.1,
                    );
                }
            });
        }
    });

    let log = log.lock().expect("log lock");
    assert_eq!(log.len(), total, "every request was recorded");
    assert_eq!(log.dropped().by_capacity, 0, "and none were dropped");

    // Each event's peer must match the machine ID recorded beside it. A leaked
    // address would pair one request's machine with another's address.
    let mut seen_sequences = Vec::with_capacity(total);
    let mut by_machine: HashMap<[u8; 16], Peer> = HashMap::new();
    for event in log.iter() {
        seen_sequences.push(event.sequence);

        let machine = event.client_machine_id.0.to_bytes();
        let value = u128::from_be_bytes(machine);
        let thread = usize::try_from(value / 1_000).expect("in range");
        let index = usize::try_from(value % 1_000).expect("in range");

        assert_eq!(
            event.peer,
            Some(peer_for(thread, index)),
            "event {} paired machine {thread}-{index} with the wrong address",
            event.sequence
        );
        assert_eq!(
            event.workstation_name.as_str(),
            format!("host-{thread}-{index}"),
            "event {} paired a machine with another request's name",
            event.sequence
        );
        assert!(
            by_machine
                .insert(machine, peer_for(thread, index))
                .is_none(),
            "machine {thread}-{index} was recorded twice"
        );
    }

    // `OBS-004` (#180): sequence numbers are dense, unique and ordered, even
    // though sixteen threads produced them and every timestamp repeats.
    let expected: Vec<u64> = (0..u64::try_from(total).expect("in range")).collect();
    assert_eq!(seen_sequences, expected, "ordering is stable under load");
}

/// `POL-001` (#89) under load: the shared world converges on the real number of
/// distinct machines, and the reported count still saturates.
#[test]
fn the_client_count_is_consistent_under_concurrent_load() {
    let mut entropy = DeterministicEntropy::from_seed(0xBEEF);
    let identity = Arc::new(
        HostIdentity::generate(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap())
            .expect("deterministic entropy always yields an identity"),
    );
    let counts = Arc::new(Mutex::new(ClientCounts::new()));
    let barrier = Arc::new(Barrier::new(THREADS));

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let identity = Arc::clone(&identity);
            let counts = Arc::clone(&counts);
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for index in 0..REQUESTS_PER_THREAD {
                    let request = request_for(thread, index);
                    let mut counts = counts.lock().expect("counts lock");
                    let (decision, _) = evaluate(
                        &request,
                        &identity,
                        &mut counts,
                        Instant::from_nanos(0),
                        None,
                    );
                    let Decision::Grant(grant) = decision else {
                        panic!("an unknown product must activate: {decision:?}");
                    };
                    assert!(
                        grant.counts.reported >= 25,
                        "never below the minimum that activates"
                    );
                    assert!(
                        grant.counts.reported <= 50,
                        "and never above the saturation value"
                    );
                }
            });
        }
    });

    // Every distinct machine that fitted is held; the table is bounded, so the
    // number is the bound rather than the total offered.
    let counts = counts.lock().expect("counts lock");
    let cached = counts.cached_for(ApplicationId(kmsrs_db::APPLICATIONS[0].guid));
    assert_eq!(
        usize::try_from(cached).expect("in range"),
        kmsrs_policy::counting::MAX_CACHED_PER_APPLICATION,
        "the bound holds under contention"
    );
}
