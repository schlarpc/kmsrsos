//! The six host-state behaviours, end to end (`TEST-009`, #230).
//!
//! `kmsrs-policy` tests each of these against the count model directly. This
//! runs them through [`Host::activate`] — the same function the RPC state
//! machine is handed as its `activate` callback — so what is checked is the
//! behaviour a client would actually observe, not the behaviour of an internal
//! structure that something else might fail to call correctly.
//!
//! The six, in the issue's own words: pre-charge; saturation at `2N`;
//! per-client views never mutating global state; 30-day decay decrementing;
//! renewal deleting and reinserting; eviction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::Guid;
use kmsrs_policy::counting::{CMID_EXPIRY, MAX_CACHED_PER_APPLICATION};
use kmsrs_policy::events::Peer;
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
use std::net::{IpAddr, Ipv4Addr};

/// A product no build knows, so the gate always grants and the test is about
/// counting rather than about the gate.
const UNKNOWN: [u8; 16] = [0xAB; 16];

fn fresh_host() -> Host {
    let mut entropy = DeterministicEntropy::from_seed(0x1234_5678);
    Host::new(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap()
}

fn windows() -> Guid {
    kmsrs_db::APPLICATIONS
        .iter()
        .find(|entry| entry.name == "Windows")
        .expect("the Windows application is in the shipped data")
        .guid
}

fn workstation(name: &str) -> WorkstationName {
    let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
    for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
        *slot = unit;
    }
    WorkstationName::decode(&field)
}

fn request(machine: u128, required: u32) -> Request {
    Request {
        version: ProtocolVersion { major: 6, minor: 0 },
        client_kind: ClientKind::VirtualMachine,
        license_status: LicenseStatus::Unlicensed,
        grace: GraceMinutes(0),
        application: ApplicationId(windows()),
        sku: SkuId(Guid::from_bytes(UNKNOWN)),
        counted: KmsCountedId(Guid::from_bytes(UNKNOWN)),
        client_machine_id: ClientMachineId(Guid::from_bytes(machine.to_be_bytes())),
        required_clients: RequiredClients(required),
        client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
        previous_client_machine_id: None,
        workstation_name: workstation("host.example"),
    }
}

fn context(seconds: u64) -> RequestContext {
    RequestContext {
        peer: Some(Peer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 50_000,
        }),
        now: Instant::from_nanos(seconds.saturating_mul(1_000_000_000)),
        host_time: None,
    }
}

/// The count a request was answered with.
fn count_of(decision: &Decision) -> u32 {
    match decision {
        Decision::Grant(grant) => grant.count,
        Decision::Refuse(result) => panic!("refused: {result:?}"),
    }
}

fn activate(host: &mut Host, machine: u128, required: u32, seconds: u64) -> u32 {
    count_of(&host.activate(&request(machine, required), context(seconds)))
}

/// **Pre-charge.** The very first client to ask is told the number that
/// activates it, not the number of machines this host has seen. Without this a
/// fresh host activates nobody and every emulator would be useless on day one.
#[test]
fn one_the_first_client_is_told_the_number_that_activates_it() {
    let mut host = fresh_host();
    assert_eq!(activate(&mut host, 1, 25, 0), 25);
    assert_eq!(
        host.counts().cached_for(ApplicationId(windows())),
        1,
        "and the host is honest with itself about holding one machine"
    );

    // Server and Office ask for 5 and are told 5.
    let mut host = fresh_host();
    assert_eq!(activate(&mut host, 1, 5, 0), 5);
}

/// **Saturation at `2N`.** The reported count rises with real clients and then
/// stops — 50 for a client SKU asking 25, 10 for a server or Office asking 5.
#[test]
fn two_the_count_saturates_at_twice_the_required_number() {
    let mut host = fresh_host();
    let mut seen = Vec::new();
    for machine in 1..=80_u128 {
        seen.push(activate(&mut host, machine, 25, 0));
    }

    assert_eq!(seen[0], 25, "floored while the world is small");
    assert_eq!(seen[79], 50, "saturated once it is not");
    assert!(
        seen.windows(2).all(|pair| pair[0] <= pair[1]),
        "the reported count must never go backwards as clients join"
    );
    assert!(
        seen.iter().all(|count| (25..=50).contains(count)),
        "and must stay between the floor and the ceiling"
    );

    let mut host = fresh_host();
    for machine in 1..=40_u128 {
        activate(&mut host, machine, 5, 0);
    }
    assert_eq!(activate(&mut host, 41, 5, 0), 10);
}

/// **Per-client views never mutate global state.** This is the one that makes
/// the overcharge attack unrepresentable rather than mitigated: a genuine host
/// is permanently disabled by 376 required clients followed by 671
/// activations, and vlmcsd reproduces the bug faithfully enough to need a
/// restart.
#[test]
fn three_an_anomalous_demand_is_visible_to_nobody_else() {
    let mut host = fresh_host();
    for machine in 1..=60_u128 {
        activate(&mut host, machine, 25, 0);
    }
    let honest_before = activate(&mut host, 1, 25, 0);

    // The attack, run in full.
    for machine in 1_000..=1_671_u128 {
        let reported = activate(&mut host, machine, 400, 0);
        assert_eq!(reported, 400, "the attacker gets what it asked for");
    }

    let honest_after = activate(&mut host, 1, 25, 0);
    assert_eq!(
        honest_before, honest_after,
        "and no honest client can tell the attack happened"
    );
    assert_eq!(honest_after, 50);
}

/// **30-day decay decrements.** A machine that stops renewing is removed and
/// the count falls. Neither existing implementation does this at all.
#[test]
fn four_a_machine_that_stops_renewing_is_forgotten_after_thirty_days() {
    let mut host = fresh_host();
    for machine in 1..=60_u128 {
        activate(&mut host, machine, 25, 0);
    }
    assert_eq!(host.counts().cached_for(ApplicationId(windows())), 60);

    // One machine keeps renewing; the rest go quiet.
    let mut when = 0_u64;
    let step = CMID_EXPIRY.as_secs() / 2;
    for _ in 0..4 {
        when += step;
        activate(&mut host, 1, 25, when);
    }

    assert_eq!(
        host.counts().cached_for(ApplicationId(windows())),
        1,
        "only the machine that kept renewing survives"
    );
    assert_eq!(
        activate(&mut host, 1, 25, when),
        25,
        "and the count has decayed back to the floor"
    );
}

/// **Renewal deletes and reinserts.** Microsoft's host does exactly this, and
/// it is what makes one ordering serve both expiry and eviction: a renewed
/// machine moves to the newest end rather than keeping its original place.
#[test]
fn five_renewal_moves_a_machine_to_the_newest_end() {
    let mut host = fresh_host();
    for machine in 1..=10_u128 {
        activate(&mut host, machine, 25, 0);
    }

    // Machine 1 is the oldest. Renew it just before the window closes.
    let almost = CMID_EXPIRY.as_secs() - 10;
    activate(&mut host, 1, 25, almost);
    assert_eq!(
        host.counts().cached_for(ApplicationId(windows())),
        10,
        "a renewal is not a new machine"
    );

    // Past the window measured from the original sighting: the nine that never
    // renewed are gone and machine 1 is not.
    let past = CMID_EXPIRY.as_secs() + 10;
    activate(&mut host, 99, 25, past);
    assert_eq!(
        host.counts().cached_for(ApplicationId(windows())),
        2,
        "machine 1 and the new arrival"
    );
}

/// **Eviction.** A full table drops its oldest entry rather than returning
/// `0xC004D104` the way a genuine host would. Evicting is strictly more
/// compatible, and with per-client views the refusal protects nothing.
#[test]
fn six_a_full_table_evicts_instead_of_refusing() {
    let mut host = fresh_host();
    for machine in 0..u128::try_from(MAX_CACHED_PER_APPLICATION).unwrap() {
        activate(&mut host, machine, 25, 0);
    }
    assert_eq!(
        usize::try_from(host.counts().cached_for(ApplicationId(windows()))).unwrap(),
        MAX_CACHED_PER_APPLICATION
    );

    // Well past the bound, every request is still answered and the table stays
    // at its bound.
    for machine in 10_000..10_500_u128 {
        let reported = activate(&mut host, machine, 25, 0);
        assert_eq!(reported, 50, "machine {machine} was not answered normally");
    }
    assert_eq!(
        usize::try_from(host.counts().cached_for(ApplicationId(windows()))).unwrap(),
        MAX_CACHED_PER_APPLICATION,
        "the bound holds"
    );
}

/// Every one of the above is also in the event log, which is what an operator
/// would look at to see any of it happen.
#[test]
fn the_log_records_what_the_model_did() {
    let mut host = fresh_host();
    for machine in 1..=5_u128 {
        activate(&mut host, machine, 25, 0);
    }
    activate(&mut host, 1, 25, 60);

    assert_eq!(host.events().len(), 6, "six requests, six records");
    assert_eq!(
        host.events()
            .iter()
            .filter(|event| event.activated())
            .count(),
        6
    );
    let last = host.events().iter().next_back().unwrap();
    assert_eq!(last.client_machine_id.0.to_bytes()[15], 1);
    assert!(last.peer.is_some(), "with the address it came from");
}
