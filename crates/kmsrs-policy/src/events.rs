//! The in-memory event log (`OBS-004`, #180; `OBS-005`, #181).
//!
//! # One record per request, not one row per machine
//!
//! py-kms keeps a mutable row per client machine and overwrites its timestamp,
//! machine name, SKU, licence status and ePID on every request. The result is
//! that "what activated last Tuesday?" is not a query its data model can
//! answer — the answer was overwritten on Wednesday. This log appends one
//! immutable record per *request*, so history is history.
//!
//! Six separate forks convergently reinvented some version of this, which the
//! audit calls the most-wanted missing feature in the entire ecosystem. The
//! source address (`OBS-005`, #181) is the single most requested field in it.
//!
//! # Bounded in both dimensions
//!
//! No disk I/O means the log lives in memory, and memory is finite, so it is
//! bounded by **capacity** and by a **retention window** — either alone is
//! insufficient. Capacity alone lets a quiet host hold records from years ago;
//! retention alone lets a busy host exhaust memory inside the window.
//!
//! # Why the client count is *not* derived from this log
//!
//! `OBS-004` (#180) suggests the log's derived views could feed `POL-001` (#89)
//! and `POL-003` (#91) directly — one data structure serving both fleet
//! visibility and CMID decay. It does not, and the reason is a fingerprint:
//! a capacity-bounded log evicts by *volume*, so a burst of unrelated traffic
//! would silently drop machine IDs that are still within their 30-day window
//! and the reported count would fall. The count would then depend on how busy
//! the host had been rather than on how many machines exist, which is exactly
//! the kind of observable a prober can drive.
//!
//! [`crate::counting::ClientCounts`] therefore stays the authority on the
//! count, bounded per application and evicting only its own oldest entries. The
//! log records what the counting model decided — [`Activation::reported_count`]
//! and [`Activation::cached_count`] — so the views over it *explain* `POL-001`
//! and `POL-003` without being their source of truth.

use crate::counting::CountOutcome;
use crate::gate::{Grant, Observations, Refusal};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::IpAddr;
use core::time::Duration;
use kmsrs_db::Guid;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::kms::status::LicenseStatus;
use kmsrs_proto::kms::version::ProtocolVersion;
use kmsrs_proto::time::Instant;
use kmsrs_proto::types::{
    ApplicationId, ClientKind, ClientMachineId, CsvlkSelection, KmsCountedId, SkuId,
    WorkstationName,
};

/// How many events the log holds before the oldest is dropped.
pub const DEFAULT_CAPACITY: usize = 4_096;

/// How long an event is kept.
///
/// The same 30 days a client machine ID survives (`POL-003`, #91), so the log
/// always covers the whole window the counting model is working over. A shorter
/// retention would leave an operator unable to see why a machine expired.
pub const DEFAULT_RETENTION: Duration = crate::counting::CMID_EXPIRY;

/// Where a request came from (`OBS-005`, #181).
///
/// The address is captured by the platform layer from the accepted connection
/// and travels **with the request**, never through a shared slot. py-kms writes
/// the peer address into the process-global `srv_config['raddr']`, so a
/// concurrent connection can overwrite it before the first request is handled;
/// the Organization fork then persists that racy value as `lastRequestIP`
/// (`ARCH-014`, #14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Peer {
    /// The client's address.
    ///
    /// IPv6-native: an IPv4 client is carried as an IPv4-mapped address by the
    /// platform layer, so there is one representation rather than two.
    pub address: IpAddr,
    /// The client's source port.
    pub port: u16,
}

/// A request this host activated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// Which host key answered, and whether the product was recognised
    /// (`POL-017`, #105).
    pub selection: CsvlkSelection,
    /// The count sent to this client (`POL-001`, #89).
    pub reported_count: u32,
    /// How many machines the host was actually holding for the application.
    ///
    /// Recorded alongside [`Activation::reported_count`] because the two differ
    /// whenever the view floors or saturates, and an operator seeing only the
    /// reported number cannot tell which happened.
    pub cached_count: u32,
    /// What the counting model did with this machine ID.
    pub outcome: CountOutcome,
    /// How many machine IDs this request retired by expiry (`POL-003`, #91).
    pub expired: u32,
    /// Whether the client declared an implausible `N_Policy` (`POL-006`, #94).
    pub anomalous_demand: bool,
}

/// What happened to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Activated.
    Activated(Activation),
    /// Refused, with the reason (`POL-016`, #104).
    Refused(Refusal),
}

/// One request, recorded immutably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// A number that increases by one per recorded event and is never reused.
    ///
    /// This, not the timestamp, is what makes ordering stable: two requests
    /// handled on different threads can read the same clock value, and a log
    /// sorted by timestamp would then order them arbitrarily. The sequence is
    /// assigned inside [`EventLog::record`], so whichever request reaches the
    /// log first is first, permanently.
    pub sequence: u64,
    /// When it was handled.
    pub at: Instant,
    /// Where it came from (`OBS-005`, #181).
    ///
    /// `None` only on a transport with no meaningful peer.
    pub peer: Option<Peer>,
    /// The protocol version the client spoke.
    pub version: ProtocolVersion,
    /// The application GUID the client claimed.
    pub application: ApplicationId,
    /// The product the client asked about, kept as a raw GUID so an unknown
    /// product is still legible (`POL-017`, #105).
    pub counted: KmsCountedId,
    /// The SKU the client claimed (`OBS-006`, #182).
    ///
    /// A host **reads and ignores** it (`KMS-018`, #34) — the counted ID is
    /// what a decision is made on — so this is recorded for the operator's
    /// benefit and never for a policy's. It is the second half of the composite
    /// identity: one machine activating Windows and Office is two rows in
    /// [`EventLog::clients`], and the SKU is what tells them apart.
    pub sku: SkuId,
    /// The client's machine ID.
    pub client_machine_id: ClientMachineId,
    /// The client's licence status.
    pub license_status: LicenseStatus,
    /// Whether the client said it was a virtual machine (`KMS-017`, #33).
    ///
    /// Recorded and never acted upon: no policy path reads it, because a host
    /// that refused virtual machines would be trivially distinguishable from
    /// one that did not.
    pub client_kind: ClientKind,
    /// The name the client sent — untrusted, and never a gate (`POL-015`, #103).
    pub workstation_name: WorkstationName,
    /// How far the client's clock was from this host's (`POL-011`, #99).
    pub clock_skew: Option<Duration>,
    /// Whether the database recognised the product.
    pub known_product: bool,
    /// What this host did.
    pub outcome: Outcome,
}

impl Event {
    /// Whether this request was activated.
    #[must_use]
    pub const fn activated(&self) -> bool {
        matches!(self.outcome, Outcome::Activated(_))
    }
}

/// Why an event left the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    /// Evicted because the log was full.
    pub by_capacity: u64,
    /// Removed because it fell outside the retention window.
    pub by_retention: u64,
}

/// The bounded, append-only event log (`OBS-004`, #180).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLog {
    events: VecDeque<Event>,
    capacity: usize,
    retention: Duration,
    next_sequence: u64,
    dropped: Dropped,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_RETENTION)
    }
}

impl EventLog {
    /// A log with the given bounds.
    ///
    /// A capacity of zero is raised to one: a log that cannot hold an event is
    /// a bug at the call site, and silently discarding everything would be a
    /// worse outcome than holding one record.
    #[must_use]
    pub fn new(capacity: usize, retention: Duration) -> Self {
        Self {
            events: VecDeque::new(),
            capacity: capacity.max(1),
            retention,
            next_sequence: 0,
            dropped: Dropped::default(),
        }
    }

    /// Record a request and what this host did about it.
    ///
    /// Returns the sequence number assigned, so a caller can correlate a log
    /// line with the record.
    pub fn record(
        &mut self,
        request: &Request,
        peer: Option<Peer>,
        now: Instant,
        outcome: Outcome,
        observations: Observations,
    ) -> u64 {
        self.expire(now);

        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);

        if self.events.len() >= self.capacity {
            self.events.pop_front();
            self.dropped.by_capacity = self.dropped.by_capacity.saturating_add(1);
        }

        self.events.push_back(Event {
            sequence,
            at: now,
            peer,
            version: request.version,
            application: request.application,
            counted: request.counted,
            sku: request.sku,
            client_machine_id: request.client_machine_id,
            license_status: request.license_status,
            client_kind: request.client_kind,
            workstation_name: request.workstation_name.clone(),
            clock_skew: observations.clock_skew,
            known_product: observations.known_product,
            outcome,
        });

        sequence
    }

    /// Record a granted request, reading the counting outcome off the grant.
    pub fn record_grant(
        &mut self,
        request: &Request,
        peer: Option<Peer>,
        now: Instant,
        grant: &Grant<'_>,
        observations: Observations,
    ) -> u64 {
        let outcome = Outcome::Activated(Activation {
            selection: grant.selection,
            reported_count: grant.counts.reported,
            cached_count: grant.counts.cached,
            outcome: grant.counts.outcome,
            expired: grant.counts.expired,
            anomalous_demand: grant.counts.anomalous_demand,
        });
        self.record(request, peer, now, outcome, observations)
    }

    /// Drop events outside the retention window.
    ///
    /// Events are appended in sequence order and timestamps are monotonic, so
    /// this stops at the first record still inside the window.
    pub fn expire(&mut self, now: Instant) -> u64 {
        let mut removed = 0_u64;
        while let Some(oldest) = self.events.front() {
            if now.saturating_duration_since(oldest.at) < self.retention {
                break;
            }
            self.events.pop_front();
            removed = removed.saturating_add(1);
        }
        self.dropped.by_retention = self.dropped.by_retention.saturating_add(removed);
        removed
    }

    /// Every event held, oldest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Event> + '_ {
        self.events.iter()
    }

    /// The most recent events, newest first.
    pub fn recent(&self, limit: usize) -> impl Iterator<Item = &Event> + '_ {
        self.events.iter().rev().take(limit)
    }

    /// How many events are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// How many events have been recorded since the log was created, including
    /// those since dropped.
    #[must_use]
    pub const fn recorded(&self) -> u64 {
        self.next_sequence
    }

    /// How many events have left the log, and why.
    ///
    /// Surfaced rather than hidden: a log silently discarding records reads as
    /// a complete history when it is not.
    #[must_use]
    pub const fn dropped(&self) -> Dropped {
        self.dropped
    }

    /// The number of distinct machines seen for an application in the log.
    ///
    /// A *view*, not the count sent to clients — see the module documentation
    /// for why the two are deliberately different data structures.
    #[must_use]
    pub fn distinct_machines(&self, application: ApplicationId) -> usize {
        let mut seen: VecDeque<Guid> = VecDeque::new();
        for event in &self.events {
            if event.application != application || !event.activated() {
                continue;
            }
            let cmid = event.client_machine_id.0;
            if !seen.contains(&cmid) {
                seen.push_back(cmid);
            }
        }
        seen.len()
    }

    /// The fleet, one row per `(machine, SKU)` (`OBS-006`, #182).
    ///
    /// # Why that key, and not either half of it
    ///
    /// py-kms has keyed this three times, six years apart, and got a different
    /// answer each time: `clientMachineId` alone (2019 fork), then
    /// `(cmid, applicationId)` (upstream), then `(cmid, skuId)` (2025 fork).
    /// The reason it keeps being rediscovered is that **the right key depends
    /// on what the row is for**, and there are two different things here:
    ///
    /// * The **count** a client is told is per `(cmid, application)`, because
    ///   that is what a genuine host caches — one machine activating Windows
    ///   and Office is one machine to the Windows bucket and one to the Office
    ///   bucket (`POL-002`, #90). [`crate::counting::ClientCounts`] owns that,
    ///   and this view is not its source.
    /// * The **fleet view** an operator reads is per `(cmid, SKU)`, because a
    ///   machine running Windows Enterprise and Office LTSC is two things they
    ///   maintain. Keying on the application would merge Office and Project
    ///   into one row; keying on the machine alone merges everything and loses
    ///   the answer to "what is on that box".
    ///
    /// Keying on the machine alone is also the shape that produces py-kms's
    /// original defect: a mutable row per machine, overwritten on every
    /// request, so the SKU column shows whichever product asked last.
    ///
    /// # Bounded
    ///
    /// Walks the log once and returns at most `limit` rows, most recently seen
    /// first. The log is already bounded in both dimensions, so this is
    /// `O(log)` in time and `O(limit)` in output — MelroyB's dashboard sorts
    /// the whole log per view (`OBS-012`, #188).
    #[must_use]
    pub fn clients(&self, limit: usize) -> Vec<ClientView> {
        let mut rows: Vec<ClientView> = Vec::new();

        for event in &self.events {
            let key = (event.client_machine_id.0, event.sku.0);
            if let Some(row) = rows
                .iter_mut()
                .find(|row| (row.client_machine_id.0, row.sku.0) == key)
            {
                row.requests = row.requests.saturating_add(1);
                if event.activated() {
                    row.activations = row.activations.saturating_add(1);
                }
                // Last writer wins for the mutable columns, which is right for
                // a "most recent" view and is why they are named that way.
                row.last_seen = event.at;
                row.last_sequence = event.sequence;
                row.workstation_name = event.workstation_name.clone();
                row.application = event.application;
                row.counted = event.counted;
                row.peer = event.peer;
                row.activated_last = event.activated();
            } else {
                rows.push(ClientView {
                    client_machine_id: event.client_machine_id,
                    sku: event.sku,
                    application: event.application,
                    counted: event.counted,
                    workstation_name: event.workstation_name.clone(),
                    peer: event.peer,
                    first_seen: event.at,
                    last_seen: event.at,
                    last_sequence: event.sequence,
                    requests: 1,
                    activations: u64::from(event.activated()),
                    activated_last: event.activated(),
                });
            }
        }

        // Most recently seen first, by sequence rather than by timestamp: two
        // requests handled on different threads can read the same clock value,
        // and the sequence is what makes the order stable.
        rows.sort_by_key(|row| core::cmp::Reverse(row.last_sequence));
        rows.truncate(limit);
        rows
    }
}

/// One row of the fleet view (`OBS-006`, #182).
///
/// Derived from the log on demand rather than maintained alongside it. That is
/// the whole difference from py-kms's model: there is no row to overwrite, so
/// "what activated last Tuesday?" is still answerable on Wednesday.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientView {
    /// The machine.
    pub client_machine_id: ClientMachineId,
    /// The SKU it asked about — the other half of the key.
    pub sku: SkuId,
    /// The application that SKU belongs to, as of the most recent request.
    pub application: ApplicationId,
    /// The counted ID the most recent request named.
    pub counted: KmsCountedId,
    /// The name it most recently called itself. Untrusted (`POL-015`, #103).
    pub workstation_name: WorkstationName,
    /// Where the most recent request came from (`OBS-005`, #181).
    pub peer: Option<Peer>,
    /// When this pair was first seen, within the retained window.
    pub first_seen: Instant,
    /// When it was last seen.
    pub last_seen: Instant,
    /// The sequence number of the most recent request, which is what the view
    /// is ordered by.
    pub last_sequence: u64,
    /// How many requests this pair made.
    pub requests: u64,
    /// How many of them were activated.
    pub activations: u64,
    /// Whether the most recent one was.
    pub activated_last: bool,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::duration_suboptimal_units,
        clippy::expect_used,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{DEFAULT_RETENTION, EventLog, Outcome, Peer};
    use crate::counting::ClientCounts;
    use crate::gate::{Decision, Observations, Refusal, evaluate};
    use crate::identity::HostIdentity;
    use alloc::vec::Vec;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use core::time::Duration;
    use kmsrs_db::{Guid, KeyKind};
    use kmsrs_proto::entropy::testing::DeterministicEntropy;
    use kmsrs_proto::kms::request::Request;
    use kmsrs_proto::kms::status::LicenseStatus;
    use kmsrs_proto::kms::version::ProtocolVersion;
    use kmsrs_proto::time::{FileTime, Instant};
    use kmsrs_proto::types::{
        ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
        RequiredClients, SkuId, WorkstationName,
    };

    fn workstation(name: &str) -> WorkstationName {
        let mut field = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
        for (slot, unit) in field.iter_mut().zip(name.encode_utf16()) {
            *slot = unit;
        }
        WorkstationName::decode(&field)
    }

    fn identity() -> HostIdentity {
        let mut entropy = DeterministicEntropy::from_seed(0x5eed);
        HostIdentity::generate(&mut entropy, kmsrs_db::Date::new(2026, 8, 1).unwrap()).unwrap()
    }

    fn application() -> Guid {
        kmsrs_db::APPLICATIONS.first().unwrap().guid
    }

    fn request_for(counted: Guid, machine: u8, name: &str) -> Request {
        Request {
            version: ProtocolVersion { major: 6, minor: 0 },
            client_kind: ClientKind::VirtualMachine,
            license_status: LicenseStatus::Unlicensed,
            grace: GraceMinutes(0),
            application: ApplicationId(application()),
            sku: SkuId(counted),
            counted: KmsCountedId(counted),
            client_machine_id: ClientMachineId(Guid::from_bytes([machine; 16])),
            required_clients: RequiredClients(25),
            client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
            previous_client_machine_id: None,
            workstation_name: workstation(name),
        }
    }

    fn peer(last: u8) -> Peer {
        Peer {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            port: u16::from(last) + 1024,
        }
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_nanos(seconds * 1_000_000_000)
    }

    /// Drive a request all the way through the gate and into the log, which is
    /// how the server will use it.
    fn handle(
        log: &mut EventLog,
        counts: &mut ClientCounts,
        identity: &HostIdentity,
        request: &Request,
        peer: Option<Peer>,
        now: Instant,
    ) -> u64 {
        let (decision, observed) = evaluate(request, identity, counts, now, None);
        match decision {
            Decision::Grant(grant) => log.record_grant(request, peer, now, &grant, observed),
            Decision::Refuse(refusal) => {
                log.record(request, peer, now, Outcome::Refused(refusal), observed)
            }
        }
    }

    /// `OBS-004` (#180): one immutable record per request. py-kms keeps one
    /// mutable row per machine and overwrites it, so "what activated last
    /// Tuesday" is unanswerable — this is the test that says it is answerable
    /// here.
    #[test]
    fn a_machine_activating_repeatedly_leaves_a_history_not_a_row() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let unknown = Guid::from_bytes([0xAB; 16]);

        // The same machine, three times, with a different name each time.
        for (index, name) in ["tuesday", "wednesday", "thursday"].iter().enumerate() {
            let request = request_for(unknown, 1, name);
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(1)),
                at(index as u64 * 3_600),
            );
        }

        assert_eq!(log.len(), 3, "three requests, three records");
        let names: Vec<&str> = log
            .iter()
            .map(|event| event.workstation_name.as_str())
            .collect();
        assert_eq!(names, ["tuesday", "wednesday", "thursday"]);

        // The first record still says what it said, which is the whole point.
        let first = log.iter().next().unwrap();
        assert_eq!(first.at, at(0));
        assert!(first.activated());
    }

    /// `OBS-005` (#181). The address travels with the request; py-kms puts it
    /// in a process-global that a concurrent connection can overwrite before
    /// the first request is handled (`ARCH-014`, #14).
    #[test]
    fn every_event_carries_its_own_source_address() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let unknown = Guid::from_bytes([0xAB; 16]);

        // Interleave requests from different peers, as concurrent connections
        // would arrive.
        for machine in 1..=8_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(u64::from(machine)),
            );
        }

        for event in log.iter() {
            let machine = event.client_machine_id.0.to_bytes()[0];
            assert_eq!(
                event.peer,
                Some(peer(machine)),
                "event {} lost its peer",
                event.sequence
            );
        }
    }

    /// IPv6 is the native representation, so an address is never silently
    /// narrowed.
    #[test]
    fn an_ipv6_peer_survives_the_round_trip() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let expected = Peer {
            address,
            port: 49_152,
        };

        let request = request_for(Guid::from_bytes([0xAB; 16]), 1, "host");
        handle(
            &mut log,
            &mut counts,
            &identity,
            &request,
            Some(expected),
            at(0),
        );
        assert_eq!(log.iter().next().unwrap().peer, Some(expected));
    }

    /// `OBS-004` (#180): bounded by capacity, and the loss is reported rather
    /// than silent.
    #[test]
    fn the_log_is_bounded_by_capacity() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::new(4, DEFAULT_RETENTION);
        let unknown = Guid::from_bytes([0xAB; 16]);

        for machine in 1..=10_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(u64::from(machine)),
            );
        }

        assert_eq!(log.len(), 4);
        assert_eq!(log.recorded(), 10, "all ten were recorded");
        assert_eq!(log.dropped().by_capacity, 6, "and six were dropped");

        // The four that survive are the newest four, in order.
        let sequences: Vec<u64> = log.iter().map(|event| event.sequence).collect();
        assert_eq!(sequences, [6, 7, 8, 9]);
    }

    /// And bounded by time, because capacity alone lets a quiet host hold
    /// records from years ago.
    #[test]
    fn the_log_is_bounded_by_retention() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::new(1_000, Duration::from_hours(1));
        let unknown = Guid::from_bytes([0xAB; 16]);

        for machine in 1..=5_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(u64::from(machine)),
            );
        }
        assert_eq!(log.len(), 5, "well inside capacity");

        // Two hours later, everything has aged out.
        let request = request_for(unknown, 6, "host");
        handle(
            &mut log,
            &mut counts,
            &identity,
            &request,
            Some(peer(6)),
            at(7_200),
        );
        assert_eq!(log.len(), 1, "only the new one is inside the window");
        assert_eq!(log.dropped().by_retention, 5);
    }

    /// The default retention covers the whole window the counting model works
    /// over, so an operator can always see why a machine expired.
    #[test]
    fn retention_covers_the_cmid_expiry_window() {
        assert_eq!(DEFAULT_RETENTION, crate::counting::CMID_EXPIRY);
    }

    /// `OBS-004` (#180): ordering is stable because the sequence number is
    /// assigned at record time, not derived from the clock. Two requests
    /// handled on different threads can read the same clock value; a log
    /// ordered by timestamp would order them arbitrarily.
    #[test]
    fn ordering_is_stable_when_timestamps_tie() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let unknown = Guid::from_bytes([0xAB; 16]);

        // Every request at the same instant, as a burst of concurrent
        // connections would produce.
        for machine in 1..=20_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(0),
            );
        }

        let sequences: Vec<u64> = log.iter().map(|event| event.sequence).collect();
        let expected: Vec<u64> = (0..20).collect();
        assert_eq!(sequences, expected, "insertion order, permanently");

        // And no sequence number is ever reused.
        let mut sorted = sequences.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), sequences.len());
    }

    /// A refusal is a first-class record. An operator asking why a client is
    /// not activating needs to see the attempts that failed, which is exactly
    /// what a log holding only successes cannot show.
    ///
    /// Uses the application-mismatch refusal rather than the retail one,
    /// because that gate is unconditional while the retail gate is a build-time
    /// flag (`POL-010`, #98) — a test keyed on the flag would be testing the
    /// gate rather than the log.
    #[test]
    fn refusals_are_recorded_too() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();

        let product = kmsrs_db::PRODUCTS
            .iter()
            .find(|entry| entry.kind == KeyKind::KmsClient && entry.application.is_some())
            .unwrap();
        let other = kmsrs_db::APPLICATIONS
            .iter()
            .find(|entry| Some(entry.guid) != product.application)
            .unwrap();

        let mut request = request_for(product.activation_id, 1, "probe");
        request.application = ApplicationId(other.guid);

        handle(
            &mut log,
            &mut counts,
            &identity,
            &request,
            Some(peer(9)),
            at(0),
        );

        let event = log.iter().next().unwrap();
        assert!(!event.activated());
        assert_eq!(
            event.outcome,
            Outcome::Refused(Refusal::ApplicationMismatch)
        );
        assert_eq!(event.peer, Some(peer(9)), "including where it came from");
        assert_eq!(event.workstation_name.as_str(), "probe");
    }

    /// The log records what the counting model decided, so a view over it
    /// explains `POL-001` (#89) without being its source of truth.
    #[test]
    fn an_activation_records_both_the_reported_and_the_real_count() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let unknown = Guid::from_bytes([0xAB; 16]);

        for machine in 1..=60_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(0),
            );
        }

        let last = log.iter().next_back().unwrap();
        let Outcome::Activated(activation) = &last.outcome else {
            panic!("{last:?}");
        };
        assert_eq!(activation.reported_count, 50, "saturated");
        assert_eq!(activation.cached_count, 60, "but 60 are really held");
        assert_eq!(log.distinct_machines(ApplicationId(application())), 60);

        // The first request is the interesting one: one machine cached, but 25
        // reported, because the view floors at N_Policy.
        let first = log.iter().next().unwrap();
        let Outcome::Activated(activation) = &first.outcome else {
            panic!("{first:?}");
        };
        assert_eq!(activation.reported_count, 25);
        assert_eq!(activation.cached_count, 1);
    }

    /// The count sent to clients must not depend on how busy the host has been,
    /// which is why it is not derived from a capacity-bounded log. This is the
    /// test that would fail if someone rewired `POL-001` onto the log.
    #[test]
    fn log_pressure_does_not_move_the_reported_count() {
        let identity = identity();
        let unknown = Guid::from_bytes([0xAB; 16]);

        // Two hosts, identical traffic, wildly different log capacities.
        let mut reported = Vec::new();
        for capacity in [4_usize, 4_096] {
            let mut counts = ClientCounts::new();
            let mut log = EventLog::new(capacity, DEFAULT_RETENTION);
            for machine in 1..=40_u8 {
                let request = request_for(unknown, machine, "host");
                handle(
                    &mut log,
                    &mut counts,
                    &identity,
                    &request,
                    Some(peer(machine)),
                    at(0),
                );
            }
            let last = log.iter().next_back().unwrap();
            let Outcome::Activated(activation) = &last.outcome else {
                panic!("{last:?}");
            };
            reported.push(activation.reported_count);
        }

        assert_eq!(
            reported[0], reported[1],
            "a log that drops records must not change what clients are told"
        );
    }

    #[test]
    fn recent_returns_the_newest_first() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::default();
        let unknown = Guid::from_bytes([0xAB; 16]);

        for machine in 1..=10_u8 {
            let request = request_for(unknown, machine, "host");
            handle(
                &mut log,
                &mut counts,
                &identity,
                &request,
                Some(peer(machine)),
                at(u64::from(machine)),
            );
        }

        let sequences: Vec<u64> = log.recent(3).map(|event| event.sequence).collect();
        assert_eq!(sequences, [9, 8, 7]);
        assert!(
            log.recent(100).count() == 10,
            "a limit past the end is fine"
        );
    }

    /// A capacity of zero would otherwise discard everything silently.
    #[test]
    fn a_zero_capacity_log_still_holds_one_event() {
        let identity = identity();
        let mut counts = ClientCounts::new();
        let mut log = EventLog::new(0, DEFAULT_RETENTION);
        let request = request_for(Guid::from_bytes([0xAB; 16]), 1, "host");
        handle(
            &mut log,
            &mut counts,
            &identity,
            &request,
            Some(peer(1)),
            at(0),
        );
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }
    /// `OBS-006` (#182): one machine activating Windows and Office produces
    /// **two view rows and one count entry per application**.
    ///
    /// py-kms keyed this three times, six years apart — the machine alone, then
    /// `(machine, application)`, then `(machine, SKU)` — because the right key
    /// depends on what the row is for, and nobody wrote down that there were
    /// two questions. This test is that sentence, executable.
    #[test]
    fn one_machine_with_two_products_is_two_rows_and_two_counts() {
        let windows = ApplicationId(Guid::from_bytes([0x55; 16]));
        let office = ApplicationId(Guid::from_bytes([0x0f; 16]));
        let machine = ClientMachineId(Guid::from_bytes([0xAB; 16]));

        let mut log = EventLog::new(64, DEFAULT_RETENTION);
        let mut counts = ClientCounts::new();

        for (application, sku, counted) in [
            (windows, [0x01_u8; 16], [0xC1_u8; 16]),
            (office, [0x02_u8; 16], [0xC2_u8; 16]),
        ] {
            let request = request_from(application, sku, counted, machine);
            let view = counts.observe(
                application,
                machine,
                request.required_clients,
                Instant::from_nanos(1),
            );
            log.record(
                &request,
                None,
                Instant::from_nanos(1),
                Outcome::Activated(super::Activation {
                    selection: kmsrs_proto::types::CsvlkSelection::Fallback { index: 0 },
                    reported_count: view.reported,
                    cached_count: view.cached,
                    outcome: view.outcome,
                    expired: view.expired,
                    anomalous_demand: view.anomalous_demand,
                }),
                Observations {
                    known_product: true,
                    clock_skew: None,
                    clock_skewed: false,
                },
            );
        }

        // Two rows in the fleet view: the machine runs two products, and an
        // operator maintains both.
        let rows = log.clients(16);
        assert_eq!(rows.len(), 2, "{rows:#?}");
        assert!(rows.iter().all(|row| row.client_machine_id == machine));
        let skus: Vec<Guid> = rows.iter().map(|row| row.sku.0).collect();
        assert!(skus.contains(&Guid::from_bytes([0x01; 16])));
        assert!(skus.contains(&Guid::from_bytes([0x02; 16])));

        // One count entry per application: to the Windows bucket it is one
        // machine, and to the Office bucket it is one machine.
        assert_eq!(counts.cached_for(windows), 1);
        assert_eq!(counts.cached_for(office), 1);
        assert_eq!(log.distinct_machines(windows), 1);
        assert_eq!(log.distinct_machines(office), 1);
    }

    /// The same machine asking about the same SKU twice is **one** row, with
    /// the request count rising.
    ///
    /// The other half of the key: without it, a machine that renews every seven
    /// days becomes a hundred rows and the view is a log with extra steps.
    #[test]
    fn repeated_requests_for_one_product_stay_one_row() {
        let windows = ApplicationId(Guid::from_bytes([0x55; 16]));
        let machine = ClientMachineId(Guid::from_bytes([0xAB; 16]));
        let mut log = EventLog::new(64, DEFAULT_RETENTION);

        for round in 1..=5_u64 {
            log.record(
                &request_from(windows, [0x01; 16], [0xC1; 16], machine),
                None,
                Instant::from_nanos(round),
                Outcome::Refused(Refusal::PreviewProduct),
                Observations {
                    known_product: true,
                    clock_skew: None,
                    clock_skewed: false,
                },
            );
        }

        let rows = log.clients(16);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].requests, 5);
        assert_eq!(rows[0].activations, 0, "none of them activated");
        assert!(!rows[0].activated_last);
        assert_eq!(rows[0].first_seen, Instant::from_nanos(1));
        assert_eq!(rows[0].last_seen, Instant::from_nanos(5));
    }

    /// The view is bounded and ordered most-recent-first, by sequence rather
    /// than by timestamp — two requests handled on different threads can read
    /// the same clock value, and the sequence is what makes the order stable.
    #[test]
    fn the_fleet_view_is_bounded_and_most_recent_first() {
        let windows = ApplicationId(Guid::from_bytes([0x55; 16]));
        let mut log = EventLog::new(256, DEFAULT_RETENTION);

        for index in 0..40_u128 {
            let machine = ClientMachineId(Guid::from_bytes(index.to_be_bytes()));
            log.record(
                &request_from(windows, [0x01; 16], [0xC1; 16], machine),
                None,
                // Every request at the same instant, which is the case a
                // timestamp sort gets wrong.
                Instant::from_nanos(7),
                Outcome::Refused(Refusal::PreviewProduct),
                Observations {
                    known_product: true,
                    clock_skew: None,
                    clock_skewed: false,
                },
            );
        }

        let rows = log.clients(10);
        assert_eq!(rows.len(), 10, "the view is not bounded");
        for pair in rows.windows(2) {
            assert!(
                pair[0].last_sequence > pair[1].last_sequence,
                "the view is not most-recent-first"
            );
        }
        // The most recent is the last machine recorded.
        assert_eq!(
            rows[0].client_machine_id.0,
            Guid::from_bytes(39_u128.to_be_bytes())
        );
    }

    /// A request with the fields these tests vary.
    fn request_from(
        application: ApplicationId,
        sku: [u8; 16],
        counted: [u8; 16],
        machine: ClientMachineId,
    ) -> Request {
        let mut units = [0_u16; kmsrs_proto::types::WORKSTATION_NAME_UNITS];
        for (slot, unit) in units.iter_mut().zip("WKS-000001".encode_utf16()) {
            *slot = unit;
        }

        Request {
            version: ProtocolVersion::from_wire(0x0006_0000),
            client_kind: ClientKind::BareMetal,
            license_status: LicenseStatus::from_wire(2),
            grace: GraceMinutes(0),
            application,
            sku: SkuId(Guid::from_bytes(sku)),
            counted: KmsCountedId(Guid::from_bytes(counted)),
            client_machine_id: machine,
            previous_client_machine_id: None,
            client_time: ClientTime(FileTime::from_ticks(133_000_000_000_000_000)),
            required_clients: RequiredClients(25),
            workstation_name: WorkstationName::decode(&units),
        }
    }
}
