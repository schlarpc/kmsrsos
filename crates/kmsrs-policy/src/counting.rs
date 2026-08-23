//! The client-count model (`POL-001`, #89 … `POL-007`, #95).
//!
//! # A saturating world model, viewed per client
//!
//! A genuine KMS host caches up to `2N` client machine IDs and reports how many
//! it is holding, so the number it returns saturates at 50 for Windows client
//! SKUs and 10 for server and Office. Both existing emulators arrive at the same
//! numbers by arithmetic rather than by counting anything.
//!
//! This model counts real CMIDs into a shared world and then answers each
//! request from a *view* over it:
//!
//! ```text
//! world    = min(cached_for_this_application, 2 * min(N, 100))
//! reported = if N <= 100 { max(world, N) } else { world }
//! ```
//!
//! The second line is the one that matters, and the fact that it is **never
//! written back** is the whole design. A demand is satisfied for the client
//! that made it and for nobody else. There is no detection surface, because
//! every honest client sending the same `N_Policy` sees the same number.
//!
//! # Why the floor stops at 100 (`POL-019`, #313)
//!
//! Because a floor that does not stop is itself the tell. `N_Policy` is 25 for
//! Windows client SKUs and 5 for server and Office; 100 is four times the
//! largest value any Microsoft product has ever declared, so no real client is
//! within sight of it. Above it, answering the demand back means telling a
//! machine this host has never seen that it is caching five thousand others —
//! which no genuine host says, and which nothing else on the wire reveals.
//!
//! Beyond the floor the answer is `world`: how many machines are actually
//! cached. That is not a refusal and not a strict mode — it is the same
//! sentence a genuine host says, and a client that would have failed to
//! activate against a real host fails here too. vlmcsd refuses outright with
//! `0x8007000D`, which is a third answer nobody real gives (declined item D38).
//!
//! # The overcharge attack is not mitigated, it is unrepresentable
//!
//! A genuine host can be permanently disabled: an overcharge request declaring
//! 376 or more required clients, followed by 671 activations, poisons its table
//! for good. vlmcsd is deliberately bug-compatible and needs a restart to
//! recover (`POL-005`, #93). Here the attack has no target — the request that
//! would poison the table cannot write to it, because *no* request writes an
//! `N_Policy` anywhere.
//!
//! # Expiry
//!
//! Microsoft's host removes a CMID after 30 days without renewal and
//! decrements; on renewal the entry is deleted and re-inserted (`POL-003`,
//! #91). That period is not folklore — it is
//! `Security-SPP-CMIDExpirationPeriod`, 43200 minutes, read out of Microsoft's
//! own licence artifacts by the extraction pipeline. Neither existing
//! implementation has this, which makes it the missing half of the only
//! feature that models real host behaviour at all.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::time::Duration;
use kmsrs_db::Guid;
use kmsrs_proto::time::Instant;
use kmsrs_proto::types::{ApplicationId, ClientMachineId, RequiredClients};

/// How long a cached client machine ID survives without renewal
/// (`POL-003`, #91).
///
/// 43200 minutes. Taken from `Security-SPP-CMIDExpirationPeriod` in Microsoft's
/// KMS host licences rather than from anyone's guess.
#[expect(
    clippy::duration_suboptimal_units,
    reason = "43200 minutes is the value Microsoft's artifact states, in the unit               it states it in; rounding it to 720 hours would make the constant               stop matching the field it was read from"
)]
pub const CMID_EXPIRY: Duration = Duration::from_mins(43_200);

/// The largest `N_Policy` this model will honour (`POL-006`, #94;
/// `POL-019`, #313).
///
/// Two things at once, and they are the same number for the same reason.
///
/// It bounds **how much state a declaration can make this host hold**, because
/// otherwise a single request declaring four billion required clients would
/// decide the memory footprint. It is also the point past which the reported
/// count stops being floored at the demand and becomes the world — because a
/// host that answers "five thousand" to a machine it has never seen has told a
/// prober something no genuine host would.
///
/// 100 is four times the largest value any Microsoft product declares:
/// `N_Policy` is 25 for Windows client SKUs and 5 for server and Office. Every
/// real client is comfortably inside it, and every request outside it is a
/// diagnostic tool or a probe.
pub const MAX_TRACKED_REQUIRED_CLIENTS: u32 = 100;

/// The most client machine IDs cached per application.
///
/// Twice [`MAX_TRACKED_REQUIRED_CLIENTS`], because that is the most a genuine
/// host would hold for the largest `N_Policy` this model tracks.
pub const MAX_CACHED_PER_APPLICATION: usize = 200;

/// The most applications tracked at once.
///
/// Three exist — Windows, Office 2010, Office 2013 and later — and Office 2013
/// through LTSC 2024 share one, because they share an application GUID
/// (`POL-002`, #90). The bound is larger than three so that a client sending an
/// application GUID this build has never heard of still gets counted rather
/// than sharing a bucket with something else.
pub const MAX_APPLICATIONS: usize = 8;

/// One cached client machine ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cached {
    cmid: Guid,
    seen: Instant,
}

/// The cache for one application (`POL-002`, #90).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Bucket {
    application: Option<Guid>,
    /// Oldest first, so expiry and eviction both work from the front.
    entries: VecDeque<Cached>,
}

/// What happened to a client machine ID when it was counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CountOutcome {
    /// A machine this host had not seen was added.
    Inserted,
    /// A machine this host already knew renewed (`POL-004`, #92).
    Renewed,
    /// A machine was added, and the oldest was evicted to make room
    /// (`POL-007`, #95).
    ///
    /// Evicting is strictly more compatible than a genuine host's refusal. With
    /// per-client views the 671-entry cap that makes a real host return
    /// `0xC004D104` is never reached in a way that matters, so there is nothing
    /// to gain by reproducing the refusal.
    InsertedWithEviction,
}

/// What a request should be told, and what the model learned from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountView {
    /// The number to put in the response.
    pub reported: u32,
    /// How many machines this host is actually holding for the application.
    pub cached: u32,
    /// What happened to this request's machine ID.
    pub outcome: CountOutcome,
    /// How many entries expiry removed while answering this request.
    pub expired: u32,
    /// Whether the client's `N_Policy` was above what this model tracks
    /// (`POL-006`, #94).
    ///
    /// Recorded so it can be logged. The request is still answered — refusing
    /// an unusual demand would be a difference from a genuine host, and the
    /// demand cannot hurt anything because it is never written back.
    pub anomalous_demand: bool,
}

/// The shared client-count world.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientCounts {
    buckets: Vec<Bucket>,
}

impl ClientCounts {
    /// An empty world.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: Vec::new(),
        }
    }

    /// Count a request and compute the view to answer it with.
    ///
    /// This is the only method that mutates, and what it writes is exactly one
    /// thing: that this machine ID was seen at this time. The client's
    /// `N_Policy` influences the *answer* and never the state, which is what
    /// makes the overcharge attack unrepresentable (`POL-005`, #93).
    pub fn observe(
        &mut self,
        application: ApplicationId,
        cmid: ClientMachineId,
        required: RequiredClients,
        now: Instant,
    ) -> CountView {
        let index = self.bucket_for(application.0, now);
        let Some(bucket) = self.buckets.get_mut(index) else {
            // Unreachable: `bucket_for` returns an index it has just ensured
            // exists. Answering from an empty world rather than panicking keeps
            // the model total, which is what `ARCH-008` asks of it.
            return CountView {
                reported: required.0.max(1),
                cached: 0,
                outcome: CountOutcome::Inserted,
                expired: 0,
                anomalous_demand: required.0 > MAX_TRACKED_REQUIRED_CLIENTS,
            };
        };

        let expired = bucket.expire(now);
        let outcome = bucket.record(cmid.0, now);
        let cached = u32::try_from(bucket.entries.len()).unwrap_or(u32::MAX);

        let demand = required.0;
        let anomalous_demand = demand > MAX_TRACKED_REQUIRED_CLIENTS;
        let tracked = demand.clamp(1, MAX_TRACKED_REQUIRED_CLIENTS);

        // A genuine host caches `2N` and reports how many it holds, so the
        // count saturates there.
        let saturation = tracked.saturating_mul(2);
        let world = cached.min(saturation);

        // Floored at `N`, the minimum that activates — not at `2N`. py-kms
        // reflects 10000 back for a demand of 5000, which the audit calls
        // neither realistic nor safe (`POL-006`, #94).
        //
        // `POL-019` (#313): the floor applies only up to what this model
        // tracks. Beyond that the answer is the world — how many machines this
        // host is actually holding — which is exactly what a genuine host says.
        // Reflecting an absurd demand back is a one-packet emulator test: no
        // real host has ever told a machine it had never seen that it was
        // caching five thousand others.
        let reported = if anomalous_demand {
            world
        } else {
            world.max(demand)
        };

        CountView {
            reported,
            cached,
            outcome,
            expired,
            anomalous_demand,
        }
    }

    /// How many machines are cached for an application, without observing.
    ///
    /// For the web UI and the event log, which must be able to read the world
    /// without changing it.
    #[must_use]
    pub fn cached_for(&self, application: ApplicationId) -> u32 {
        self.buckets
            .iter()
            .find(|bucket| bucket.application == Some(application.0))
            .map_or(0, |bucket| {
                u32::try_from(bucket.entries.len()).unwrap_or(u32::MAX)
            })
    }

    /// Every application this host has seen, with its cached count.
    pub fn applications(&self) -> impl Iterator<Item = (ApplicationId, u32)> + '_ {
        self.buckets.iter().filter_map(|bucket| {
            let application = bucket.application?;
            Some((
                ApplicationId(application),
                u32::try_from(bucket.entries.len()).unwrap_or(u32::MAX),
            ))
        })
    }

    /// The index of the bucket for an application, creating it if there is
    /// room.
    ///
    /// When there is not, the bucket whose newest entry is oldest is reused. A
    /// client sending an unrecognised application GUID must not be able to make
    /// this host allocate without bound, and must not silently share a bucket
    /// with a different product either.
    ///
    /// This returns an index rather than a `&mut Bucket` so that it does not
    /// have to produce a reference on a path that cannot happen — every way of
    /// writing that needs either an `unwrap` or an `unsafe`, and the crate
    /// forbids both.
    fn bucket_for(&mut self, application: Guid, now: Instant) -> usize {
        if let Some(position) = self
            .buckets
            .iter()
            .position(|bucket| bucket.application == Some(application))
        {
            return position;
        }

        if self.buckets.len() < MAX_APPLICATIONS {
            self.buckets.push(Bucket {
                application: Some(application),
                entries: VecDeque::new(),
            });
            return self.buckets.len().saturating_sub(1);
        }

        // Reuse the bucket whose newest entry is oldest, so a burst of unknown
        // application GUIDs displaces stale buckets rather than live ones.
        let stalest = self
            .buckets
            .iter()
            .enumerate()
            .min_by_key(|(_, bucket)| bucket.entries.back().map_or(now, |entry| entry.seen))
            .map_or(0, |(index, _)| index);
        if let Some(bucket) = self.buckets.get_mut(stalest) {
            bucket.application = Some(application);
            bucket.entries.clear();
        }
        stalest
    }
}

impl Bucket {
    /// Drop entries older than the expiry period (`POL-003`, #91).
    ///
    /// Entries are ordered oldest-first, so this stops at the first live one.
    fn expire(&mut self, now: Instant) -> u32 {
        let mut removed = 0_u32;
        while let Some(oldest) = self.entries.front() {
            if now.saturating_duration_since(oldest.seen) < CMID_EXPIRY {
                break;
            }
            self.entries.pop_front();
            removed = removed.saturating_add(1);
        }
        removed
    }

    /// Insert or renew a machine ID (`POL-004`, #92).
    ///
    /// A renewal deletes the entry and re-inserts it at the back, which is what
    /// Microsoft's host does and what keeps the ordering usable for both expiry
    /// and eviction.
    fn record(&mut self, cmid: Guid, now: Instant) -> CountOutcome {
        if let Some(position) = self.entries.iter().position(|entry| entry.cmid == cmid) {
            self.entries.remove(position);
            self.entries.push_back(Cached { cmid, seen: now });
            return CountOutcome::Renewed;
        }

        let evicted = if self.entries.len() >= MAX_CACHED_PER_APPLICATION {
            self.entries.pop_front();
            true
        } else {
            false
        };
        self.entries.push_back(Cached { cmid, seen: now });

        if evicted {
            CountOutcome::InsertedWithEviction
        } else {
            CountOutcome::Inserted
        }
    }
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

    use super::{
        CMID_EXPIRY, ClientCounts, CountOutcome, MAX_APPLICATIONS, MAX_CACHED_PER_APPLICATION,
        MAX_TRACKED_REQUIRED_CLIENTS,
    };
    use core::time::Duration;
    use kmsrs_db::Guid;
    use kmsrs_proto::time::Instant;
    use kmsrs_proto::types::{ApplicationId, ClientMachineId, RequiredClients};

    fn windows() -> ApplicationId {
        ApplicationId(Guid::from_bytes([0x55; 16]))
    }

    fn office() -> ApplicationId {
        ApplicationId(Guid::from_bytes([0x0f; 16]))
    }

    fn client(number: u8) -> ClientMachineId {
        ClientMachineId(Guid::from_bytes([number; 16]))
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_nanos(seconds.saturating_mul(1_000_000_000))
    }

    /// `POL-001` (#89): a single client sees the minimum that activates, and
    /// the count saturates at `2N` — 50 for a client SKU, 10 for server and
    /// Office.
    #[test]
    fn the_reported_count_floors_at_n_and_saturates_at_twice_n() {
        let mut counts = ClientCounts::new();

        // One Windows client declaring 25: the answer is 25, which is what
        // makes the very first activation succeed.
        let view = counts.observe(windows(), client(1), RequiredClients(25), at(0));
        assert_eq!(view.reported, 25);
        assert_eq!(view.cached, 1);

        // Sixty distinct machines: saturates at 50 and stays there.
        for number in 2..=60_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        let view = counts.observe(windows(), client(61), RequiredClients(25), at(0));
        assert_eq!(view.cached, 61);
        assert_eq!(view.reported, 50, "a client SKU saturates at 50");

        // Server and Office declare 5, so they saturate at 10.
        let mut counts = ClientCounts::new();
        for number in 1..=30_u8 {
            counts.observe(office(), client(number), RequiredClients(5), at(0));
        }
        let view = counts.observe(office(), client(31), RequiredClients(5), at(0));
        assert_eq!(view.reported, 10, "server and Office saturate at 10");
    }

    /// `POL-005` (#93). The attack needs the declared count to reach shared
    /// state. It cannot, so there is nothing to poison.
    #[test]
    fn an_overcharge_request_cannot_affect_any_other_client() {
        let mut counts = ClientCounts::new();
        for number in 1..=10_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        let before = counts.observe(windows(), client(11), RequiredClients(25), at(0));

        // The attack: declare far more than any real product needs, then
        // activate repeatedly.
        for number in 100..=200_u8 {
            let view = counts.observe(windows(), client(number), RequiredClients(400), at(0));
            assert!(view.anomalous_demand);
            assert!(
                view.reported <= 200,
                "an absurd demand must not be reflected back (POL-019, #313); \
                 got {}",
                view.reported
            );
        }

        // An honest client's answer is unchanged apart from the machines that
        // genuinely joined.
        let after = counts.observe(windows(), client(11), RequiredClients(25), at(0));
        assert_eq!(after.reported, 50, "still the saturation value");
        assert!(before.reported <= after.reported);
        assert_eq!(after.outcome, CountOutcome::Renewed);
    }

    /// `POL-006` (#94): every plausible demand is accepted and answered with
    /// the minimum that activates. py-kms reflects `2N` back — 10000 for a
    /// demand of 5000 — which the audit calls neither realistic nor safe.
    #[test]
    fn a_plausible_demand_is_answered_with_exactly_what_it_asked_for() {
        let mut counts = ClientCounts::new();
        for (demand, expected) in [
            (0_u32, 1_u32),
            (1, 1),
            (5, 5),
            (25, 25),
            (MAX_TRACKED_REQUIRED_CLIENTS, MAX_TRACKED_REQUIRED_CLIENTS),
        ] {
            let view = counts.observe(windows(), client(1), RequiredClients(demand), at(0));
            assert_eq!(view.reported, expected, "demand {demand}");
            assert!(!view.anomalous_demand, "demand {demand}");
        }
    }

    /// `POL-019` (#313): an absurd demand is answered the way a genuine host
    /// answers it — with how many machines are actually cached.
    ///
    /// This is the one probe the previous behaviour failed. A prober sends
    /// `N_Policy = 5000` from a machine the host has never seen; a real host
    /// reports its small cache and the client does not activate. Reflecting
    /// 5000 back was a fact about this program that nothing else on the wire
    /// revealed, and it took one packet to read.
    ///
    /// Note what is *not* done here: the request is still answered, still
    /// counted, and still gets an ePID. Refusing it — vlmcsd returns
    /// `0x8007000D` — would be a third behaviour, equally distinctive, and is
    /// declined as D38 (#283).
    #[test]
    fn an_absurd_demand_is_answered_the_way_a_genuine_host_answers_it() {
        let mut counts = ClientCounts::new();

        // A host that has seen nobody. It is holding exactly this client.
        for demand in [MAX_TRACKED_REQUIRED_CLIENTS + 1, 1_000, 5_000, u32::MAX] {
            let mut fresh = ClientCounts::new();
            let view = fresh.observe(windows(), client(1), RequiredClients(demand), at(0));
            assert!(view.anomalous_demand, "demand {demand}");
            assert_eq!(
                view.reported, 1,
                "demand {demand} was reflected back rather than answered with \
                 the cache size"
            );
        }

        // A busy host answers with what it holds, still capped at the
        // saturation value a genuine host would report.
        for number in 1..=60_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        let view = counts.observe(windows(), client(61), RequiredClients(5_000), at(0));
        assert_eq!(view.cached, 61);
        assert_eq!(view.reported, 61, "the answer is the world, not the demand");
        assert!(view.anomalous_demand);
    }

    /// The boundary is exactly [`MAX_TRACKED_REQUIRED_CLIENTS`], and crossing
    /// it changes only what an absurd demand is told.
    ///
    /// A test on the constant rather than on 100, so raising the bound cannot
    /// leave this asserting yesterday's number.
    #[test]
    fn the_floor_stops_exactly_at_what_the_model_tracks() {
        let mut counts = ClientCounts::new();
        let at_bound = counts.observe(
            windows(),
            client(1),
            RequiredClients(MAX_TRACKED_REQUIRED_CLIENTS),
            at(0),
        );
        assert_eq!(at_bound.reported, MAX_TRACKED_REQUIRED_CLIENTS);
        assert!(!at_bound.anomalous_demand);

        let past_bound = counts.observe(
            windows(),
            client(2),
            RequiredClients(MAX_TRACKED_REQUIRED_CLIENTS + 1),
            at(0),
        );
        assert!(past_bound.anomalous_demand);
        assert_eq!(past_bound.reported, past_bound.cached);

        // And the value every real Microsoft product declares is nowhere near
        // it, which is the whole argument for putting the boundary here.
        for real in [5_u32, 25] {
            assert!(real.saturating_mul(4) <= MAX_TRACKED_REQUIRED_CLIENTS);
        }
    }

    /// A zero demand is treated as one, not as zero: `N < 1 ? 1 : N << 1`.
    #[test]
    fn a_zero_demand_still_activates() {
        let mut counts = ClientCounts::new();
        let view = counts.observe(windows(), client(1), RequiredClients(0), at(0));
        assert_eq!(view.reported, 1);
        assert!(!view.anomalous_demand);
    }

    /// `POL-004` (#92): a known machine returns the count unchanged rather than
    /// inflating it.
    #[test]
    fn renewing_a_known_machine_does_not_change_the_count() {
        let mut counts = ClientCounts::new();
        for number in 1..=5_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        let first = counts.observe(windows(), client(3), RequiredClients(25), at(10));
        assert_eq!(first.outcome, CountOutcome::Renewed);
        assert_eq!(first.cached, 5, "renewal must not add an entry");

        let second = counts.observe(windows(), client(3), RequiredClients(25), at(20));
        assert_eq!(second.cached, 5);
    }

    /// `POL-003` (#91): 30 days without renewal and the entry goes, and the
    /// count decrements. This exists in neither existing implementation.
    #[test]
    fn a_machine_that_stops_renewing_expires_after_thirty_days() {
        let mut counts = ClientCounts::new();
        for number in 1..=10_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        assert_eq!(counts.cached_for(windows()), 10);

        // One day short of the period: everything is still cached.
        let almost = CMID_EXPIRY.as_secs() - 1;
        let view = counts.observe(windows(), client(11), RequiredClients(25), at(almost));
        assert_eq!(view.expired, 0);
        assert_eq!(view.cached, 11);

        // Past it: the ten that stopped renewing are gone, and only the one
        // that renewed at `almost` survives alongside the new arrival.
        let past = CMID_EXPIRY.as_secs() + 1;
        let view = counts.observe(windows(), client(12), RequiredClients(25), at(past));
        assert_eq!(view.expired, 10, "the ten that never renewed");
        assert_eq!(view.cached, 2);
        assert_eq!(counts.cached_for(windows()), 2);
    }

    /// A renewal resets the clock, which is why the entry is deleted and
    /// re-inserted rather than updated in place.
    #[test]
    fn renewal_resets_the_expiry_clock() {
        let mut counts = ClientCounts::new();
        counts.observe(windows(), client(1), RequiredClients(25), at(0));

        let half = CMID_EXPIRY.as_secs() / 2;
        counts.observe(windows(), client(1), RequiredClients(25), at(half));

        // Thirty days after the *first* sighting, the entry is still live
        // because it renewed halfway through.
        let view = counts.observe(
            windows(),
            client(2),
            RequiredClients(25),
            at(CMID_EXPIRY.as_secs() + 1),
        );
        assert_eq!(view.expired, 0);
        assert_eq!(view.cached, 2);
    }

    /// `POL-007` (#95): a full table evicts rather than refusing. A genuine
    /// host returns `0xC004D104` here; evicting is strictly more compatible and
    /// there is nothing to gain from reproducing the refusal.
    #[test]
    fn a_full_table_evicts_the_oldest_rather_than_refusing() {
        let mut counts = ClientCounts::new();
        for number in 0..MAX_CACHED_PER_APPLICATION {
            let cmid = ClientMachineId(Guid::from_bytes(
                u128::try_from(number).unwrap().to_be_bytes(),
            ));
            let view = counts.observe(windows(), cmid, RequiredClients(25), at(0));
            assert_eq!(view.outcome, CountOutcome::Inserted);
        }
        assert_eq!(
            counts.cached_for(windows()),
            u32::try_from(MAX_CACHED_PER_APPLICATION).unwrap()
        );

        let view = counts.observe(windows(), client(0xFF), RequiredClients(25), at(0));
        assert_eq!(view.outcome, CountOutcome::InsertedWithEviction);
        assert_eq!(
            view.cached,
            u32::try_from(MAX_CACHED_PER_APPLICATION).unwrap(),
            "the table stays at its bound"
        );
        assert_eq!(view.reported, 50, "and the answer is unaffected");
    }

    /// `POL-002` (#90): one bucket per application, so Office activity does not
    /// inflate the Windows count.
    #[test]
    fn applications_are_counted_separately() {
        let mut counts = ClientCounts::new();
        for number in 1..=40_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        for number in 1..=3_u8 {
            counts.observe(office(), client(number), RequiredClients(5), at(0));
        }

        assert_eq!(counts.cached_for(windows()), 40);
        assert_eq!(counts.cached_for(office()), 3);

        let view = counts.observe(office(), client(4), RequiredClients(5), at(0));
        assert_eq!(view.cached, 4, "Windows activity must not leak in");
        assert_eq!(view.reported, 5);

        let seen: alloc::vec::Vec<(ApplicationId, u32)> = counts.applications().collect();
        assert_eq!(seen.len(), 2);
    }

    /// An unrecognised application GUID is counted in its own bucket rather
    /// than sharing one, and cannot make this host allocate without bound.
    #[test]
    fn unknown_applications_are_bounded_rather_than_unbounded() {
        let mut counts = ClientCounts::new();
        for number in 0..(MAX_APPLICATIONS + 4) {
            let application = ApplicationId(Guid::from_bytes(
                u128::try_from(number).unwrap().to_be_bytes(),
            ));
            counts.observe(
                application,
                client(1),
                RequiredClients(25),
                at(number as u64),
            );
        }
        assert_eq!(counts.applications().count(), MAX_APPLICATIONS);
    }

    /// The expiry period is the one Microsoft's own artifacts declare, not a
    /// guess: `Security-SPP-CMIDExpirationPeriod` is 43200 minutes.
    #[test]
    fn the_expiry_period_is_thirty_days() {
        assert_eq!(CMID_EXPIRY, Duration::from_mins(43_200));
        assert_eq!(CMID_EXPIRY, Duration::from_hours(24 * 30));
    }

    /// `POL-009` (#97): there is no `MinActiveClients` column, and there must
    /// not be one (declined item D34).
    ///
    /// The field is inert in both existing implementations for opposite
    /// reasons. vlmcsd reads it to floor the reported count but never writes
    /// it, and it is 0 for every host key in the shipped blob. py-kms carries
    /// real-looking values in `KmsDataBase.xml` — 50 for Windows and 10 for
    /// each Office application — that no code path reads.
    ///
    /// Those are exactly the numbers this model derives from `2N`, which is why
    /// the concept is subsumed rather than dropped. This test is what makes
    /// that claim checkable: if the floor ever stopped falling out of the
    /// counting model, someone would be tempted to add the column back.
    #[test]
    fn the_saturation_values_subsume_min_active_clients() {
        let mut counts = ClientCounts::new();

        // py-kms's Windows AppItem says 50. That is `2 * 25`.
        for number in 1..=200_u8 {
            counts.observe(windows(), client(number), RequiredClients(25), at(0));
        }
        let view = counts.observe(windows(), client(201), RequiredClients(25), at(0));
        assert_eq!(view.reported, 50);

        // Its Office AppItems say 10. That is `2 * 5`.
        for number in 1..=200_u8 {
            counts.observe(office(), client(number), RequiredClients(5), at(0));
        }
        let view = counts.observe(office(), client(201), RequiredClients(5), at(0));
        assert_eq!(view.reported, 10);
    }
}
