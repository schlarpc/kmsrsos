//! The host: everything this process claims and remembers
//! (`ARCH-014`, #14; `TEST-009`, #230).
//!
//! This is the wiring between three sans-io pieces that deliberately do not
//! know about each other — [`kmsrs_proto::wire::connection`], which turns bytes
//! into a decoded [`Request`] and a [`Decision`] back into bytes;
//! [`kmsrs_policy`], which decides; and the identity drawn once at start-up.
//!
//! # There is no shared mutable configuration map
//!
//! `ARCH-014` (#14) exists because of a specific bug shape. py-kms keeps the
//! peer address in the process-global `srv_config['raddr']`, so a second
//! connection can overwrite it between the first connection's accept and its
//! request handling; the Organization fork then persists that racy value as
//! `lastRequestIP`. Of the forks surveyed, only MelroyB's fixed it.
//!
//! Nothing here is a map of per-request values. [`Host`] holds exactly three
//! things — the identity, the count model and the event log — and every one of
//! them is *shared state by intent*, guarded by the caller. Everything about a
//! request travels as an argument to [`Host::activate`] and is dropped when it
//! returns. There is no field for a peer address to be written into, which is
//! why the bug cannot be reproduced here rather than merely not being present.

use kmsrs_policy::counting::ClientCounts;
use kmsrs_policy::events::{EventLog, Outcome, Peer};
use kmsrs_policy::gate::{self, Observations};
use kmsrs_policy::identity::HostIdentity;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::request::Request;
use kmsrs_proto::time::{FileTime, Instant};
use kmsrs_proto::types::Intervals;
use kmsrs_proto::wire::connection::{Decision, Grant};

/// Everything a request needs to know about where it came from.
///
/// Passed by value into [`Host::activate`] and dropped when it returns. The
/// point of the type is that it is an *argument*: there is nowhere else for it
/// to live (`ARCH-014`, #14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext {
    /// Where the request came from (`OBS-005`, #181).
    pub peer: Option<Peer>,
    /// The monotonic clock reading for this request.
    pub now: Instant,
    /// The host's wall clock, used *only* to measure skew for the log.
    ///
    /// `None` on a platform without a usable one. Nothing in the response
    /// derives from it — the v6 key schedule comes from the client's own
    /// timestamp, which is why this server needs no accurate clock
    /// (`ARCH-004`, #4).
    pub host_time: Option<FileTime>,
}

/// The activation host.
#[derive(Debug)]
pub struct Host {
    identity: HostIdentity,
    counts: ClientCounts,
    events: EventLog,
    intervals: Intervals,
}

impl Host {
    /// Draw this process's identity and start with an empty world.
    ///
    /// # Errors
    ///
    /// Returns [`kmsrs_policy::EntropyUnavailable`] if the entropy source
    /// failed. Starting without one would mean serving a predictable identity,
    /// which is worse than not starting (`OS-012`, #263).
    pub fn new(
        entropy: &mut dyn Entropy,
        today: kmsrs_db::Date,
    ) -> Result<Self, kmsrs_policy::EntropyUnavailable> {
        Ok(Self {
            identity: HostIdentity::generate(entropy, today)?,
            counts: ClientCounts::new(),
            events: EventLog::default(),
            intervals: Intervals::DEFAULT,
        })
    }

    /// Use different activation and renewal intervals (`KMS-021`, #37).
    #[must_use]
    pub const fn with_intervals(mut self, intervals: Intervals) -> Self {
        self.intervals = intervals;
        self
    }

    /// Decide a request, count it, and log it.
    ///
    /// This is the function [`kmsrs_proto::wire::connection::Connection::step`]
    /// is handed as its `activate` callback. It is total: every path returns a
    /// [`Decision`], and both variants of `Decision` produce a response
    /// (`POL-016`, #104).
    pub fn activate(&mut self, request: &Request, context: RequestContext) -> Decision {
        let (decision, observations) = gate::evaluate(
            request,
            &self.identity,
            &mut self.counts,
            context.now,
            context.host_time,
        );

        match decision {
            gate::Decision::Grant(grant) => {
                self.events
                    .record_grant(request, context.peer, context.now, &grant, observations);
                Decision::Grant(Grant {
                    epid: grant.identity.epid,
                    count: grant.counts.reported,
                    intervals: self.intervals,
                    hardware_id: grant.identity.hardware_id,
                })
            }
            gate::Decision::Refuse(refusal) => {
                self.events.record(
                    request,
                    context.peer,
                    context.now,
                    Outcome::Refused(refusal),
                    observations,
                );
                Decision::Refuse(refusal.hresult())
            }
        }
    }

    /// What this host would decide, without deciding it.
    ///
    /// For the web UI and diagnostics. Does not count, log, or mutate anything.
    #[must_use]
    pub fn inspect(&self, request: &Request) -> Observations {
        let mut scratch = self.counts.clone();
        let (_, observations) = gate::evaluate(
            request,
            &self.identity,
            &mut scratch,
            Instant::from_nanos(0),
            None,
        );
        observations
    }

    /// The identity this host claims.
    #[must_use]
    pub const fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// The client-count world (`POL-001`, #89).
    #[must_use]
    pub const fn counts(&self) -> &ClientCounts {
        &self.counts
    }

    /// The event log (`OBS-004`, #180).
    #[must_use]
    pub const fn events(&self) -> &EventLog {
        &self.events
    }

    /// The intervals this host reports (`KMS-021`, #37).
    #[must_use]
    pub const fn intervals(&self) -> Intervals {
        self.intervals
    }
}
