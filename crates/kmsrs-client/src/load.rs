//! Load, soak and charging (`CLI-006`, #212; `CLI-007`, #213).
//!
//! # Load
//!
//! `vlmcs` can send N requests in a row, and its own examples suggest 100000.
//! It is strictly sequential and single-threaded, so what it measures is round
//! trip latency times N — which is a fact about the network, not about the
//! host. [`Soak`] adds concurrency, which is the thing that finds the bugs a
//! KMS host actually has: a shared CMID table under contention, a connection
//! ceiling reached from several directions at once, an event log being written
//! from every worker (`TEST-011`, #232).
//!
//! Each worker may hold one association open for the whole run or rebind per
//! request ([`Soak::reconnect`]). Both are worth exercising and they stress
//! different things: one is the request path, the other is the accept path and
//! the connection ceiling.
//!
//! # Charging
//!
//! A KMS host will not activate anything until it has seen `N_Policy` distinct
//! machines. Charging is sending activations from fresh machine identities until
//! the reported count reaches that threshold, and `vlmcs` implements it by
//! starting at `NCountPolicy - 1` and recomputing `RequestsToGo` from each
//! response's count.
//!
//! Its abort condition — *"the KMS server does not increment its active
//! clients"* — is right for a real host and **wrong here**, which is the
//! interesting part. Under `POL-001` (#89) the reported count saturates at `2N`
//! and every honest client sees the same number, so a host that is already
//! saturated correctly reports a count that does not rise. That is the steady
//! state, not a failure, and [`Charge`] reports it as [`Charged::Saturated`]
//! rather than as an error.

use crate::names::{self, Flavour};
use crate::request::RequestFields;
use crate::session::{Exchange, ProbeError, Session};
use core::net::SocketAddr;
use core::time::Duration;
use kmsrs_proto::entropy::Entropy;
use std::collections::BTreeSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// How a soak run varies each request.
///
/// A run in which every request carries the same machine ID is a run measuring
/// *renewals*: after the first, every one of them finds an existing entry and
/// the count never moves (`POL-004`, #92). That is a legitimate thing to
/// measure and it is not what "ten thousand clients" means, so which one is
/// happening has to be a choice rather than an accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vary {
    /// Draw a fresh client machine ID per request.
    pub machine_id: bool,
    /// Draw a fresh workstation name per request (`CLI-010`, #216).
    pub workstation_name: Option<Flavour>,
}

impl Default for Vary {
    fn default() -> Self {
        // A fresh machine per request by default, because a soak run that is
        // silently measuring renewals looks exactly like one that is not.
        // `vlmcs` makes the same choice, and for the same reason.
        Self {
            machine_id: true,
            workstation_name: None,
        }
    }
}

/// A load run (`CLI-006`, #212).
#[derive(Debug, Clone)]
pub struct Soak {
    /// Where to send them.
    pub target: SocketAddr,
    /// How long to wait for each reply.
    pub timeout: Duration,
    /// What to send.
    pub fields: RequestFields,
    /// How many requests in total.
    pub requests: u64,
    /// How many workers send them.
    pub concurrency: usize,
    /// Whether each request gets a fresh connection and bind.
    ///
    /// False holds one association per worker for the whole run, which is what
    /// a real client does. True exercises the accept path and the connection
    /// ceiling instead, which is where a server breaks under load.
    pub reconnect: bool,
    /// What varies per request.
    pub vary: Vary,
}

/// What a load run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoakReport {
    /// How many activations came back decodable.
    pub completed: u64,
    /// How many failed, for any reason.
    pub failed: u64,
    /// The first failure, so a run that fails ten thousand times says why once.
    pub first_failure: Option<String>,
    /// The highest count any response reported.
    pub highest_count: u32,
    /// How many distinct ePIDs were seen.
    ///
    /// A genuine host has **one** for its lifetime (`ID-001`, #106), so anything
    /// above one from a single host is the loudest tell there is — and a soak
    /// run is where a per-response generator shows up most clearly.
    pub distinct_epids: usize,
}

impl Soak {
    /// Run it.
    ///
    /// Returns what happened rather than failing on the first error: a load run
    /// that stopped at the first refused connection would measure the moment a
    /// host got busy rather than what it did afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] only if the run could not be started at all —
    /// which today means an entropy source that will not produce the identities
    /// the run needs (`OS-012`, #263). Per-request failures are counted, not
    /// returned.
    pub fn run(&self, entropy: &mut dyn Entropy) -> Result<SoakReport, ProbeError> {
        let remaining = AtomicU64::new(self.requests);
        let shared = Mutex::new(SoakReport::default());
        let epids: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::default());

        // Every worker needs its own entropy, and the caller has one source. So
        // the identities are drawn up front, here, on one thread — which also
        // makes a run reproducible from a seed, and makes an entropy failure a
        // start-up error rather than a partial run.
        let plans = self.plan(entropy)?;
        let plans = Mutex::new(plans.into_iter());

        std::thread::scope(|scope| {
            for _ in 0..self.concurrency.max(1) {
                let remaining = &remaining;
                let shared = &shared;
                let epids = &epids;
                let plans = &plans;
                scope.spawn(move || self.worker(remaining, plans, shared, epids));
            }
        });

        let mut report = shared.into_inner().unwrap_or_default();
        report.distinct_epids = epids.into_inner().map_or(0, |set| set.len());
        Ok(report)
    }

    /// The per-request fields, drawn in advance.
    fn plan(&self, entropy: &mut dyn Entropy) -> Result<Vec<RequestFields>, ProbeError> {
        let mut plans = Vec::new();
        for _ in 0..self.requests {
            let mut fields = self.fields.clone();
            if self.vary.machine_id {
                let bytes = kmsrs_proto::entropy::EntropyExt::array::<16>(entropy)
                    .map_err(|_| ProbeError::EntropyUnavailable)?;
                fields.client_machine_id = kmsrs_db::Guid::from_bytes(bytes);
            }
            if let Some(flavour) = self.vary.workstation_name {
                fields.workstation_name = names::generate(flavour, entropy)
                    .map_err(|_| ProbeError::EntropyUnavailable)?;
            }
            plans.push(fields);
        }
        Ok(plans)
    }

    /// One worker: take work until there is none, then stop.
    fn worker(
        &self,
        remaining: &AtomicU64,
        plans: &Mutex<std::vec::IntoIter<RequestFields>>,
        shared: &Mutex<SoakReport>,
        epids: &Mutex<BTreeSet<String>>,
    ) {
        // A worker's own entropy, for the request IVs. The per-request
        // identities came from `plan`, on one thread, so a run is reproducible
        // from a seed; this is the framing, which has to be unpredictable and
        // has to be per-worker.
        //
        // The OS source rather than the caller's: it is zero-sized and holds no
        // state (`CRY-013`, #52), so every worker having one costs nothing and
        // means no worker waits on another's lock. Sharing the caller's `&mut`
        // across threads is not possible, and serialising through a mutex would
        // make the generator the thing under test.
        let mut entropy = kmsrs_server::OsEntropy;
        let mut session: Option<Session> = None;

        loop {
            if remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                    left.checked_sub(1)
                })
                .is_err()
            {
                return;
            }

            let Some(fields) = plans.lock().ok().and_then(|mut plans| plans.next()) else {
                return;
            };

            if self.reconnect {
                session = None;
            }
            if session.is_none() {
                match Session::open(self.target, self.timeout, true, &mut |_| {}) {
                    Ok(open) => session = Some(open),
                    Err(error) => {
                        Self::record_failure(shared, &error);
                        continue;
                    }
                }
            }

            let Some(open) = session.as_mut() else {
                continue;
            };
            match open.activate(&fields, &mut entropy, &mut |_| {}) {
                Ok(exchange) => {
                    Self::record_success(shared, epids, &exchange);
                }
                Err(error) => {
                    Self::record_failure(shared, &error);
                    // A failed exchange leaves the association in an unknown
                    // state, so the next request starts a new one rather than
                    // compounding the first failure into every one after it.
                    session = None;
                }
            }
        }
    }

    fn record_success(
        shared: &Mutex<SoakReport>,
        epids: &Mutex<BTreeSet<String>>,
        exchange: &Exchange,
    ) {
        if let Ok(mut report) = shared.lock() {
            report.completed = report.completed.saturating_add(1);
            report.highest_count = report.highest_count.max(exchange.count);
        }
        if let Ok(mut seen) = epids.lock() {
            seen.insert(exchange.epid.clone());
        }
    }

    fn record_failure(shared: &Mutex<SoakReport>, error: &ProbeError) {
        if let Ok(mut report) = shared.lock() {
            report.failed = report.failed.saturating_add(1);
            if report.first_failure.is_none() {
                report.first_failure = Some(error.to_string());
            }
        }
    }
}

/// How a charging run ended (`CLI-007`, #213).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Charged {
    /// The reported count reached the threshold.
    Reached {
        /// What it reached.
        count: u32,
        /// How many requests it took.
        requests: u32,
    },
    /// The count stopped rising before the threshold, because the host is
    /// already reporting all it will.
    ///
    /// **Not a failure.** `vlmcs` aborts here with *"the KMS server does not
    /// increment its active clients"*, which is the right diagnosis for a real
    /// host and the wrong one for a saturated one: under `POL-001` (#89) the
    /// count saturates at `2N` and every honest client sees the same number, so
    /// a host that is already serving everybody reports a count that does not
    /// move. That is the steady state.
    Saturated {
        /// The count it settled at.
        count: u32,
        /// The threshold that was being charged towards.
        threshold: u32,
    },
}

/// Charge a host towards its activation threshold (`CLI-007`, #213).
#[derive(Debug, Clone)]
pub struct Charge {
    /// Where to send them.
    pub target: SocketAddr,
    /// How long to wait for each reply.
    pub timeout: Duration,
    /// What to send. `required_clients` is the threshold being charged towards.
    pub fields: RequestFields,
    /// How many requests to send before giving up, whatever the count does.
    pub limit: u32,
}

/// How many consecutive requests may fail to move the count before the host is
/// called saturated.
///
/// One is too few: a renewal legitimately leaves the count unchanged
/// (`POL-004`, #92), and a fresh machine ID can still collide with an evicted
/// entry. Three consecutive is a host that has stopped counting.
pub const STALL_ROUNDS: u32 = 3;

impl Charge {
    /// Send activations from fresh machines until the count reaches the
    /// threshold, stalls, or the limit runs out.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeError`] if the host could not be reached or answered with
    /// something that did not decode. A count that will not rise is
    /// [`Charged::Saturated`], not an error.
    pub fn run(&self, entropy: &mut dyn Entropy) -> Result<Charged, ProbeError> {
        let threshold = self.fields.required_clients;
        let mut session = Session::open(self.target, self.timeout, true, &mut |_| {})?;

        let mut best = 0_u32;
        let mut stalled = 0_u32;

        for sent in 1..=self.limit {
            let mut fields = self.fields.clone();
            // A distinct machine every time, because a repeat is a renewal and
            // a renewal is exactly what does not move the count.
            let bytes = kmsrs_proto::entropy::EntropyExt::array::<16>(entropy)
                .map_err(|_| ProbeError::EntropyUnavailable)?;
            fields.client_machine_id = kmsrs_db::Guid::from_bytes(bytes);

            let exchange = session.activate(&fields, entropy, &mut |_| {})?;

            if exchange.count >= threshold {
                return Ok(Charged::Reached {
                    count: exchange.count,
                    requests: sent,
                });
            }

            if exchange.count > best {
                best = exchange.count;
                stalled = 0;
            } else {
                stalled = stalled.saturating_add(1);
                if stalled >= STALL_ROUNDS {
                    return Ok(Charged::Saturated {
                        count: best,
                        threshold,
                    });
                }
            }
        }

        Ok(Charged::Saturated {
            count: best,
            threshold,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{Charged, Soak, Vary};
    use crate::names::Flavour;
    use crate::request::RequestFields;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};
    use core::time::Duration;
    use kmsrs_proto::entropy::testing::{DeterministicEntropy, FailingEntropy};

    fn nowhere() -> SocketAddr {
        // TEST-NET-3, which is not routed anywhere, so a connection attempt
        // fails rather than reaching something.
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 1688)
    }

    fn soak(requests: u64, concurrency: usize) -> Soak {
        Soak {
            target: nowhere(),
            timeout: Duration::from_millis(50),
            fields: RequestFields::default(),
            requests,
            concurrency,
            reconnect: false,
            vary: Vary::default(),
        }
    }

    /// The default varies the machine ID, because a run that does not is
    /// measuring renewals — every request after the first finds an existing
    /// entry and the count never moves.
    #[test]
    fn the_default_sends_a_fresh_machine_per_request() {
        assert!(Vary::default().machine_id);
        assert_eq!(Vary::default().workstation_name, None);
    }

    /// The plan is drawn up front, so identities are distinct and a run is
    /// reproducible from a seed.
    #[test]
    fn every_planned_request_carries_a_distinct_machine() {
        let mut entropy = DeterministicEntropy::from_seed(0x50AC_0001);
        let plans = soak(256, 1).plan(&mut entropy).unwrap();
        assert_eq!(plans.len(), 256);

        let machines: std::collections::BTreeSet<_> = plans
            .iter()
            .map(|fields| fields.client_machine_id.to_bytes())
            .collect();
        assert_eq!(machines.len(), 256, "two requests shared a machine ID");
    }

    /// Varying the name is opt-in and produces valid ones (`CLI-010`, #216).
    #[test]
    fn a_varied_workstation_name_is_drawn_per_request() {
        let mut entropy = DeterministicEntropy::from_seed(0x50AC_0002);
        let mut plan = soak(64, 1);
        plan.vary.workstation_name = Some(Flavour::NetBios);

        let plans = plan.plan(&mut entropy).unwrap();
        let names: std::collections::BTreeSet<_> = plans
            .iter()
            .map(|fields| fields.workstation_name.clone())
            .collect();
        assert!(names.len() > 60, "only {} distinct names", names.len());
        for fields in &plans {
            assert!(
                fields.to_body().is_ok(),
                "{} does not fit the wire field",
                fields.workstation_name
            );
        }
    }

    /// An entropy failure stops the run before it starts, rather than producing
    /// a partial one whose machines quietly stopped being distinct.
    #[test]
    fn a_failed_entropy_source_stops_the_run_rather_than_degrading_it() {
        let mut entropy = FailingEntropy;
        assert!(soak(4, 1).run(&mut entropy).is_err());
    }

    /// A host that cannot be reached produces a report, not an error. A load
    /// run that stopped at the first refused connection would be measuring the
    /// moment a host got busy rather than what it did afterwards.
    #[test]
    fn an_unreachable_host_is_counted_rather_than_raised() {
        let mut entropy = DeterministicEntropy::from_seed(0x50AC_0003);
        let report = soak(4, 2).run(&mut entropy).unwrap();
        assert_eq!(report.completed, 0);
        assert_eq!(report.failed, 4, "every request must be accounted for");
        assert!(
            report.first_failure.is_some(),
            "a run that failed four times must say why once"
        );
    }

    /// Every request is dispatched exactly once however many workers there are.
    #[test]
    fn the_work_is_shared_and_not_duplicated() {
        let mut entropy = DeterministicEntropy::from_seed(0x50AC_0004);
        for concurrency in [1_usize, 2, 8] {
            let report = soak(16, concurrency).run(&mut entropy).unwrap();
            assert_eq!(
                report.completed.saturating_add(report.failed),
                16,
                "{concurrency} workers accounted for the wrong number of requests"
            );
        }
    }

    /// `CLI-007` (#213): saturation is a result, not a failure.
    ///
    /// `vlmcs` aborts here with "the KMS server does not increment its active
    /// clients", which is the right diagnosis for a real host and the wrong one
    /// for a saturated one — and under `POL-001` (#89) saturated is this host's
    /// steady state.
    #[test]
    fn saturation_is_a_result_and_not_an_error() {
        let saturated = Charged::Saturated {
            count: 50,
            threshold: 25,
        };
        // The type says it: there is no error variant for this, so a caller
        // cannot accidentally treat it as one.
        assert!(matches!(saturated, Charged::Saturated { .. }));
        assert_ne!(
            saturated,
            Charged::Reached {
                count: 50,
                requests: 1
            }
        );
    }
}
