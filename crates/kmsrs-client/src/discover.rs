//! Finding a KMS host by SRV record, the way a Windows client does
//! (`DISC-001`, #143; `CLI-011`, #217).
//!
//! # What this is for
//!
//! A Windows client with no `/skms` configured looks up `_vlmcs._tcp` in the
//! domains it searches, and that is how a real KMS deployment is found. This
//! client can do the same, which turns "did I publish the record correctly?"
//! into something answerable without a Windows VM.
//!
//! # Two things vlmcsd got wrong that are worth not repeating
//!
//! **It bundles a DNS parser.** vlmcsd carries several hundred lines of
//! BIND-style resolver code to do one SRV lookup. `hickory-resolver` is already
//! in this workspace for `OS-020` (#336), so the lookup here is a library call.
//!
//! **Its weighting is not RFC 2782's.** vlmcsd sorts by
//! `(rand % 256) * isqrt(weight * 1000)` descending, and `DISC-001` quotes that
//! formula. It is an approximation, and a biased one: it makes a record's
//! expected sort key proportional to `sqrt(weight)`, where RFC 2782 §"Weight"
//! asks for a *selection probability* proportional to `weight`. With two
//! records weighted 1 and 100, the specification picks the second about 99 % of
//! the time and vlmcsd's formula picks it about 91 %.
//!
//! So [`order`] implements the specification's algorithm rather than the
//! formula the issue quoted — running sums and a uniform draw in `0..=total`,
//! repeated — because the issue's definition of done says "ordering matches RFC
//! 2782" and those are two different things. With equal weights, or with one
//! host, the two agree; a KMS deployment is usually one host, which is why
//! nobody has noticed.
//!
//! # Ordering is separate from resolving on purpose
//!
//! [`order`] is a pure function over records and a source of randomness, so the
//! weighting can be tested statistically without a DNS server (axiom A7).
//! [`resolve`] is the part that touches the network.

use core::net::SocketAddr;

/// The service a KMS host publishes itself under.
///
/// Fixed by Microsoft, and the reason this is a constant rather than an option:
/// a client that looked up something else would find nothing, and a flag to set
/// it would be a flag whose only correct value is this one.
pub const SERVICE: &str = "_vlmcs._tcp";

/// One SRV record, before its target has been resolved to an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Lower is tried first. RFC 2782: "clients MUST attempt to contact the
    /// target host with the lowest-numbered priority they can reach".
    pub priority: u16,
    /// Relative selection weight among records of equal priority.
    pub weight: u16,
    /// The port to connect to.
    pub port: u16,
    /// The target hostname, as published.
    pub target: String,
}

/// What went wrong looking one up.
#[derive(Debug)]
pub enum DiscoverError {
    /// The resolver could not be built from the system's configuration.
    NoResolver(String),
    /// The lookup failed, or the name does not exist.
    Lookup(String),
    /// The name resolved, but to no usable record.
    ///
    /// RFC 2782's explicit "no service available" signal is a single record
    /// with target `.`, and it is worth distinguishing from "nothing answered":
    /// one means the zone says there is no KMS host, the other means the zone
    /// was never asked.
    NoService,
    /// Records were found but none of their targets resolved to an address.
    NoAddresses,
}

impl core::fmt::Display for DiscoverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoResolver(detail) => {
                write!(formatter, "no usable DNS configuration: {detail}")
            }
            Self::Lookup(detail) => write!(formatter, "the SRV lookup failed: {detail}"),
            Self::NoService => write!(
                formatter,
                "the zone publishes {SERVICE} with target '.', which RFC 2782 \
                 defines as \"no service available\""
            ),
            Self::NoAddresses => write!(
                formatter,
                "every {SERVICE} target failed to resolve to an address"
            ),
        }
    }
}

impl std::error::Error for DiscoverError {}

/// Order candidates the way RFC 2782 says a client must try them.
///
/// Ascending priority. Within one priority, records are selected one at a time:
/// a running sum of weights is built, a number is drawn uniformly from
/// `0..=total`, and the first record whose running sum is at least that number
/// is taken and removed. Repeat until the priority is empty.
///
/// `draw` is handed an exclusive upper bound and must return a value below it.
/// Taking it as an argument rather than reading a generator is axiom A7, and it
/// is what makes the weighting testable: the statistical tests below drive it
/// with a counter and with a fixed value.
///
/// # Weight zero
///
/// RFC 2782 gives weight-zero records "a small chance of being selected" rather
/// than none, which the running-sum method produces for free — a zero-weight
/// record does not advance the sum, so it is picked exactly when the draw lands
/// on the sum so far. Special-casing it, as some implementations do by sorting
/// zero-weight records last, is a different behaviour from the specification's.
#[must_use]
pub fn order(mut candidates: Vec<Candidate>, mut draw: impl FnMut(u32) -> u32) -> Vec<Candidate> {
    // Stable, so records of equal priority keep the order they arrived in and
    // the only thing that reorders them is the weighting below.
    candidates.sort_by_key(|candidate| candidate.priority);

    let mut ordered = Vec::with_capacity(candidates.len());
    let mut rest = candidates;

    while !rest.is_empty() {
        let priority = rest.first().map_or(0, |candidate| candidate.priority);
        let boundary = rest
            .iter()
            .position(|candidate| candidate.priority != priority)
            .unwrap_or(rest.len());
        let mut group: Vec<Candidate> = rest.drain(..boundary).collect();

        while !group.is_empty() {
            let total: u32 = group
                .iter()
                .map(|candidate| u32::from(candidate.weight))
                .sum();
            // `total + 1` because the draw is over the inclusive range
            // `0..=total`, which is what makes a run of zero-weight records
            // reachable at all.
            let target = draw(total.saturating_add(1));

            let mut running = 0_u32;
            let mut chosen = group.len().saturating_sub(1);
            for (index, candidate) in group.iter().enumerate() {
                running = running.saturating_add(u32::from(candidate.weight));
                if running >= target {
                    chosen = index;
                    break;
                }
            }
            ordered.push(group.remove(chosen));
        }
    }

    ordered
}

/// Look up `_vlmcs._tcp` in `domain` and return the candidates, ordered.
///
/// # Errors
///
/// See [`DiscoverError`]. A name that does not exist and a name that exists
/// with no usable record are different answers, because they mean different
/// things to whoever published the zone.
pub fn resolve(
    domain: &str,
    mut draw: impl FnMut(u32) -> u32,
) -> Result<Vec<Candidate>, DiscoverError> {
    let name = query_name(domain);

    // A runtime of its own, and only for this. The rest of the client is
    // blocking `std::net` on purpose — a diagnostic tool that reproduces what a
    // Windows client does has no use for concurrency — but `hickory-resolver`
    // is async, and building a current-thread runtime for one lookup is
    // cheaper than making the whole client async to accommodate it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| DiscoverError::NoResolver(error.to_string()))?;

    let records = runtime.block_on(async {
        // The **system** resolver, deliberately: `/etc/resolv.conf` on Linux
        // and the interface configuration on Windows. That is what a real
        // client uses, and this tool exists to answer "would a real client find
        // this host?" — a hand-configured nameserver would be answering a
        // different question.
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .map_err(|error| DiscoverError::NoResolver(error.to_string()))?
            .build()
            .map_err(|error| DiscoverError::NoResolver(error.to_string()))?;

        resolver
            .srv_lookup(&name)
            .await
            .map_err(|error| DiscoverError::Lookup(error.to_string()))
    })?;

    let mut candidates = Vec::new();
    // `answers()` rather than a typed iterator: `srv_lookup` returns a plain
    // `Lookup`, and filtering to the SRV rdata is what turns it into the
    // records this is about. A CNAME in the answer section is skipped rather
    // than mistaken for one.
    for record in records
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::SRV(srv) => Some(srv),
            _ => None,
        })
    {
        let target = record.target.to_utf8();
        // RFC 2782: "A target of '.' means that the service is decidedly not
        // available at this domain."
        if target == "." || target.is_empty() {
            return Err(DiscoverError::NoService);
        }
        candidates.push(Candidate {
            priority: record.priority,
            weight: record.weight,
            port: record.port,
            target,
        });
    }

    if candidates.is_empty() {
        return Err(DiscoverError::NoService);
    }
    Ok(order(candidates, &mut draw))
}

/// Resolve one candidate's target to socket addresses.
///
/// Returns every address the name has, in the order the resolver gave them, so
/// a caller falling through can try a host's A and AAAA records before moving
/// on to the next candidate.
///
/// # Errors
///
/// Returns [`DiscoverError::NoAddresses`] if the name resolves to nothing.
pub fn addresses(candidate: &Candidate) -> Result<Vec<SocketAddr>, DiscoverError> {
    use std::net::ToSocketAddrs as _;

    // The stub resolver here rather than hickory, and the difference matters:
    // this is an A/AAAA lookup, which is exactly what the system resolver is
    // for and what a Windows client would do with the SRV target. Hickory is
    // used above because `ToSocketAddrs` cannot ask for SRV at all.
    let resolved: Vec<SocketAddr> = (candidate.target.trim_end_matches('.'), candidate.port)
        .to_socket_addrs()
        .map_err(|_| DiscoverError::NoAddresses)?
        .collect();

    if resolved.is_empty() {
        return Err(DiscoverError::NoAddresses);
    }
    Ok(resolved)
}

/// Walk ordered candidates and return the first address that is reachable.
///
/// This is the second half of RFC 2782 — "try each candidate until one works" —
/// and it is a function over two callbacks rather than a loop in `main` so that
/// the falling-through can be tested without a zone or a socket (axiom A7).
///
/// `reachable` decides what "works" means, and the caller passes one that
/// **connects and binds**. That distinction is the whole point: a host that
/// accepts a connection and then refuses the RPC bind cannot activate anything,
/// so stopping at the first open port would report a broken host as a working
/// one. The Organization fork's client takes the first answer with no priority
/// or weight handling at all, which is the same mistake one step earlier.
///
/// `report` is called for every candidate that fails, because a target that
/// does not resolve or does not answer is a broken zone and the operator
/// running this is the person who can fix it (`SEC-012`, #204).
pub fn first_reachable(
    candidates: &[Candidate],
    mut addresses_of: impl FnMut(&Candidate) -> Result<Vec<SocketAddr>, DiscoverError>,
    mut reachable: impl FnMut(&Candidate, SocketAddr) -> bool,
    mut report: impl FnMut(&Candidate, &str),
) -> Option<SocketAddr> {
    for candidate in candidates {
        let addresses = match addresses_of(candidate) {
            Ok(addresses) => addresses,
            Err(error) => {
                report(candidate, &error.to_string());
                continue;
            }
        };
        for address in addresses {
            if reachable(candidate, address) {
                return Some(address);
            }
            report(candidate, &format!("{address} did not answer"));
        }
    }
    None
}

/// The name to query for a domain./// The name to query for a domain.
///
/// An empty domain queries `_vlmcs._tcp` unqualified, which lets the system
/// resolver apply its own search list — the behaviour a Windows client has, and
/// the one `DISC-004` (#146) exists to measure.
#[must_use]
pub fn query_name(domain: &str) -> String {
    let domain = domain.trim().trim_start_matches('.').trim_end_matches('.');
    if domain.is_empty() {
        format!("{SERVICE}.")
    } else {
        format!("{SERVICE}.{domain}.")
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

    use super::{Candidate, DiscoverError, SERVICE, first_reachable, order, query_name};
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn socket(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)), 1688)
    }

    fn candidate(priority: u16, weight: u16, target: &str) -> Candidate {
        Candidate {
            priority,
            weight,
            port: 1688,
            target: target.to_owned(),
        }
    }

    /// A draw that always returns zero, which selects the first record whose
    /// running sum reaches zero — that is, the first record in the group.
    fn lowest(_bound: u32) -> u32 {
        0
    }

    /// The headline: priority first, always, whatever the weights say.
    #[test]
    fn priority_beats_weight() {
        let ordered = order(
            vec![
                candidate(20, 1000, "far"),
                candidate(0, 0, "near"),
                candidate(10, 500, "middle"),
            ],
            lowest,
        );

        let targets: Vec<&str> = ordered.iter().map(|c| c.target.as_str()).collect();
        assert_eq!(targets, vec!["near", "middle", "far"]);
    }

    /// Every record comes back exactly once, whatever the draw does.
    ///
    /// A selection algorithm that loses or duplicates a record is worse than
    /// one that orders badly: the client silently never tries a host that was
    /// published.
    #[test]
    fn ordering_is_a_permutation() {
        let input = vec![
            candidate(0, 1, "a"),
            candidate(0, 5, "b"),
            candidate(0, 0, "c"),
            candidate(1, 7, "d"),
            candidate(1, 0, "e"),
        ];

        for seed in 0..64_u32 {
            let mut counter = seed;
            let ordered = order(input.clone(), |bound| {
                counter = counter.wrapping_add(7);
                counter.checked_rem(bound.max(1)).unwrap_or(0)
            });

            assert_eq!(ordered.len(), input.len(), "seed {seed} lost a record");
            for original in &input {
                assert_eq!(
                    ordered
                        .iter()
                        .filter(|c| c.target == original.target)
                        .count(),
                    1,
                    "seed {seed}: {} appears the wrong number of times",
                    original.target
                );
            }
            // Priorities are still non-decreasing.
            for pair in ordered.windows(2) {
                assert!(pair[0].priority <= pair[1].priority, "seed {seed}");
            }
        }
    }

    /// **The property vlmcsd's formula does not have.**
    ///
    /// RFC 2782 asks for a selection probability proportional to the weight.
    /// With weights 1 and 99 the heavy record should come first about 99 % of
    /// the time; vlmcsd's `sqrt`-based key would give it about 91 %.
    ///
    /// Driven with a uniform sweep rather than a generator, so the test is
    /// exact rather than flaky: every draw value in range is tried once, and
    /// the count is the true proportion.
    #[test]
    fn weight_decides_selection_in_proportion() {
        let mut heavy_first = 0_u32;
        let total = 101_u32;

        for value in 0..total {
            let ordered = order(
                vec![candidate(0, 1, "light"), candidate(0, 99, "heavy")],
                |bound| value.min(bound.saturating_sub(1)),
            );
            if ordered[0].target == "heavy" {
                heavy_first += 1;
            }
        }

        // The light record is chosen only when the draw lands in `0..=1`, which
        // is 2 of the 101 values; everything above picks the heavy one.
        assert!(
            heavy_first >= 97,
            "the heavy record came first {heavy_first}/101 times, which is not \
             proportional to its weight"
        );
    }

    /// A zero-weight record is reachable, which RFC 2782 requires — "a small
    /// chance of being selected", not none.
    ///
    /// Implementations that sort zero-weight records last never try them first,
    /// which is a different behaviour from the specification's and matters when
    /// every record in a zone is weight zero, as the instructions page's own
    /// example recommends.
    #[test]
    fn a_zero_weight_record_can_still_be_chosen_first() {
        let ordered = order(
            vec![candidate(0, 0, "zero"), candidate(0, 10, "ten")],
            lowest,
        );
        assert_eq!(ordered[0].target, "zero");
    }

    /// All-zero weights, which is what the instructions page tells operators to
    /// publish, must still produce a usable ordering rather than dividing by a
    /// zero total.
    #[test]
    fn a_zone_of_all_zero_weights_still_orders() {
        let ordered = order(
            vec![
                candidate(0, 0, "a"),
                candidate(0, 0, "b"),
                candidate(0, 0, "c"),
            ],
            lowest,
        );
        assert_eq!(ordered.len(), 3);
        let mut targets: Vec<&str> = ordered.iter().map(|c| c.target.as_str()).collect();
        targets.sort_unstable();
        assert_eq!(targets, vec!["a", "b", "c"]);
    }

    /// The name is the service plus the domain, fully qualified, and an empty
    /// domain leaves the search list to the resolver.
    #[test]
    fn the_query_name_is_built_the_way_a_client_builds_it() {
        assert_eq!(query_name("example.com"), format!("{SERVICE}.example.com."));
        // Whatever shape the operator typed.
        assert_eq!(
            query_name("example.com."),
            format!("{SERVICE}.example.com.")
        );
        assert_eq!(
            query_name(".example.com"),
            format!("{SERVICE}.example.com.")
        );
        assert_eq!(
            query_name("  example.com  "),
            format!("{SERVICE}.example.com.")
        );
        // Unqualified, so the resolver applies its own search list.
        assert_eq!(query_name(""), format!("{SERVICE}."));
        assert_eq!(query_name("."), format!("{SERVICE}."));
    }

    /// One host is the common case and must be trivially correct.
    #[test]
    fn a_single_record_is_returned_unchanged() {
        let only = candidate(0, 0, "kms.example.com.");
        let ordered = order(vec![only.clone()], lowest);
        assert_eq!(ordered, vec![only]);
    }

    /// An empty zone orders to nothing rather than panicking.
    #[test]
    fn no_records_order_to_no_candidates() {
        assert!(order(Vec::new(), lowest).is_empty());
    }

    /// **`DISC-001`'s second requirement: fall through on failure.**
    ///
    /// The first candidate resolves and is unreachable, the second does not
    /// resolve at all, and the third answers. A client that stopped at the
    /// first candidate — or that treated an unresolvable target as fatal —
    /// would never reach it.
    #[test]
    fn an_unreachable_candidate_falls_through_to_the_next() {
        let candidates = vec![
            candidate(0, 0, "dead"),
            candidate(1, 0, "missing"),
            candidate(2, 0, "alive"),
        ];
        let mut failures = Vec::new();

        let chosen = first_reachable(
            &candidates,
            |candidate| match candidate.target.as_str() {
                "missing" => Err(DiscoverError::NoAddresses),
                "dead" => Ok(vec![socket(1)]),
                _ => Ok(vec![socket(3)]),
            },
            |candidate, _| candidate.target == "alive",
            |candidate, detail| failures.push(format!("{}: {detail}", candidate.target)),
        );

        assert_eq!(chosen, Some(socket(3)));
        assert_eq!(failures.len(), 2, "both failures reported: {failures:?}");
        assert!(failures[0].starts_with("dead"));
        assert!(failures[1].starts_with("missing"));
    }

    /// Every address of one candidate is tried before the next candidate is.
    ///
    /// A host with an A and a AAAA record is one host, and RFC 2782 orders
    /// *hosts*. Moving on after the first address would skip a working stack
    /// because the other one is down — which on a dual-stacked network is the
    /// common failure rather than the exotic one.
    #[test]
    fn every_address_of_a_candidate_is_tried_before_the_next_candidate() {
        let candidates = vec![candidate(0, 0, "dual"), candidate(1, 0, "other")];
        let mut tried = Vec::new();

        let chosen = first_reachable(
            &candidates,
            |candidate| {
                if candidate.target == "dual" {
                    Ok(vec![socket(1), socket(2)])
                } else {
                    Ok(vec![socket(9)])
                }
            },
            |_, address| {
                tried.push(address);
                address == socket(2)
            },
            |_, _| {},
        );

        assert_eq!(chosen, Some(socket(2)));
        assert_eq!(tried, vec![socket(1), socket(2)]);
    }

    /// Nothing reachable is `None` rather than a panic or a default address.
    #[test]
    fn nothing_reachable_is_no_answer() {
        let candidates = vec![candidate(0, 0, "a"), candidate(0, 0, "b")];
        let chosen = first_reachable(
            &candidates,
            |_| Ok(vec![socket(1)]),
            |_, _| false,
            |_, _| {},
        );
        assert_eq!(chosen, None);
    }
}
