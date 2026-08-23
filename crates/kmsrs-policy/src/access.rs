//! Who may connect, and how often (`POL-013`, #101; `POL-014`, #102).
//!
//! Both gates key on the **source address**, which is the one identifier a
//! client cannot choose. Everything else in a KMS request is client-supplied:
//! the machine ID, the workstation name, the declared client count. A quota
//! keyed on any of those is a quota an abuser resets by changing a field
//! (`POL-015`, #103).
//!
//! # Addresses are canonical before anything looks at them
//!
//! An IPv4 client arriving on a dual-stack socket is `::ffff:1.2.3.4`; the same
//! client on an IPv4 socket is `1.2.3.4`. [`canonical`] collapses the two, and
//! both gates apply it themselves rather than trusting the caller — so an IPv4
//! rule matches an IPv4 client however it arrived, and one machine occupies one
//! rate-limit bucket rather than two.
//!
//! This is where the existing implementations fall down. vlmcsd's `-o` only
//! distinguishes RFC1918-class private from public, which NAT defeats entirely.
//! KptCheeseWhiz's fork is IPv4-only and denies **all** IPv6 including loopback
//! once filtering is enabled. MelroyB's is the only sane rule grammar in either
//! network, and his normalisation lives in the matcher alone, so his logs and
//! his filter disagree about who connected.
//!
//! # Default allow-all, deliberately
//!
//! An empty [`AccessList`] permits everything. A KMS host that refuses by
//! default is a KMS host that does not work out of the box, and the failure
//! mode — clients that cannot activate for a reason nothing logs — is far worse
//! than the failure mode of the open default.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::time::Duration;
use kmsrs_db::Guid;
use kmsrs_proto::time::Instant;

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form.
///
/// IPv4-**compatible** addresses (`::1.2.3.4`, deprecated by RFC 4291) are
/// deliberately not collapsed: they are not how a dual-stack socket reports an
/// IPv4 peer, and treating them as equivalent would let a peer choose which
/// spelling to arrive as — which is exactly what keying on the source address
/// is supposed to prevent.
#[must_use]
pub fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// One entry in an access list.
///
/// The grammar is MelroyB's, which the audit calls the only sane one in either
/// fork network: single addresses, CIDR blocks, and inclusive start–end ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Exactly this address.
    Address(IpAddr),
    /// This prefix.
    ///
    /// A prefix longer than the address family allows never matches, rather
    /// than matching everything — a typo must fail closed for an allow rule and
    /// open for a deny rule, and "never matches" is that in both directions.
    Cidr {
        /// The network address.
        base: IpAddr,
        /// How many leading bits must agree.
        prefix: u8,
    },
    /// An inclusive range, in the same family.
    Range {
        /// First address, inclusive.
        start: IpAddr,
        /// Last address, inclusive.
        end: IpAddr,
    },
}

impl Rule {
    /// Whether this rule covers an address.
    #[must_use]
    pub fn matches(self, address: IpAddr) -> bool {
        let address = canonical(address);
        match self {
            Self::Address(rule) => canonical(rule) == address,
            Self::Cidr { base, prefix } => prefix_matches(canonical(base), prefix, address),
            Self::Range { start, end } => {
                let (start, end) = (canonical(start), canonical(end));
                match (start, end, address) {
                    (IpAddr::V4(low), IpAddr::V4(high), IpAddr::V4(value)) => {
                        let value = u32::from(value);
                        value >= u32::from(low) && value <= u32::from(high)
                    }
                    (IpAddr::V6(low), IpAddr::V6(high), IpAddr::V6(value)) => {
                        let value = u128::from(value);
                        value >= u128::from(low) && value <= u128::from(high)
                    }
                    // A range whose ends are in different families, or an
                    // address in neither, matches nothing.
                    _ => false,
                }
            }
        }
    }
}

/// Whether `address` is inside `base/prefix`.
fn prefix_matches(base: IpAddr, prefix: u8, address: IpAddr) -> bool {
    match (base, address) {
        (IpAddr::V4(base), IpAddr::V4(address)) => {
            masked_v4(base, prefix) == masked_v4(address, prefix).filter(|_| prefix <= 32)
                && prefix <= 32
        }
        (IpAddr::V6(base), IpAddr::V6(address)) => {
            prefix <= 128 && masked_v6(base, prefix) == masked_v6(address, prefix)
        }
        // A rule and an address in different families never match. Both have
        // been canonicalised, so this is a genuine family difference rather
        // than a spelling one.
        _ => false,
    }
}

/// The top `prefix` bits of an IPv4 address, or `None` if the prefix is too
/// long to be meaningful.
fn masked_v4(address: Ipv4Addr, prefix: u8) -> Option<u32> {
    if prefix > 32 {
        return None;
    }
    if prefix == 0 {
        return Some(0);
    }
    let shift = 32_u32.checked_sub(u32::from(prefix))?;
    u32::from(address).checked_shr(shift)
}

/// The top `prefix` bits of an IPv6 address.
fn masked_v6(address: Ipv6Addr, prefix: u8) -> Option<u128> {
    if prefix > 128 {
        return None;
    }
    if prefix == 0 {
        return Some(0);
    }
    let shift = 128_u32.checked_sub(u32::from(prefix))?;
    u128::from(address).checked_shr(shift)
}

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Denial {
    /// An allow list exists and this address is not in it.
    NotAllowed,
    /// A deny rule matched.
    Denied,
}

/// Who may connect (`POL-013`, #101).
///
/// A build-time value. An access list decides whether this host answers at all,
/// which is visible to whoever is asking — so it belongs with the settings that
/// can change a byte on the wire, not with the runtime ones (`CFG-001`, #166).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessList {
    /// If non-empty, only these are permitted.
    pub allow: &'static [Rule],
    /// These are refused, even if an allow rule matches.
    pub deny: &'static [Rule],
}

impl AccessList {
    /// An empty list, which permits everything.
    pub const OPEN: Self = Self {
        allow: &[],
        deny: &[],
    };

    /// Whether an address may connect.
    ///
    /// Deny wins over allow, because the alternative — allow winning — makes a
    /// broad allow rule silently defeat a specific deny rule, which is never
    /// what the person writing them meant.
    ///
    /// # Errors
    ///
    /// Returns [`Denial`] saying which gate refused, so the event log can say
    /// *why* rather than only that something was refused (`POL-014`, #102).
    pub fn check(&self, address: IpAddr) -> Result<(), Denial> {
        if self.deny.iter().any(|rule| rule.matches(address)) {
            return Err(Denial::Denied);
        }
        if !self.allow.is_empty() && !self.allow.iter().any(|rule| rule.matches(address)) {
            return Err(Denial::NotAllowed);
        }
        Ok(())
    }

    /// Whether this list refuses anything at all.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

/// How many requests a single source may make in a burst (`POL-014`, #102).
///
/// # Why this is so large
///
/// The bucket is keyed on the source address, and **a whole site behind NAT is
/// one source address**. A limit tuned for one machine would refuse a
/// legitimate office the morning everyone turns their computers on, and a
/// refusal is both a broken client and a fingerprint — a genuine KMS host does
/// not rate-limit.
///
/// So this is set where only sustained, obviously-synthetic traffic reaches it.
/// It is a backstop against a loop hammering one host, not a quota.
pub const BURST: u32 = 240;

/// How many requests per second a source earns back.
///
/// A real client renews on a seven-day interval, so any steady rate above a
/// trickle is already unusual. One per second still allows 86 400 activations a
/// day from one address.
pub const REFILL_PER_SECOND: u32 = 1;

/// The most sources tracked at once.
///
/// Bounded because the table is in memory and its keys come from outside. At
/// the limit the least recently seen entry is dropped, which is the right
/// failure: forgetting an old source means it starts with a full bucket, and a
/// full bucket is the permissive answer.
pub const MAX_TRACKED_SOURCES: usize = 4_096;

/// What the rate limiter decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Proceed.
    Allowed {
        /// Tokens left in this source's bucket, for the log.
        remaining: u32,
    },
    /// Refused for now.
    Limited {
        /// How long until a token is available.
        retry_after: Duration,
    },
}

/// One source's bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    address: IpAddr,
    application: Guid,
    tokens: u32,
    last_refill: Instant,
    last_seen: Instant,
}

/// A token bucket per (source address, application) (`POL-014`, #102).
///
/// Keyed on the application as well as the address, because "stop one product
/// being hammered" is a different question from "stop this host being
/// hammered", and the issue asks for the former. Both halves of the key are
/// things the client cannot choose freely: the address is the transport's, and
/// the application must match the product for the request to be answered at
/// all (`POL-010`, #98).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimiter {
    buckets: Vec<Bucket>,
    burst: u32,
    refill_per_second: u32,
}

impl RateLimiter {
    /// A limiter with the shipped defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: Vec::new(),
            burst: BURST,
            refill_per_second: REFILL_PER_SECOND,
        }
    }

    /// A limiter with explicit bounds, for tests.
    #[must_use]
    pub const fn with(burst: u32, refill_per_second: u32) -> Self {
        Self {
            buckets: Vec::new(),
            burst,
            refill_per_second,
        }
    }

    /// Take a token for a request, or say how long to wait.
    pub fn admit(&mut self, address: IpAddr, application: Guid, now: Instant) -> Admission {
        let address = canonical(address);
        let index = self.bucket_for(address, application, now);
        let Some(bucket) = self.buckets.get_mut(index) else {
            // Unreachable: `bucket_for` returns an index it just ensured
            // exists. Admitting is the safe direction — a limiter that fails
            // closed would refuse legitimate clients on a bug.
            return Admission::Allowed {
                remaining: self.burst,
            };
        };

        // Refill for the time that has passed.
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        let earned = elapsed
            .as_secs()
            .saturating_mul(u64::from(self.refill_per_second));
        if earned > 0 {
            bucket.tokens = u32::try_from(u64::from(bucket.tokens).saturating_add(earned))
                .unwrap_or(u32::MAX)
                .min(self.burst);
            bucket.last_refill = now;
        }
        bucket.last_seen = now;

        if bucket.tokens == 0 {
            let per_second = u64::from(self.refill_per_second.max(1));
            return Admission::Limited {
                retry_after: Duration::from_secs(1_u64.div_euclid(per_second).max(1)),
            };
        }
        bucket.tokens = bucket.tokens.saturating_sub(1);
        Admission::Allowed {
            remaining: bucket.tokens,
        }
    }

    /// How many sources are tracked.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Find or create a bucket, evicting the stalest if the table is full.
    fn bucket_for(&mut self, address: IpAddr, application: Guid, now: Instant) -> usize {
        if let Some(index) = self
            .buckets
            .iter()
            .position(|bucket| bucket.address == address && bucket.application == application)
        {
            return index;
        }

        let fresh = Bucket {
            address,
            application,
            // A source seen for the first time starts full.
            tokens: self.burst,
            last_refill: now,
            last_seen: now,
        };

        if self.buckets.len() < MAX_TRACKED_SOURCES {
            self.buckets.push(fresh);
            return self.buckets.len().saturating_sub(1);
        }

        let stalest = self
            .buckets
            .iter()
            .enumerate()
            .min_by_key(|(_, bucket)| bucket.last_seen)
            .map_or(0, |(index, _)| index);
        if let Some(slot) = self.buckets.get_mut(stalest) {
            *slot = fresh;
        }
        stalest
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
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        AccessList, Admission, BURST, Denial, MAX_TRACKED_SOURCES, RateLimiter, Rule, canonical,
    };
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use kmsrs_db::Guid;
    use kmsrs_proto::time::Instant;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn mapped(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped())
    }

    fn at(seconds: u64) -> Instant {
        Instant::from_nanos(seconds.saturating_mul(1_000_000_000))
    }

    fn app() -> Guid {
        Guid::from_bytes([0x55; 16])
    }

    /// `POL-013` (#101): the default permits everything. A KMS host that
    /// refuses out of the box is a KMS host that does not work out of the box.
    #[test]
    fn the_default_allows_everything() {
        let open = AccessList::OPEN;
        assert!(open.is_open());
        for address in [
            v4(127, 0, 0, 1),
            v4(10, 0, 0, 5),
            v4(8, 8, 8, 8),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(open.check(address), Ok(()), "{address}");
        }
        assert_eq!(AccessList::default().check(v4(1, 2, 3, 4)), Ok(()));
    }

    /// `POL-013` (#101): an IPv4-mapped client matches an IPv4 rule. Without
    /// this, a rule written as `10.0.0.0/8` silently stops applying the moment
    /// the client arrives over a dual-stack socket.
    #[test]
    fn an_ipv4_mapped_client_matches_an_ipv4_rule() {
        const ALLOW: &[Rule] = &[Rule::Cidr {
            base: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        }];
        let list = AccessList {
            allow: ALLOW,
            deny: &[],
        };

        assert_eq!(list.check(v4(10, 1, 2, 3)), Ok(()), "plain IPv4");
        assert_eq!(list.check(mapped(10, 1, 2, 3)), Ok(()), "IPv4-mapped");
        assert_eq!(list.check(v4(11, 1, 2, 3)), Err(Denial::NotAllowed));
        assert_eq!(list.check(mapped(11, 1, 2, 3)), Err(Denial::NotAllowed));
    }

    /// The same, for a deny rule — a filter that can be evaded by connecting
    /// over IPv6 is not a filter.
    #[test]
    fn a_deny_rule_cannot_be_evaded_by_arriving_as_ipv4_mapped() {
        const DENY: &[Rule] = &[Rule::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)))];
        let list = AccessList {
            allow: &[],
            deny: DENY,
        };

        assert_eq!(list.check(v4(192, 0, 2, 9)), Err(Denial::Denied));
        assert_eq!(list.check(mapped(192, 0, 2, 9)), Err(Denial::Denied));
        assert_eq!(list.check(v4(192, 0, 2, 10)), Ok(()));
    }

    /// Deny wins, so a broad allow cannot silently defeat a specific deny.
    #[test]
    fn deny_beats_allow() {
        const ALLOW: &[Rule] = &[Rule::Cidr {
            base: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        }];
        const DENY: &[Rule] = &[Rule::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))];
        let list = AccessList {
            allow: ALLOW,
            deny: DENY,
        };
        assert_eq!(list.check(v4(10, 0, 0, 6)), Ok(()));
        assert_eq!(list.check(v4(10, 0, 0, 7)), Err(Denial::Denied));
    }

    /// The three rule shapes, including the IPv6 ones a fork got wrong by being
    /// IPv4-only.
    #[test]
    fn every_rule_shape_matches_what_it_should() {
        assert!(Rule::Address(v4(1, 2, 3, 4)).matches(v4(1, 2, 3, 4)));
        assert!(!Rule::Address(v4(1, 2, 3, 4)).matches(v4(1, 2, 3, 5)));

        let cidr = Rule::Cidr {
            base: v4(192, 168, 1, 0),
            prefix: 24,
        };
        assert!(cidr.matches(v4(192, 168, 1, 0)));
        assert!(cidr.matches(v4(192, 168, 1, 255)));
        assert!(!cidr.matches(v4(192, 168, 2, 0)));

        let range = Rule::Range {
            start: v4(10, 0, 0, 10),
            end: v4(10, 0, 0, 20),
        };
        assert!(range.matches(v4(10, 0, 0, 10)), "inclusive at the start");
        assert!(range.matches(v4(10, 0, 0, 20)), "and at the end");
        assert!(range.matches(v4(10, 0, 0, 15)));
        assert!(!range.matches(v4(10, 0, 0, 9)));
        assert!(!range.matches(v4(10, 0, 0, 21)));

        // IPv6 works, including loopback — the fork that got this wrong denied
        // its own loopback once filtering was enabled.
        let v6 = Rule::Cidr {
            base: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix: 32,
        };
        assert!(v6.matches(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 9, 9, 9, 9, 9, 9))));
        assert!(!v6.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(
            Rule::Address(IpAddr::V6(Ipv6Addr::LOCALHOST)).matches(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    /// A `/0` matches its whole family and nothing outside it.
    #[test]
    fn a_zero_prefix_matches_its_family_only() {
        let all_v4 = Rule::Cidr {
            base: v4(0, 0, 0, 0),
            prefix: 0,
        };
        assert!(all_v4.matches(v4(1, 2, 3, 4)));
        assert!(all_v4.matches(mapped(1, 2, 3, 4)), "canonicalised first");
        assert!(!all_v4.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    /// A prefix longer than the family allows matches nothing, rather than
    /// matching everything — a typo must not silently open or close the gate.
    #[test]
    fn an_impossible_prefix_matches_nothing() {
        let broken = Rule::Cidr {
            base: v4(10, 0, 0, 0),
            prefix: 33,
        };
        assert!(!broken.matches(v4(10, 0, 0, 1)));
        assert!(!broken.matches(v4(11, 0, 0, 1)));

        let broken6 = Rule::Cidr {
            base: IpAddr::V6(Ipv6Addr::LOCALHOST),
            prefix: 129,
        };
        assert!(!broken6.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    /// A range whose ends are in different families matches nothing rather than
    /// producing a nonsense comparison.
    #[test]
    fn a_mixed_family_range_matches_nothing() {
        let mixed = Rule::Range {
            start: v4(10, 0, 0, 0),
            end: IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        assert!(!mixed.matches(v4(10, 0, 0, 1)));
        assert!(!mixed.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    /// `NET-012` (#161) restated where the gates use it.
    #[test]
    fn canonicalisation_collapses_only_ipv4_mapped() {
        assert_eq!(canonical(mapped(1, 2, 3, 4)), v4(1, 2, 3, 4));
        assert_eq!(canonical(v4(1, 2, 3, 4)), v4(1, 2, 3, 4));
        let compatible = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0102, 0x0304));
        assert_eq!(canonical(compatible), compatible, "deprecated ::1.2.3.4");
    }

    /// `POL-014` (#102): the limit is per source, not global. One noisy address
    /// must not affect anyone else.
    #[test]
    fn the_limit_is_per_source() {
        let mut limiter = RateLimiter::with(3, 1);
        let noisy = v4(198, 51, 100, 1);
        let quiet = v4(198, 51, 100, 2);

        for _ in 0..3 {
            assert!(matches!(
                limiter.admit(noisy, app(), at(0)),
                Admission::Allowed { .. }
            ));
        }
        assert!(
            matches!(
                limiter.admit(noisy, app(), at(0)),
                Admission::Limited { .. }
            ),
            "the noisy source is limited"
        );

        assert!(
            matches!(
                limiter.admit(quiet, app(), at(0)),
                Admission::Allowed { .. }
            ),
            "and nobody else is"
        );
    }

    /// Keyed on the application too, so hammering one product does not exhaust
    /// another's budget for the same source.
    #[test]
    fn the_limit_is_per_application_as_well() {
        let mut limiter = RateLimiter::with(2, 1);
        let source = v4(198, 51, 100, 1);
        let other = Guid::from_bytes([0x0f; 16]);

        for _ in 0..2 {
            limiter.admit(source, app(), at(0));
        }
        assert!(matches!(
            limiter.admit(source, app(), at(0)),
            Admission::Limited { .. }
        ));
        assert!(
            matches!(
                limiter.admit(source, other, at(0)),
                Admission::Allowed { .. }
            ),
            "a different application has its own bucket"
        );
    }

    /// Tokens come back with time, so a limited source recovers on its own.
    #[test]
    fn a_bucket_refills() {
        let mut limiter = RateLimiter::with(2, 1);
        let source = v4(198, 51, 100, 1);

        limiter.admit(source, app(), at(0));
        limiter.admit(source, app(), at(0));
        assert!(matches!(
            limiter.admit(source, app(), at(0)),
            Admission::Limited { .. }
        ));

        // One second later, one token.
        assert!(matches!(
            limiter.admit(source, app(), at(1)),
            Admission::Allowed { .. }
        ));
        assert!(matches!(
            limiter.admit(source, app(), at(1)),
            Admission::Limited { .. }
        ));

        // Long enough to refill past the burst: it caps rather than growing.
        let Admission::Allowed { remaining } = limiter.admit(source, app(), at(10_000)) else {
            panic!("should have refilled");
        };
        assert_eq!(remaining, 1, "capped at the burst, then one taken");
    }

    /// An IPv4-mapped and a plain IPv4 client are one bucket, not two —
    /// otherwise the limit is doubled by connecting both ways.
    #[test]
    fn one_client_gets_one_bucket_however_it_arrives() {
        let mut limiter = RateLimiter::with(2, 1);
        limiter.admit(v4(198, 51, 100, 1), app(), at(0));
        limiter.admit(mapped(198, 51, 100, 1), app(), at(0));
        assert_eq!(limiter.tracked(), 1, "one source, one bucket");
        assert!(matches!(
            limiter.admit(v4(198, 51, 100, 1), app(), at(0)),
            Admission::Limited { .. }
        ));
    }

    /// The table is bounded, and forgetting an old source is permissive rather
    /// than restrictive.
    #[test]
    fn the_table_is_bounded_and_forgets_permissively() {
        let mut limiter = RateLimiter::with(1, 1);
        for index in 0..(MAX_TRACKED_SOURCES + 100) {
            let address = IpAddr::V4(Ipv4Addr::from(u32::try_from(index).unwrap()));
            assert!(
                matches!(
                    limiter.admit(address, app(), at(index as u64)),
                    Admission::Allowed { .. }
                ),
                "a new source starts with a full bucket"
            );
        }
        assert_eq!(limiter.tracked(), MAX_TRACKED_SOURCES);
    }

    /// The shipped burst is deliberately generous, because a whole site behind
    /// NAT is one source address. This test exists to make anyone lowering it
    /// think about that first.
    #[test]
    fn the_shipped_burst_tolerates_a_nat_ted_site() {
        assert!(
            BURST >= 200,
            "a limit tuned for one machine refuses an office behind NAT the \
             morning everyone turns their computers on — and a refusal is both \
             a broken client and a fingerprint"
        );
        let mut limiter = RateLimiter::new();
        let gateway = v4(198, 51, 100, 1);
        for index in 0..200 {
            assert!(
                matches!(
                    limiter.admit(gateway, app(), at(0)),
                    Admission::Allowed { .. }
                ),
                "machine {index} behind the gateway was refused"
            );
        }
    }
}
