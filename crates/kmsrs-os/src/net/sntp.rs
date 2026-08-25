//! SNTP, so this machine's clock is not whatever the hypervisor felt like
//! (`OS-020`, #336).
//!
//! # What the clock is actually for
//!
//! Less than the issue assumed, and the difference is worth stating because it
//! decides how hard this has to try.
//!
//! * **Nothing in a response derives from it.** The v6 key schedule derives from
//!   the *client's* timestamp, which is why this host works on a target whose
//!   `SystemTime` is a CMOS read plus local ticks (`ARCH-004`, #4).
//! * **Every deadline in the program is monotonic.** Connection deadlines are
//!   tokio's, the activation interval is measured against an injected monotonic
//!   reading, and `clock_settime` on `CLOCK_REALTIME` does not move
//!   `CLOCK_MONOTONIC`. So a step here **cannot** be observed by
//!   `kmsrs-policy` as time going backwards — not because this code is careful
//!   about it, but because there is no path by which it could be.
//! * **The wall clock is read exactly once**, by `entry::today`, to bound the
//!   randomised activation date in the ePID (`ID-007`, #112). That happens at
//!   start-up, before this task can have corrected anything, and the value is
//!   then stable for the life of the process — which `ID-001` (#106) requires.
//! * **The skew check does not run at all today.** `driver.rs` passes
//!   `host_time: None`, so `POL-011` (#99) is inert and `strict-clock-skew`
//!   changes nothing. That is #346 (`POL-020`), filed rather than fixed here.
//!
//! So the honest summary is that this makes the *log* truthful and prepares the
//! ground for #346, rather than fixing a live activation bug. That is a good
//! enough reason — a host whose console timestamps are hours out is a host
//! nobody can correlate with anything — and it is not a good enough reason to
//! refuse to serve over, which is what decides the question below.
//!
//! # What happens when no server answers
//!
//! **The host serves with the unsynchronised clock, and says so once.** Decided
//! explicitly, per this issue's definition of done, and the reasoning is the
//! list above: a KMS host that refused to activate anything because it could
//! not reach an NTP server would be trading its entire function for a log
//! field. On the platforms this target supports the clock is already close —
//! kvmclock, the Hyper-V reference TSC, or a real RTC — and Microsoft's
//! tolerance is ±4 hours.
//!
//! # Where the servers come from
//!
//! Option 42 of the lease first, which on an air-gapped LAN is the only
//! reachable source and is the operator's own infrastructure either way. It is
//! a list of *addresses*, so it needs no resolver.
//!
//! [`POOL`] is the fallback and it is a hostname, which is the whole reason
//! this target has a resolver at all — see the decision in `docs/decisions.md`.
//! The resolver is configured from the lease's option 6, because axiom A5 means
//! there is no `/etc/resolv.conf` and no libc resolver that could read one.

use core::time::Duration;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

/// The fallback time source, as a build-time constant (axiom A3;
/// `CFG-001`, #166).
///
/// Not reachable through `KMSRSOS_CONFIG`, which may only touch settings that
/// cannot change a byte on the wire — and while this one cannot either, the
/// rule is that the build decides and there is no reason to make an exception
/// for it. An operator who wants a different source has two better routes than
/// a config file: DHCP option 42, which this prefers anyway, or a rebuild.
///
/// `pool.ntp.org` rather than a vendor's. The vendor pools ask for their own
/// clients and this is not one of theirs; the general pool's terms cover
/// exactly this use.
const POOL: &str = "pool.ntp.org";

/// The NTP port.
const NTP_PORT: u16 = 123;

/// An SNTP packet is 48 bytes and this client sends and expects no extension
/// fields — no authenticator, no NTS.
const PACKET: usize = 48;

/// Seconds between 1900-01-01 and 1970-01-01, which is what an NTP timestamp
/// counts from and Unix time does not.
const NTP_TO_UNIX: i128 = 2_208_988_800;

/// Nanoseconds in a second, as the width the offset arithmetic is done in.
const NANOS: i128 = 1_000_000_000;

/// 2^32, the divisor of an NTP fraction and the width of an era.
const ERA: i128 = 4_294_967_296;

/// How long to wait for one server before trying the next.
const TIMEOUT: Duration = Duration::from_secs(3);

/// How often to ask again once a reading has been taken.
///
/// 1024 seconds is `ntpd`'s default maximum poll and is what the pool's terms
/// ask of a client that is not running a discipline loop. On a LAN server it is
/// far more often than this host needs.
const POLL: Duration = Duration::from_secs(1024);

/// How long to wait after a round in which nothing answered.
///
/// Shorter than [`POLL`], because the interesting case is a machine that booted
/// before its DHCP server or its time server did, and longer than a retry storm.
const RETRY: Duration = Duration::from_mins(1);

/// How far out the clock has to be before it is worth stepping.
///
/// There is no slew here — SNTP, not NTP, and `adjtimex` is not reachable
/// without `unsafe` — so the choice is step or leave alone. Stepping by
/// milliseconds every seventeen minutes would be churn on a host that measures
/// nothing in wall-clock time; a second is well inside the ±4 hour band that is
/// the only thing the wall clock is compared against.
const STEP_THRESHOLD: Duration = Duration::from_secs(1);

/// The largest offset this will apply without saying something louder.
///
/// A correction bigger than a day means the clock was not merely drifting —
/// a VM restored from a snapshot, or a machine with a dead RTC battery — and
/// while stepping it is still right, an operator should know it happened.
const SURPRISING: Duration = Duration::from_hours(24);

/// The stratum values a client should accept.
///
/// 0 is "kiss-o'-death" — a server telling this client to go away, which
/// carries no time at all — and 16 means unsynchronised. Both are replies whose
/// timestamps must not be used.
const STRATUM: core::ops::RangeInclusive<u8> = 1..=15;

/// A reading from one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reading {
    /// How far this host's clock is *behind* the server's, in nanoseconds.
    /// Negative means the host is ahead.
    pub(crate) offset_nanos: i128,
    /// The round trip, which is how much the offset could be wrong by.
    pub(crate) delay_nanos: i128,
    /// How far from a reference clock the server is.
    pub(crate) stratum: u8,
}

/// Why a datagram was not a usable reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unusable {
    /// Not 48 bytes.
    WrongLength,
    /// The mode field was not 4 — this is not a server's reply to a client.
    NotAServerReply,
    /// The leap indicator was 3: the server's own clock is not synchronised.
    Unsynchronised,
    /// Stratum 0 (a kiss-o'-death) or 16 (unsynchronised).
    Stratum(u8),
    /// The originate timestamp did not echo what this client sent.
    ///
    /// The one check that makes an off-path forgery hard: an attacker who
    /// cannot see the request cannot guess the randomised transmit timestamp.
    NotOurRequest,
    /// A timestamp field was zero where it may not be.
    NoTimestamp,
}

impl core::fmt::Display for Unusable {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength => formatter.write_str("not 48 bytes"),
            Self::NotAServerReply => formatter.write_str("mode is not 4"),
            Self::Unsynchronised => formatter.write_str("the server says it is unsynchronised"),
            Self::Stratum(stratum) => write!(formatter, "stratum {stratum}"),
            Self::NotOurRequest => formatter.write_str("the originate timestamp is not ours"),
            Self::NoTimestamp => formatter.write_str("a timestamp is zero"),
        }
    }
}

/// Build the 48 bytes of a client request.
///
/// `transmit` is this client's clock at departure, as an NTP timestamp. RFC
/// 4330 §5 says to randomise its low order: the server echoes it into the
/// originate field, so it is the only thing distinguishing a real reply from a
/// forgery by somebody who cannot see the request.
pub(crate) fn request(transmit: u64) -> [u8; PACKET] {
    let mut packet = [0_u8; PACKET];
    // LI = 0 (no warning), VN = 4, Mode = 3 (client).
    if let Some(first) = packet.first_mut() {
        *first = 0b00_100_011;
    }
    // Everything between here and the transmit timestamp is zero from a client,
    // which is what RFC 4330 §5's "the client initializes all other fields to
    // zero" means. Sending a poll interval or a precision would be describing a
    // discipline loop this does not have.
    if let Some(field) = packet.get_mut(40..48) {
        field.copy_from_slice(&transmit.to_be_bytes());
    }
    packet
}

/// Turn a reply into a reading, or say why it is not one.
///
/// `sent` and `received` are this host's clock at departure and arrival, as NTP
/// timestamps. The offset is RFC 4330 §5's:
///
/// ```text
/// offset = ((T2 - T1) + (T3 - T4)) / 2
/// delay  =  (T4 - T1) - (T3 - T2)
/// ```
///
/// where T1 is `sent`, T2 and T3 are the server's receive and transmit, and T4
/// is `received`. Halving the sum is what cancels the one-way delay, on the
/// assumption that the two directions are symmetric — which is the assumption
/// SNTP is built on and the reason `delay` is reported alongside.
///
/// # Errors
///
/// Returns [`Unusable`] for a reply this client must not take time from.
pub(crate) fn reading(reply: &[u8], sent: u64, received: u64) -> Result<Reading, Unusable> {
    let reply: &[u8; PACKET] = reply.try_into().map_err(|_| Unusable::WrongLength)?;

    let first = *reply.first().unwrap_or(&0);
    // Bits 0-1 are the leap indicator, 2-4 the version, 5-7 the mode.
    let leap = first >> 6;
    let mode = first & 0b111;
    if mode != 4 {
        return Err(Unusable::NotAServerReply);
    }
    if leap == 3 {
        return Err(Unusable::Unsynchronised);
    }
    let stratum = *reply.get(1).unwrap_or(&0);
    if !STRATUM.contains(&stratum) {
        return Err(Unusable::Stratum(stratum));
    }

    let originate = timestamp_at(reply, 24).ok_or(Unusable::NoTimestamp)?;
    let server_received = timestamp_at(reply, 32).ok_or(Unusable::NoTimestamp)?;
    let server_transmit = timestamp_at(reply, 40).ok_or(Unusable::NoTimestamp)?;

    if originate != sent {
        return Err(Unusable::NotOurRequest);
    }
    if server_transmit == 0 || server_received == 0 {
        return Err(Unusable::NoTimestamp);
    }

    let t1 = unix_nanos(sent);
    let t2 = unix_nanos(server_received);
    let t3 = unix_nanos(server_transmit);
    let t4 = unix_nanos(received);

    let forward = t2.checked_sub(t1).ok_or(Unusable::NoTimestamp)?;
    let backward = t3.checked_sub(t4).ok_or(Unusable::NoTimestamp)?;
    let offset_nanos = forward
        .checked_add(backward)
        .and_then(|sum| sum.checked_div(2))
        .ok_or(Unusable::NoTimestamp)?;

    let round = t4.checked_sub(t1).ok_or(Unusable::NoTimestamp)?;
    let served = t3.checked_sub(t2).ok_or(Unusable::NoTimestamp)?;
    let delay_nanos = round.checked_sub(served).unwrap_or(0);

    Ok(Reading {
        offset_nanos,
        delay_nanos,
        stratum,
    })
}

/// The 64-bit NTP timestamp at a byte offset.
fn timestamp_at(reply: &[u8; PACKET], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let field: [u8; 8] = reply.get(at..end)?.try_into().ok()?;
    Some(u64::from_be_bytes(field))
}

/// An NTP timestamp as nanoseconds since the Unix epoch.
///
/// The era check is RFC 4330 §3 and is not decoration. NTP's seconds field is
/// 32 bits and wraps in **February 2036**, which is inside the service life of
/// anything shipping now: if the high bit is set the timestamp is in era 0
/// (1900–2036), and if it is clear the timestamp is in era 1 (2036–2172) and a
/// whole era has to be added. A client without this check will read 2036 as
/// 1900 and step its clock back 136 years.
pub(crate) fn unix_nanos(timestamp: u64) -> i128 {
    let seconds = i128::from(timestamp >> 32);
    let fraction = i128::from(timestamp & 0xFFFF_FFFF);

    let era_seconds = if seconds & 0x8000_0000 == 0 {
        seconds.saturating_add(ERA)
    } else {
        seconds
    };
    let unix_seconds = era_seconds.saturating_sub(NTP_TO_UNIX);

    let whole = unix_seconds.saturating_mul(NANOS);
    // The fraction is a binary fraction of a second: value / 2^32.
    let part = fraction.saturating_mul(NANOS).checked_div(ERA).unwrap_or(0);
    whole.saturating_add(part)
}

/// Nanoseconds since the Unix epoch as an NTP timestamp.
///
/// The inverse, and it has the same era to think about — a host whose clock is
/// past 2036 must send a timestamp in era 1, or every server will echo back
/// something the [`reading`] check reads as somebody else's request.
pub(crate) fn ntp_timestamp(unix_nanos_now: i128) -> u64 {
    let unix_seconds = unix_nanos_now.checked_div(NANOS).unwrap_or(0);
    let remainder = unix_nanos_now
        .checked_rem(NANOS)
        .unwrap_or(0)
        .clamp(0, NANOS);

    let ntp_seconds = unix_seconds.saturating_add(NTP_TO_UNIX);
    // Wrapping into the right era is exactly the modulo the format wants.
    let era_seconds = ntp_seconds.checked_rem(ERA).unwrap_or(0);
    let fraction = remainder
        .saturating_mul(ERA)
        .checked_div(NANOS)
        .unwrap_or(0);

    let high = u64::try_from(era_seconds).unwrap_or(0);
    let low = u64::try_from(fraction).unwrap_or(0);
    high.checked_shl(32).unwrap_or(0) | (low & 0xFFFF_FFFF)
}

/// This host's realtime clock, in nanoseconds since the Unix epoch.
fn now_unix_nanos() -> i128 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    i128::from(time.tv_sec)
        .saturating_mul(NANOS)
        .saturating_add(i128::from(time.tv_nsec))
}

/// Where the time comes from, as the lease last described it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Sources {
    /// Option 42, in the server's order of preference.
    pub(crate) ntp: Vec<Ipv4Addr>,
    /// Option 6, which is what the resolver is configured with when the pool
    /// has to be looked up.
    pub(crate) dns: Vec<Ipv4Addr>,
}

/// Keep this host's clock honest, for the life of the machine (`OS-020`, #336).
///
/// Spawned on the one runtime, beside the DHCP client and the KMS listeners.
/// `lease` is how it learns what the lease said; a renewal that changes the NTP
/// servers is picked up on the next poll rather than needing a restart.
pub(crate) fn spawn(lease: tokio::sync::watch::Receiver<Sources>) {
    tokio::spawn(async move {
        discipline(lease).await;
    });
}

/// One line of JSON on every console, through the tee of `OS-028` (#345).
fn say(level: &str, detail: &str) {
    println!("{{\"level\":\"{level}\",\"event\":\"clock\",\"detail\":\"{detail}\"}}");
}

/// Poll, step, repeat.
async fn discipline(mut lease: tokio::sync::watch::Receiver<Sources>) {
    // Said once, not once per failed round. A host that cannot reach a time
    // server is a host serving with the clock it booted with, which is a fact
    // an operator wants exactly one line about.
    let mut complained = false;
    let mut ever_synchronised = false;

    loop {
        let sources = lease.borrow_and_update().clone();
        let addresses = servers(&sources).await;

        if let Some(reading) = best(&addresses).await {
            complained = false;
            ever_synchronised = true;
            apply(reading);
            tokio::time::sleep(POLL).await;
        } else {
            if !complained {
                complained = true;
                say("warn", &nothing_answered(ever_synchronised, &addresses));
            }
            tokio::time::sleep(RETRY).await;
        }
    }
}

/// What to say when no server answered.
///
/// A function rather than two `format!`s inline, so the decision this issue
/// asked to be made explicitly — **serve with the unsynchronised clock** — is
/// something a test can read. The boot check cannot make that decision
/// deterministic on its own: whether `pool.ntp.org` resolves inside a build
/// sandbox is a property of the sandbox.
fn nothing_answered(ever_synchronised: bool, addresses: &[SocketAddr]) -> String {
    if ever_synchronised {
        return format!(
            "no time server answered; keeping the clock as it is. Tried: {}",
            describe(addresses)
        );
    }
    format!(
        "no time server answered, so this host is serving with the clock it \
         booted with. That is not a reason to refuse to activate anything — \
         nothing in a KMS response derives from this host's clock — but \
         timestamps in this log may be wrong. Tried: {}",
        describe(addresses)
    )
}

/// What was tried, for a log line an operator can act on.
fn describe(addresses: &[SocketAddr]) -> String {
    if addresses.is_empty() {
        return format!("nothing — the lease supplied no option 42 and {POOL} did not resolve");
    }
    addresses
        .iter()
        .map(|address| address.ip().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The servers to ask, this round.
///
/// Option 42 where the lease supplied it, because that is the operator's own
/// infrastructure and on an air-gapped LAN the only thing reachable. The pool
/// otherwise, which needs the resolver and therefore needs option 6.
async fn servers(sources: &Sources) -> Vec<SocketAddr> {
    if !sources.ntp.is_empty() {
        return sources
            .ntp
            .iter()
            .map(|address| SocketAddr::from((*address, NTP_PORT)))
            .collect();
    }
    resolve_pool(&sources.dns).await
}

/// Look [`POOL`] up through the lease's own resolvers.
async fn resolve_pool(nameservers: &[Ipv4Addr]) -> Vec<SocketAddr> {
    if nameservers.is_empty() {
        // No option 42 and no option 6. There is nothing to ask and nothing to
        // ask it with; `discipline` reports it.
        return Vec::new();
    }

    // Built from the lease rather than from a file: axiom A5 means there is no
    // /etc/resolv.conf, which is why `hickory-resolver`'s `system-config`
    // feature is off in the workspace manifest.
    let config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        nameservers
            .iter()
            .map(|address| NameServerConfig::udp_and_tcp(IpAddr::V4(*address)))
            .collect::<Vec<_>>(),
    );
    // `builder_with_config`, never `builder_tokio` — the latter reads
    // /etc/resolv.conf, which axiom A5 says does not exist here.
    let resolver: TokioResolver =
        match TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()).build() {
            Ok(resolver) => resolver,
            Err(error) => {
                say("warn", &format!("cannot build a resolver: {error}"));
                return Vec::new();
            }
        };

    match tokio::time::timeout(TIMEOUT, resolver.lookup_ip(format!("{POOL}."))).await {
        Ok(Ok(answer)) => answer
            .iter()
            // IPv4 only, and not from indifference: the lease this is
            // configured from is DHCPv4, option 42 is a list of v4 addresses,
            // and `ask` binds a v4 socket. A AAAA answer here would be a
            // server nothing in this module could reach.
            .filter_map(|address| match address {
                IpAddr::V4(address) => Some(SocketAddr::from((address, NTP_PORT))),
                IpAddr::V6(_) => None,
            })
            .collect(),
        Ok(Err(error)) => {
            say("warn", &format!("cannot resolve {POOL}: {error}"));
            Vec::new()
        }
        Err(_) => {
            say("warn", &format!("resolving {POOL} timed out"));
            Vec::new()
        }
    }
}

/// Ask each server in turn and take the first usable answer.
///
/// First rather than best. Choosing between four readings is a discipline loop,
/// which is what SNTP is defined as not being (RFC 4330 §1), and there is
/// nothing here for a better reading to improve — the tolerance this feeds is
/// four hours wide.
async fn best(addresses: &[SocketAddr]) -> Option<Reading> {
    for &address in addresses {
        match ask(address).await {
            Ok(reading) => return Some(reading),
            Err(reason) => say("info", &format!("{}: {reason}", address.ip())),
        }
    }
    None
}

/// One exchange with one server.
async fn ask(address: SocketAddr) -> Result<Reading, String> {
    // A fresh socket per exchange, bound to an ephemeral port. The port is then
    // part of what an off-path forger would have to guess, alongside the
    // randomised transmit timestamp.
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect(address)
        .await
        .map_err(|error| error.to_string())?;

    // RFC 4330 §5: randomise the low order of the transmit timestamp. The
    // server echoes it, so it is the nonce that makes a blind reply hard.
    let departure = now_unix_nanos();
    let nonce = i128::from(kmsrs_server::entropy::random_u32().unwrap_or(1));
    let sent = ntp_timestamp(departure.saturating_add(nonce.checked_rem(NANOS).unwrap_or(0)));

    socket
        .send(&request(sent))
        .await
        .map_err(|error| error.to_string())?;

    let mut buffer = [0_u8; PACKET];
    let read = tokio::time::timeout(TIMEOUT, socket.recv(&mut buffer))
        .await
        .map_err(|_| "no answer".to_owned())?
        .map_err(|error| error.to_string())?;

    let arrival = ntp_timestamp(now_unix_nanos());
    reading(buffer.get(..read).unwrap_or_default(), sent, arrival)
        .map_err(|unusable| unusable.to_string())
}

/// Step the clock, if the reading says it is worth doing.
fn apply(reading: Reading) {
    let magnitude = reading.offset_nanos.unsigned_abs();
    let threshold = STEP_THRESHOLD.as_nanos();
    if magnitude < threshold {
        return;
    }

    let corrected = now_unix_nanos().saturating_add(reading.offset_nanos);
    let Some(timespec) = timespec(corrected) else {
        say("warn", "the corrected time does not fit a timespec");
        return;
    };

    match rustix::time::clock_settime(rustix::time::ClockId::Realtime, timespec) {
        Ok(()) => {
            let seconds = reading
                .offset_nanos
                .checked_div(NANOS)
                .unwrap_or(reading.offset_nanos);
            let level = if magnitude > SURPRISING.as_nanos() {
                "warn"
            } else {
                "info"
            };
            say(
                level,
                &format!(
                    "stepped {seconds}s from a stratum {} server (round trip {}ms). \
                     Nothing in a KMS response derives from this clock, and every \
                     deadline in this program is monotonic, so no request in flight \
                     sees time move",
                    reading.stratum,
                    reading
                        .delay_nanos
                        .checked_div(1_000_000)
                        .unwrap_or_default()
                ),
            );
        }
        // EPERM means no CAP_SYS_TIME, which pid 1 has and a developer running
        // this on their workstation does not. Not fatal either way.
        Err(error) => say("warn", &format!("cannot set the clock: {error}")),
    }
}

/// Nanoseconds since the epoch as a `timespec`, or `None` if it will not fit.
fn timespec(unix_nanos_value: i128) -> Option<rustix::time::Timespec> {
    let seconds = unix_nanos_value.checked_div(NANOS)?;
    let remainder = unix_nanos_value.checked_rem(NANOS)?;
    // `clock_settime` will not take a negative nanosecond field, so a negative
    // remainder borrows a second.
    let (seconds, nanos) = if remainder < 0 {
        (seconds.checked_sub(1)?, remainder.checked_add(NANOS)?)
    } else {
        (seconds, remainder)
    };
    Some(rustix::time::Timespec {
        tv_sec: i64::try_from(seconds).ok()?,
        tv_nsec: i64::try_from(nanos).ok()?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        NANOS, PACKET, Reading, Unusable, nothing_answered, ntp_timestamp, reading, request,
        unix_nanos,
    };

    /// Build a server reply with the timestamps given, as NTP values.
    fn reply(originate: u64, server_received: u64, server_transmit: u64) -> [u8; PACKET] {
        let mut packet = [0_u8; PACKET];
        // LI = 0, VN = 4, Mode = 4 (server).
        packet[0] = 0b00_100_100;
        packet[1] = 2; // stratum
        packet[24..32].copy_from_slice(&originate.to_be_bytes());
        packet[32..40].copy_from_slice(&server_received.to_be_bytes());
        packet[40..48].copy_from_slice(&server_transmit.to_be_bytes());
        packet
    }

    /// A timestamp for a whole number of Unix seconds.
    fn at(unix_seconds: i128) -> u64 {
        ntp_timestamp(unix_seconds.saturating_mul(NANOS))
    }

    #[test]
    fn a_request_is_a_client_packet_of_version_four() {
        let packet = request(0x1234_5678_9ABC_DEF0);
        assert_eq!(packet.len(), 48);
        assert_eq!(packet[0] >> 6, 0, "leap indicator");
        assert_eq!((packet[0] >> 3) & 0b111, 4, "version");
        assert_eq!(packet[0] & 0b111, 3, "mode 3 is a client");
        assert_eq!(
            &packet[40..48],
            &0x1234_5678_9ABC_DEF0_u64.to_be_bytes(),
            "the transmit timestamp is what the server echoes"
        );
        assert!(
            packet[1..40].iter().all(|byte| *byte == 0),
            "RFC 4330 §5: a client zeroes everything else"
        );
    }

    /// The plain case: the server's clock is ten seconds ahead of ours and the
    /// round trip is symmetric.
    #[test]
    fn an_offset_is_the_average_of_the_two_directions() {
        // Host sends at 1000, server sees 1010, replies at 1010, host gets it
        // at 1002 — so two seconds of round trip and ten seconds of offset.
        let got = reading(&reply(at(1000), at(1010), at(1010)), at(1000), at(1002)).unwrap();

        assert_eq!(got.offset_nanos, 9 * NANOS, "((1010-1000)+(1010-1002))/2");
        assert_eq!(got.delay_nanos, 2 * NANOS, "(1002-1000)-(1010-1010)");
        assert_eq!(got.stratum, 2);
    }

    /// A host that is *ahead* gets a negative offset, and stepping by it must
    /// move the clock backwards rather than wrapping.
    #[test]
    fn a_host_ahead_of_the_server_gets_a_negative_offset() {
        let got = reading(&reply(at(2000), at(1990), at(1990)), at(2000), at(2000)).unwrap();
        assert_eq!(got.offset_nanos, -10 * NANOS);
    }

    /// The check that makes an off-path forgery hard: the reply must echo the
    /// randomised timestamp this client sent.
    #[test]
    fn a_reply_that_does_not_echo_our_timestamp_is_refused() {
        let forged = reply(at(999), at(5000), at(5000));
        assert_eq!(
            reading(&forged, at(1000), at(1001)),
            Err(Unusable::NotOurRequest)
        );
    }

    #[test]
    fn a_server_that_says_it_is_lost_is_not_believed() {
        // Leap indicator 3 — the server's own clock is unsynchronised.
        let mut packet = reply(at(1000), at(1010), at(1010));
        packet[0] |= 0b1100_0000;
        assert_eq!(
            reading(&packet, at(1000), at(1002)),
            Err(Unusable::Unsynchronised)
        );

        // Stratum 0 is a kiss-o'-death and carries no time at all.
        let mut kod = reply(at(1000), at(1010), at(1010));
        kod[1] = 0;
        assert_eq!(reading(&kod, at(1000), at(1002)), Err(Unusable::Stratum(0)));

        // Stratum 16 means unsynchronised.
        let mut lost = reply(at(1000), at(1010), at(1010));
        lost[1] = 16;
        assert_eq!(
            reading(&lost, at(1000), at(1002)),
            Err(Unusable::Stratum(16))
        );
    }

    /// Our own request, reflected back at us, is not a reply.
    #[test]
    fn a_client_packet_is_not_a_reply() {
        let mut packet = reply(at(1000), at(1010), at(1010));
        packet[0] = 0b00_100_011;
        assert_eq!(
            reading(&packet, at(1000), at(1002)),
            Err(Unusable::NotAServerReply)
        );
    }

    #[test]
    fn a_short_datagram_is_refused() {
        assert_eq!(reading(&[], 0, 0), Err(Unusable::WrongLength));
        assert_eq!(reading(&[0_u8; 47], 0, 0), Err(Unusable::WrongLength));
    }

    /// A server that answers with a zero transmit timestamp has told us
    /// nothing, and treating zero as "1900" would step the clock back a
    /// century.
    #[test]
    fn a_zero_timestamp_is_not_a_time() {
        let packet = reply(at(1000), at(1010), 0);
        assert_eq!(
            reading(&packet, at(1000), at(1002)),
            Err(Unusable::NoTimestamp)
        );
    }

    /// **February 2036.** NTP's seconds field is 32 bits and wraps there. A
    /// client that ignores RFC 4330 §3's era rule reads the first timestamp
    /// after the wrap as 1900 and steps its clock back 136 years — which is
    /// inside the service life of anything shipping now, so it is a test rather
    /// than a comment.
    #[test]
    fn the_2036_wrap_is_read_as_2036_and_not_1900() {
        // 2_085_978_496 = 2036-02-07T06:28:16Z, just after the wrap.
        let after_the_wrap: i128 = 2_085_978_496;
        let timestamp = at(after_the_wrap);

        assert!(
            timestamp >> 32 < 0x8000_0000,
            "this timestamp is in era 1, which is the case under test"
        );
        assert_eq!(
            unix_nanos(timestamp),
            after_the_wrap.saturating_mul(NANOS),
            "era 1 must not be read as 1900"
        );

        // And a whole exchange across the wrap produces a sane offset rather
        // than a 136-year one.
        let got = reading(
            &reply(
                at(after_the_wrap),
                at(after_the_wrap + 5),
                at(after_the_wrap + 5),
            ),
            at(after_the_wrap),
            at(after_the_wrap + 1),
        )
        .unwrap();
        // ((t+5)-(t)) + ((t+5)-(t+1)), halved: 4.5 seconds.
        assert_eq!(got.offset_nanos, 4_500_000_000);
    }

    /// The two conversions are inverses to within the resolution of a 32-bit
    /// fraction, which is about a quarter of a nanosecond.
    #[test]
    fn a_timestamp_round_trips() {
        for unix_seconds in [0_i128, 1, 1_000_000_000, 2_085_978_495, 2_085_978_497] {
            let nanos = unix_seconds.saturating_mul(NANOS);
            assert_eq!(unix_nanos(ntp_timestamp(nanos)), nanos, "{unix_seconds}");
        }
    }

    /// The decision this issue asked for explicitly: **no reachable time server
    /// is not a reason to stop serving.** Asserted on the sentence an operator
    /// reads, because that sentence is where the decision lives — there is no
    /// code path to test for "refused to serve", since there is deliberately
    /// no such path.
    #[test]
    fn an_unreachable_time_server_is_not_a_reason_to_stop_serving() {
        let said = nothing_answered(false, &[]);
        assert!(
            said.contains("serving with the clock it booted with"),
            "the first thing an operator must learn is that the host is still \
             working: {said}"
        );
        assert!(
            said.contains("not a reason to refuse to activate anything"),
            "and why, so nobody 'fixes' it by making it fatal: {said}"
        );
        assert!(
            said.contains("no option 42"),
            "and what was tried, so it can be acted on: {said}"
        );
    }

    /// Once a reading has been taken, a later failure is a smaller thing to
    /// say: the clock is already close, and repeating the paragraph above
    /// every minute would be noise.
    #[test]
    fn a_later_failure_says_less() {
        let first = nothing_answered(false, &[]);
        let later = nothing_answered(true, &[]);
        assert!(later.len() < first.len(), "{later}");
        assert!(later.contains("keeping the clock as it is"), "{later}");
    }

    /// A `Reading` is `Copy` and compares by value, which is what lets the
    /// tests above be one line each.
    #[test]
    fn a_reading_compares_by_value() {
        let one = Reading {
            offset_nanos: 1,
            delay_nanos: 2,
            stratum: 3,
        };
        assert_eq!(one, one);
    }
}
