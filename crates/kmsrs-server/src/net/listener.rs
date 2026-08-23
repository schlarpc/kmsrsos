//! Binding, with the socket options that differ per platform
//! (`NET-001`, #150; `NET-009`, #159; `NET-003`, #152).
//!
//! # `SO_REUSEADDR` and `SO_EXCLUSIVEADDRUSE` are opposites
//!
//! On Unix, `SO_REUSEADDR` lets a new process bind a port still held in
//! `TIME_WAIT` by a dead one — without it a restart fails for a minute or two.
//! On Windows the same name means something else entirely: it lets an unrelated
//! process **steal** a port already bound, and the option that means what Unix
//! means is `SO_EXCLUSIVEADDRUSE`. They are semantic opposites, and vlmcsd's
//! own diagnostic text confuses them.
//!
//! So `SO_REUSEADDR` is set on Unix only, and
//! `SO_EXCLUSIVEADDRUSE` is left to the Windows default, which already means
//! what Unix's `SO_REUSEADDR` means. Setting the same-named option on both
//! platforms would be the bug.
//!
//! `SO_REUSEPORT` is deliberately never set. It is not needed here — one
//! process binds each address once — and setting it is what kills py-kms's
//! start-up on Windows, where the constant does not exist.
//!
//! # `IPV6_V6ONLY` is set explicitly, in both senses of the word
//!
//! Left at the platform default, whether an IPv4 client can reach this host
//! depends on `net.ipv6.bindv6only` — a sysctl. On a stock Linux the `[::]`
//! socket accepts IPv4 too, so the `0.0.0.0` bind then fails with
//! `EADDRINUSE`, and the operator is told IPv4 is not being served when it is.
//!
//! Setting `IPV6_V6ONLY=1` makes the two sockets genuinely independent, so what
//! is bound is what was asked for on every platform. That is also why this is
//! two sockets rather than one dual-stack socket: OpenBSD refuses
//! `IPV6_V6ONLY=0` outright, and py-kms's fallback for exactly that case
//! triggers on one exact exception *string* — which stops matching the moment a
//! platform words its error differently.
//!
//! # Stack-existence probes
//!
//! Each address is bound independently and a failure is not fatal
//! (`NET-001`, #150). A host with IPv6 disabled serves IPv4, and a host with
//! only IPv6 serves that. Failing to bind *everything* is the only fatal case,
//! because a server that listens nowhere is not a server.

use crate::net::addr::{BACKLOG, bind_addresses};
use core::net::SocketAddr;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::TcpListener;

/// A bound listener and the address it is bound to.
#[derive(Debug)]
pub struct Bound {
    /// The listening socket.
    pub listener: TcpListener,
    /// The address it is actually bound to.
    ///
    /// Read back from the socket rather than remembered, so that a bind to
    /// port 0 — which the tests use — reports the port the kernel chose.
    pub address: SocketAddr,
}

/// Why binding produced nothing usable.
#[derive(Debug)]
pub struct NothingBound {
    /// What each address said, in the order they were tried.
    pub failures: Vec<(SocketAddr, io::Error)>,
}

impl core::fmt::Display for NothingBound {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("no address could be bound:")?;
        for (address, error) in &self.failures {
            write!(f, "\n  {address}: {error}")?;
        }
        Ok(())
    }
}

impl core::error::Error for NothingBound {}

/// What binding produced: the listeners that came up, and what the rest said.
///
/// A named type rather than a bare tuple, because "the successes and the
/// failures" is the shape the whole module is about (`NET-001`, #150) and a
/// caller that ignored the second half would report a half-bound server as a
/// fully bound one.
pub type BindOutcome = (Vec<Bound>, Vec<(SocketAddr, io::Error)>);

/// Bind every address this build listens on.
///
/// Returns whatever bound, plus what the rest said. Only binding *nothing* is
/// an error.
///
/// # Errors
///
/// Returns [`NothingBound`] if no address could be bound, carrying every
/// underlying error — a start-up failure that names one of two addresses is a
/// start-up failure nobody can diagnose.
pub fn bind_all() -> Result<BindOutcome, NothingBound> {
    bind_each(bind_addresses())
}

/// Bind a specific set of addresses.
///
/// # Errors
///
/// Returns [`NothingBound`] if none could be bound.
pub fn bind_each(addresses: &[SocketAddr]) -> Result<BindOutcome, NothingBound> {
    let mut bound = Vec::new();
    let mut failures = Vec::new();

    for address in addresses {
        match bind_one(*address) {
            Ok(entry) => bound.push(entry),
            // `NET-001` (#150): a missing stack is a fact about the host, not
            // an error. This is the stack-existence probe — attempting the bind
            // *is* the probe, which is more reliable than asking the OS whether
            // it has a stack and then racing with the answer.
            Err(error) => failures.push((*address, error)),
        }
    }

    if bound.is_empty() {
        return Err(NothingBound { failures });
    }
    Ok((bound, failures))
}

/// Bind one address.
pub(crate) fn bind_one(address: SocketAddr) -> io::Result<Bound> {
    let domain = if address.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // `NET-009` (#159): `SO_REUSEADDR` on Unix lets a restart rebind a port
    // still in `TIME_WAIT`. On Windows the same name lets an unrelated process
    // *steal* a bound port, so it is not set there — the Windows default
    // already means what Unix's `SO_REUSEADDR` means. They are opposites, which
    // vlmcsd's own diagnostic text confuses.
    //
    // Note what `cfg(unix)` does on the third platform: Hermit is not
    // `target_family = "unix"`, so this is skipped there. That happens to be
    // right — Hermit's `setsockopt` is a stub and `SO_REUSEADDR` is a silent
    // no-op — but it is right by luck, not by intent. `cfg(unix)` silently
    // taking the non-Unix branch on Hermit is the trap `docs/research-findings.md`
    // §R2 names, so every use of it in this crate is worth a note saying which
    // branch Hermit lands in and whether that was the intended one.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;

    // `NET-001` (#150): make the two sockets genuinely independent, so what is
    // bound is what was asked for rather than whatever `net.ipv6.bindv6only`
    // happens to say.
    //
    // Unreachable on Hermit, and that is now by construction rather than by
    // accident: `KMS_BIND_ADDRESSES` has no IPv6 entry there (`OS-009`, #260).
    // Hermit's `setsockopt` is a stub that returns `EINVAL` for this option, so
    // before that change the single-socket outcome came out of *this* `?` — an
    // error path that also told the operator IPv6 was unavailable rather than
    // that it does not exist on the target.
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    socket.bind(&SockAddr::from(address))?;
    // `NET-003` (#152): a backlog sized to the worker pool. vlmcsd hardcodes
    // `SOMAXCONN` — 4096 on modern Linux — which is far deeper than a bounded
    // pool can drain, turning a connection flood from a fast refusal into a
    // slow one.
    socket.listen(BACKLOG)?;

    let listener = TcpListener::from(socket);
    let actual = listener.local_addr()?;
    Ok(Bound {
        listener,
        address: actual,
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

    use super::{bind_each, bind_one};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn ephemeral(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 0)
    }

    #[test]
    fn binding_reports_the_port_the_kernel_chose() {
        let bound = bind_one(ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        assert_ne!(bound.address.port(), 0, "the real port is read back");
        assert!(bound.address.is_ipv4());
    }

    /// `NET-001` (#150): one stack failing must not stop the other. The test
    /// pairs a bindable address with an unbindable one and asserts the server
    /// still comes up.
    #[test]
    fn one_address_failing_does_not_stop_the_others() {
        // 203.0.113.1 is TEST-NET-3 and is not assigned to this host, so
        // binding it fails everywhere without needing privileges.
        let unbindable = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 0);
        let bindable = ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST));

        let (bound, failures) = bind_each(&[unbindable, bindable]).unwrap();
        assert_eq!(bound.len(), 1, "the good one bound");
        assert_eq!(
            failures.len(),
            1,
            "and the bad one was reported, not hidden"
        );
        assert_eq!(failures[0].0, unbindable);
    }

    /// Binding nothing is the one fatal case, and the error names every
    /// address that failed rather than just the first.
    #[test]
    fn binding_nothing_is_an_error_that_names_everything() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 0);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 0);
        let failure = bind_each(&[a, b]).unwrap_err();
        assert_eq!(failure.failures.len(), 2);

        let text = failure.to_string();
        assert!(text.contains("203.0.113.1"), "{text}");
        assert!(text.contains("203.0.113.2"), "{text}");
    }

    /// Both stacks bind on a host that has both. Skipped rather than failed
    /// where IPv6 is unavailable, since that is a property of the machine.
    #[test]
    fn both_loopback_stacks_bind_when_present() {
        let (bound, _) = bind_each(&[
            ephemeral(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ])
        .unwrap();
        assert!(!bound.is_empty());
        assert!(
            bound.iter().any(|entry| entry.address.is_ipv4()),
            "IPv4 loopback must always be available"
        );
    }

    /// `NET-009` (#159): a restart must not be blocked by `TIME_WAIT`. On Unix
    /// `std::net` sets `SO_REUSEADDR`, which is what makes rebinding the same
    /// port work; this checks the behaviour rather than the option.
    ///
    /// `cfg(unix)` is false on Hermit (`ARCH-015`, #15), so this does not
    /// compile there — which is the intended branch, twice over: the option is
    /// a silent no-op on that target (`OS-010`, #261), and a unikernel guest
    /// has no restart to rebind through in the first place.
    #[cfg(unix)]
    #[test]
    fn a_port_can_be_rebound_after_its_listener_is_dropped() {
        let first = bind_one(ephemeral(IpAddr::V4(Ipv4Addr::LOCALHOST))).unwrap();
        let port = first.address.port();
        drop(first);

        let again = bind_one(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        assert!(again.is_ok(), "rebinding {port} failed: {:?}", again.err());
    }
}
