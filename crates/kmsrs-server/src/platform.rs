//! What differs per target, named once (`OS-009`, #260; `OS-010`, #261;
//! `OS-015`, #298; `OS-007`, #258).
//!
//! One `mio` event loop runs on Linux, Windows and Hermit, so I/O plumbing is
//! no longer a platform difference. What is left is **socket semantics** and
//! the handful of operating-system services Hermit simply does not have, and
//! those are facts rather than abstractions — no readiness layer models "this
//! platform's `setsockopt` is a stub" or "this platform has no signals".
//!
//! # Why constants and not `cfg` on the item
//!
//! A `#[cfg(target_os = "hermit")]` item is only ever *compiled* on Hermit,
//! which is precisely the target this test suite cannot run on. A `const bool`
//! read by an ordinary `if` compiles both branches everywhere, so the branch
//! this host does not take is still type-checked, still linted, and — because
//! the data it selects is `pub` — still assertable by a test running on Linux.
//!
//! The one place that is not possible is [`install_shutdown_handler`], because
//! the `ctrlc` crate does not build for Hermit at all: it selects its
//! implementation with `#[cfg(unix)]` and `#[cfg(windows)]`, and Hermit is
//! neither, so the module simply does not exist there. That is a *dependency*
//! that is absent, not a branch that is wrong, and no runtime `bool` can paper
//! over a crate that will not compile. Everything testable about it is stated
//! in [`SIGNALS_EXIST`] instead.
//!
//! # The audit
//!
//! [`SOCKET_OPTIONS`] is the `OS-010` (#261) audit in executable form: every
//! socket option this program sets, what Hermit does with it, and whether
//! anything here depends on the answer. `tests/platform_invariants.rs` fails if
//! a new `set_*` call appears in `net/` without a row here, which is what stops
//! the audit becoming a comment that used to be true.

/// Whether this target must bind exactly one socket (`OS-009`, #260).
///
/// True on Hermit, for two reasons taken from the kernel source rather than
/// inferred:
///
/// * `bind()` records the address and then ignores it — `listen()` passes only
///   the *port* to smoltcp. One `0.0.0.0` socket therefore already accepts on
///   every local address, and two sockets on one port race with **no defined
///   dispatch**: which one receives a connection is unspecified.
/// * Hermit never gets an IPv6 address at all. smoltcp has v6 compiled in, but
///   the kernel only ever assigns IPv4 and speaks DHCPv4 only — no SLAAC, no
///   RA, no DHCPv6.
pub const SINGLE_SOCKET_ONLY: bool = cfg!(target_os = "hermit");

/// Whether this target delivers signals at all (`OS-015`, #298).
///
/// False on Hermit. `docs/research-findings.md` §R2: *"No signals. Shutdown is
/// normal control flow."* There is no `kill(2)`, no console control handler and
/// nothing that could raise one — a Hermit guest stops when the hypervisor
/// stops it.
///
/// Before this existed, `main` installed a `ctrlc` handler unconditionally and
/// the doc comment asserted it worked everywhere. It could not: `ctrlc` does not
/// compile for Hermit. Naming the fact makes the absence deliberate rather than
/// a build failure discovered by whoever first tries the target.
pub const SIGNALS_EXIST: bool = !cfg!(target_os = "hermit");

/// Whether `setsockopt` on this target does what it says (`OS-010`, #261).
///
/// False on Hermit, where it is a stub: only `TCP_NODELAY` is honoured,
/// `SO_REUSEADDR` is a **silent no-op**, and `SO_RCVTIMEO`, `SO_SNDTIMEO`,
/// `IPV6_V6ONLY`, `SO_KEEPALIVE` and `SO_LINGER` all return `EINVAL`.
///
/// This is the worst failure shape there is — the calls succeed on the two
/// platforms anybody develops on and fail only on the one nobody can attach a
/// debugger to — which is why [`SOCKET_OPTIONS`] enumerates every use rather
/// than trusting that none of them matters.
pub const SETSOCKOPT_IS_A_STUB: bool = cfg!(target_os = "hermit");

/// Whether this target's wall clock is trustworthy (`OS-007`, #258).
///
/// False on Hermit. Its monotonic clock is solid — TSC and APIC, microsecond
/// resolution — but `SystemTime` is one CMOS RTC read at boot plus local ticks:
/// one-second granularity, no pvclock, no NTP, no slew, and it drifts. A
/// live-migrated guest keeps ticking from wherever it was.
///
/// It does not matter, and that is by construction rather than by luck. The
/// wall clock is read exactly once, in `main`, to bound the randomised
/// activation date inside the ePID (`ID-007`, #112); every deadline in the
/// driver is measured against the injected monotonic clock (`ARCH-004`, #4),
/// and the v6 response key derives from the *client's* timestamp rather than
/// from ours (`CRY-007`, #46). `platform_invariants.rs` is what keeps that
/// true: it fails if a second wall-clock read appears anywhere in a shipped
/// crate.
pub const WALL_CLOCK_IS_TRUSTWORTHY: bool = !cfg!(target_os = "hermit");

/// What Hermit does with a socket option (`OS-010`, #261).
///
/// Taken from `hermit-os/kernel`'s `setsockopt` rather than from its
/// documentation, which does not mention the restriction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HermitBehaviour {
    /// Honoured, and means what it means everywhere else.
    Honoured,

    /// Accepted and discarded. The call returns success and nothing happens —
    /// the failure mode that cannot be detected by checking a return value.
    SilentNoOp,

    /// Returns `EINVAL`. Loud, and therefore the easy case.
    Rejected,

    /// Not reached on Hermit at all, because [`SINGLE_SOCKET_ONLY`] removes the
    /// socket that would have been given it.
    Unreachable,
}

/// One socket option, and what depending on it would cost on Hermit.
///
/// The `OS-010` (#261) audit. Every option Hermit's stub `setsockopt`
/// mishandles has a row, whether or not this program sets it — an audit that
/// listed only current uses would say nothing about the next one somebody adds.
#[derive(Debug, Clone, Copy)]
pub struct SocketOptionUse {
    /// The option's conventional name.
    pub option: &'static str,

    /// The `socket2` or `std` setter, spelled exactly as it appears in source,
    /// or `None` if the server does not set this option.
    ///
    /// The invariant test greps `net/` for these, so it is a key rather than
    /// prose: a `set_*` call with no row here fails the build.
    pub setter: Option<&'static str>,

    /// Why it is set, or why it is not.
    pub reason: &'static str,

    /// What Hermit does with it.
    pub hermit: HermitBehaviour,

    /// Whether correct operation on Hermit depends on it taking effect.
    ///
    /// Every row must be `false`. That is the whole content of `OS-010`: no
    /// socket option may be load-bearing on the one target where `setsockopt`
    /// does not work.
    pub load_bearing_on_hermit: bool,
}

/// Every socket option Hermit's stub `setsockopt` mishandles, audited
/// (`OS-010`, #261).
///
/// The server sets two of the seven, and neither matters on Hermit. The two
/// that used to matter — a read timeout via `SO_RCVTIMEO`, and `IPV6_V6ONLY`
/// deciding the socket count by way of its own error path — are gone:
/// deadlines are poll timeouts computed from the injected clock
/// (`OS-014`, #297), and the socket count is [`SINGLE_SOCKET_ONLY`] rather
/// than the residue of a failed `setsockopt` (`OS-009`, #260).
pub const SOCKET_OPTIONS: &[SocketOptionUse] = &[
    SocketOptionUse {
        option: "SO_REUSEADDR",
        setter: Some("set_reuse_address"),
        reason: "let a restart rebind a port still held in TIME_WAIT \
                 (NET-009, #159)",
        // `cfg(unix)` is false on Hermit, so the call is not compiled there at
        // all. Were it compiled it would be a silent no-op, which is why the
        // row records the behaviour rather than only the omission.
        hermit: HermitBehaviour::SilentNoOp,
        // A rebind that fails means a restart waits out TIME_WAIT. On Hermit
        // there is no restart to wait for: the guest *is* the process, and a
        // new one boots with a fresh network stack.
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "IPV6_V6ONLY",
        setter: Some("set_only_v6"),
        reason: "make the two wildcard sockets genuinely independent instead \
                 of leaving it to net.ipv6.bindv6only (NET-001, #150)",
        hermit: HermitBehaviour::Unreachable,
        // Only ever called for an IPv6 address, and Hermit's bind list has
        // none (`OS-009`, #260).
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "TCP_NODELAY",
        setter: None,
        reason: "left at the OS default until measured (NET-015, #164); the \
                 exchange is one request, one response and a single write of \
                 at most 384 bytes, so Nagle has nothing to coalesce",
        hermit: HermitBehaviour::Honoured,
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "SO_RCVTIMEO",
        setter: None,
        reason: "a deadline is the poll timeout, computed from the injected \
                 clock, so it behaves identically on every target \
                 (NET-004, #153; OS-014, #297)",
        hermit: HermitBehaviour::Rejected,
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "SO_SNDTIMEO",
        setter: None,
        reason: "same as SO_RCVTIMEO; a peer that has stopped reading is \
                 bounded by MAX_OUTBOUND and the connection deadline, not by \
                 a socket timeout",
        hermit: HermitBehaviour::Rejected,
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "SO_KEEPALIVE",
        setter: None,
        reason: "a KMS conversation is seconds long and already has a total \
                 deadline; keepalive probes measured in hours cannot bound it",
        hermit: HermitBehaviour::Rejected,
        load_bearing_on_hermit: false,
    },
    SocketOptionUse {
        option: "SO_LINGER",
        setter: None,
        reason: "responses are written before close and the default graceful \
                 close is what a genuine host does; a lingering close would \
                 be a timing difference for nothing",
        hermit: HermitBehaviour::Rejected,
        load_bearing_on_hermit: false,
    },
];

/// Whether a shutdown signal handler was installed (`OS-015`, #298).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalHandling {
    /// A handler is installed and will run on SIGINT, SIGTERM or a Windows
    /// console control event.
    Installed,

    /// This target has no signals, so there was nothing to install
    /// ([`SIGNALS_EXIST`]).
    ///
    /// Not an error. A Hermit guest is stopped by its hypervisor, and the
    /// drain path is reached through [`crate::net::driver::ShutdownHandle`]
    /// rather than through a handler.
    Unsupported,
}

/// A signal handler that could not be installed on a target that has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalError(String);

impl core::fmt::Display for SignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for SignalError {}

/// Ask the operating system to run `handler` when it is told to stop
/// (`NET-007`, #157; `OS-015`, #298).
///
/// SIGINT and SIGTERM on Unix, `SetConsoleCtrlHandler` on Windows, and nothing
/// at all on Hermit — where the answer is [`SignalHandling::Unsupported`]
/// rather than an error, because a target with no signals has not failed to
/// deliver one.
///
/// # Errors
///
/// Returns [`SignalError`] if the target has signals and the handler could not
/// be installed. A caller should carry on serving: a host that cannot be
/// stopped politely is still a host that activates.
pub fn install_shutdown_handler<F>(handler: F) -> Result<SignalHandling, SignalError>
where
    F: FnMut() + Send + 'static,
{
    #[cfg(target_os = "hermit")]
    {
        // Hermit has no signals, so there is no handler to install and nothing
        // that could ever call this one. Dropped explicitly rather than left
        // unused, so the parameter is visibly consumed on every target.
        drop(handler);
        Ok(SignalHandling::Unsupported)
    }

    #[cfg(not(target_os = "hermit"))]
    {
        ctrlc::set_handler(handler).map_err(|error| SignalError(error.to_string()))?;
        Ok(SignalHandling::Installed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        HermitBehaviour, SETSOCKOPT_IS_A_STUB, SIGNALS_EXIST, SINGLE_SOCKET_ONLY, SOCKET_OPTIONS,
        SignalHandling, WALL_CLOCK_IS_TRUSTWORTHY, install_shutdown_handler,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Every capability here says the same thing about which target this is, so
    /// a new one added with the wrong polarity is visible immediately.
    #[test]
    fn every_capability_agrees_about_the_target() {
        let hermit = cfg!(target_os = "hermit");
        assert_eq!(SINGLE_SOCKET_ONLY, hermit);
        assert_eq!(SETSOCKOPT_IS_A_STUB, hermit);
        assert_eq!(SIGNALS_EXIST, !hermit);
        assert_eq!(WALL_CLOCK_IS_TRUSTWORTHY, !hermit);
    }

    /// `OS-010` (#261): the audit's entire content. No socket option may be
    /// load-bearing on the target whose `setsockopt` does not work.
    #[test]
    fn no_socket_option_is_load_bearing_on_hermit() {
        assert!(
            !SOCKET_OPTIONS.is_empty(),
            "an empty audit would pass vacuously and prove nothing"
        );
        for use_ in SOCKET_OPTIONS {
            assert!(
                !use_.load_bearing_on_hermit,
                "{} ({:?}) is load-bearing on a target where setsockopt is a stub",
                use_.option, use_.setter
            );
        }
    }

    /// A row whose behaviour is `Honoured` must be one Hermit actually honours.
    /// Only `TCP_NODELAY` is, so this catches a row added with an optimistic
    /// guess in it.
    #[test]
    fn only_tcp_nodelay_is_recorded_as_honoured() {
        for use_ in SOCKET_OPTIONS {
            if use_.hermit == HermitBehaviour::Honoured {
                assert_eq!(
                    use_.option, "TCP_NODELAY",
                    "Hermit honours exactly one socket option, and it is not {}",
                    use_.option
                );
            }
        }
    }

    /// The audit covers every option `docs/research-findings.md` §R2 names as
    /// mishandled, not only the ones currently set. An audit narrowed to
    /// current uses says nothing about the next one somebody adds.
    #[test]
    fn the_audit_covers_every_option_hermit_mishandles() {
        for option in [
            "SO_REUSEADDR",
            "IPV6_V6ONLY",
            "TCP_NODELAY",
            "SO_RCVTIMEO",
            "SO_SNDTIMEO",
            "SO_KEEPALIVE",
            "SO_LINGER",
        ] {
            assert!(
                SOCKET_OPTIONS.iter().any(|use_| use_.option == option),
                "{option} is not in the OS-010 audit"
            );
        }
    }

    /// Each option appears once. A duplicated row would let one copy say
    /// `load_bearing_on_hermit = false` while the real use elsewhere is not.
    #[test]
    fn the_audit_has_no_duplicate_rows() {
        let mut seen: Vec<&str> = SOCKET_OPTIONS.iter().map(|use_| use_.option).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "an option is audited twice");
    }

    /// `OS-015` (#298): what is installed matches what the target has.
    ///
    /// The handler itself is never invoked here — this asserts the contract,
    /// which is that a target without signals reports `Unsupported` rather than
    /// an error, and a target with them reports `Installed`.
    #[test]
    fn signal_handling_matches_the_target() {
        static FIRED: AtomicBool = AtomicBool::new(false);
        let outcome = install_shutdown_handler(|| FIRED.store(true, Ordering::Release));

        if SIGNALS_EXIST {
            assert_eq!(outcome, Ok(SignalHandling::Installed));
        } else {
            assert_eq!(
                outcome,
                Ok(SignalHandling::Unsupported),
                "a target with no signals must report that, not fail"
            );
        }
        assert!(
            !FIRED.load(Ordering::Acquire),
            "installing a handler must not run it"
        );
    }
}
