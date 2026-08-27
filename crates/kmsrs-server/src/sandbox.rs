//! Taking away what this process will never need again (`SEC-005`, #197).
//!
//! # What this is, and what it is not
//!
//! Everything here happens **after the listeners are bound and before the first
//! connection is accepted**. That ordering is the whole design: binding a port
//! is the last thing this program does that a sandbox would have to permit, so
//! after it there is nothing left to give up. A process that has dropped a
//! capability cannot be talked into using it, which is a different and stronger
//! statement than "the code does not call that".
//!
//! It is **not** a privilege drop. There is never a privilege to drop — 1688 is
//! unprivileged and this program is not meant to start as root (declined item
//! D41). It is not a container, a namespace, or a launcher. Everything is
//! applied by the process to itself, which is what makes it work in a scratch
//! container, under systemd, and on a bare-metal boot without anything
//! arranging it.
//!
//! # The Linux measures
//!
//! | | what it stops | shipping? |
//! |---|---|---|
//! | **Landlock**, empty ruleset | opening any path, and opening any socket | yes |
//! | **`no_new_privs`** | a `setuid` binary gaining privileges through an `exec` | yes |
//! | **seccomp** allowlist | every syscall this program does not make | yes — `SEC-018` (#355) |
//!
//! The third shipped last, and it shipped **measured** rather than reasoned.
//! The first two are verifiable in a way a syscall filter is not: Landlock
//! either denies a path or it does not, and `tests/sandbox.rs` checks exactly
//! that in a real sandboxed subprocess. An allowlist is a claim about every
//! syscall this process will ever make across every libc, allocator and kernel
//! it ships to, and the cost of getting it wrong is the process being killed on
//! something nobody predicted, in production. So `SEC-005` (#197) deliberately
//! left it out, `SEC-018` (#355) filled it in, and what filled it in was
//! `harness/linux/syscall-survey.sh` — `strace` over a server driven through
//! every path #355 names, on both libc targets, with what those runs measured
//! checked in under `harness/linux/surveys/`.
//!
//! The two surveys are the argument for the shape of the list on their own.
//! The same program, the same requests, the same kernel: glibc calls
//! `epoll_wait` and musl calls `epoll_pwait`, and no line of this workspace
//! chooses either. So the measurement is a floor and the list is written a
//! family at a time above it — a test asserts the floor is covered, and
//! `tests/sandbox.rs` serves real activations through the real filter, which
//! is what would catch a family that was drawn too small.
//!
//! Landlock is the one worth arguing for, because `no-file-access` already
//! proves that no shipped crate *calls* `open`. The difference is what happens
//! when something else does: a dependency, a panic handler writing a core file,
//! a future change nobody reviewed against axiom A5. The invariant test is a
//! statement about the source; Landlock is a statement about the process.
//!
//! # Why the bare-metal target is deliberately not sandboxed
//!
//! On the `OS-017` (#333) target this process **is** the userland. It mounts
//! `devtmpfs`, `/proc` and `/sys`; it speaks netlink to configure an interface;
//! it steps `CLOCK_REALTIME` over SNTP; it reaps orphans; and it calls
//! `reboot(2)` to power the machine off. A filter that permitted all of that
//! would permit most of what a filter is for, and one that did not would kill
//! pid 1 — which is a kernel panic, not a failed request.
//!
//! The value is also much lower there. A sandbox limits what a *compromised
//! process* can reach, and on a machine whose entire userland is this one
//! process there is nothing else to reach. The isolation that matters on that
//! target is the hypervisor's, and `docs/deployment.md` argues it.
//!
//! So [`Sandbox::apply`] is called from the hosted entry point and not from
//! `serve_with`, and `the_bare_metal_target_is_not_sandboxed` asserts that
//! rather than leaving it to be inferred.
//!
//! # Windows gets less, and says so
//!
//! Windows has **no self-applicable filesystem sandbox**. AppContainer and
//! restricted tokens are launch-time constructs: they are properties a parent
//! gives a child, so using them would mean shipping a launcher process whose
//! only job is to start the real one. That is a bigger change to what is
//! deployed than the mitigation is worth, and `PKG-008` (#245) deliberately has
//! no installer for the same reason.
//!
//! What *is* self-applicable is a set of process mitigation policies, and
//! `SEC-019` (#356) applies five of them. Doing so required reopening the
//! workspace's unsafe boundary, because every route to
//! `SetProcessMitigationPolicy` is raw FFI and no safe wrapper exists on any
//! crate. That was a decision taken in review rather than a gap filled in
//! passing; the argument is in `docs/decisions.md`, and the boundary is one
//! call in the Windows `platform` module below.
//!
//! The result is that a Windows host is still genuinely less confined than a
//! Linux one — it has no filesystem sandbox at all — and [`Report`] says so in
//! as many words rather than reporting "hardened" on both.

/// Whether this target has a sandbox to apply at all (`SEC-005`, #197).
///
/// A `const bool` rather than a `cfg` on an item, so both branches of every
/// caller compile and are tested on every platform — the rule the whole
/// `platform.rs` module exists to keep. The two Linux-only *crates* are gated
/// in the manifest, because a crate that does not build cannot be selected
/// around by a runtime value; nothing else here is.
pub const SANDBOX_IS_AVAILABLE: bool = cfg!(any(target_os = "linux", windows));

/// Whether this target can deny itself the filesystem.
///
/// Linux only, and the asymmetry is the honest part of `SEC-005` (#197):
/// Windows has no equivalent a process can apply to itself. See the module
/// documentation.
pub const FILESYSTEM_CAN_BE_DENIED: bool = cfg!(target_os = "linux");

/// Whether this target can restrict which syscalls it may make.
///
/// Linux, **and an architecture somebody has surveyed** (`SEC-018`, #355). A
/// seccomp filter is written in syscall numbers, the numbers differ per
/// architecture, and the list of which ones this process makes was measured on
/// the two architectures this program ships to (`PKG-004`, #241) rather than
/// derived. A third Linux architecture would compile — `libc` has its numbers
/// — and nobody would have watched it serve a request under the filter, which
/// is the one thing #355 says a syscall allowlist may not be built without. So
/// it reports [`Applied::NotOnThisTarget`] there rather than shipping a guess.
pub const SYSCALLS_CAN_BE_RESTRICTED: bool = cfg!(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
));

/// One measure, and how it went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Applied. The process no longer has this capability.
    Yes,
    /// Not attempted, because this target has no such thing.
    ///
    /// Distinct from [`Applied::Failed`] on purpose: "Windows has no Landlock"
    /// and "Landlock is here and refused" are different facts, and reporting
    /// both as "not applied" would hide the second.
    NotOnThisTarget,
    /// Attempted and refused by the kernel.
    ///
    /// Usually an older kernel without the feature. **Not fatal**: a host that
    /// refused to activate anything because it could not sandbox itself would
    /// be trading its entire function for a hardening measure, which is the
    /// same shape of mistake as [D35] and as `POL-011`'s clock-skew tolerance.
    ///
    /// [D35]: https://github.com/schlarpc/kmsrsos/blob/main/docs/decisions.md
    Failed,
    /// Attempted, and refused in part: these named components did not take.
    ///
    /// The composite case of [`Applied::Failed`], for a measure that is
    /// several independently-applicable pieces rather than one — Windows'
    /// five process mitigation policies are the only such measure today. The
    /// distinction is the same one [`Applied::NotOnThisTarget`] draws one
    /// level up: "some of this measure was refused" is not a fact until it
    /// says *which*, because `ProcessSystemCallDisablePolicy` being refused
    /// and `ProcessStrictHandleCheckPolicy` being refused are materially
    /// different security postures (`SEC-020`, #392).
    FailedInPart(Refusals),
}

impl Applied {
    /// How this reads in a log line.
    #[must_use]
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Yes => "applied",
            Self::NotOnThisTarget => "not available on this target",
            Self::Failed | Self::FailedInPart(_) => "refused by the kernel",
        }
    }
}

/// How this reads in a log line, refusals named (`SEC-020`, #392).
///
/// [`Applied::as_text`] is the verdict alone and stays `&'static str` because
/// most callers want only that. This is the verdict plus, for
/// [`Applied::FailedInPart`], the components that were refused — which is what
/// the start-up report prints, because an operator who learns only that a
/// mitigation was refused has learnt almost nothing.
impl core::fmt::Display for Applied {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_text())?;
        if let Self::FailedInPart(refusals) = self {
            write!(formatter, " ({refusals})")?;
        }
        Ok(())
    }
}

/// Which components of a composite measure the kernel refused (`SEC-020`,
/// #392).
///
/// A fixed name table and a bitmask over it, which is what lets [`Report`]
/// carry an attributed refusal and stay `Copy` and platform-independent: no
/// allocation, no lifetime, and nothing Windows-shaped for the Linux and
/// bare-metal reports to leave empty. The table is a `const` in the platform
/// module that owns the measure, so the names in the log line are the same
/// names the code applies, in the same order.
///
/// Bits above `names.len()` are ignored rather than being a way to name a
/// component that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusals {
    /// Every component of the measure, in the order it is applied.
    names: &'static [&'static str],
    /// Bit *n* set means `names[n]` was refused.
    mask: u32,
}

impl Refusals {
    /// The most components a measure may have.
    ///
    /// The width of the mask. Asserted at the point of construction rather
    /// than left to truncate silently, because a sixth policy added to a
    /// 32-entry table is a thing that would work and a thirty-third is not.
    pub const MAX_COMPONENTS: usize = u32::BITS as usize;

    /// Attribute a refusal to components of `names`.
    ///
    /// # Panics
    ///
    /// If `names` is longer than [`Refusals::MAX_COMPONENTS`]. That is a
    /// programming error in the platform module's table, not a runtime
    /// condition, and every caller's table is a `const`.
    #[must_use]
    pub const fn new(names: &'static [&'static str], mask: u32) -> Self {
        assert!(
            names.len() <= Self::MAX_COMPONENTS,
            "a measure has more components than the refusal mask has bits"
        );
        Self { names, mask }
    }

    /// Nothing refused.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.mask == 0
    }

    /// The refused components, in the order they are applied.
    pub fn iter(self) -> impl Iterator<Item = &'static str> {
        self.names
            .iter()
            .enumerate()
            .filter(move |&(index, _)| {
                u32::try_from(index).is_ok_and(|bit| self.mask & (1 << bit) != 0)
            })
            .map(|(_, name)| *name)
    }
}

/// The refused components, comma-separated, for the start-up report.
impl core::fmt::Display for Refusals {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (position, name) in self.iter().enumerate() {
            if position > 0 {
                formatter.write_str(", ")?;
            }
            formatter.write_str(name)?;
        }
        Ok(())
    }
}

/// What the sandbox managed to do.
///
/// Returned rather than logged from inside, so the caller owns the message and
/// the tests can assert on the outcome without capturing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Filesystem access denied outright.
    pub filesystem: Applied,
    /// `no_new_privs`, so an `exec` cannot gain privileges.
    pub no_new_privileges: Applied,
    /// Syscalls restricted to the ones this program makes.
    pub syscalls: Applied,
    /// Windows process mitigation policies.
    pub process_mitigations: Applied,
}

impl Report {
    /// Nothing attempted. The starting value, and what an unsandboxed target
    /// reports.
    pub const NOTHING: Self = Self {
        filesystem: Applied::NotOnThisTarget,
        no_new_privileges: Applied::NotOnThisTarget,
        syscalls: Applied::NotOnThisTarget,
        process_mitigations: Applied::NotOnThisTarget,
    };

    /// Whether every measure this target has was applied.
    ///
    /// A target with no measures is vacuously complete, which is why this is
    /// not the same question as "is this process sandboxed".
    #[must_use]
    pub fn complete(&self) -> bool {
        self.each()
            .iter()
            .all(|(_, applied)| matches!(applied, Applied::Yes | Applied::NotOnThisTarget))
    }

    /// Whether anything was actually given up.
    #[must_use]
    pub fn anything_applied(&self) -> bool {
        self.each()
            .iter()
            .any(|(_, applied)| matches!(applied, Applied::Yes))
    }

    /// Each measure and its name, for logging and for tests.
    #[must_use]
    pub const fn each(&self) -> [(&'static str, Applied); 4] {
        [
            ("filesystem", self.filesystem),
            ("no-new-privileges", self.no_new_privileges),
            ("syscalls", self.syscalls),
            ("process-mitigations", self.process_mitigations),
        ]
    }
}

/// Apply everything this target has, after binding (`SEC-005`, #197).
///
/// Never fails. Every measure that cannot be applied is recorded in the
/// [`Report`] and the process carries on serving — see [`Applied::Failed`] for
/// why that is the right answer rather than a refusal to start.
#[must_use]
pub fn apply() -> Report {
    platform::apply()
}

/// Whether the syscall filter permits `name` (`SEC-018`, #355).
///
/// Exposed for `tests/sandbox.rs`, which reads the checked-in surveys under
/// `harness/linux/surveys/` and asserts that every syscall the shipped binary
/// was *observed* making is one the filter allows. That comparison has to
/// happen somewhere, and the alternative — a second copy of the list in the
/// test — is a second thing to forget.
///
/// A name the filter does not know is `false` rather than an error: the
/// question this answers is "would this be permitted", and on a target with no
/// filter nothing is refused, so everything is.
#[must_use]
pub fn names_a_permitted_syscall(name: &str) -> bool {
    platform::names_a_permitted_syscall(name)
}

#[cfg(target_os = "linux")]
mod platform {
    //! Landlock, `no_new_privs` and seccomp (`SEC-005`, #197).

    use super::{Applied, Refusals, Report};

    /// Apply the Linux measures, in the order that makes each one safe.
    ///
    /// **`no_new_privs` first, then Landlock, then seccomp**, and the order is
    /// load-bearing rather than stylistic:
    ///
    /// * Landlock *requires* `no_new_privs` — the kernel refuses
    ///   `landlock_restrict_self` without it, because a sandbox an `exec` could
    ///   escape is not one.
    /// * seccomp goes last because the filter must permit the syscalls the two
    ///   before it make. Applying it first would make the rest of this function
    ///   the first thing it killed.
    pub(super) fn apply() -> Report {
        let no_new_privileges = match rustix::thread::set_no_new_privs(true) {
            Ok(()) => Applied::Yes,
            Err(_) => Applied::Failed,
        };

        // Landlock is not attempted without `no_new_privs`, because the kernel
        // would refuse it anyway and "refused" would then be a misleading
        // report — the cause is the line above, not Landlock.
        let filesystem = if no_new_privileges == Applied::Yes {
            deny_the_filesystem()
        } else {
            Applied::Failed
        };

        let syscalls = restrict_syscalls();

        Report {
            filesystem,
            no_new_privileges,
            syscalls,
            process_mitigations: Applied::NotOnThisTarget,
        }
    }

    /// An empty Landlock ruleset: every path denied, and no new socket.
    ///
    /// "Empty" is the whole policy. A ruleset that *handles* a right without
    /// granting it to any path denies that right everywhere, so there is no
    /// allowlist to get wrong and no path to maintain — which is only possible
    /// because axiom A5 means this program opens nothing after start-up.
    /// `no_shipped_crate_touches_the_filesystem` is the source-level statement
    /// of that; this is the kernel's.
    ///
    /// # Why the network rights are in here too
    ///
    /// Landlock ABI 4 added `BindTcp` and `ConnectTcp`, and this process needs
    /// neither once it is running: the listeners are already bound, and a KMS
    /// host never makes an outgoing connection — `NET-001` (#150) is the rule
    /// that it does not even read its own address. Handling both and granting
    /// neither means a compromised request path cannot open a socket to
    /// anywhere, which is a larger restriction than the filesystem one and
    /// costs nothing here.
    ///
    /// # What is deliberately still permitted
    ///
    /// Handles already open. Landlock governs *opening*, so stderr, the
    /// listening sockets and every accepted connection are unaffected — which
    /// is precisely why this is applied after binding rather than before.
    ///
    /// # The ABI, and why it is the highest rather than the oldest
    ///
    /// Naming `ABI::V1` would handle only the rights that existed in Linux
    /// 5.13, leaving everything added since — `Truncate` in ABI 3, `IoctlDev`
    /// in ABI 5 — *unhandled*, which in Landlock means allowed. So the newest
    /// ABI this crate knows is named, and the default best-effort compatibility
    /// silently drops whatever the running kernel does not have. That is the
    /// right way round: a new kernel denies more, an old one denies what it
    /// can, and neither refuses to start.
    fn deny_the_filesystem() -> Applied {
        use landlock::{
            ABI, Access, AccessFs, AccessNet, Ruleset, RulesetAttr as _, RulesetStatus,
        };

        // The greatest ABI this crate version knows about. Best-effort
        // compatibility is the default, so an older kernel degrades instead of
        // failing.
        let abi = ABI::V9;

        let outcome = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|ruleset| ruleset.handle_access(AccessNet::from_all(abi)))
            .and_then(landlock::Ruleset::create)
            .and_then(landlock::RulesetCreated::restrict_self);

        match outcome {
            // `FullyEnforced` is the answer wanted. `PartiallyEnforced` means
            // an older kernel enforced the rights it has, which is still worth
            // having and is what best-effort is for. `NotEnforced` means
            // Landlock is not compiled in at all.
            Ok(status) => match status.ruleset {
                RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => Applied::Yes,
                RulesetStatus::NotEnforced => Applied::Failed,
            },
            Err(_) => Applied::Failed,
        }
    }

    /// The syscalls this process makes once the sandbox is on, **measured**
    /// (`SEC-018`, #355).
    ///
    /// # Where this list came from
    ///
    /// `harness/linux/syscall-survey.sh`, run against both libc targets, with
    /// the syscall sets those runs produced checked in under
    /// `harness/linux/surveys/`. #355 is explicit that a list written from a
    /// reading of what the code appears to call is not the same as knowing,
    /// and the two surveys prove the point on their own: the same program,
    /// driven through the same requests on the same kernel, calls
    /// `epoll_wait` under glibc and `epoll_pwait` under musl, and glibc alone
    /// reaches for `brk`, `gettid`, `mprotect` and `sched_getaffinity`. Neither
    /// difference is visible in this workspace's source.
    ///
    /// So the surveys are the **floor**, not the list.
    /// `the_allowlist_covers_every_syscall_the_survey_measured` asserts that
    /// floor is covered, and everything above it is here because the whole
    /// family is: a filter that permitted `epoll_wait` and not `epoll_pwait`
    /// would have shipped fine and died the first time it ran on the other
    /// libc, and the same argument applies to `read`/`readv`,
    /// `sendto`/`sendmsg`, `nanosleep`/`clock_nanosleep` and every other pair
    /// where the choice belongs to a library rather than to this program.
    ///
    /// # What is deliberately absent
    ///
    /// `execve` and `execveat`; `ptrace`, `process_vm_readv` and
    /// `process_vm_writev`; `mount`, `pivot_root`, `chroot`, `unshare` and
    /// `setns`; `bpf`, `perf_event_open`, `io_uring_setup`, `userfaultfd`,
    /// `add_key`, `keyctl`, `init_module`, `finit_module` and `kexec_load`; and
    /// every syscall that writes to a filesystem. None of them appears in
    /// either survey, none is reachable from this program's source, and each is
    /// a step in a real escalation chain.
    ///
    /// **`socket` is the one worth naming**, because it is the measure Landlock
    /// cannot take. Landlock ABI 4 governs `bind` and `connect` *for TCP*; it
    /// says nothing about creating a socket, so an `AF_UNIX` or `AF_NETLINK`
    /// socket is outside its reach entirely and inside this filter's. It is in
    /// [`SOFT_DENIED`] rather than simply absent, for the reason given there.
    const ALLOWED: &[(&str, libc::c_long)] = &[
        // --- Descriptors this process already has ---------------------------
        //
        // The listeners, the accepted connections, and stderr. Opening a *new*
        // descriptor is not in here; using one that exists is most of what a
        // server does.
        ("read", libc::SYS_read),
        ("readv", libc::SYS_readv),
        ("pread64", libc::SYS_pread64),
        ("write", libc::SYS_write),
        ("writev", libc::SYS_writev),
        ("pwrite64", libc::SYS_pwrite64),
        ("lseek", libc::SYS_lseek),
        ("close", libc::SYS_close),
        // The socket half of the same thing. `accept4` is how a connection
        // arrives; `shutdown` is how a drain ends one. Every send and receive
        // form is here because which one is used is tokio's and the libc's
        // choice: the surveys show `recvfrom` and `sendto`, and a version bump
        // that moved to `recvmsg` would otherwise be a production kill.
        ("accept4", libc::SYS_accept4),
        ("shutdown", libc::SYS_shutdown),
        ("recvfrom", libc::SYS_recvfrom),
        ("recvmsg", libc::SYS_recvmsg),
        ("recvmmsg", libc::SYS_recvmmsg),
        ("sendto", libc::SYS_sendto),
        ("sendmsg", libc::SYS_sendmsg),
        ("sendmmsg", libc::SYS_sendmmsg),
        ("getsockname", libc::SYS_getsockname),
        ("getpeername", libc::SYS_getpeername),
        ("getsockopt", libc::SYS_getsockopt),
        // `NET-004` (#153) sets options on the sockets it accepts.
        ("setsockopt", libc::SYS_setsockopt),
        // Non-blocking mode, and the `FIONBIO`/`isatty` route to the same
        // question. `ioctl` is the widest thing in this list and it is bounded
        // by the descriptors that exist: two listeners, the connections, and
        // stderr. Nothing here can open another.
        ("fcntl", libc::SYS_fcntl),
        ("ioctl", libc::SYS_ioctl),
        ("dup", libc::SYS_dup),
        ("dup3", libc::SYS_dup3),
        // --- Memory -----------------------------------------------------------
        //
        // The allocator's, not this program's: `brk` appears under glibc and
        // not under musl, `madvise` is how both return pages. `mprotect` is
        // here because the allocator uses it for guard pages; the systemd unit
        // sets `MemoryDenyWriteExecute=yes`, which is where a `PROT_EXEC`
        // mapping is refused, and that is a better place for it than a filter
        // that cannot see the flags without a per-argument rule.
        ("mmap", libc::SYS_mmap),
        ("munmap", libc::SYS_munmap),
        ("mprotect", libc::SYS_mprotect),
        ("mremap", libc::SYS_mremap),
        ("madvise", libc::SYS_madvise),
        ("brk", libc::SYS_brk),
        // --- The event loop ---------------------------------------------------
        //
        // One tokio current-thread runtime (`ARCH-005`/`OS-024`), so this is an
        // `epoll` set and a wakeup descriptor. Every wait form is allowed for
        // the `epoll_wait`/`epoll_pwait` reason above; `poll` and `ppoll` are
        // here because a libc may implement a timed wait either way.
        ("epoll_create1", libc::SYS_epoll_create1),
        ("epoll_ctl", libc::SYS_epoll_ctl),
        ("epoll_pwait", libc::SYS_epoll_pwait),
        ("ppoll", libc::SYS_ppoll),
        ("pselect6", libc::SYS_pselect6),
        ("eventfd2", libc::SYS_eventfd2),
        // Connection deadlines are tokio's (`OS-024`, #340), and tokio drives
        // them off the `epoll` timeout rather than a timer descriptor — but
        // that is an implementation detail of the version in the lockfile, and
        // this is the family it would move within.
        ("timerfd_create", libc::SYS_timerfd_create),
        ("timerfd_settime", libc::SYS_timerfd_settime),
        ("timerfd_gettime", libc::SYS_timerfd_gettime),
        // --- Time -------------------------------------------------------------
        //
        // Absent from both surveys, and allowed anyway. `clock_gettime` is
        // served from the vDSO on every architecture this ships to, so it never
        // reaches the kernel and never reaches this filter — until the day it
        // does, which is what a `vdso=0` boot, a kernel without a vDSO clock
        // for the requested id, or `CLOCK_TAI` all produce. A syscall that is
        // invisible in a trace precisely because it usually is not a syscall is
        // the worst possible thing to leave out.
        ("clock_gettime", libc::SYS_clock_gettime),
        ("clock_getres", libc::SYS_clock_getres),
        ("clock_nanosleep", libc::SYS_clock_nanosleep),
        ("nanosleep", libc::SYS_nanosleep),
        ("gettimeofday", libc::SYS_gettimeofday),
        // --- Synchronisation and scheduling -----------------------------------
        ("futex", libc::SYS_futex),
        ("set_robust_list", libc::SYS_set_robust_list),
        ("get_robust_list", libc::SYS_get_robust_list),
        ("rseq", libc::SYS_rseq),
        ("membarrier", libc::SYS_membarrier),
        ("set_tid_address", libc::SYS_set_tid_address),
        ("sched_yield", libc::SYS_sched_yield),
        ("sched_getaffinity", libc::SYS_sched_getaffinity),
        ("getcpu", libc::SYS_getcpu),
        // --- Signals ----------------------------------------------------------
        //
        // `rt_sigreturn` is not optional: it is how the kernel returns from
        // *any* signal handler, so a filter without it kills the process on the
        // first `SIGTERM` — which is the shutdown path, and would have made
        // every clean stop an abnormal one. `restart_syscall` is the same shape
        // of trap: the kernel injects it when a signal interrupts a restartable
        // call, and nothing in this program ever writes it.
        ("rt_sigreturn", libc::SYS_rt_sigreturn),
        ("rt_sigaction", libc::SYS_rt_sigaction),
        ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
        ("rt_sigsuspend", libc::SYS_rt_sigsuspend),
        ("rt_sigtimedwait", libc::SYS_rt_sigtimedwait),
        ("sigaltstack", libc::SYS_sigaltstack),
        ("restart_syscall", libc::SYS_restart_syscall),
        // --- Who this process is, and stopping being it -----------------------
        //
        // All read-only, and `exit_group` is how a clean shutdown ends.
        // `tgkill` is what `abort` is built from: a panic that reaches the
        // runtime must still be able to end the process, and one killed by this
        // filter instead would be reported by the kernel as a seccomp violation
        // rather than as the panic it is.
        ("getpid", libc::SYS_getpid),
        ("gettid", libc::SYS_gettid),
        ("getppid", libc::SYS_getppid),
        ("getuid", libc::SYS_getuid),
        ("geteuid", libc::SYS_geteuid),
        ("getgid", libc::SYS_getgid),
        ("getegid", libc::SYS_getegid),
        ("prctl", libc::SYS_prctl),
        ("tgkill", libc::SYS_tgkill),
        ("exit", libc::SYS_exit),
        ("exit_group", libc::SYS_exit_group),
        // --- Entropy ----------------------------------------------------------
        //
        // `SEC-011` (#203) re-tests the entropy source every five minutes for
        // the life of the process, so this one is not a start-up call that
        // happens to be traced — it is the reason the survey runs for longer
        // than the requests take.
        ("getrandom", libc::SYS_getrandom),
        // --- Threads ----------------------------------------------------------
        //
        // The hosted build runs one current-thread runtime and creates no
        // thread after binding, which the surveys confirm. These are allowed
        // regardless, and the trade is worth stating: what a thread could do
        // with them is bounded by everything else in this list — above all by
        // `execve` being absent, so a new thread or a fork runs *this* code —
        // whereas leaving them out means a tokio release that lazily starts its
        // blocking pool kills a production process on a code path nobody
        // changed.
        ("clone", libc::SYS_clone),
        ("clone3", libc::SYS_clone3),
        // --- Architecture-specific ---------------------------------------------
        //
        // `cfg` on an item, which this workspace otherwise avoids in favour of
        // a `const bool` — and here there is no choice, because a syscall an
        // architecture does not have is not a constant with a different value,
        // it is a constant that does not exist. aarch64 dropped the numbers
        // x86_64 keeps for compatibility, so each list holds what its target
        // still has.
        #[cfg(target_arch = "x86_64")]
        ("arch_prctl", libc::SYS_arch_prctl),
        #[cfg(target_arch = "x86_64")]
        ("poll", libc::SYS_poll),
        #[cfg(target_arch = "x86_64")]
        ("epoll_wait", libc::SYS_epoll_wait),
        #[cfg(target_arch = "x86_64")]
        ("dup2", libc::SYS_dup2),
        #[cfg(target_arch = "x86_64")]
        ("select", libc::SYS_select),
    ];

    /// Denied with an errno rather than with a kill (`SEC-018`, #355).
    ///
    /// # Why there is a second answer at all
    ///
    /// #355 asks for the failure action to be argued rather than defaulted, and
    /// puts the two candidates plainly: `KillProcess` turns a missed syscall
    /// into an outage, and `Errno(EPERM)` can turn one into a subtly wrong
    /// answer. The argument here is that the choice is not the same for every
    /// syscall, so it is not made once.
    ///
    /// **`KillProcess` is the default**, and it is [`FILTER_MISMATCH_ACTION`].
    /// A KMS host's failure that matters is not an outage — it is an answer
    /// that is wrong on the wire, because a client that gets a subtly wrong
    /// response is a client that has detected an emulator, and because the
    /// activation it recorded is one nobody can undo. A process that has just
    /// made a syscall its own model of itself says it never makes is a process
    /// whose next response nobody can predict, and continuing with `EPERM` is
    /// exactly the "keep going and hope" that `POL-011` and the entropy
    /// self-test both refuse. It is also the *diagnosable* choice: the kernel
    /// writes an audit record naming the syscall number, which is more than a
    /// swallowed `EPERM` leaves behind, and `Restart=on-failure` in the shipped
    /// unit turns it into a restart rather than a permanent stop.
    ///
    /// # And why these three are not that
    ///
    /// Each is a syscall this program provably never makes after binding, whose
    /// only callers are error paths in the standard library that already handle
    /// a failure, and where a kill would be strictly worse than a refusal:
    ///
    /// * `openat` and `open` — Landlock already denies every path, so these
    ///   already fail; making them fail *harder* buys nothing, and `std`
    ///   reaches for `/proc/self/maps` when a panic prints a backtrace. A
    ///   panicking connection task is survivable today and must not become a
    ///   process kill.
    /// * `socket` and `socketpair` — the measure Landlock cannot take, since it
    ///   governs `bind` and `connect` for TCP and not the creation of an
    ///   `AF_UNIX` or `AF_NETLINK` socket. Refusing it with `EPERM` denies the
    ///   thing while leaving a caller able to say so.
    ///
    /// It is also what makes the filter **observable from inside the process**,
    /// which is what `tests/sandbox.rs` needs: a test can watch a socket that
    /// could be created before the sandbox fail to be created after it. There
    /// is no way to observe a `KillProcess` rule except by dying.
    ///
    /// These are in [`ALLOWED`] as well, and that is required rather than
    /// redundant: the kernel takes the **most severe** action across all
    /// installed filters, so an `Errno` filter stacked under a filter that
    /// killed them would never be reached.
    const SOFT_DENIED: &[(&str, libc::c_long)] = &[
        ("openat", libc::SYS_openat),
        ("socket", libc::SYS_socket),
        ("socketpair", libc::SYS_socketpair),
        #[cfg(target_arch = "x86_64")]
        ("open", libc::SYS_open),
    ];

    /// What the kernel does with a syscall that is in neither list.
    ///
    /// Named rather than written inline so that `tests/sandbox.rs` can assert
    /// on it: "the filter kills rather than degrades" is a security property of
    /// this program and is argued at length on [`SOFT_DENIED`], and a change
    /// from `KillProcess` to `Errno` would be invisible in a diff of a
    /// function body.
    pub(crate) const FILTER_MISMATCH_ACTION: seccompiler::SeccompAction =
        seccompiler::SeccompAction::KillProcess;

    /// What a soft denial returns. `EPERM`, which is what Landlock returns for
    /// the network rights and what a caller is likeliest to have a branch for.
    pub(crate) const SOFT_DENIED_ERRNO: u32 = 1; // EPERM

    /// The two filters, in the order they are installed and named for the
    /// report (`SEC-020`, #392).
    const FILTERS: [&str; 2] = ["allowlist", "soft-denials"];

    /// The architecture this filter is compiled for, if it is one that has
    /// been surveyed.
    ///
    /// `seccompiler` knows three, and this program ships to two of them
    /// (`PKG-004`, #241). Anything else returns `None` and the measure reports
    /// [`Applied::NotOnThisTarget`] — which is the honest answer: seccomp is
    /// there, and *this build* has no measured list for the architecture. A
    /// filter guessed for a target nobody surveyed is the thing #355 exists to
    /// refuse.
    #[cfg(target_arch = "x86_64")]
    const TARGET_ARCH: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::x86_64);
    #[cfg(target_arch = "aarch64")]
    const TARGET_ARCH: Option<seccompiler::TargetArch> = Some(seccompiler::TargetArch::aarch64);
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const TARGET_ARCH: Option<seccompiler::TargetArch> = None;

    /// Compile one filter and install it on **every** thread.
    ///
    /// `apply_filter_all_threads` rather than `apply_filter`, and the
    /// difference is the whole measure: `seccomp(2)` filters a *thread*, the
    /// runtime has more than one by the time the sandbox is applied, and a
    /// filter on the calling thread alone would leave the others running
    /// unfiltered while the report said `applied`. `no_new_privs` is already
    /// set by the caller, which is what the kernel requires before it will
    /// synchronise a filter across threads.
    fn install(
        syscalls: &[(&str, libc::c_long)],
        matched: seccompiler::SeccompAction,
        mismatch: seccompiler::SeccompAction,
    ) -> bool {
        use seccompiler::{BpfProgram, SeccompFilter};

        let Some(arch) = TARGET_ARCH else {
            return false;
        };
        // An empty rule vector means "this syscall, whatever its arguments".
        // There is no argument-inspecting rule here on purpose: a seccomp
        // filter cannot dereference a pointer, so the arguments it can check
        // are the scalar ones, and a rule that checked a flag word would be a
        // rule that looked precise and was not.
        let rules = syscalls
            .iter()
            .map(|&(_, number)| (number, Vec::new()))
            .collect();

        let Ok(filter) = SeccompFilter::new(rules, mismatch, matched, arch) else {
            return false;
        };
        let Ok(program) = TryInto::<BpfProgram>::try_into(filter) else {
            return false;
        };
        seccompiler::apply_filter_all_threads(&program).is_ok()
    }

    /// The syscall allowlist (`SEC-018`, #355).
    ///
    /// Two filters, because the kernel takes the most severe action across all
    /// of them and there is no way to say "kill by default, except return
    /// `EPERM` for these three" in one. The softening filter turns
    /// [`SOFT_DENIED`] into `EPERM` and allows everything else; the allowlist
    /// filter allows what [`ALLOWED`] and [`SOFT_DENIED`] name and kills the
    /// rest. `Errno` outranks `Allow`, so the three end up refused rather than
    /// permitted, and everything unnamed ends up killed.
    ///
    /// # The order is load-bearing, and it is not the obvious one
    ///
    /// The softening filter goes on **first**. Installing a filter is itself a
    /// `seccomp(2)`, and `seccomp` is deliberately not in [`ALLOWED`] — a
    /// process that has finished confining itself has no business installing
    /// another filter. Put the allowlist on first and the very next call, the
    /// one that installs the softening filter, is killed by the filter that was
    /// just applied. That is not a hypothetical: it is what the first version
    /// of this function did, and `tests/sandbox.rs` caught it by dying with
    /// `SIGSYS` before the test could print a line.
    ///
    /// # On an older kernel
    ///
    /// Reports [`Applied::Failed`] and the process goes on serving, exactly as
    /// Landlock does. `CONFIG_SECCOMP_FILTER` has been near-universal since
    /// Linux 3.5 and `SECCOMP_RET_KILL_PROCESS` needs 4.14, so this is a narrow
    /// case — but the argument is not about how narrow it is. A host that
    /// refused to activate anything because it could not confine itself would
    /// have traded its entire function for a hardening measure, which is the
    /// shape of mistake [D35] names and the same answer `OS-020` (#336) gives
    /// for an unsynchronised clock.
    ///
    /// [D35]: https://github.com/schlarpc/kmsrsos/blob/main/docs/decisions.md
    fn restrict_syscalls() -> Applied {
        use seccompiler::SeccompAction;

        if TARGET_ARCH.is_none() {
            return Applied::NotOnThisTarget;
        }

        if !install(
            SOFT_DENIED,
            SeccompAction::Errno(SOFT_DENIED_ERRNO),
            SeccompAction::Allow,
        ) {
            // Nothing is installed, so nothing has changed and `Failed` is the
            // whole truth. Three rules and an `Allow` default is the simplest
            // filter this kernel could be asked for, so a refusal here means
            // `CONFIG_SECCOMP_FILTER` is absent rather than that anything about
            // this list is wrong — and the allowlist is not attempted, because
            // it would fail for the same reason.
            return Applied::Failed;
        }

        if install(
            &permitted_by_the_killing_filter(),
            SeccompAction::Allow,
            FILTER_MISMATCH_ACTION,
        ) {
            return Applied::Yes;
        }

        // The softening is in force and the allowlist is not, which leaves a
        // process that refuses three syscalls and permits everything else —
        // laxer than intended, and the direction an operator has to be told
        // about. Saying "refused" alone would be unreadable, so it says which
        // of the two did not take (`SEC-020`, #392).
        Applied::FailedInPart(Refusals::new(&FILTERS, 0b01))
    }

    /// What the killing filter allows: everything in [`ALLOWED`], **and**
    /// everything in [`SOFT_DENIED`].
    ///
    /// The second half is required rather than redundant. The kernel takes the
    /// most severe action across every installed filter, so a syscall this
    /// filter killed could never reach the `Errno` filter underneath it —
    /// passing [`ALLOWED`] alone here would silently turn all three soft
    /// denials back into process kills, and the only symptom would be a
    /// panicking connection task taking the host down with it.
    fn permitted_by_the_killing_filter() -> Vec<(&'static str, libc::c_long)> {
        ALLOWED.iter().chain(SOFT_DENIED).copied().collect()
    }

    /// Whether the filter permits `name`.
    ///
    /// [`SOFT_DENIED`] counts as permitted here and that is the right answer
    /// rather than a convenience: those syscalls are allowed by the filter that
    /// kills, and refused with `EPERM` by the one that does not. What the
    /// caller is asking is whether making this call ends the process, and for
    /// these three it does not.
    pub(super) fn names_a_permitted_syscall(name: &str) -> bool {
        ALLOWED
            .iter()
            .chain(SOFT_DENIED)
            .any(|&(allowed, _)| allowed == name)
    }

    #[cfg(test)]
    mod tests {
        #![allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            reason = "test code: a failed expectation should abort loudly"
        )]

        use super::{ALLOWED, SOFT_DENIED};

        /// A syscall in both lists is deliberate; a syscall twice in one is a
        /// merge nobody noticed.
        ///
        /// The rule map is a `BTreeMap`, so a duplicate is silently discarded
        /// rather than rejected — which would make a copy-paste in a list of a
        /// hundred numbers invisible.
        #[test]
        fn no_syscall_is_named_twice_in_one_list() {
            for (which, list) in [("ALLOWED", ALLOWED), ("SOFT_DENIED", SOFT_DENIED)] {
                let mut seen: Vec<libc::c_long> = list.iter().map(|&(_, nr)| nr).collect();
                let before = seen.len();
                seen.sort_unstable();
                seen.dedup();
                assert_eq!(before, seen.len(), "{which} names a syscall twice");
            }
        }

        /// Every soft-denied syscall is allowed by the filter that kills.
        ///
        /// The composition, checked where it can be broken. `EPERM` comes from
        /// a filter stacked *under* the allowlist, and the kernel takes the
        /// most severe action across both — so a syscall the allowlist killed
        /// would never reach the one that returns an errno.
        ///
        /// This is the cheap half of that guard. The expensive half is
        /// `a_socket_that_could_be_created_before_the_sandbox_cannot_be_after`,
        /// which asserts the errno a real sandboxed process really returns: get
        /// this wrong and that child dies with `SIGSYS` instead of reporting.
        #[test]
        fn every_soft_denied_syscall_is_allowed_by_the_filter_that_kills() {
            let permitted = super::permitted_by_the_killing_filter();
            for &(name, number) in SOFT_DENIED {
                assert!(
                    permitted.iter().any(|&(_, allowed)| allowed == number),
                    "{name} is soft-denied but not permitted by the allowlist \
                     filter, so it is killed before the errno filter is \
                     consulted (SEC-018, #355)"
                );
            }
        }

        /// The names in the table are the syscalls the numbers mean.
        ///
        /// The names exist so that a failure can be read, and so that
        /// `the_allowlist_covers_every_syscall_the_survey_measured` can compare
        /// this table against `strace` output. A name that had drifted from its
        /// constant would make both of those lie, and there is exactly one
        /// spot-check that does not depend on the table being right: `read` is
        /// syscall 0 on x86_64 and 63 on aarch64, and neither number is
        /// negotiable.
        #[test]
        fn the_names_are_attached_to_the_right_numbers() {
            let read = ALLOWED
                .iter()
                .find(|&&(name, _)| name == "read")
                .expect("read is allowed");
            assert_eq!(read.1, libc::SYS_read);
            assert_eq!(read.1, if cfg!(target_arch = "x86_64") { 0 } else { 63 });
        }
    }
}

#[cfg(windows)]
mod platform {
    //! Windows, which gets less — and the reason is not that nobody tried
    //! (`SEC-005`, #197; `SEC-019`, #356).
    //!
    //! # What Windows cannot do at all
    //!
    //! There is **no self-applicable filesystem sandbox**. AppContainer and
    //! restricted tokens are properties a parent gives a child at launch, so
    //! either would mean shipping a launcher process whose only job is to start
    //! the real one — a bigger change to what is deployed than the mitigation is
    //! worth, and the same argument that leaves `PKG-008` (#245) without an
    //! installer. There is no equivalent of Landlock's network rights either.
    //!
    //! So `filesystem` and `syscalls` report `NotOnThisTarget`, and that is the
    //! truth rather than a gap being glossed: **a Windows host is less confined
    //! than a Linux one.**
    //!
    //! # What Windows does do (`SEC-019`, #356)
    //!
    //! `SetProcessMitigationPolicy` is self-applicable, and five policies are
    //! applied here. `DisallowWin32kSystemCalls` is the one that matters most
    //! and costs least: it removes the `win32k.sys` attack surface, by a wide
    //! margin the largest source of Windows kernel escalations, and this is a
    //! console service that writes to stderr and speaks TCP, so it has no use
    //! for it at all.
    //!
    //! Every route to that function is raw FFI — `windows-sys` and `windows`
    //! both expose it as an `unsafe extern` function and no safe wrapper crate
    //! exists — so this module is **the one unsafe boundary in the workspace**.
    //! `SEC-019` is where that was decided rather than assumed; the reasoning
    //! is in `docs/decisions.md`. The boundary is one call in [`set`], the
    //! manifest downgrades `unsafe_code` from `forbid` to `deny` so that call
    //! must name itself, and `unsafe_is_confined_to_the_one_boundary` fails if
    //! it ever appears anywhere else.
    //!
    //! # On which Windows this has been observed (`PKG-022`, #385)
    //!
    //! **Windows 11 build 26200, on x86_64 and on ARM64.** Both architectures,
    //! and on ARM64 all five policies are accepted —
    //! `ProcessSystemCallDisablePolicy` included, which was the one in doubt:
    //! it removes the `win32k.sys` surface, and `win32k` on ARM64 is a
    //! different build of a driver with its own history of what is and is not
    //! filterable.
    //!
    //! For two issues that was not so. `PKG-020` (#379) shipped the ARM64
    //! build having never executed it, because there was nowhere to: no ARM64
    //! Windows hosted runner, no Windows on Graviton, and emulating one to
    //! test a *process mitigation* would answer a question about the emulator.
    //! The first of those stopped being true — `windows-11-arm` is a standard
    //! GitHub-hosted runner — so `harness/windows/arm64-smoke.ps1` now starts
    //! the **cross-compiled artifact**, the one an operator downloads rather
    //! than one rebuilt on the test machine, serves an activation through it,
    //! and asserts on the line this module produces. It runs on every pull
    //! request, which is a stronger thing than having run once.
    //!
    //! It is worth saying what was *not* the argument for shipping it before
    //! that, because it is the standing lesson of `PKG-018` (#374): the API
    //! being architecture-independent — every structure here is a flag word
    //! rather than anything with a register layout, which
    //! [`the_policy_structures_are_still_flag_words`](tests::the_policy_structures_are_still_flag_words)
    //! asserts on whichever target it compiles for — is a reason to *expect*
    //! it to work and is not a test. Control Flow Guard produced an artifact
    //! whose header made an honest claim and which died before logging a line.
    //!
    //! A refusal remains non-fatal: [`apply`] reports
    //! [`Applied::FailedInPart`] rather than aborting, because "this kernel
    //! declined a mitigation" happens on older builds and is not a reason to
    //! stop serving. It names the policies it names, because five policies
    //! reported as one line saying "refused" is a report an operator cannot
    //! act on — `SEC-020` (#392).

    use super::{Applied, Refusals, Report};
    use windows_sys::Win32::System::Threading::{
        PROCESS_MITIGATION_POLICY, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
        ProcessImageLoadPolicy, ProcessStrictHandleCheckPolicy, ProcessSystemCallDisablePolicy,
        SetProcessMitigationPolicy,
    };

    /// The policies applied, each with the flag word that enables it.
    ///
    /// Every one of these `PROCESS_MITIGATION_*` structures is a union of a
    /// `DWORD Flags` and a bitfield of the same width, so a bare `u32` is the
    /// buffer the call wants. `the_policy_structures_are_still_flag_words`
    /// fails if a future SDK grows one past four bytes, which is the only way
    /// this could quietly start passing a short buffer.
    const POLICIES: [(&str, PROCESS_MITIGATION_POLICY, u32); 5] = [
        // Bit 0, `DisallowWin32kSystemCalls`. The whole win32k surface, which a
        // service with no GUI never touches.
        ("win32k", ProcessSystemCallDisablePolicy, 0b1),
        // Bit 0, `ProhibitDynamicCode`. Nothing here makes a page executable at
        // run time, so injected shellcode has nowhere to live.
        ("dynamic-code", ProcessDynamicCodePolicy, 0b1),
        // Bit 0, `DisableExtensionPoints`. AppInit DLLs, IMEs and window hooks
        // — third-party code the loader would otherwise inject.
        ("extension-points", ProcessExtensionPointDisablePolicy, 0b1),
        // Bits 0 and 1, `NoRemoteImages` and `NoLowMandatoryLabelImages`: no
        // DLL from a remote or low-integrity location.
        ("image-load", ProcessImageLoadPolicy, 0b11),
        // Bits 0 and 1, `RaiseExceptionOnInvalidHandleReference` and
        // `HandleExceptionsPermanentlyEnabled`: an invalid handle becomes an
        // exception rather than a silent bug.
        ("strict-handles", ProcessStrictHandleCheckPolicy, 0b11),
    ];

    /// Apply one mitigation policy to this process.
    ///
    /// Returns whether the kernel accepted it. A refusal is not fatal and not
    /// even unexpected — see [`apply`].
    fn set(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> bool {
        // SAFETY: `SetProcessMitigationPolicy` reads `dwlength` bytes from
        // `lpbuffer` and writes nothing. `flags` is a live `u32` local for the
        // whole call, so the pointer is valid and aligned for the four bytes
        // named by `size_of_val`, and the length cannot disagree with the
        // buffer because it is derived from that same local. The policy
        // identifier is one of the constants above, so it names a policy this
        // Windows either knows — in which case the flag word is the documented
        // width — or does not, in which case it fails cleanly and returns 0.
        // There is no handle, no allocation and no lifetime beyond the call.
        #[expect(
            unsafe_code,
            reason = "the one boundary in the workspace: SetProcessMitigationPolicy \
                      has no safe wrapper on any crate (`SEC-019`, #356)"
        )]
        let accepted = unsafe {
            SetProcessMitigationPolicy(
                policy,
                core::ptr::from_ref(&flags).cast(),
                size_of_val(&flags),
            )
        };
        accepted != 0
    }

    /// The policy names alone, in [`POLICIES`] order.
    ///
    /// Derived from the one table rather than written a second time: a name
    /// list that could drift from the list of what is applied would put a
    /// wrong policy name in a security report, which is worse than no name.
    #[expect(
        clippy::indexing_slicing,
        reason = "a const block: an index past the table is a compile error, not a panic"
    )]
    const POLICY_NAMES: [&str; POLICIES.len()] = {
        let mut names = [""; POLICIES.len()];
        let mut index = 0;
        while index < POLICIES.len() {
            names[index] = POLICIES[index].0;
            index += 1;
        }
        names
    };

    /// Which policies this process failed to apply, in [`POLICIES`] order.
    ///
    /// Separate from [`apply`] so a refusal can be attributed to a policy
    /// rather than reported as a bare "something failed" — and returning
    /// [`Refusals`] rather than a `Vec` so that attribution survives into
    /// [`Report`], which is `Copy` and has no allocation in it (`SEC-020`,
    /// #392).
    fn refused() -> Refusals {
        let mut mask = 0_u32;
        for (index, &(_, policy, flags)) in POLICIES.iter().enumerate() {
            if !set(policy, flags) {
                // `index` is bounded by `POLICIES.len()`, which is five; the
                // `Refusals::new` assertion below is what keeps that true if
                // the table ever grows.
                if let Ok(bit) = u32::try_from(index) {
                    mask |= 1_u32 << bit;
                }
            }
        }
        Refusals::new(&POLICY_NAMES, mask)
    }

    pub(super) fn apply() -> Report {
        let refused = refused();
        Report {
            filesystem: Applied::NotOnThisTarget,
            no_new_privileges: Applied::NotOnThisTarget,
            syscalls: Applied::NotOnThisTarget,
            process_mitigations: if refused.is_empty() {
                Applied::Yes
            } else {
                Applied::FailedInPart(refused)
            },
        }
    }

    /// Windows has no syscall filter, so nothing is refused by one.
    pub(super) const fn names_a_permitted_syscall(_name: &str) -> bool {
        true
    }

    #[cfg(test)]
    mod tests {
        #![allow(
            clippy::unwrap_used,
            clippy::expect_used,
            clippy::panic,
            reason = "test code: a failed expectation should abort loudly"
        )]

        use windows_sys::Win32::System::SystemServices::{
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY,
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
        };

        /// `SEC-019` (#356): every policy buffer is still a four-byte flag word.
        ///
        /// [`super::set`] passes a `u32`. If a future SDK widens any of these
        /// structures, that becomes a short buffer for a call that reads
        /// `dwlength` bytes — so the assumption is asserted rather than
        /// commented.
        #[test]
        fn the_policy_structures_are_still_flag_words() {
            assert_eq!(
                size_of::<PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY>(),
                4
            );
            assert_eq!(size_of::<PROCESS_MITIGATION_DYNAMIC_CODE_POLICY>(), 4);
            assert_eq!(
                size_of::<PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY>(),
                4
            );
            assert_eq!(size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(), 4);
            assert_eq!(
                size_of::<PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY>(),
                4
            );
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    //! A target with nothing to apply.

    use super::Report;

    pub(super) const fn apply() -> Report {
        Report::NOTHING
    }

    /// Nothing is filtered here, so nothing is refused.
    pub(super) const fn names_a_permitted_syscall(_name: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        Applied, FILESYSTEM_CAN_BE_DENIED, Refusals, Report, SANDBOX_IS_AVAILABLE,
        SYSCALLS_CAN_BE_RESTRICTED,
    };

    /// A stand-in for a platform module's policy table.
    const COMPONENTS: [&str; 4] = ["first", "second", "third", "fourth"];

    /// The capability constants agree with each other.
    ///
    /// A target that can deny the filesystem is a target with a sandbox; the
    /// two constants drifting apart would make the log say one thing and the
    /// behaviour do another.
    #[test]
    fn the_capability_constants_are_consistent() {
        if FILESYSTEM_CAN_BE_DENIED || SYSCALLS_CAN_BE_RESTRICTED {
            assert!(SANDBOX_IS_AVAILABLE);
        }
        // Both filesystem denial and syscall restriction are Linux features,
        // and neither exists without the other.
        assert_eq!(FILESYSTEM_CAN_BE_DENIED, SYSCALLS_CAN_BE_RESTRICTED);
    }

    /// "Nothing attempted" is not "everything failed".
    #[test]
    fn nothing_applied_is_complete_but_empty() {
        let nothing = Report::NOTHING;
        assert!(
            nothing.complete(),
            "a target with no measures is not failing"
        );
        assert!(!nothing.anything_applied());
    }

    /// A failure anywhere makes the report incomplete, which is what the log
    /// line is keyed on.
    #[test]
    fn a_failure_is_visible_in_the_report() {
        let report = Report {
            filesystem: Applied::Failed,
            ..Report::NOTHING
        };
        assert!(!report.complete());
        assert!(!report.anything_applied());
    }

    /// Every measure has a name, and every name is distinct — so a log line
    /// naming one cannot be mistaken for another.
    #[test]
    fn every_measure_is_named_distinctly() {
        let names: Vec<&str> = Report::NOTHING
            .each()
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "a measure name is duplicated");
        assert_eq!(names.len(), 4);
    }

    /// Each outcome reads differently, because an operator distinguishing
    /// "this target has no Landlock" from "Landlock refused" is the entire
    /// reason the two are separate variants.
    #[test]
    fn each_outcome_reads_differently() {
        let texts = [
            Applied::Yes.as_text(),
            Applied::NotOnThisTarget.as_text(),
            Applied::Failed.as_text(),
        ];
        let mut sorted = texts;
        sorted.sort_unstable();
        sorted.iter().reduce(|previous, current| {
            assert_ne!(previous, current);
            current
        });
    }

    /// `SEC-020` (#392): a refusal reads back the components it was given, in
    /// the order they are applied.
    #[test]
    fn a_refusal_names_its_components_in_order() {
        let refusals = Refusals::new(&COMPONENTS, 0b1010);
        assert_eq!(refusals.to_string(), "second, fourth");
        assert_eq!(
            refusals.iter().collect::<Vec<_>>(),
            vec!["second", "fourth"]
        );
        assert!(!refusals.is_empty());
    }

    /// A mask bit above the table names nothing, rather than panicking or
    /// naming the wrong component.
    #[test]
    fn a_bit_past_the_table_names_nothing() {
        let refusals = Refusals::new(&COMPONENTS, 0b1_0000);
        assert_eq!(refusals.to_string(), "");
        assert_eq!(refusals.iter().count(), 0);
    }

    /// An empty mask is the "everything took" case, which is what
    /// `platform::apply` keys `Applied::Yes` on.
    #[test]
    fn nothing_refused_is_empty() {
        assert!(Refusals::new(&COMPONENTS, 0).is_empty());
    }

    /// A partial refusal is a failure of the whole report, the same as a
    /// wholesale one — it is only the *line* that differs.
    #[test]
    fn a_partial_refusal_is_still_incomplete() {
        let report = Report {
            process_mitigations: Applied::FailedInPart(Refusals::new(&COMPONENTS, 0b1)),
            ..Report::NOTHING
        };
        assert!(!report.complete());
        assert!(!report.anything_applied());
    }

    /// The verdict word is the same for both refusal shapes; only the detail
    /// differs. `Applied::as_text` is what a caller wanting the bare verdict
    /// gets, and `Display` is what the start-up report prints.
    #[test]
    fn a_partial_refusal_still_reads_as_a_refusal() {
        let partial = Applied::FailedInPart(Refusals::new(&COMPONENTS, 0b11));
        assert_eq!(partial.as_text(), Applied::Failed.as_text());
        assert_eq!(partial.to_string(), "refused by the kernel (first, second)");
        assert_eq!(Applied::Failed.to_string(), "refused by the kernel");
        assert_eq!(Applied::Yes.to_string(), "applied");
    }
}
