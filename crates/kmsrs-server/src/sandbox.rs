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
//! | **seccomp** allowlist | every syscall this program does not make | no — `SEC-018` (#355) |
//!
//! The third is split out rather than guessed at. The first two are verifiable:
//! Landlock either denies a path or it does not, and `tests/sandbox.rs` checks
//! exactly that in a real sandboxed subprocess. A syscall allowlist is a claim
//! about every syscall this process will ever make across every libc, allocator
//! and kernel it ships to, and the cost of getting it wrong is the process being
//! killed on something nobody predicted, in production, with no log line because
//! the process is gone. That list has to be measured, which is #355.
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
//! What *is* self-applicable is a set of process mitigation policies — and they
//! are **not** applied either, because every route to
//! `SetProcessMitigationPolicy` is raw FFI and this workspace forbids `unsafe`
//! with no exception. That conflict is real and is a decision for a review:
//! `SEC-019` (#356). Until it is taken, the Windows build reports
//! `process_mitigations: Failed` rather than claiming a hardening it does not
//! have.
//!
//! The result is that a Windows host is genuinely less confined than a Linux
//! one, and [`Report`] says so in as many words rather than reporting
//! "hardened" on both.

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
pub const SYSCALLS_CAN_BE_RESTRICTED: bool = cfg!(target_os = "linux");

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
}

impl Applied {
    /// How this reads in a log line.
    #[must_use]
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Yes => "applied",
            Self::NotOnThisTarget => "not available on this target",
            Self::Failed => "refused by the kernel",
        }
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

#[cfg(target_os = "linux")]
mod platform {
    //! Landlock, `no_new_privs` and seccomp (`SEC-005`, #197).

    use super::{Applied, Report};

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

    /// The syscall allowlist.
    ///
    /// Deliberately **not** implemented yet — see `SEC-018` (#355). Building an
    /// allowlist that is right on every libc, allocator and kernel this ships
    /// to needs empirical work that a filter written from a list of what the
    /// code *appears* to call does not substitute for, and the failure mode of
    /// getting it wrong is the process dying on a syscall nobody predicted,
    /// under load, in production.
    ///
    /// Reporting `Failed` rather than `Yes` is the point: the [`Report`] the
    /// operator sees says the syscall filter is not in place, which is true.
    fn restrict_syscalls() -> Applied {
        Applied::Failed
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
    //! # What Windows *could* do, and why it does not yet
    //!
    //! `SetProcessMitigationPolicy` is self-applicable and would close a great
    //! deal — `DisallowWin32kSystemCalls` alone removes the largest source of
    //! Windows kernel escalations, and this is a console service with no GUI, so
    //! it costs nothing.
    //!
    //! It is not called here because **it cannot be called from this
    //! workspace**. Every route to it is raw FFI: `windows-sys` and `windows`
    //! both expose it as an `unsafe extern` function, and this workspace sets
    //! `unsafe_code = "forbid"` at the root with no exception —
    //! `no_shipped_crate_contains_unsafe` fails on the word appearing anywhere
    //! in a shipped crate, deliberately over-reaching so that a reader grepping
    //! for it finds nothing.
    //!
    //! That is a real conflict between two things this project wants, and
    //! resolving it is a decision for a review rather than something to slip in
    //! beside a Linux change. `SEC-019` (#356) is where it gets taken. Until
    //! then this reports `Failed` rather than `NotOnThisTarget`, because the
    //! capability *does* exist on this target and is not being used — and those
    //! are different facts.

    use super::{Applied, Report};

    pub(super) const fn apply() -> Report {
        Report {
            filesystem: Applied::NotOnThisTarget,
            no_new_privileges: Applied::NotOnThisTarget,
            syscalls: Applied::NotOnThisTarget,
            process_mitigations: Applied::Failed,
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
        Applied, FILESYSTEM_CAN_BE_DENIED, Report, SANDBOX_IS_AVAILABLE, SYSCALLS_CAN_BE_RESTRICTED,
    };

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
}
