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

    use super::{Applied, Report};
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

    /// Which policies this process failed to apply, in [`POLICIES`] order.
    ///
    /// Separate from [`apply`] so a refusal can be attributed to a policy
    /// rather than reported as a bare "something failed".
    fn refused() -> Vec<&'static str> {
        POLICIES
            .into_iter()
            .filter(|&(_, policy, flags)| !set(policy, flags))
            .map(|(name, _, _)| name)
            .collect()
    }

    pub(super) fn apply() -> Report {
        Report {
            filesystem: Applied::NotOnThisTarget,
            no_new_privileges: Applied::NotOnThisTarget,
            syscalls: Applied::NotOnThisTarget,
            process_mitigations: if refused().is_empty() {
                Applied::Yes
            } else {
                Applied::Failed
            },
        }
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
