//! Process 1 (`OS-017`, #333; `OS-021`, #337).
//!
//! On the bare-metal target the initramfs contains exactly one file and this is
//! it. There is no init system, no shell and no libc on disk: the kernel
//! finishes booting, executes `/init`, and this program is what runs.
//!
//! Everything here is a duty the kernel does *not* perform for pid 1 and that
//! nothing else in the image can perform either. It is deliberately short —
//! the KMS host itself is [`kmsrs_server::entry::serve`], unchanged and shared
//! with the Linux and Windows builds, and this crate exists to make the
//! machine habitable before handing over.
//!
//! # What is different about pid 1
//!
//! Each of these is something the kernel does differently for process 1, and
//! each produces a failure that looks like something else:
//!
//! * **Nothing is mounted.** `/proc` and `/sys` do not exist unless pid 1
//!   mounts them, and `/dev` holds exactly one node — `/dev/console`, which
//!   comes from the kernel's built-in initramfs (`usr/default_cpio_list`) and is
//!   what the kernel hands init as fds 0, 1 and 2. Everything else `/dev`
//!   should contain arrives with devtmpfs, which pid 1 mounts.
//! * **Exit is a kernel panic.** `Attempted to kill init!`. With
//!   `panic = "abort"` a Rust panic ends the machine, which is the same
//!   contract the unikernel had; the difference is that the diagnostic is now a
//!   kernel oops on a console that exists.
//! * **Orphans are reparented here.** They must be waited on or they become
//!   permanent zombies. This program spawns nothing today, so that is a latent
//!   requirement rather than a live leak — and it is free to do now and
//!   irritating to retrofit.
//! * **There is one console, and the kernel picked it.** Fds 0, 1 and 2 are
//!   `/dev/console`, which resolves to the *last* `console=` entry, while
//!   kernel messages go to all of them. So the boot looks healthy on the serial
//!   line and the program looks dead. [`console`] fixes that by teeing this
//!   process's output to every console `/proc/consoles` lists (`OS-028`, #345).
//!
//! # No `unsafe`
//!
//! `mount(2)`, `mkdir(2)` and `waitpid(2)` are syscalls, and reaching them
//! normally means an `unsafe` libc call. Axiom A1 has had no exception since
//! `OS-018` (#334) removed the Hermit boundary, and `rustix` is how it stays
//! that way: safe bindings, checked by `workspace_invariants.rs`, which fails
//! if the word `unsafe` appears anywhere in this workspace.

mod console;
mod power;

use rustix::fs::Mode;
use rustix::mount::MountFlags;
use std::process::ExitCode;

/// The pseudo-filesystems this machine needs, and why each one.
///
/// A table rather than three calls, so that a reader can see the whole of what
/// pid 1 mounts, and so `tests` can assert the set has not quietly grown. There
/// is no real filesystem here and there is not going to be: axiom A5 is
/// structural on this target, because the kernel is built with `CONFIG_BLOCK`
/// unset and has no block layer to mount anything from.
const MOUNTS: &[Mount] = &[
    Mount {
        source: "devtmpfs",
        target: "/dev",
        fstype: "devtmpfs",
        why: "the kernel's built-in initramfs supplies /dev/console and nothing \
              else; the guest-agent channel of OS-022 (#338) is a device node \
              that only devtmpfs will create",
    },
    Mount {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        why: "/proc/consoles is how OS-028 (#345) finds every console the \
              kernel registered, so pid 1's own log is legible on a machine \
              whose operator reads the serial port rather than the \
              framebuffer; and it is the first thing anyone wants when a \
              guest misbehaves",
    },
    Mount {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        why: "where a network interface's state is legible, which OS-019 \
              (#335) will need when it stops using the kernel's DHCP client",
    },
];

/// One pseudo-filesystem pid 1 mounts.
#[derive(Debug, Clone, Copy)]
struct Mount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    /// Why this one is here. Prose, but load-bearing prose: the list is short
    /// and every future addition should have to write one of these, which is
    /// what `tests::only_pseudo_filesystems_are_mounted` checks.
    ///
    /// Read by the tests rather than by `main`, which is what the lint below
    /// is about — the field's purpose is to make the table self-justifying.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by tests, not main"))]
    why: &'static str,
}

fn main() -> ExitCode {
    // Mounting comes first because everything else depends on it: /proc is
    // where the console list lives and /dev is where the console nodes appear.
    //
    // The results are held rather than printed, because until the tee below is
    // installed the only place a line can go is /dev/console — which on a
    // machine with two consoles is precisely the one the operator may not be
    // watching (`OS-028`, #345). Nothing is lost by waiting: if the tee cannot
    // be installed, fds 1 and 2 are still what the kernel supplied and these
    // lines go exactly where they would have gone anyway.
    let mut mounted = Vec::new();
    let mut notes = Vec::new();
    for mount in MOUNTS {
        match mount_one(mount) {
            Ok(()) => mounted.push(mount.target),
            Err(error) => {
                // Not fatal. A missing /proc is a worse debugging experience,
                // not a host that cannot activate — and refusing to serve over
                // it would trade a working KMS host for a tidy one.
                notes.push(format!(
                    "{{\"level\":\"warn\",\"event\":\"mount\",\"detail\":\"{} on {}: {error}\"}}",
                    mount.fstype, mount.target
                ));
            }
        }
    }

    // `OS-028` (#345): from here on, everything this process writes to stdout
    // or stderr reaches every console the kernel registered, not just the last
    // `console=` entry. That includes the KMS host's own log lines, since
    // `serve` writes to the same descriptors, and a panic message, which on
    // pid 1 is the last thing this machine will ever say.
    notes.push(match console::tee_stdio() {
        Ok(consoles) => format!(
            "{{\"level\":\"info\",\"event\":\"console\",\"detail\":\"logging to {}\"}}",
            consoles.join(" ")
        ),
        Err(reason) => format!(
            "{{\"level\":\"info\",\"event\":\"console\",\"detail\":\"inherited stderr: {reason}\"}}"
        ),
    });

    // Stated positively, and on purpose. "No warning appeared" is not evidence
    // that anything mounted — it is equally consistent with this code never
    // running — so the boot check in `nix flake check` greps for this line
    // rather than for the absence of the one above. Since `OS-028` (#345) it
    // is also the assertion that the tee works: the check looks for it on the
    // *serial* console of a machine that also has a framebuffer.
    notes.push(format!(
        "{{\"level\":\"info\",\"event\":\"pid1\",\"detail\":\"mounted {}\"}}",
        if mounted.is_empty() {
            "nothing".to_owned()
        } else {
            mounted.join(" ")
        }
    ));

    for note in &notes {
        println_stderr(note);
    }

    reap_orphans_forever();

    // `OS-026` (#343): `qm shutdown` is an ACPI event that reaches an input
    // device nobody was reading. Said out loud either way — a host that cannot
    // be stopped politely still activates, but an operator pressing Shutdown
    // and watching nothing happen deserves to find the reason in the log
    // rather than in an issue tracker.
    println_stderr(&match power::watch_power_button() {
        Ok(nodes) => format!(
            "{{\"level\":\"info\",\"event\":\"power\",\"detail\":\"watching {}\"}}",
            nodes.join(" ")
        ),
        Err(reason) => format!(
            "{{\"level\":\"warn\",\"event\":\"power\",\"detail\":\"the power \
             button is not being watched, so a hypervisor's shutdown request \
             will do nothing: {reason}\"}}"
        ),
    });

    let outcome = kmsrs_server::entry::serve();

    // `OS-026` (#343): the drain has finished, so stop the machine rather than
    // returning. Pid 1 returning is `Attempted to kill init!` — the machine
    // does stop, because the command line says `panic=-1`, but what an operator
    // sees after pressing Shutdown is a kernel oops, which is not what a clean
    // stop looks like.
    if let Some(error) = power::power_off("serve returned") {
        println_stderr(&format!(
            "{{\"level\":\"warn\",\"event\":\"power\",\"detail\":\"reboot(2): \
             {error}; falling back to exiting, which panics the kernel\"}}"
        ));
    }
    outcome
}

/// One line to stderr, which on this target is `/dev/console`.
///
/// A function rather than a bare `eprintln!` so the log shape has one place to
/// change if it ever needs to match `kmsrs_server::log` exactly. It does not
/// today: these three lines happen before the logger exists, which is the whole
/// reason they are here.
fn println_stderr(line: &str) {
    eprintln!("{line}");
}

/// Mount one entry, creating its mount point if the initramfs did not.
///
/// The initramfs carries `/dev` because the kernel's built-in cpio does; it
/// carries neither `/proc` nor `/sys`, because the manifest is one line and
/// there is no reason for it to be three.
fn mount_one(mount: &Mount) -> Result<(), rustix::io::Errno> {
    // `EEXIST` is the normal case for /dev, which the initramfs already carries.
    if let Err(error) = rustix::fs::mkdir(mount.target, Mode::from_bits_truncate(0o755))
        && error != rustix::io::Errno::EXIST
    {
        return Err(error);
    }
    rustix::mount::mount(
        mount.source,
        mount.target,
        mount.fstype,
        MountFlags::empty(),
        None,
    )
}

/// Reap orphaned children for the life of the machine (`OS-021`, #337).
///
/// A thread rather than a task, and a blocking `waitpid` rather than a signal
/// handler: installing a `SIGCHLD` handler is the usual answer and it needs
/// either `unsafe` or a runtime, and this has to work before
/// [`kmsrs_server::entry::serve`] has built one.
///
/// The `ECHILD` case is the normal one — this program spawns nothing, so there
/// is usually no child to wait for and `waitpid` returns immediately. Sleeping
/// a second before retrying turns what would be a spin into a thread that costs
/// nothing. It is not a hot path; it is insurance against the day something
/// here does fork, at which point the alternative is a zombie table that grows
/// until the machine stops.
fn reap_orphans_forever() {
    std::thread::Builder::new()
        .name("reaper".to_owned())
        .spawn(|| {
            loop {
                // `Ok(Some(_))` means a child was reaped, so look again at
                // once: several may have exited together. Everything else —
                // no children (`ECHILD`, the normal case here, since this
                // program spawns nothing), an interruption, or anything
                // unexpected — waits a second first, which is what keeps this
                // from being a spin. None of them is worth ending the reaper
                // over: if it stops, zombies accumulate silently.
                if !matches!(
                    rustix::process::waitpid(None, rustix::process::WaitOptions::empty()),
                    Ok(Some(_))
                ) {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        })
        .map_or_else(
            |error| {
                eprintln!(
                    "{{\"level\":\"warn\",\"event\":\"reaper\",\"detail\":\"not started: {error}\"}}"
                );
            },
            |handle| {
                // Deliberately not joined: it runs for the life of the machine,
                // and pid 1 returning is a kernel panic anyway.
                drop(handle);
            },
        );
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::MOUNTS;

    /// The mount list is what the module says it is, and has not grown a real
    /// filesystem.
    ///
    /// Axiom A5 is structural on this target — the kernel is built with
    /// `CONFIG_BLOCK` unset, so there is no block layer to mount anything from
    /// — but the list is the place a future `ext4` would appear first, and it
    /// should have to be argued for at a review rather than added quietly.
    #[test]
    fn only_pseudo_filesystems_are_mounted() {
        let allowed = ["devtmpfs", "proc", "sysfs", "tmpfs"];
        for mount in MOUNTS {
            assert!(
                allowed.contains(&mount.fstype),
                "{} is not a pseudo-filesystem; axiom A5 says this machine has \
                 no storage (OS-021, #337)",
                mount.fstype
            );
            assert!(
                !mount.why.is_empty(),
                "{} was added without a reason",
                mount.target
            );
            assert!(
                mount.target.starts_with('/'),
                "{} is not an absolute path",
                mount.target
            );
        }
    }

    /// `/dev` is mounted, because `OS-022` (#338) cannot open a device node
    /// that nothing created.
    #[test]
    fn devtmpfs_is_mounted() {
        assert!(
            MOUNTS.iter().any(|mount| mount.target == "/dev"),
            "without devtmpfs the only node in /dev is the console the kernel \
             put there, and the guest-agent channel is a node"
        );
    }

    /// No duplicate targets, which would mean mounting over something.
    #[test]
    fn every_mount_point_is_distinct() {
        let mut seen = Vec::new();
        for mount in MOUNTS {
            assert!(
                !seen.contains(&mount.target),
                "{} is mounted twice",
                mount.target
            );
            seen.push(mount.target);
        }
    }
}
