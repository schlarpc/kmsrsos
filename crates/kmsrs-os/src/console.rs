//! Where pid 1's own log lines go (`OS-028`, #345).
//!
//! # The problem this exists for
//!
//! The kernel hands process 1 `/dev/console` as fds 0, 1 and 2, and
//! `/dev/console` resolves to the **last** `console=` entry on the command
//! line. Kernel messages, by contrast, go to *every* registered console. So a
//! machine with both a framebuffer and a serial port shows the whole boot on
//! the serial line and then nothing further, while the program's own output
//! goes somewhere the operator may not be looking.
//!
//! Which console an operator can actually read is a property of the platform,
//! not of this program:
//!
//! | Platform | Readable console |
//! |---|---|
//! | Proxmox / QEMU with noVNC | framebuffer, `tty0` |
//! | EC2 — `GetConsoleOutput`, serial console (`OS-027`, #344) | `ttyS0` only |
//! | Any machine with a serial port and no display | `ttyS0` |
//!
//! Ordering `console=` for one of those breaks the others, and the EC2 shape is
//! the worst a failure can take: kernel messages still arrive, so the boot looks
//! healthy while the program looks dead.
//!
//! # What this does instead
//!
//! `/proc/consoles` enumerates what the kernel registered. Pid 1 reads it, opens
//! each console's device node, replaces fds 1 and 2 with a pipe, and pumps that
//! pipe out to all of them. The `console=` order then stops deciding anything,
//! which is worth more than getting it right for the platform we happened to
//! test on.
//!
//! Teeing the *fds* rather than teaching [`kmsrs_server::log`] about a second
//! sink is deliberate. It means a Rust panic — which on pid 1 is the last thing
//! this machine will ever say — is teed too, and it means the server crate needs
//! no knowledge of a mechanism only one of its three targets has.
//!
//! # Scope
//!
//! Bare metal only. There is no `/proc/consoles` on Windows and nothing worth
//! teeing on an ordinary Linux host where stderr is a journal or a pipe, so
//! [`tee_stdio`] reports why it did nothing and leaves fds 1 and 2 exactly as
//! the kernel supplied them.
//!
//! # Failure is never fatal
//!
//! A console that disappears must not take down a host that is serving. Every
//! failure here — an unreadable `/proc/consoles`, a device node that will not
//! open, a write that stops working halfway through the machine's life — is
//! reported once and then tolerated.

use core::fmt;
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use std::time::Duration;

/// The kernel's list of registered consoles.
const PROC_CONSOLES: &str = "/proc/consoles";

/// Where devtmpfs puts the console device nodes. Pid 1 mounts it before it
/// calls this, which is the reason the mount is not optional.
const DEV: &str = "/dev/";

/// How long to wait before retrying a console that answered `EAGAIN`.
///
/// The device nodes are opened non-blocking, so a slow console — a real 115200
/// serial port is about 11 kB/s — reports a full buffer rather than stalling
/// the pump. Waiting and retrying is what turns that into "slow" instead of
/// "lossy".
const RETRY_PAUSE: Duration = Duration::from_millis(2);

/// How many `EAGAIN`s in a row before the rest of a write is abandoned.
///
/// The product is the ceiling on how long one console may hold up the others:
/// 128 × 2 ms ≈ 0.25 s. A console that is merely slow finishes well inside
/// that; one that is wedged — hardware flow control asserted with nothing on
/// the other end — is dropped rather than allowed to stop a host that is
/// serving.
const MAX_STALLS: u32 = 128;

/// Read buffer for the pump, and so the largest write forwarded at once.
const CHUNK: usize = 4096;

/// Why fds 1 and 2 were left alone.
///
/// An enum rather than a string because each variant is a different fact about
/// the machine, and the ordinary Linux and Windows builds reach
/// [`Self::NoProcConsoles`] on every start-up — that one is not a problem and
/// should not read like one.
#[derive(Debug)]
pub(crate) enum Untee {
    /// No `/proc/consoles`. The normal outcome anywhere but bare metal.
    NoProcConsoles(Errno),
    /// The kernel registered no console this program may write to.
    NoWritableConsole,
    /// Every device node failed to open, with the reasons.
    NoConsoleOpened(String),
    /// `pipe(2)` failed, which means the machine is out of descriptors.
    Pipe(Errno),
    /// The pump thread would not start.
    Pump(std::io::Error),
}

impl fmt::Display for Untee {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProcConsoles(error) => write!(formatter, "{PROC_CONSOLES}: {error}"),
            Self::NoWritableConsole => {
                write!(formatter, "{PROC_CONSOLES} lists no writable console")
            }
            Self::NoConsoleOpened(reasons) => write!(formatter, "no console opened: {reasons}"),
            Self::Pipe(error) => write!(formatter, "pipe: {error}"),
            Self::Pump(error) => write!(formatter, "pump thread: {error}"),
        }
    }
}

/// Send this process's stdout and stderr to every console the kernel
/// registered (`OS-028`, #345).
///
/// Returns the console names now being written to, in the order
/// `/proc/consoles` listed them, or the reason nothing changed.
///
/// # Errors
///
/// Returns [`Untee`] when the tee could not be installed. Every variant leaves
/// fds 1 and 2 as the kernel supplied them, so the caller's next `eprintln!`
/// still reaches `/dev/console`; none of them is a reason to stop booting.
pub(crate) fn tee_stdio() -> Result<Vec<String>, Untee> {
    let listing = read_proc(PROC_CONSOLES).map_err(Untee::NoProcConsoles)?;

    let mut sinks = Vec::new();
    let mut refused = Vec::new();
    for name in writable_consoles(&listing) {
        match open_console(name) {
            Ok(fd) => sinks.push(Sink {
                name: name.to_owned(),
                fd,
                writable: true,
            }),
            Err(error) => refused.push(format!("{name}: {error}")),
        }
    }

    if sinks.is_empty() {
        return Err(if refused.is_empty() {
            Untee::NoWritableConsole
        } else {
            Untee::NoConsoleOpened(refused.join(", "))
        });
    }

    let names: Vec<String> = sinks.iter().map(|sink| sink.name.clone()).collect();
    let (read_end, write_end) = rustix::pipe::pipe().map_err(Untee::Pipe)?;

    // The pump starts *before* the redirect, and that order is the whole of the
    // error handling. Spawn first and fds 1 and 2 are untouched if it fails;
    // redirect first and a failed spawn would leave this process writing into a
    // pipe nobody reads, which stalls the host as soon as 64 kB accumulates.
    std::thread::Builder::new()
        .name("console".to_owned())
        .spawn(move || pump(&read_end, Tee { sinks }))
        .map_err(Untee::Pump)?;

    // A failure here is survivable and deliberately not reported: whichever of
    // the two succeeded, the pump is reading, and if neither did then dropping
    // `write_end` closes the pipe and the pump exits on EOF. Either way the
    // machine keeps booting.
    let _: Result<(), Errno> = rustix::stdio::dup2_stdout(&write_end);
    let _: Result<(), Errno> = rustix::stdio::dup2_stderr(&write_end);
    // Fds 1 and 2 are now the only writers, so the pump sees EOF exactly when
    // this process is gone rather than never.
    drop(write_end);

    Ok(names)
}

/// One console, and whether it is still accepting output.
#[derive(Debug)]
struct Sink {
    /// As `/proc/consoles` spelled it: `tty0`, `ttyS0`, `hvc0`.
    name: String,
    /// The device node, open non-blocking.
    fd: OwnedFd,
    /// Cleared the first time a write to this console fails. A console that
    /// has gone away is not retried on every subsequent line, which would turn
    /// one dead serial port into a syscall per log line forever.
    writable: bool,
}

/// The fan-out. Holds every console and no state beyond their health.
#[derive(Debug)]
struct Tee {
    sinks: Vec<Sink>,
}

impl Tee {
    /// Write one chunk to every console still accepting output.
    ///
    /// Failures are recorded on the sink and announced on the consoles that
    /// still work, so an operator watching the surviving console learns that
    /// another one stopped. Nothing is propagated: this runs on a thread whose
    /// only job is output, and there is nobody to report a failure to report.
    fn write(&mut self, bytes: &[u8]) {
        let mut lost = Vec::new();
        for sink in &mut self.sinks {
            if !sink.writable {
                continue;
            }
            if let Err(error) = write_bounded(&sink.fd, bytes) {
                sink.writable = false;
                lost.push(format!("{}: {error}", sink.name));
            }
        }
        for reason in &lost {
            let notice = format!(
                "{{\"level\":\"warn\",\"event\":\"console\",\"detail\":\"stopped writing to {reason}\"}}\n"
            );
            for sink in &mut self.sinks {
                if sink.writable {
                    // Best effort by construction: this notice is itself
                    // output, and a console that fails while being told about
                    // another console's failure is caught on the next line.
                    let _: Result<(), Errno> = write_bounded(&sink.fd, notice.as_bytes());
                }
            }
        }
    }
}

/// Forward everything written to fds 1 and 2 until this process is gone.
///
/// Reads rather than `select`s: there is exactly one source, so there is
/// nothing to multiplex.
fn pump(read_end: &OwnedFd, mut tee: Tee) {
    let mut buffer = [0_u8; CHUNK];
    loop {
        match rustix::io::read(read_end, &mut buffer[..]) {
            // Every writer closed, which for pid 1 means the machine is
            // ending. Nothing further will arrive.
            Ok(0) => return,
            Ok(read) => tee.write(buffer.get(..read).unwrap_or_default()),
            Err(Errno::INTR) => {}
            // A read error on a pipe this process owns both ends of is not a
            // recoverable condition, and spinning on it would be worse than
            // silence.
            Err(_) => return,
        }
    }
}

/// Write all of `bytes`, tolerating short writes and a bounded amount of
/// back-pressure.
///
/// `EAGAIN` is the expected case on a busy serial console, not an error;
/// `MAX_STALLS` is what stops a wedged one from becoming this machine's
/// deadline.
fn write_bounded(fd: &OwnedFd, bytes: &[u8]) -> Result<(), Errno> {
    let mut rest = bytes;
    let mut stalls = 0_u32;
    while !rest.is_empty() {
        match rustix::io::write(fd, rest) {
            // A zero-length write on a non-empty buffer is a device that will
            // never make progress; treated as the I/O error it effectively is.
            Ok(0) => return Err(Errno::IO),
            Ok(written) => {
                rest = rest.get(written..).unwrap_or_default();
                stalls = 0;
            }
            Err(Errno::AGAIN) => {
                stalls = stalls.saturating_add(1);
                if stalls > MAX_STALLS {
                    return Err(Errno::AGAIN);
                }
                std::thread::sleep(RETRY_PAUSE);
            }
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Open one console's device node, non-blocking and without taking it as a
/// controlling terminal.
///
/// Both flags matter. `O_NOCTTY` keeps pid 1 — which has no controlling
/// terminal and wants none — from acquiring one by opening a tty. `O_NONBLOCK`
/// is the difference between opening a serial port and hanging on one: without
/// it, `open(2)` on a tty with modem control blocks in `tty_port_block_til_ready`
/// until carrier detect asserts, and a machine whose whole job is to boot
/// unattended cannot afford to wait for a cable.
fn open_console(name: &str) -> Result<OwnedFd, Errno> {
    let mut path = String::with_capacity(DEV.len().saturating_add(name.len()));
    path.push_str(DEV);
    path.push_str(name);
    rustix::fs::open(
        path.as_str(),
        OFlags::WRONLY | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
}

/// The consoles in a `/proc/consoles` listing that this program may write to,
/// deduplicated and in the kernel's order.
///
/// The format is `fs/proc/consoles.c`'s: a name padded to 21 columns, then an
/// `RWU` triple in which `W` means the console has a write method, then the
/// flags in parentheses and the device number.
///
/// ```text
/// tty0                 -WU (EC p  )    4:1
/// ttyS0                -W- (E  p  )    4:64
/// ```
///
/// The device number is deliberately *not* used to find the node. For the VT
/// console the name is `tty0` while the number is whichever VT is in the
/// foreground — 4:1 above — and `/dev/tty0` is the one that means "the console
/// the operator is looking at".
fn writable_consoles(listing: &str) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(operations)) = (fields.next(), fields.next()) else {
            continue;
        };
        // `-W-`: read, write, unblank. Without a write method there is nothing
        // to send output to, and `braille` devices are the reason that is not
        // hypothetical.
        if !operations.contains('W') {
            continue;
        }
        if !is_device_name(name) {
            continue;
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Whether a name from `/proc/consoles` may be pasted onto `/dev/`.
///
/// The kernel generates that file, so this is not defending against a hostile
/// input so much as refusing to build a path out of text on trust. A name is a
/// driver name and an index and nothing else: no separator, no `..`, no dot.
fn is_device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Read a procfs file whose size `stat(2)` reports as zero.
///
/// Which is all of them, so the usual read-the-length-then-allocate does not
/// work and the only answer is to read until EOF.
fn read_proc(path: &str) -> Result<String, Errno> {
    let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut out = Vec::new();
    let mut buffer = [0_u8; CHUNK];
    loop {
        match rustix::io::read(&fd, &mut buffer[..]) {
            Ok(0) => break,
            Ok(read) => out.extend_from_slice(buffer.get(..read).unwrap_or_default()),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
    String::from_utf8(out).map_err(|_| Errno::ILSEQ)
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

    use super::{CHUNK, Sink, Tee, is_device_name, writable_consoles};
    use rustix::fd::OwnedFd;
    use rustix::io::Errno;

    /// Drain a pipe to a string.
    ///
    /// `std::fs::File::from(fd)` would be the short way and is unavailable:
    /// `no_shipped_crate_touches_the_filesystem` forbids this tree the name
    /// `std::fs`, in test code as much as anywhere else.
    fn drain(end: &OwnedFd) -> String {
        let mut out = Vec::new();
        let mut buffer = [0_u8; CHUNK];
        loop {
            match rustix::io::read(end, &mut buffer[..]) {
                Ok(0) => break,
                Ok(read) => out.extend_from_slice(&buffer[..read]),
                Err(Errno::INTR) => {}
                Err(error) => panic!("reading the pipe back: {error}"),
            }
        }
        String::from_utf8(out).expect("the tee wrote UTF-8")
    }

    /// A real listing from the shipped kernel, with both consoles this target
    /// is built to have.
    const PROXMOX_LISTING: &str = "\
tty0                 -WU (EC p  )    4:1
ttyS0                -W- (E  p  )    4:64
";

    #[test]
    fn both_consoles_are_found_in_order() {
        assert_eq!(writable_consoles(PROXMOX_LISTING), ["tty0", "ttyS0"]);
    }

    /// A console with no write method cannot be an output sink. `braille` is
    /// the in-tree example.
    #[test]
    fn a_console_without_a_write_method_is_skipped() {
        let listing = "ttyS0                -W- (E  p  )    4:64\n\
                       brl                  R-- (E     )\n";
        assert_eq!(writable_consoles(listing), ["ttyS0"]);
    }

    #[test]
    fn a_name_is_never_a_path() {
        assert!(is_device_name("ttyS0"));
        assert!(is_device_name("hvc0"));
        assert!(!is_device_name("../etc/passwd"));
        assert!(!is_device_name("tty/0"));
        assert!(!is_device_name(".."));
        assert!(!is_device_name(""));
    }

    #[test]
    fn a_listing_that_is_not_one_yields_nothing() {
        assert!(writable_consoles("").is_empty());
        assert!(writable_consoles("garbage\n").is_empty());
    }

    /// Two pipes standing in for two consoles: the point of `OS-028` (#345) is
    /// that one line reaches *both*, so the test fails if either stops
    /// receiving.
    ///
    /// Pipes rather than files because axiom A5 forbids this tree the temp file
    /// the obvious version of this test would use.
    #[test]
    fn every_console_receives_every_line() {
        let (first_read, first_write) = rustix::pipe::pipe().unwrap();
        let (second_read, second_write) = rustix::pipe::pipe().unwrap();

        let mut tee = Tee {
            sinks: vec![
                Sink {
                    name: "first".to_owned(),
                    fd: first_write,
                    writable: true,
                },
                Sink {
                    name: "second".to_owned(),
                    fd: second_write,
                    writable: true,
                },
            ],
        };
        tee.write(b"{\"event\":\"pid1\"}\n");
        drop(tee);

        for (label, end) in [("first", first_read), ("second", second_read)] {
            assert_eq!(
                drain(&end),
                "{\"event\":\"pid1\"}\n",
                "the {label} console did not receive the line"
            );
        }
    }

    /// A console that goes away does not take the others with it, and the
    /// survivors are told.
    #[test]
    fn a_dead_console_does_not_silence_a_live_one() {
        let (live_read, live_write) = rustix::pipe::pipe().unwrap();
        let (dead_read, dead_write) = rustix::pipe::pipe().unwrap();
        // Closing the read end makes every write to `dead_write` fail with
        // EPIPE, which is what a console disappearing looks like from here.
        drop(dead_read);

        let mut tee = Tee {
            sinks: vec![
                Sink {
                    name: "dead".to_owned(),
                    fd: dead_write,
                    writable: true,
                },
                Sink {
                    name: "live".to_owned(),
                    fd: live_write,
                    writable: true,
                },
            ],
        };
        tee.write(b"first\n");
        tee.write(b"second\n");
        drop(tee);

        let got = drain(&live_read);
        assert!(
            got.starts_with("first\n"),
            "the live console lost the line that killed the dead one: {got:?}"
        );
        assert!(
            got.contains("stopped writing to dead"),
            "the survivor was not told the other console went away: {got:?}"
        );
        assert!(
            got.ends_with("second\n"),
            "the live console stopped receiving after the other one died: {got:?}"
        );
    }
}
