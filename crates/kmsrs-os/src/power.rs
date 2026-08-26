//! The power button, and the one way this machine is asked to stop
//! (`OS-026`, #343).
//!
//! # Why a program has to do anything about this
//!
//! `qm shutdown` — the Proxmox web UI's "Shutdown" button — sends an ACPI
//! power-button event. The kernel turns that into an **input event** on a
//! `/dev/input/eventN` node and does nothing else with it. On an ordinary
//! machine `acpid` or `systemd-logind` reads that node; here there is no
//! userland at all, so nothing reads it and the press is discarded.
//!
//! An operator therefore presses Shutdown, watches nothing happen, and
//! eventually uses `qm stop`, which is the hypervisor pulling the power on a
//! host with connections in flight. That is the class of quiet failure
//! `OS-018` (#334) removed Hermit to be rid of.
//!
//! # The button reaches the same drain as SIGTERM
//!
//! Not a parallel shutdown path — *the same one*. The watcher signals its own
//! process, and everything after that is [`kmsrs_server`]'s existing handler:
//! in-flight connections drain, the listeners close, `serve` returns
//! (`NET-007`, #157). A second mechanism would be a second place for the drain
//! to be subtly different, and `OS-022` (#338)'s `guest-shutdown` is a third
//! caller of this same function rather than a third path.
//!
//! Signalling pid 1 is safe precisely because of the rule that usually makes
//! pid 1 awkward: the kernel discards a signal that pid 1 has no handler for.
//! So a press that arrives before [`kmsrs_server::entry::serve`] has installed
//! its handler is ignored, where on any other process it would be an immediate
//! kill. [`request_shutdown`] says so on the console rather than leaving the
//! operator to wonder, and a second press works.
//!
//! # Finding the button without hardcoding `event0`
//!
//! Which node the button lands on depends on what else the hypervisor attached
//! — Proxmox adds a USB tablet by default on some machine types — so the device
//! is found by *capability*. `/sys/class/input/eventN/device/capabilities/key`
//! is the key bitmap the kernel already publishes as text, and the button is
//! whichever device claims `KEY_POWER`.
//!
//! Reading a bitmap out of sysfs rather than asking the device with
//! `EVIOCGBIT` is not a workaround. Axiom A1 forbids `unsafe`, and rustix's
//! ioctl interface requires it of the caller; sysfs is the same information
//! through an interface made of text.

use core::fmt;
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

/// Where the kernel publishes one directory per input device.
const SYS_CLASS_INPUT: &str = "/sys/class/input";

/// Where devtmpfs puts the event nodes.
const DEV_INPUT: &str = "/dev/input/";

/// `EV_KEY`, from `include/uapi/linux/input-event-codes.h`.
const EV_KEY: u16 = 0x01;

/// `KEY_POWER`, from the same header. The ACPI power button, the one a
/// hypervisor's "shutdown" control presses.
const KEY_POWER: u16 = 116;

/// A key event's `value` for a press. Releases are `0` and autorepeat is `2`;
/// only the press is acted on, so holding the button does not queue a second
/// shutdown.
const PRESSED: i32 = 1;

/// `struct input_event` begins with a `struct timeval`, which is two `long`s.
///
/// Sized from `usize` rather than written as 16, because that is the same width
/// as the kernel's `long` for a native process on every target this builds for.
/// A 32-bit userland on a 64-bit kernel would disagree, and there is no such
/// build here — both bare-metal targets are 64-bit, and the aarch64 one turns
/// `CONFIG_COMPAT` off so its kernel has no 32-bit entry points to disagree
/// through (`OS-032`, #376).
const TIME_BYTES: usize = size_of::<usize>().saturating_mul(2);

/// Offset of `__u16 type`.
const TYPE_AT: usize = TIME_BYTES;
/// Offset of `__u16 code`.
const CODE_AT: usize = TIME_BYTES.saturating_add(2);
/// Offset of `__s32 value`.
const VALUE_AT: usize = TIME_BYTES.saturating_add(4);
/// The whole record: a `timeval`, two `__u16` and one `__s32`.
const EVENT_BYTES: usize = TIME_BYTES.saturating_add(8);

/// How many events one read may collect. Evdev hands over whole records, and a
/// button press arrives as two — the key event and the `EV_SYN` that ends the
/// packet.
const BATCH: usize = 16;

/// The watcher's read buffer.
const BUFFER_BYTES: usize = EVENT_BYTES.saturating_mul(BATCH);

/// Why no power button is being watched.
#[derive(Debug)]
pub(crate) enum NoButton {
    /// `/sys/class/input` could not be listed, which on this target means the
    /// input subsystem is not in the kernel.
    NoInputSubsystem(Errno),
    /// The subsystem is there and nothing in it claims `KEY_POWER`.
    NoDeviceClaimsPower,
    /// Every candidate node failed to open, with the reasons.
    NoDeviceOpened(String),
    /// The watcher thread would not start.
    Watcher(std::io::Error),
}

impl fmt::Display for NoButton {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInputSubsystem(error) => write!(formatter, "{SYS_CLASS_INPUT}: {error}"),
            Self::NoDeviceClaimsPower => {
                write!(formatter, "no input device claims KEY_POWER")
            }
            Self::NoDeviceOpened(reasons) => write!(formatter, "no device opened: {reasons}"),
            Self::Watcher(error) => write!(formatter, "watcher thread: {error}"),
        }
    }
}

/// Watch every device that claims `KEY_POWER` and drain on a press
/// (`OS-026`, #343).
///
/// Returns the event nodes now being watched, or the reason none is. One
/// thread per device: there are one or two of them for the life of the machine,
/// and a blocking read is what `kmsrs-os` already does for the reaper, so this
/// adds no event loop beside the driver's (`ARCH-005`, #5; `OS-024`, #340).
///
/// # Errors
///
/// Returns [`NoButton`] when nothing is being watched. That is not fatal — it
/// is the state this target shipped in until this issue — but it means
/// `qm shutdown` does nothing, so the caller says so on the console.
pub(crate) fn watch_power_button() -> Result<Vec<String>, NoButton> {
    let candidates = power_button_nodes().map_err(NoButton::NoInputSubsystem)?;
    if candidates.is_empty() {
        return Err(NoButton::NoDeviceClaimsPower);
    }

    let mut watching = Vec::new();
    let mut refused = Vec::new();
    for node in candidates {
        match open_event_node(&node) {
            Ok(fd) => {
                let named = node.clone();
                match std::thread::Builder::new()
                    .name("power".to_owned())
                    .spawn(move || watch(&named, &fd))
                {
                    // Deliberately not joined: it runs until the button is
                    // pressed or the machine ends.
                    Ok(handle) => {
                        drop(handle);
                        watching.push(node);
                    }
                    Err(error) => return Err(NoButton::Watcher(error)),
                }
            }
            Err(error) => refused.push(format!("{node}: {error}")),
        }
    }

    if watching.is_empty() {
        return Err(NoButton::NoDeviceOpened(refused.join(", ")));
    }
    Ok(watching)
}

/// Ask this host to drain and stop, as if the operator had sent SIGTERM
/// (`OS-026`, #343).
///
/// The single entry point for "something outside this process wants the machine
/// to stop". The power button calls it; `OS-022` (#338)'s `guest-shutdown` is
/// meant to call it too, so that a hypervisor gets the same drain whichever of
/// the two mechanisms it reaches for.
///
/// `source` names what asked, and appears on the console. That matters more
/// here than it looks: the alternative is an operator seeing a host stop with
/// no record of who told it to.
pub(crate) fn request_shutdown(source: &str) {
    // Through the tee of `OS-028` (#345), so it lands on every console rather
    // than only on whichever one the command line ended with.
    println!("{{\"level\":\"info\",\"event\":\"power\",\"detail\":\"{source}: draining\"}}");

    match rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM) {
        Ok(()) => {}
        Err(error) => {
            println!(
                "{{\"level\":\"warn\",\"event\":\"power\",\"detail\":\"{source}: \
                 could not signal this process: {error}\"}}"
            );
        }
    }
}

/// Stop the machine, now that the drain has finished (`OS-026`, #343).
///
/// The other half of handling the button, and the half that is easy to leave
/// out. Without it, `serve` returns, `main` returns, and **pid 1 exiting is a
/// kernel panic** — `Attempted to kill init!`. With `panic=-1` on the command
/// line the machine does then stop, so a check that only asserted "the VM is no
/// longer running" would pass; what an operator would see is an oops on the
/// noVNC console after pressing Shutdown, which is indistinguishable from a
/// crash.
///
/// `reboot(2)` with `LINUX_REBOOT_CMD_POWER_OFF` is the ACPI power-off the
/// hypervisor asked for in the first place, so the guest stops the way `qm
/// shutdown` means and Proxmox records a clean stop.
///
/// Returns the error if the syscall failed, in which case the caller should go
/// on returning and let the panic stop the machine — ugly, but stopping is
/// still what was asked for.
pub(crate) fn power_off(reason: &str) -> Option<Errno> {
    println!("{{\"level\":\"info\",\"event\":\"power\",\"detail\":\"{reason}: powering off\"}}");

    // The line above is in a pipe, not on a console: `OS-028` (#345) put a pump
    // thread between this process and the hardware, and `reboot(2)` does not
    // return. Long enough for a 115200 serial port to have taken several lines,
    // and irrelevant on a shutdown path that the hypervisor allows seconds for.
    std::thread::sleep(SETTLE);

    rustix::system::reboot(rustix::system::RebootCommand::PowerOff).err()
}

/// How long to let the console pump catch up before the machine stops.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(250);

/// Read events from one device until it says the button was pressed.
///
/// Returns after the first press. A second press is not needed and would not
/// help — the drain is already running, and the operator pressing again is
/// asking for something this program deliberately does not do, which is stop
/// without draining. That escalation belongs to the signal handler, which
/// already implements it for a second SIGTERM.
fn watch(node: &str, fd: &OwnedFd) {
    let mut buffer = [0_u8; BUFFER_BYTES];
    loop {
        let read = match rustix::io::read(fd, &mut buffer[..]) {
            Ok(0) => return,
            Ok(read) => read,
            Err(Errno::INTR) => continue,
            Err(error) => {
                println!(
                    "{{\"level\":\"warn\",\"event\":\"power\",\"detail\":\"{node}: {error}\"}}"
                );
                return;
            }
        };
        let records = buffer.get(..read).unwrap_or_default();
        if records.chunks_exact(EVENT_BYTES).any(is_power_press) {
            request_shutdown("acpi power button");
            return;
        }
    }
}

/// Whether one `struct input_event` is a press of the power button.
fn is_power_press(record: &[u8]) -> bool {
    read_u16(record, TYPE_AT) == Some(EV_KEY)
        && read_u16(record, CODE_AT) == Some(KEY_POWER)
        && read_i32(record, VALUE_AT) == Some(PRESSED)
}

/// A native-endian `u16` at an offset, or `None` if the record is short.
///
/// Native endianness because the kernel wrote the struct for this machine; this
/// is a memory layout, not a wire format, and the `TryFrom`-only rule for wire
/// handling is about the other thing.
fn read_u16(record: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let bytes: [u8; 2] = record.get(at..end)?.try_into().ok()?;
    Some(u16::from_ne_bytes(bytes))
}

/// A native-endian `i32` at an offset, or `None` if the record is short.
fn read_i32(record: &[u8], at: usize) -> Option<i32> {
    let end = at.checked_add(4)?;
    let bytes: [u8; 4] = record.get(at..end)?.try_into().ok()?;
    Some(i32::from_ne_bytes(bytes))
}

/// The `eventN` names of every input device that claims `KEY_POWER`.
fn power_button_nodes() -> Result<Vec<String>, Errno> {
    let directory = rustix::fs::open(
        SYS_CLASS_INPUT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;

    let mut nodes = Vec::new();
    for entry in rustix::fs::Dir::read_from(&directory)? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        // `/sys/class/input` holds `inputN` and `eventN` alike; only the latter
        // has a node under /dev to read events from.
        if !name.starts_with("event") {
            continue;
        }
        let bitmap = format!("{SYS_CLASS_INPUT}/{name}/device/capabilities/key");
        let Ok(contents) = read_sysfs(&bitmap) else {
            continue;
        };
        if capability_bit(&contents, u32::from(KEY_POWER)) {
            nodes.push(name.to_owned());
        }
    }
    // `read_from` yields directory order, which is arbitrary. Sorted so that a
    // machine with two candidates logs them the same way every boot.
    nodes.sort();
    Ok(nodes)
}

/// Whether `bit` is set in a sysfs capability bitmap.
///
/// The kernel prints these as `unsigned long` groups in hex, separated by
/// spaces, **most significant group first** and with no zero padding:
///
/// ```text
/// 0 0 0 0 0 0 0 0 0 0 0 0 0 0 10000000000000 0
/// ```
///
/// So the group holding bit *n* is counted from the end of the list, not the
/// start — which is the detail that makes hand-rolling this worth a test.
fn capability_bit(bitmap: &str, bit: u32) -> bool {
    let per_group = usize::BITS;
    let (Some(group_from_end), Some(offset)) =
        (bit.checked_div(per_group), bit.checked_rem(per_group))
    else {
        return false;
    };

    let groups: Vec<&str> = bitmap.split_whitespace().collect();
    let Some(index) = usize::try_from(group_from_end)
        .ok()
        .and_then(|from_end| groups.len().checked_sub(1)?.checked_sub(from_end))
    else {
        return false;
    };
    let Some(Ok(value)) = groups
        .get(index)
        .map(|group| u64::from_str_radix(group, 16))
    else {
        return false;
    };
    value
        .checked_shr(offset)
        .is_some_and(|shifted| shifted & 1 == 1)
}

/// Open one event node for reading.
fn open_event_node(node: &str) -> Result<OwnedFd, Errno> {
    let mut path = String::with_capacity(DEV_INPUT.len().saturating_add(node.len()));
    path.push_str(DEV_INPUT);
    path.push_str(node);
    rustix::fs::open(
        path.as_str(),
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Read a sysfs attribute, which is a short line the kernel formats on demand
/// and whose `stat` size is a page rather than its length.
fn read_sysfs(path: &str) -> Result<String, Errno> {
    let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut out = Vec::new();
    let mut buffer = [0_u8; 512];
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

    use super::{
        CODE_AT, EV_KEY, EVENT_BYTES, KEY_POWER, PRESSED, TYPE_AT, VALUE_AT, capability_bit,
        is_power_press,
    };

    /// Build one `struct input_event` the way the kernel would.
    fn event(kind: u16, code: u16, value: i32) -> Vec<u8> {
        let mut record = vec![0_u8; EVENT_BYTES];
        record[TYPE_AT..TYPE_AT + 2].copy_from_slice(&kind.to_ne_bytes());
        record[CODE_AT..CODE_AT + 2].copy_from_slice(&code.to_ne_bytes());
        record[VALUE_AT..VALUE_AT + 4].copy_from_slice(&value.to_ne_bytes());
        record
    }

    #[test]
    fn a_power_press_is_recognised() {
        assert!(is_power_press(&event(EV_KEY, KEY_POWER, PRESSED)));
    }

    /// The release is the second half of every press, and acting on it would
    /// mean draining twice.
    #[test]
    fn a_release_is_not_a_press() {
        assert!(!is_power_press(&event(EV_KEY, KEY_POWER, 0)));
    }

    /// Autorepeat, which a held button produces.
    #[test]
    fn autorepeat_is_not_a_press() {
        assert!(!is_power_press(&event(EV_KEY, KEY_POWER, 2)));
    }

    /// Proxmox attaches a USB tablet by default on some machine types, so a
    /// device that is not the button is the normal case, not the edge one.
    #[test]
    fn another_key_is_not_the_power_button() {
        // KEY_ESC.
        assert!(!is_power_press(&event(EV_KEY, 1, PRESSED)));
        // EV_SYN, which ends every packet.
        assert!(!is_power_press(&event(0, 0, 0)));
    }

    #[test]
    fn a_short_record_is_not_a_press() {
        assert!(!is_power_press(&[]));
        assert!(!is_power_press(&event(EV_KEY, KEY_POWER, PRESSED)[..4]));
    }

    /// The real bitmap of the ACPI power button, as `/sys` prints it on the
    /// shipped kernel: `KEY_POWER` is bit 116, so it lands in the second group
    /// counted from the end, at offset 52.
    #[test]
    fn the_power_button_bitmap_is_read_from_the_right_end() {
        let acpi_button = "10000000000000 0";
        assert!(capability_bit(acpi_button, u32::from(KEY_POWER)));
        // KEY_ESC (1) is in the last group and is not set here.
        assert!(!capability_bit(acpi_button, 1));
    }

    /// A tablet's bitmap: keys in the low groups, nothing at 116.
    #[test]
    fn a_pointing_device_is_not_the_power_button() {
        let tablet = "1f0000 0 0 0 0";
        assert!(!capability_bit(tablet, u32::from(KEY_POWER)));
    }

    #[test]
    fn a_bitmap_that_is_not_one_claims_nothing() {
        assert!(!capability_bit("", u32::from(KEY_POWER)));
        assert!(!capability_bit("zzz", u32::from(KEY_POWER)));
        // Too few groups to reach bit 116.
        assert!(!capability_bit("ffffffffffffffff", u32::from(KEY_POWER)));
    }
}
