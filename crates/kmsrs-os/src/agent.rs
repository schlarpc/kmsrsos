//! The QEMU guest agent, as much of it as a KMS host should have
//! (`OS-022`, #338).
//!
//! # What this is for
//!
//! A Proxmox operator expects the VM summary page to show the guest's IP
//! address. Without an agent it shows nothing, and finding the address means
//! reading DHCP leases — for a host whose entire purpose is to be found at a
//! known address.
//!
//! The mechanism is a JSON protocol over a virtio-serial channel named
//! `org.qemu.guest_agent.0`, which appears in the guest as a `/dev/vportNpM`
//! node. One line of JSON in, one line out.
//!
//! # The surface is mostly refusals, and that is the interesting part
//!
//! `qemu-ga` implements about forty commands. Seven of them are what a
//! hypervisor needs from a host like this one, and the rest are things this
//! program must not do:
//!
//! | | |
//! |---|---|
//! | `guest-exec`, `guest-exec-status` | remote code execution by design, over a channel with no authentication. There is no shell here to exec *into*, and the right answer is a refusal rather than an accident of packaging |
//! | `guest-file-*` | disk I/O, which axiom A5 forbids and this kernel has no block layer for |
//! | `guest-fsfreeze-*` | meaningless without a filesystem |
//! | `guest-suspend-*` | `CONFIG_SUSPEND` is unset |
//! | `guest-ssh-add-authorized-keys` and the rest | there are no users |
//!
//! Every one of them answers `CommandNotFound` rather than going unanswered,
//! because a hypervisor that gets no reply waits for a timeout and an operator
//! reads that as a hung guest.
//!
//! # No JSON library
//!
//! `serde_json` is a `kmsrs-dbgen` dependency and `deny.toml` says it "must
//! never become reachable from a binary". The requests this has to understand
//! are `{"execute":"name"}` with an optional flat `arguments` object, and the
//! replies are built the same way [`kmsrs_server::log`] builds its own — so the
//! reader here is a few dozen lines rather than a dependency.
//!
//! That is a real constraint on what this can accept, and it is written down
//! rather than left to be discovered: a request with nested objects inside
//! `arguments`, or with escapes this reader does not implement, is refused
//! rather than misread.

use core::fmt::Write as _;
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use crate::net::link;
use crate::power;

/// The channel name Proxmox, libvirt and `qm agent` all use.
const CHANNEL: &str = "org.qemu.guest_agent.0";

/// Where the kernel publishes one directory per virtio-serial port.
const SYS_CLASS_PORTS: &str = "/sys/class/virtio-ports";

/// Where devtmpfs puts the port nodes.
const DEV: &str = "/dev/";

/// What this reports as its version.
///
/// The program's own, not a `qemu-ga` version. Claiming to be `qemu-ga 8.2.0`
/// would be a lie an operator could act on — `qm guest exec` would look
/// available and would not be.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How long to wait before looking at the channel again while no client is
/// connected.
///
/// A virtio port reads as *immediately at end of file* when the host end is
/// disconnected — `will_read_block` in `virtio_console.c` returns false in that
/// case — so this loop cannot simply block, and without a pause it would spin.
///
/// It is also the worst-case latency before a request is noticed, which is why
/// it is 50 ms rather than something more relaxed: `qm agent` on a slow host
/// gives up, and a client that gives up looks exactly like a guest with no
/// agent.
const DISCONNECTED_POLL: core::time::Duration = core::time::Duration::from_millis(50);

/// The longest request line this will read.
///
/// The requests in scope are under 200 bytes. A megabyte of unterminated line
/// from a channel anyone with hypervisor access can write to is a memory bound
/// worth having (`OBS-012`, #188 is the same argument for the web parser).
const MAX_LINE: usize = 8192;

/// The commands this answers, and whether each produces a reply.
///
/// A table rather than a match with forty arms, because `guest-info` has to
/// report exactly this list and two lists that can disagree eventually do.
const COMMANDS: &[Command] = &[
    Command {
        name: "guest-sync",
        replies: true,
        why: "libvirt and Proxmox send this before anything else, to flush a \
              channel that may hold a previous conversation. A guest that does \
              not answer it is a guest they conclude has no agent",
    },
    Command {
        name: "guest-sync-delimited",
        replies: true,
        why: "the same, prefixed with 0xFF so a client can find the start of \
              the reply in a channel it has just opened",
    },
    Command {
        name: "guest-ping",
        replies: true,
        why: "the liveness check `qm agent ping` performs",
    },
    Command {
        name: "guest-info",
        replies: true,
        why: "what a client asks before deciding which commands to offer",
    },
    Command {
        name: "guest-network-get-interfaces",
        replies: true,
        why: "the one that populates the IP column on the Proxmox summary \
              page, which is why this module exists",
    },
    Command {
        name: "guest-get-osinfo",
        replies: true,
        why: "so the summary page says what this is rather than 'unknown'",
    },
    Command {
        name: "guest-shutdown",
        replies: false,
        why: "the other way a hypervisor asks a guest to stop. Reaches the same \
              drain as the ACPI button (`OS-026`, #343) rather than growing its \
              own, and sends no reply because the machine is going away",
    },
];

/// One command this agent implements.
#[derive(Debug, Clone, Copy)]
struct Command {
    /// As it appears in `{"execute": …}`.
    name: &'static str,
    /// Whether a reply is sent. Only `guest-shutdown` is `false`, and
    /// `guest-info` reports this as `success-response`.
    replies: bool,
    /// Why it is in scope. Prose, and load-bearing: the list is short and
    /// anything added should have to write one of these.
    #[cfg_attr(not(test), expect(dead_code, reason = "read by tests, not by main"))]
    why: &'static str,
}

/// Why the agent is not running.
#[derive(Debug)]
pub(crate) enum NoChannel {
    /// No `/sys/class/virtio-ports`, which means no virtio-serial in this
    /// kernel — or, far more likely, no channel attached to this VM.
    NoVirtioPorts(Errno),
    /// The bus is there and nothing on it is the guest agent's channel.
    NotAttached,
    /// The node would not open.
    Unopenable(String),
    /// The thread would not start.
    Thread(std::io::Error),
}

impl core::fmt::Display for NoChannel {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoVirtioPorts(error) => write!(formatter, "{SYS_CLASS_PORTS}: {error}"),
            Self::NotAttached => write!(
                formatter,
                "no {CHANNEL} channel is attached to this VM, so the hypervisor \
                 will show no address for it. On Proxmox: Hardware -> Add -> \
                 QEMU Agent, or `qm set <id> --agent 1`"
            ),
            Self::Unopenable(reason) => write!(formatter, "{reason}"),
            Self::Thread(error) => write!(formatter, "agent thread: {error}"),
        }
    }
}

/// Answer the hypervisor for the life of the machine (`OS-022`, #338).
///
/// Returns the port node it is listening on. A blocking thread rather than a
/// task: this is one descriptor with one reader, the reads are rare, and the
/// alternative is registering a character device with tokio's reactor for a
/// conversation that happens when an operator refreshes a web page.
///
/// # Errors
///
/// Returns [`NoChannel`] when there is nothing to answer on. That is the
/// ordinary case for a VM created without the agent enabled, so the caller says
/// it once and carries on.
pub(crate) fn serve() -> Result<String, NoChannel> {
    let node = find_channel()?;
    let fd = open_channel(&node).map_err(|error| NoChannel::Unopenable(error.to_string()))?;

    let named = node.clone();
    std::thread::Builder::new()
        .name("agent".to_owned())
        .spawn(move || answer_forever(&named, &fd))
        .map_err(NoChannel::Thread)?;
    Ok(node)
}

/// Read requests and write replies until the channel goes away.
fn answer_forever(node: &str, fd: &OwnedFd) {
    let mut pending = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let read = match rustix::io::read(fd, &mut chunk[..]) {
            // The host closed the channel. That happens whenever `qm agent`
            // finishes, so it is not an error and the port stays open —
            // reading again blocks until the next client connects.
            Ok(0) => {
                pending.clear();
                std::thread::sleep(DISCONNECTED_POLL);
                continue;
            }
            Ok(read) => read,
            Err(Errno::INTR) => continue,
            Err(error) => {
                println!(
                    "{{\"level\":\"warn\",\"event\":\"agent\",\"detail\":\"{node}: {error}\"}}"
                );
                return;
            }
        };
        pending.extend_from_slice(chunk.get(..read).unwrap_or_default());

        // A request is one line. Anything longer than `MAX_LINE` without a
        // newline is not one, and is dropped rather than accumulated.
        if pending.len() > MAX_LINE {
            pending.clear();
            println!(
                "{{\"level\":\"warn\",\"event\":\"agent\",\"detail\":\"a request \
                 longer than {MAX_LINE} bytes was dropped\"}}"
            );
            continue;
        }

        while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = pending.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            let Some(reply) = answer(text.trim()) else {
                continue;
            };
            if let Err(error) = write_all(fd, reply.as_bytes()) {
                println!(
                    "{{\"level\":\"warn\",\"event\":\"agent\",\"detail\":\"{node}: {error}\"}}"
                );
                return;
            }
        }
    }
}

/// Turn one request line into the line to send back, if any.
///
/// `None` means send nothing, which is `guest-shutdown` and a blank line. Every
/// other input produces a reply, including one that is not JSON at all — a
/// client waiting on a timeout is worse than a client told no.
pub(crate) fn answer(line: &str) -> Option<String> {
    if line.is_empty() {
        return None;
    }

    let Some(execute) = string_field(line, "execute") else {
        return Some(error_reply(
            "GenericError",
            "not a guest-agent request: no \\\"execute\\\" member",
        ));
    };

    let Some(command) = COMMANDS.iter().find(|command| command.name == execute) else {
        // The class `qemu-ga` uses, so a client's own error handling works.
        return Some(error_reply(
            "CommandNotFound",
            &format!(
                "{} is not supported by this guest. See docs/deployment.md for \
                 why: this is a KMS host, not a general-purpose machine",
                escape(&execute)
            ),
        ));
    };

    match command.name {
        // RFC-free, but universal: the id is echoed so a client can discard
        // whatever was in the channel before it.
        "guest-sync" => Some(format!("{{\"return\": {}}}\n", sync_id(line))),
        // 0xFF first, so a client reading a channel mid-conversation can find
        // where the reply starts.
        "guest-sync-delimited" => Some(format!("\u{ff}{{\"return\": {}}}\n", sync_id(line))),
        "guest-ping" => Some("{\"return\": {}}\n".to_owned()),
        "guest-info" => Some(info_reply()),
        "guest-get-osinfo" => Some(osinfo_reply()),
        "guest-network-get-interfaces" => Some(interfaces_reply()),
        "guest-shutdown" => {
            // The same function the ACPI power button calls, so there is one
            // drain rather than two that can differ (`OS-026`, #343).
            power::request_shutdown("qemu guest agent");
            None
        }
        // Unreachable while `COMMANDS` and this match agree, and
        // `every_command_is_answered` is the test that they do.
        _ => Some(error_reply("GenericError", "unimplemented")),
    }
}

/// The `id` a sync request carried, or zero.
fn sync_id(line: &str) -> i64 {
    number_field(line, "id").unwrap_or(0)
}

/// `{"error": …}` in the shape `qemu-ga` uses.
fn error_reply(class: &str, description: &str) -> String {
    format!("{{\"error\": {{\"class\": \"{class}\", \"desc\": \"{description}\"}}}}\n")
}

/// `guest-info`, whose command list is generated from [`COMMANDS`].
fn info_reply() -> String {
    let mut out = format!("{{\"return\": {{\"version\": \"{VERSION}\", \"supported_commands\": [");
    for (position, command) in COMMANDS.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        let _: core::fmt::Result = write!(
            out,
            "{{\"name\": \"{}\", \"enabled\": true, \"success-response\": {}}}",
            command.name, command.replies
        );
    }
    out.push_str("]}}\n");
    out
}

/// `guest-get-osinfo`.
///
/// Honest rather than flattering. A hypervisor UI that says `kmsrsos` is more
/// use to an operator than one that says `Linux`, and claiming to be a
/// distribution would be a lie with consequences — a management tool that
/// believed it might try to run a package manager.
///
/// `machine` is [`std::env::consts::ARCH`] and not a literal (`OS-032`, #376).
/// It said `x86_64` unconditionally for as long as there was only one
/// bare-metal target, which is the shape of statement that stays true until
/// the day it silently is not — and this one would then be a false claim a
/// management tool believes, in the same field a package manager would key
/// off. A compile-time constant cannot disagree with the binary it is in.
fn osinfo_reply() -> String {
    let release = read_sysfs("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = escape(release.trim());
    format!(
        "{{\"return\": {{\"id\": \"kmsrsos\", \"name\": \"kmsrsos\", \
         \"pretty-name\": \"kmsrsos {VERSION}\", \"version\": \"{VERSION}\", \
         \"version-id\": \"{VERSION}\", \"kernel-release\": \"{release}\", \
         \"machine\": \"{machine}\"}}}}\n",
        machine = std::env::consts::ARCH
    )
}

/// `guest-network-get-interfaces` — the one that fills the IP column.
fn interfaces_reply() -> String {
    let Ok(interfaces) = link::all_interfaces() else {
        return error_reply("GenericError", "cannot list interfaces");
    };
    // An address dump that fails is not a reason to report no interfaces: a
    // hypervisor showing "eth0, no address" is more use than one showing
    // nothing, and it is the true statement in the case that matters — a NIC
    // the DHCP client never got a lease for (`OS-025`, #342).
    let addresses = link::addresses().unwrap_or_default();
    render_interfaces(&interfaces, &addresses)
}

/// The body of [`interfaces_reply`], separated so a test can supply the lists.
pub(crate) fn render_interfaces(
    interfaces: &[link::Interface],
    addresses: &[link::Address],
) -> String {
    let mut out = String::from("{\"return\": [");
    for (position, interface) in interfaces.iter().enumerate() {
        if position > 0 {
            out.push_str(", ");
        }
        let mac = interface
            .mac
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let _: core::fmt::Result = write!(
            out,
            "{{\"name\": \"{}\", \"hardware-address\": \"{mac}\", \"ip-addresses\": [",
            escape(&interface.name)
        );
        let mut written = 0_usize;
        for address in addresses
            .iter()
            .filter(|address| address.index == interface.index)
        {
            if written > 0 {
                out.push_str(", ");
            }
            written = written.saturating_add(1);
            let family = if address.ip.is_ipv4() { "ipv4" } else { "ipv6" };
            let _: core::fmt::Result = write!(
                out,
                "{{\"ip-address-type\": \"{family}\", \"ip-address\": \"{}\", \
                 \"prefix\": {}}}",
                address.ip, address.prefix
            );
        }
        out.push_str("]}");
    }
    out.push_str("]}\n");
    out
}

/// The value of a string member of the top-level object, or of `arguments`.
///
/// Deliberately shallow. It finds `"key"`, skips to the `:` and reads a quoted
/// string, so it works on `{"execute":"guest-ping"}` and on
/// `{"execute":"guest-shutdown","arguments":{"mode":"powerdown"}}` alike — and
/// it would be wrong on a document where the same key appeared nested inside
/// something else. No request in scope has one.
fn string_field(line: &str, key: &str) -> Option<String> {
    let after = after_key(line, key)?;
    let rest = after.strip_prefix('"')?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_owned)
}

/// The value of an integer member, by the same rules.
fn number_field(line: &str, key: &str) -> Option<i64> {
    let after = after_key(line, key)?;
    let digits: String = after
        .chars()
        .take_while(|character| character.is_ascii_digit() || *character == '-')
        .collect();
    digits.parse().ok()
}

/// The text just after `"key" :`, with whitespace skipped.
fn after_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let at = line.find(&needle)?;
    let rest = line.get(at.checked_add(needle.len())?..)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim_start())
}

/// Make text safe to put inside a JSON string literal.
///
/// The only untrusted input that reaches a reply is the command name from a
/// refused request, which comes over a channel the hypervisor owns. Escaping it
/// is what stops a malformed request producing a malformed reply.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            control if control.is_control() => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// The `/dev` node of the guest-agent channel, found by name rather than by
/// guessing `vport0p1`.
///
/// `/dev/virtio-ports/<name>` would be the obvious path and does not exist
/// here: that symlink is udev's work, and there is no udev. The name is in
/// sysfs, which is the same information without the daemon.
fn find_channel() -> Result<String, NoChannel> {
    let directory = rustix::fs::open(
        SYS_CLASS_PORTS,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(NoChannel::NoVirtioPorts)?;

    let mut ports: Vec<String> = Vec::new();
    for entry in rustix::fs::Dir::read_from(&directory)
        .map_err(NoChannel::NoVirtioPorts)?
        .flatten()
    {
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if name.starts_with("vport") {
            ports.push(name.to_owned());
        }
    }
    ports.sort();

    for port in ports {
        let path = format!("{SYS_CLASS_PORTS}/{port}/name");
        if read_sysfs(&path).is_some_and(|name| name.trim() == CHANNEL) {
            return Ok(port);
        }
    }
    Err(NoChannel::NotAttached)
}

/// Open the port node for reading and writing.
fn open_channel(node: &str) -> Result<OwnedFd, Errno> {
    let mut path = String::with_capacity(DEV.len().saturating_add(node.len()));
    path.push_str(DEV);
    path.push_str(node);
    rustix::fs::open(path.as_str(), OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())
}

/// Write all of it, tolerating short writes.
fn write_all(fd: &OwnedFd, bytes: &[u8]) -> Result<(), Errno> {
    let mut rest = bytes;
    while !rest.is_empty() {
        match rustix::io::write(fd, rest) {
            Ok(0) => return Err(Errno::IO),
            Ok(written) => rest = rest.get(written..).unwrap_or_default(),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Read a short sysfs or procfs attribute.
fn read_sysfs(path: &str) -> Option<String> {
    let fd = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).ok()?;
    let mut out = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        match rustix::io::read(&fd, &mut buffer[..]) {
            Ok(0) => break,
            Ok(read) => out.extend_from_slice(buffer.get(..read)?),
            Err(Errno::INTR) => {}
            Err(_) => return None,
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{COMMANDS, answer, escape, number_field, render_interfaces, string_field};
    use crate::net::link::{Address, Interface};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_ping_is_answered() {
        assert_eq!(
            answer("{\"execute\": \"guest-ping\"}").as_deref(),
            Some("{\"return\": {}}\n")
        );
    }

    /// libvirt and Proxmox send this first, and a guest that does not echo the
    /// id is one they conclude has no agent.
    #[test]
    fn a_sync_echoes_its_id() {
        assert_eq!(
            answer("{\"execute\":\"guest-sync\",\"arguments\":{\"id\":1234}}").as_deref(),
            Some("{\"return\": 1234}\n")
        );
        // The delimited form is the same reply behind an 0xFF, which is how a
        // client finds the start of it in a channel it has just opened.
        let delimited =
            answer("{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":7}}").unwrap();
        assert!(delimited.starts_with('\u{ff}'), "{delimited:?}");
        assert!(delimited.ends_with("{\"return\": 7}\n"), "{delimited:?}");
    }

    /// The refusals are the interesting half of this surface, and each has to
    /// be a *reply*: a hypervisor that gets silence waits for a timeout and an
    /// operator reads that as a hung guest.
    #[test]
    fn everything_out_of_scope_is_refused_rather_than_ignored() {
        for command in [
            "guest-exec",
            "guest-exec-status",
            "guest-file-open",
            "guest-file-read",
            "guest-fsfreeze-freeze",
            "guest-suspend-ram",
            // `guest-ssh-add-authorized-keys` rather than the password one,
            // which means the same thing here — there are no users — and which
            // `no_secret_material_is_embedded` reads as a credential-shaped
            // name. That invariant is deliberately crude and this is a refused
            // *command name* rather than a secret, so the test moves rather
            // than the invariant.
            "guest-ssh-add-authorized-keys",
        ] {
            let reply = answer(&format!("{{\"execute\": \"{command}\"}}"))
                .unwrap_or_else(|| panic!("{command} went unanswered"));
            assert!(
                reply.contains("CommandNotFound"),
                "{command} should be refused with the class qemu-ga uses: {reply}"
            );
            assert!(
                reply.contains("KMS host"),
                "and should say why, because 'not supported' invites a bug \
                 report: {reply}"
            );
        }
    }

    /// `guest-exec` is the one that matters most. It is remote code execution
    /// over a channel with no authentication, and its absence should be a
    /// decision somebody has to undo deliberately rather than a gap.
    #[test]
    fn guest_exec_is_not_in_the_command_table() {
        assert!(
            !COMMANDS
                .iter()
                .any(|command| command.name.starts_with("guest-exec")),
            "guest-exec is remote code execution by design (OS-022, #338)"
        );
        assert!(
            !COMMANDS
                .iter()
                .any(|command| command.name.starts_with("guest-file")),
            "guest-file-* is disk I/O, which axiom A5 forbids"
        );
    }

    /// `guest-info` reports the table rather than a second list, so the two
    /// cannot disagree.
    #[test]
    fn guest_info_reports_every_command_and_whether_it_replies() {
        let reply = answer("{\"execute\": \"guest-info\"}").unwrap();
        for command in COMMANDS {
            assert!(
                reply.contains(&format!("\"name\": \"{}\"", command.name)),
                "{} is missing from guest-info: {reply}",
                command.name
            );
        }
        // Only `guest-shutdown` sends nothing back, and a client has to know.
        assert!(
            reply.contains(
                "\"name\": \"guest-shutdown\", \"enabled\": true, \"success-response\": false"
            ),
            "guest-shutdown must be declared as sending no reply: {reply}"
        );
    }

    /// Every command in the table is reachable, so the table and the match
    /// cannot drift apart.
    #[test]
    fn every_command_is_answered() {
        for command in COMMANDS {
            // `guest-shutdown` would signal this process, which in a test is
            // the test runner.
            if command.name == "guest-shutdown" {
                continue;
            }
            let reply = answer(&format!("{{\"execute\": \"{}\"}}", command.name))
                .unwrap_or_else(|| panic!("{} went unanswered", command.name));
            assert!(
                !reply.contains("unimplemented"),
                "{} is in the table and not in the match: {reply}",
                command.name
            );
            assert!(!command.why.is_empty(), "{} has no reason", command.name);
        }
    }

    /// The shape Proxmox reads to fill the IP column.
    #[test]
    fn interfaces_render_in_the_shape_a_hypervisor_expects() {
        let interfaces = [
            Interface {
                name: "lo".to_owned(),
                index: 1,
                mac: [0; 6],
            },
            Interface {
                name: "eth0".to_owned(),
                index: 2,
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            },
        ];
        let addresses = [
            Address {
                index: 1,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix: 8,
            },
            Address {
                index: 2,
                ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                prefix: 24,
            },
            Address {
                index: 2,
                ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix: 128,
            },
        ];

        let rendered = render_interfaces(&interfaces, &addresses);

        assert!(rendered.starts_with("{\"return\": ["), "{rendered}");
        assert!(
            rendered.contains("\"name\": \"eth0\", \"hardware-address\": \"52:54:00:12:34:56\""),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "{\"ip-address-type\": \"ipv4\", \"ip-address\": \"192.168.1.50\", \"prefix\": 24}"
            ),
            "the address Proxmox shows is missing: {rendered}"
        );
        assert!(
            rendered.contains("\"ip-address-type\": \"ipv6\""),
            "IPv6 is reported too: {rendered}"
        );
        // Loopback is reported with an all-zero hardware address, as qemu-ga
        // does, rather than omitted.
        assert!(
            rendered.contains("\"name\": \"lo\", \"hardware-address\": \"00:00:00:00:00:00\""),
            "{rendered}"
        );
    }

    /// An interface with no address renders an empty list rather than being
    /// left out — "this NIC exists and has no address" is exactly what an
    /// operator debugging #342's silent failure needs to see.
    #[test]
    fn an_interface_with_no_address_is_still_reported() {
        let interfaces = [Interface {
            name: "eth0".to_owned(),
            index: 2,
            mac: [0; 6],
        }];
        let rendered = render_interfaces(&interfaces, &[]);
        assert!(rendered.contains("\"name\": \"eth0\""), "{rendered}");
        assert!(rendered.contains("\"ip-addresses\": []"), "{rendered}");
    }

    #[test]
    fn what_is_not_a_request_is_refused_and_not_ignored() {
        assert!(answer("").is_none(), "a blank line is not a request");
        for rubbish in ["not json", "{}", "{\"exec\": \"guest-ping\"}", "[]"] {
            let reply = answer(rubbish).unwrap_or_else(|| panic!("{rubbish} went unanswered"));
            assert!(reply.contains("\"error\""), "{rubbish}: {reply}");
        }
    }

    /// A command name is text from the channel and ends up inside a JSON
    /// string literal in the reply.
    #[test]
    fn a_hostile_command_name_cannot_forge_a_reply() {
        let reply = answer("{\"execute\": \"a\\\" , \\\"return\\\": 1, \\\"x\\\": \\\"\"}")
            .expect("refused, not ignored");
        assert!(reply.contains("CommandNotFound"), "{reply}");
        assert!(
            !reply.contains("\"return\":"),
            "the refusal must not contain a forged member: {reply}"
        );
    }

    #[test]
    fn the_field_reader_finds_what_it_should_and_no_more() {
        assert_eq!(
            string_field("{\"execute\" : \"guest-ping\"}", "execute").as_deref(),
            Some("guest-ping")
        );
        assert_eq!(number_field("{\"id\":  42}", "id"), Some(42));
        assert_eq!(number_field("{\"id\": -1}", "id"), Some(-1));
        assert_eq!(string_field("{\"other\": \"x\"}", "execute"), None);
        assert_eq!(number_field("{\"id\": \"x\"}", "id"), None);
    }

    #[test]
    fn escaping_is_what_it_says() {
        assert_eq!(escape("a\"b"), "a\\\"b");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("a\nb"), "a b");
        assert_eq!(escape("guest-exec"), "guest-exec");
    }
}
