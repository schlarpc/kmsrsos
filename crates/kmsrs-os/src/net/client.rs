//! The task that runs the DHCP client (`OS-019`, #335).
//!
//! Everything that is not sans-io lives here: the socket, the clock, the
//! entropy, and the netlink calls that put a lease on an interface.
//! [`super::lease`] decides *what* to do and this decides *when* the doing
//! happens.
//!
//! # A plain UDP socket, not a raw one
//!
//! The usual objection is that a client with no address cannot receive a reply.
//! It can, because every message this sends before it has one sets the
//! broadcast flag (RFC 2131 §4.1), so the server broadcasts to
//! `255.255.255.255:68` and a socket bound to `0.0.0.0:68` gets it. What that
//! costs is that a *second* DHCP client on the same machine would see the same
//! datagrams — and there is no second client here, because there is no second
//! process.
//!
//! `SO_BINDTODEVICE` keeps the conversation on the interface the lease is for,
//! which matters on the multi-NIC machine [`super::link::choose`] warns about.
//!
//! # Why the address arriving late is not a problem
//!
//! The KMS listeners are already bound when this starts, because they bind
//! `0.0.0.0` and this program reads its own address for nothing (`NET-001`,
//! #150). So a DHCP server that is slow, or briefly absent, delays *clients
//! reaching* this host and never delays this host starting — and the boot does
//! not block on a lease. The alternative, waiting for an address before
//! binding, would make a DHCP outage into a KMS outage.

use core::time::Duration;
use dhcproto::v4::Message;
use dhcproto::{Decodable, Decoder, Encodable};
use kmsrs_server::facts::{Facts, Network};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;

use super::lease::{Action, Config, Lease};
use super::link::{self, Interface};
use super::sntp::Sources;
use tokio::sync::watch;

/// The port a DHCP client listens on.
const CLIENT_PORT: u16 = 68;

/// The port a DHCP server listens on.
const SERVER_PORT: u16 = 67;

/// Where a message goes when the client has no address and no server to unicast
/// to.
const EVERYONE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);

/// The largest datagram this will read.
///
/// The client advertises 1472 as the most it can reassemble (`MaxMessageSize`),
/// so anything longer is not a reply to us.
const MAX_DATAGRAM: usize = 1500;

/// How long to wait before retrying when the interface itself is not usable.
///
/// A hypervisor that attaches the NIC a moment after boot, or a switch port
/// still running spanning tree, both look like this. Retrying rather than
/// giving up, because giving up is the silent failure `OS-025` (#342) is about.
const RETRY_INTERFACE: Duration = Duration::from_secs(5);

/// Start the DHCP client (`OS-019`, #335).
///
/// Called from inside [`kmsrs_server::entry::serve_with`]'s runtime, so the
/// task it spawns is scheduled by the same executor as the KMS listeners and
/// there is no second runtime (`OS-024`, #340).
///
/// `seed` is entropy from the caller. Axiom A7 keeps the state machine free of
/// both clocks and generators, so the transaction ID and the retransmission
/// jitter are supplied rather than read.
pub(crate) fn spawn(facts: Facts, seed: u32, sources: watch::Sender<Sources>) {
    tokio::spawn(async move {
        run(facts, seed, sources).await;
    });
}

/// One line of JSON on every console, through the tee of `OS-028` (#345).
///
/// A function rather than the server's [`kmsrs_server::Logger`], for the same
/// reason `main` has one: this runs alongside the logger rather than under it,
/// and the shapes agree without being coupled.
fn say(level: &str, detail: &str) {
    println!(
        "{{\"level\":\"{level}\",\"event\":\"dhcp\",\"detail\":\"{}\"}}",
        escape(detail)
    );
}

/// Make a detail string safe to put inside a JSON string literal.
///
/// Everything logged here is either this program's own prose or a server's
/// option 56, and the second of those is remote input. Escaping it is what
/// stops a DHCP server injecting a field into this host's log.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' | '\t' => out.push(' '),
            control if control.is_control() => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// Run one netlink call on the blocking pool, flattening the join error.
///
/// A panic inside is reported as a failure rather than propagated: this is
/// pid 1, and an unwinding panic here would be a kernel panic on a host that
/// was otherwise serving.
async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, link::Failure> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(failure)) => Err(failure.to_string()),
        Err(join) => Err(join.to_string()),
    }
}

/// Take a lease and keep it, for the life of the machine.
///
/// `tokio::select!` picks its starting branch with a modulo over the branch
/// count, which trips `integer-division-remainder-used`. The arithmetic is the
/// macro's, not this program's.
#[expect(
    clippy::integer_division_remainder_used,
    reason = "tokio::select! expands to a modulo over its own branch count"
)]
async fn run(facts: Facts, seed: u32, sources: watch::Sender<Sources>) {
    let (interface, socket) = loop {
        match acquire_interface().await {
            Some(ready) => break ready,
            None => tokio::time::sleep(RETRY_INTERFACE).await,
        }
    };

    say(
        "info",
        &format!(
            "using {} ({})",
            interface.name,
            interface
                .mac
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        ),
    );

    let origin = tokio::time::Instant::now();
    let mut client = Lease::new(interface.mac, seed, Duration::ZERO);
    // What is currently on the interface, so a lease that moves can take the
    // old address off before putting the new one on.
    let mut applied: Option<(Ipv4Addr, u8)> = None;

    // The first thing to do is always "the deadline has passed", which from
    // INIT means DISCOVER.
    let mut pending = client.on_time(Duration::ZERO);
    let mut was = client.state();

    loop {
        for action in pending.drain(..) {
            perform(action, &socket, &interface, &facts, &sources, &mut applied).await;
        }

        // Every RFC 2131 transition, once each. This is the trace an operator
        // needs when a lease is not being renewed, and without it the only
        // visible symptom is an address that stops working hours after boot.
        let now_state = client.state();
        if now_state != was {
            say("info", &format!("{was:?} -> {now_state:?}"));
            was = now_state;
        }

        // `None` is the infinite lease of RFC 2131 §3.3, whose deadline is
        // `Duration::MAX` and does not fit on the clock. There is no timer in
        // that case, only the socket — which is correct: nothing is ever due.
        let mut datagram = vec![0_u8; MAX_DATAGRAM];
        let received = match origin.checked_add(client.deadline()) {
            Some(deadline) => tokio::select! {
                () = tokio::time::sleep_until(deadline) => None,
                received = socket.recv_from(&mut datagram) => Some(received),
            },
            None => Some(socket.recv_from(&mut datagram).await),
        };

        pending = match received {
            None => client.on_time(origin.elapsed()),
            Some(Ok((read, _from))) => {
                let bytes = datagram.get(..read).unwrap_or_default();
                match Message::decode(&mut Decoder::new(bytes)) {
                    Ok(message) => client.on_message(&message, origin.elapsed()),
                    // Not a DHCP message, or one this decoder will not take.
                    // Dropped rather than logged: on a busy segment this is
                    // somebody else's traffic, and logging it would be a line
                    // per broadcast.
                    Err(_) => Vec::new(),
                }
            }
            Some(Err(error)) => {
                // The socket is gone. Nothing here can rebuild it, and the host
                // keeps serving on whatever address it already has.
                say(
                    "error",
                    &format!(
                        "the DHCP socket failed: {error}; this host keeps its \
                         current address until it is restarted"
                    ),
                );
                return;
            }
        };
    }
}

/// Find a usable interface, bring it up, and bind a socket on it.
///
/// `None` means try again shortly. Each failure says why the first time it
/// happens — a machine with no usable interface must not report `listening` and
/// then sit silent, which is what `OS-025` (#342) was filed about.
async fn acquire_interface() -> Option<(Interface, UdpSocket)> {
    // Netlink is a blocking socket by choice (see `link`), and this runtime is
    // current-thread, so a round trip taken inline would stall the KMS
    // listeners with it. Microseconds either way; the point is that the rule is
    // the same everywhere rather than judged per call.
    let interfaces = match blocking(link::interfaces).await {
        Ok(interfaces) => interfaces,
        Err(error) => {
            say("error", &format!("cannot list interfaces: {error}"));
            return None;
        }
    };

    let Some((interface, note)) = link::choose(&interfaces) else {
        say(
            "error",
            "this machine has no Ethernet interface, so it will never have an \
             address and no client will ever reach it. The usual cause is a NIC \
             model with no driver in this kernel — see the supported list in \
             docs/deployment.md (OS-025, #342)",
        );
        return None;
    };
    if let Some(note) = note {
        say("warn", &note);
    }
    let interface = interface.clone();

    let index = interface.index;
    if let Err(error) = blocking(move || link::bring_up(index)).await {
        say(
            "error",
            &format!("cannot bring {} up: {error}", interface.name),
        );
        return None;
    }
    if link::has_carrier(&interface.name) == Some(false) {
        say(
            "warn",
            &format!(
                "{} has no carrier; asking anyway, in case the hypervisor is \
                 still attaching it",
                interface.name
            ),
        );
    }

    match bind_socket(&interface.name) {
        Ok(socket) => Some((interface, socket)),
        Err(error) => {
            say("error", &format!("cannot bind the DHCP port: {error}"));
            None
        }
    }
}

/// A UDP socket on port 68, broadcast-capable and pinned to one interface.
fn bind_socket(name: &str) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    // Without this, sending to 255.255.255.255 is EACCES.
    socket.set_broadcast(true)?;
    // The conversation stays on the interface the lease is for. On the
    // multi-NIC machine `link::choose` warns about, the alternative is a
    // DISCOVER leaving by whichever interface the routing table prefers, which
    // is the one with a default route — and there is no default route yet.
    socket.bind_device(Some(name.as_bytes()))?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT)).into())?;
    UdpSocket::from_std(socket.into())
}

/// Carry out one thing the state machine asked for.
async fn perform(
    action: Action,
    socket: &UdpSocket,
    interface: &Interface,
    facts: &Facts,
    sources: &watch::Sender<Sources>,
    applied: &mut Option<(Ipv4Addr, u8)>,
) {
    match action {
        Action::Broadcast(message) => send(socket, &message, EVERYONE).await,
        Action::Unicast(message, server) => {
            send(socket, &message, SocketAddrV4::new(server, SERVER_PORT)).await;
        }
        Action::Note(text) => say("info", &text),
        Action::Configure(config) => apply(&config, interface, facts, sources, applied).await,
        Action::Deconfigure => withdraw(interface, facts, sources, applied).await,
    }
}

/// Put a message on the wire.
async fn send(socket: &UdpSocket, message: &Message, to: SocketAddrV4) {
    let bytes = match message.to_vec() {
        Ok(bytes) => bytes,
        // A message this code built and cannot encode is a bug, not a network
        // condition. Said and dropped, because panicking here would be a kernel
        // panic — this is pid 1.
        Err(error) => {
            say("error", &format!("cannot encode a DHCP message: {error}"));
            return;
        }
    };
    if let Err(error) = socket.send_to(&bytes, SocketAddr::from(to)).await {
        // Normal while a link is still coming up: ENETDOWN and ENETUNREACH both
        // land here and both are fixed by the retransmission that follows.
        say("warn", &format!("cannot send to {to}: {error}"));
    }
}

/// Put a lease on the interface and publish what it taught us.
async fn apply(
    config: &Config,
    interface: &Interface,
    facts: &Facts,
    sources: &watch::Sender<Sources>,
    applied: &mut Option<(Ipv4Addr, u8)>,
) {
    // The address that is on the interface now, if it is not the one arriving.
    // Removing it first is what makes "a renewal returned a different address"
    // — the case `OS-019` (#335) singles out — leave one address behind rather
    // than two.
    if let Some((previous, prefix)) = *applied
        && previous != config.address
    {
        let index = interface.index;
        if let Err(error) = blocking(move || link::remove(index, previous, prefix)).await {
            say(
                "warn",
                &format!("cannot remove the old address {previous}: {error}"),
            );
        }
    }

    let index = interface.index;
    let owned = config.clone();
    match blocking(move || link::configure(index, &owned)).await {
        Ok(notes) => {
            *applied = Some((config.address, config.prefix));
            for note in notes {
                say("warn", &note);
            }
            say(
                "info",
                &format!(
                    "{}/{} on {}{}",
                    config.address,
                    config.prefix,
                    interface.name,
                    config.lease.map_or_else(
                        || ", lease does not expire".to_owned(),
                        |lease| format!(", lease {}s", lease.as_secs())
                    )
                ),
            );
            publish(facts, sources, Some(config));
        }
        Err(error) => say(
            "error",
            &format!(
                "cannot set {}/{} on {}: {error}; this host has an address the \
                 kernel does not know about, so nothing will reach it",
                config.address, config.prefix, interface.name
            ),
        ),
    }
}

/// Take the address off, because the lease is gone.
async fn withdraw(
    interface: &Interface,
    facts: &Facts,
    sources: &watch::Sender<Sources>,
    applied: &mut Option<(Ipv4Addr, u8)>,
) {
    let Some((address, prefix)) = applied.take() else {
        return;
    };
    let index = interface.index;
    let outcome = tokio::task::spawn_blocking(move || link::remove(index, address, prefix)).await;
    match outcome {
        Ok(Ok(())) => say("warn", &format!("{address} withdrawn")),
        Ok(Err(error)) => say("error", &format!("cannot withdraw {address}: {error}")),
        Err(error) => say(
            "error",
            &format!("withdrawing the address panicked: {error}"),
        ),
    }
    publish(facts, sources, None);
}

/// Tell the rest of the program what the lease said (`DISC-007`, #149).
///
/// The `/instructions` page renders the search domain into the SRV record it
/// tells an operator to publish, which it could not do before this issue
/// because the kernel's own DHCP client discarded options 15 and 119.
fn publish(facts: &Facts, sources: &watch::Sender<Sources>, config: Option<&Config>) {
    facts.publish(match config {
        Some(config) => Network {
            search_domains: config.search.clone(),
            address: Some(config.address),
        },
        None => Network::default(),
    });

    // `OS-020` (#336) wants option 42, and option 6 to resolve the pool with
    // when there is no option 42. Sent whether or not it changed: a `watch`
    // holds one value, so a renewal that says the same thing is a no-op the
    // reader never notices.
    let _: Result<(), watch::error::SendError<Sources>> = sources.send(match config {
        Some(config) => Sources {
            ntp: config.ntp.clone(),
            dns: config.dns.clone(),
        },
        None => Sources::default(),
    });
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::escape;

    /// Option 56 is a string a DHCP server chose, and it ends up inside a JSON
    /// string literal on this host's console. A server that sends a quote must
    /// not be able to add a field to the log.
    #[test]
    fn a_servers_message_cannot_forge_a_log_field() {
        let hostile = "no\",\"level\":\"error\",\"detail\":\"gotcha";
        let escaped = escape(hostile);
        assert!(!escaped.contains("\",\""), "quotes survived: {escaped}");
        assert!(escaped.contains("\\\""), "and are escaped: {escaped}");
    }

    #[test]
    fn control_characters_do_not_break_the_line() {
        assert_eq!(escape("a\nb\tc"), "a b c");
        assert_eq!(escape("a\\b"), "a\\\\b");
    }

    #[test]
    fn ordinary_text_is_unchanged() {
        assert_eq!(escape("192.168.1.50/24 on eth0"), "192.168.1.50/24 on eth0");
    }
}
