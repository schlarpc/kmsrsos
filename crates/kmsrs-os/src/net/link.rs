//! Finding the interface, and putting a lease on it (`OS-019`, #335).
//!
//! # Why netlink and not an ioctl
//!
//! `SIOCSIFADDR` is four lines and a dead end: it is IPv4-only, it cannot
//! express a prefix and a broadcast address together, and reaching it means an
//! `unsafe` ioctl, which axiom A1 does not allow. Netlink is a socket carrying
//! messages, so `netlink-packet-route` encodes and decodes them and nothing
//! here needs a raw syscall.
//!
//! # Blocking, deliberately
//!
//! `netlink-sys`'s `tokio` feature is off. Applying a lease is three round
//! trips to the local kernel that complete in microseconds, and they happen
//! once at boot and then once every few hours — registering a socket with the
//! reactor for that would cost more than it saves. The calls run on tokio's
//! blocking pool ([`tokio::task::spawn_blocking`] in [`super::client`]) so the
//! one scheduler still decides when they run.
//!
//! # What it does *not* do
//!
//! No DNS configuration is written anywhere, because there is nowhere to write
//! it: axiom A5 forbids `/etc/resolv.conf` and this machine has no resolver
//! reading one. The lease's option 6 is handed to `OS-020` (#336)'s resolver
//! directly instead, in memory.

use core::fmt;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkHeader,
    NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::{AddressAttribute, AddressMessage, AddressScope};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkLayerType, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{RouteNetlinkMessage, route::RouteHeader};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use std::net::{IpAddr, Ipv4Addr};

use super::lease::Config;

/// The loopback interface, which is never the one a KMS client reaches this
/// host on.
const LOOPBACK: &str = "lo";

/// The biggest netlink reply this reads.
///
/// A link dump on a machine with one NIC is a few hundred bytes; 32 KiB is the
/// conventional netlink receive buffer and leaves room for a machine somebody
/// gave eight interfaces.
const REPLY_BUFFER: usize = 32 * 1024;

/// An interface this host could take a lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Interface {
    /// `eth0`, `ens18`, whatever the kernel named it.
    pub(crate) name: String,
    /// The kernel's index, which every netlink message is addressed by.
    pub(crate) index: u32,
    /// The MAC, which is the client identifier and `chaddr`.
    pub(crate) mac: [u8; 6],
}

/// Something netlink would not do.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The socket could not be opened or bound.
    Socket(std::io::Error),
    /// A message could not be sent or a reply read.
    Exchange(std::io::Error),
    /// The kernel refused, with its errno.
    Refused(i32, String),
    /// A reply arrived that could not be parsed.
    Undecodable(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(error) => write!(formatter, "netlink socket: {error}"),
            Self::Exchange(error) => write!(formatter, "netlink: {error}"),
            Self::Refused(code, what) => {
                write!(formatter, "the kernel refused to {what}: errno {code}")
            }
            Self::Undecodable(what) => write!(formatter, "undecodable netlink reply: {what}"),
        }
    }
}

/// Every Ethernet interface that is not loopback, in kernel-index order
/// (`OS-019`, #335; `OS-025`, #342).
///
/// Sorted by index so a machine with two NICs picks the same one every boot.
/// Which one it should pick is a question this cannot answer — see
/// [`choose`] — and the honest answer is "the first, loudly".
///
/// # Errors
///
/// Returns [`Failure`] if the link dump could not be performed. That means the
/// kernel has no rtnetlink, which on this target means it was built wrong.
pub(crate) fn interfaces() -> Result<Vec<Interface>, Failure> {
    let mut socket = open()?;
    let mut request = LinkMessage::default();
    request.header.interface_family = AddressFamily::Unspec;

    let mut found = Vec::new();
    for reply in exchange(
        &mut socket,
        RouteNetlinkMessage::GetLink(request),
        NLM_F_REQUEST | NLM_F_DUMP,
        "list interfaces",
    )? {
        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) = reply else {
            continue;
        };
        // Ethernet only. A tunnel, a bridge or `lo` is not something to take a
        // DHCP lease on, and `LinkLayerType` is how the kernel says which.
        if link.header.link_layer_type != LinkLayerType::Ether {
            continue;
        }

        let mut name = None;
        let mut mac = None;
        for attribute in &link.attributes {
            match attribute {
                LinkAttribute::IfName(text) => name = Some(text.clone()),
                LinkAttribute::Address(bytes) => {
                    mac = <[u8; 6]>::try_from(bytes.as_slice()).ok();
                }
                _ => {}
            }
        }
        let (Some(name), Some(mac)) = (name, mac) else {
            continue;
        };
        if name == LOOPBACK {
            continue;
        }
        found.push(Interface {
            name,
            index: link.header.index,
            mac,
        });
    }

    found.sort_by_key(|interface| interface.index);
    Ok(found)
}

/// Which interface to take a lease on, and what to say about the choice.
///
/// This host binds `0.0.0.0` and does not read its own address (`NET-001`,
/// #150), so "which interface" is only a question about where the DHCP
/// conversation happens. With one interface — the deployment `docs/deployment.md`
/// describes and the only one `nix flake check` exercises — there is nothing to
/// decide.
///
/// With none, the machine is in the failure `OS-025` (#342) was filed about: it
/// boots, it reports `listening`, and it serves nobody forever because no
/// driver claimed the NIC. That case returns `None` and the caller shouts.
///
/// With several, the first is taken and the fact is logged. Guessing silently
/// is what would be wrong; there is no signal here that says which one the
/// clients are on.
pub(crate) fn choose(interfaces: &[Interface]) -> Option<(&Interface, Option<String>)> {
    let (first, rest) = interfaces.split_first()?;
    let note = (!rest.is_empty()).then(|| {
        let others: Vec<&str> = rest.iter().map(|other| other.name.as_str()).collect();
        format!(
            "this machine has more than one Ethernet interface; taking a lease \
             on {} and leaving {} alone. If the clients are on one of those, \
             the KMS port is bound on all of them anyway — but the address in \
             your SRV record has to be the one they can route to",
            first.name,
            others.join(", ")
        )
    });
    Some((first, note))
}

/// Bring an interface up, without waiting for it to be so.
///
/// A DISCOVER sent on a down interface goes nowhere, and the kernel does not
/// bring one up on its own now that `CONFIG_IP_PNP_DHCP` is gone.
///
/// # Errors
///
/// Returns [`Failure`] if the kernel refused.
pub(crate) fn bring_up(index: u32) -> Result<(), Failure> {
    let mut socket = open()?;
    let mut message = LinkMessage::default();
    message.header.index = index;
    // Both, and this is the part that is easy to get wrong: `flags` says what
    // to set and `change_mask` says which bits of `flags` to pay attention to.
    // Without the mask the kernel is being told to set every other flag to
    // zero as well.
    message.header.flags = LinkFlags::Up;
    message.header.change_mask = LinkFlags::Up;

    exchange(
        &mut socket,
        RouteNetlinkMessage::SetLink(message),
        NLM_F_REQUEST | NLM_F_ACK,
        "bring the interface up",
    )?;
    Ok(())
}

/// Whether an interface has carrier — a cable, or a hypervisor's virtual one.
///
/// Read from `/sys` rather than netlink because it is one byte of text and the
/// alternative is subscribing to link notifications for a fact that is wanted
/// once. `Err` means the file is not there, which is not the same as "no
/// carrier" and is treated as "carry on and let DHCP find out".
pub(crate) fn has_carrier(name: &str) -> Option<bool> {
    let path = format!("/sys/class/net/{name}/carrier");
    let fd = rustix::fs::open(
        path.as_str(),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .ok()?;
    let mut buffer = [0_u8; 8];
    // A down interface answers EINVAL here rather than `0`, which is why this
    // returns `Option` rather than `bool`.
    let read = rustix::io::read(&fd, &mut buffer[..]).ok()?;
    let text = core::str::from_utf8(buffer.get(..read)?).ok()?;
    Some(text.trim() == "1")
}

/// Put a lease on the interface: the address, and the default route.
///
/// Replacing rather than adding. `NLM_F_REPLACE` means a renewal that returned
/// the same address is a no-op instead of an `EEXIST` this would have to
/// special-case, and a renewal that returned a *different* one is handled by
/// [`remove`] first — see `OS-019` (#335), which asks for that case
/// specifically.
///
/// # Errors
///
/// Returns [`Failure`] if the kernel refused the address or the route. The
/// route failing is not fatal to the caller and the address failing is: a host
/// with no address serves nobody, and a host with no default route still serves
/// its own segment, which is where a KMS client usually is.
pub(crate) fn configure(index: u32, config: &Config) -> Result<Vec<String>, Failure> {
    let mut socket = open()?;
    let mut notes = Vec::new();

    // `..default()` rather than a struct literal: both of these types are
    // `#[non_exhaustive]`, so a field added upstream is a compile error here
    // rather than a silently different message.
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = config.prefix;
    // `Universe` rather than `Link`: this address is meant to be reachable from
    // off the segment, which is the whole point.
    message.header.scope = AddressScope::Universe;
    message.header.index = index;
    // Both, and they are not the same field. `Local` is this host's address;
    // `Address` is the peer's on a point-to-point link and the same value on a
    // broadcast one. Sending only one of them produces an address the kernel
    // accepts and does not route from.
    message.attributes = vec![
        AddressAttribute::Local(IpAddr::V4(config.address)),
        AddressAttribute::Address(IpAddr::V4(config.address)),
    ];
    if let Some(broadcast) = broadcast_of(config.address, config.prefix) {
        message
            .attributes
            .push(AddressAttribute::Broadcast(broadcast));
    }

    exchange(
        &mut socket,
        RouteNetlinkMessage::NewAddress(message),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        "set the address",
    )?;

    // The default route, if the lease named a router. A lease without option 3
    // is normal on an isolated segment and is not an error.
    if let Some(&gateway) = config.routers.first() {
        let mut route = RouteMessage::default();
        route.header.address_family = AddressFamily::Inet;
        // A default route: zero-length destination prefix.
        route.header.destination_prefix_length = 0;
        route.header.table = RouteHeader::RT_TABLE_MAIN;
        // `Dhcp` rather than `Boot`, so `ip route` shows where this came from
        // and an operator can tell it from something they added.
        route.header.protocol = RouteProtocol::Dhcp;
        route.header.scope = RouteScope::Universe;
        route.header.kind = RouteType::Unicast;
        route.attributes = vec![
            RouteAttribute::Gateway(RouteAddress::Inet(gateway)),
            RouteAttribute::Oif(index),
        ];
        match exchange(
            &mut socket,
            RouteNetlinkMessage::NewRoute(route),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            "set the default route",
        ) {
            Ok(_) => {}
            // Survivable, and worth saying. A KMS client is usually on the same
            // segment, so a host with an address and no default route still
            // activates most of what will ask it.
            Err(error) => notes.push(format!(
                "{error}; this host can still be reached from its own segment"
            )),
        }
    }

    Ok(notes)
}

/// Take an address off the interface.
///
/// Called when a lease expires with nobody willing to renew it, and before
/// applying a lease that moved. Failure is reported and not fatal: an address
/// that will not come off is a worse problem than this code can fix, and
/// refusing to continue would leave the machine with neither.
///
/// # Errors
///
/// Returns [`Failure`] if the kernel refused.
pub(crate) fn remove(index: u32, address: Ipv4Addr, prefix: u8) -> Result<(), Failure> {
    let mut socket = open()?;
    let mut message = AddressMessage::default();
    message.header.family = AddressFamily::Inet;
    message.header.prefix_len = prefix;
    message.header.scope = AddressScope::Universe;
    message.header.index = index;
    message.attributes = vec![
        AddressAttribute::Local(IpAddr::V4(address)),
        AddressAttribute::Address(IpAddr::V4(address)),
    ];
    exchange(
        &mut socket,
        RouteNetlinkMessage::DelAddress(message),
        NLM_F_REQUEST | NLM_F_ACK,
        "remove the address",
    )?;
    Ok(())
}

/// A bound rtnetlink socket.
fn open() -> Result<Socket, Failure> {
    let mut socket = Socket::new(NETLINK_ROUTE).map_err(Failure::Socket)?;
    // Port zero lets the kernel pick, which is what a program with one netlink
    // socket wants and what stops two of them colliding.
    socket
        .bind(&SocketAddr::new(0, 0))
        .map_err(Failure::Socket)?;
    Ok(socket)
}

/// Send one request and collect the replies until the kernel says it is done.
///
/// Returns the inner payloads. An `Error` payload with a non-zero code is a
/// refusal and becomes [`Failure::Refused`]; one with a zero code is the ACK
/// that ends a `NLM_F_ACK` request and is not an error at all, which is the
/// detail that makes netlink error handling surprising.
fn exchange(
    socket: &mut Socket,
    payload: RouteNetlinkMessage,
    flags: u16,
    what: &str,
) -> Result<Vec<NetlinkPayload<RouteNetlinkMessage>>, Failure> {
    let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload.into());
    message.header.flags = flags;
    message.finalize();

    let mut buffer = vec![0_u8; message.buffer_len()];
    message.serialize(&mut buffer);
    socket.send(&buffer, 0).map_err(Failure::Exchange)?;

    let mut collected = Vec::new();
    let mut receive = vec![0_u8; REPLY_BUFFER];
    'datagrams: loop {
        let read = socket
            .recv(&mut &mut receive[..], 0)
            .map_err(Failure::Exchange)?;
        let mut rest = receive.get(..read).unwrap_or_default();

        // One datagram can hold several messages, which is how a dump arrives.
        while !rest.is_empty() {
            let decoded = <NetlinkMessage<RouteNetlinkMessage>>::deserialize(rest)
                .map_err(|error| Failure::Undecodable(error.to_string()))?;
            let length = decoded.header.length as usize;

            match decoded.payload {
                NetlinkPayload::Done(_) => break 'datagrams,
                NetlinkPayload::Error(error) => {
                    // `code: None` is the ACK. Netlink says "no error" with an
                    // error message, and a client that treats every Error
                    // payload as a failure refuses every successful request.
                    if let Some(code) = error.code {
                        return Err(Failure::Refused(code.get(), what.to_owned()));
                    }
                    break 'datagrams;
                }
                other => collected.push(other),
            }

            // A zero or over-long length would loop forever or index past the
            // end; either means the kernel sent something this cannot parse.
            let Some(remainder) = rest.get(length..) else {
                break 'datagrams;
            };
            if length == 0 {
                break 'datagrams;
            }
            rest = remainder;
        }

        // A request that is not a dump gets exactly one datagram.
        if flags & NLM_F_DUMP == 0 {
            break;
        }
    }
    Ok(collected)
}

/// The broadcast address of the subnet an address sits in.
///
/// Set explicitly rather than left to the kernel, which derives it only when
/// the address is added with `IFA_F_*` defaults this does not use. Without it,
/// a DHCP renewal broadcast in REBINDING goes to the wrong place.
fn broadcast_of(address: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        // /31 and /32 have no broadcast address (RFC 3021).
        return None;
    }
    let host_bits = u32::from(32_u8.checked_sub(prefix)?);
    let mask = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(u32::MAX);
    let _ = host_bits;
    Some(Ipv4Addr::from(u32::from_be_bytes(address.octets()) | mask))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{Interface, broadcast_of, choose};
    use std::net::Ipv4Addr;

    fn interface(name: &str, index: u32) -> Interface {
        Interface {
            name: name.to_owned(),
            index,
            mac: [0x52, 0x54, 0, 0, 0, u8::try_from(index).unwrap_or(0)],
        }
    }

    /// The deployment `docs/deployment.md` describes: one NIC, nothing to
    /// decide, nothing to say about it.
    #[test]
    fn one_interface_is_chosen_silently() {
        let interfaces = [interface("eth0", 2)];
        let (chosen, note) = choose(&interfaces).unwrap();
        assert_eq!(chosen.name, "eth0");
        assert!(note.is_none(), "nothing was ambiguous: {note:?}");
    }

    /// Several NICs: the first by index, and the fact said out loud. A silent
    /// guess here is how an operator ends up with an SRV record pointing at a
    /// management interface.
    #[test]
    fn several_interfaces_are_chosen_from_loudly() {
        let interfaces = [interface("eth1", 3), interface("eth0", 2)];
        let mut sorted = interfaces.to_vec();
        sorted.sort_by_key(|interface| interface.index);
        let (chosen, note) = choose(&sorted).unwrap();
        assert_eq!(chosen.name, "eth0", "lowest index, so it is stable");
        let note = note.expect("an ambiguous choice has to be reported");
        assert!(note.contains("eth1"), "the road not taken is named: {note}");
        assert!(note.contains("SRV"), "and why it matters: {note}");
    }

    /// The failure `OS-025` (#342) exists for: no driver claimed the NIC, so
    /// there is no interface, so nothing can ever answer.
    #[test]
    fn no_interface_is_not_a_choice() {
        assert!(choose(&[]).is_none());
    }

    #[test]
    fn a_broadcast_address_is_the_top_of_the_subnet() {
        assert_eq!(
            broadcast_of(Ipv4Addr::new(192, 168, 1, 50), 24),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(
            broadcast_of(Ipv4Addr::new(10, 1, 2, 3), 8),
            Some(Ipv4Addr::new(10, 255, 255, 255))
        );
        assert_eq!(
            broadcast_of(Ipv4Addr::new(172, 16, 5, 9), 20),
            Some(Ipv4Addr::new(172, 16, 15, 255))
        );
    }

    /// RFC 3021: a /31 is a point-to-point link and has no broadcast address.
    /// Sending one would be an address the kernel rejects.
    #[test]
    fn a_point_to_point_link_has_no_broadcast_address() {
        assert_eq!(broadcast_of(Ipv4Addr::new(10, 0, 0, 1), 31), None);
        assert_eq!(broadcast_of(Ipv4Addr::new(10, 0, 0, 1), 32), None);
    }
}
