//! Bind addresses and peer normalisation (`NET-011`, #160; `NET-012`, #161;
//! `NET-002`, #151).
//!
//! # Addresses are compile-time literals
//!
//! Every address this program binds is a `const`, parsed at compile time. No
//! name resolution happens, ever — not because resolution is hard, but because
//! *partial* support for it is worse than none. Both existing implementations
//! pass `AI_NUMERICHOST`, so neither accepts a hostname; py-kms's documentation
//! nonetheless claims hostnames work, and using one is fatal at start-up.
//! Documenting a capability the code refuses is worse than not having it.
//!
//! # One representation for one client
//!
//! An IPv4 client arriving on a dual-stack socket appears as `::ffff:1.2.3.4`;
//! the same client on an IPv4 socket appears as `1.2.3.4`. Storing both means
//! one machine shows up twice in the event log, twice in a rate-limit bucket,
//! and once in an allow-list that was written with the other spelling.
//!
//! [`normalise`] collapses the two on the **storage** path, which is where
//! nobody in either ecosystem does it — MelroyB's fork normalises inside its
//! blacklist matcher only, so its logs and its filter disagree about who
//! connected.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The KMS port (`NET-002`, #151).
///
/// Not configurable, at build time or otherwise. A KMS client discovers hosts
/// by SRV record or by an explicitly configured name, and in both cases the
/// port comes from the client's side — so a server listening elsewhere is a
/// server no client will find. Making it settable could only ever break things.
pub const KMS_PORT: u16 = 1688;

/// The listen backlog (`NET-003`, #152).
///
/// vlmcsd hardcodes `SOMAXCONN`, which is 4096 on modern Linux and 0x7fffffff
/// on Windows — a queue far deeper than a bounded worker pool can ever drain,
/// which converts a connection flood from a fast refusal into a slow one. This
/// is sized to the worker pool instead: deep enough to absorb a burst, shallow
/// enough that the kernel refuses rather than queueing indefinitely.
pub const BACKLOG: i32 = 128;

/// Every address the KMS listener binds (`NET-001`, #150; `NET-002`, #151).
///
/// Two sockets rather than one dual-stack socket. That is more portable, not
/// less: OpenBSD refuses `IPV6_V6ONLY=0` outright, so a single dual-stack
/// socket cannot work there, and py-kms's fallback for exactly this case
/// triggers on one exact exception *string* — which stops matching the moment a
/// platform words its error differently.
///
/// Each is bound independently and a failure on one is not fatal, so a
/// host with no IPv6 stack serves IPv4 and vice versa (`NET-001`, #150).
pub const KMS_BIND_ADDRESSES: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), KMS_PORT),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), KMS_PORT),
];

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form (`NET-012`, #161).
///
/// Applied at accept, before the address reaches anything that stores or
/// compares it, so one client has one identity everywhere.
///
/// IPv4-**compatible** addresses (`::1.2.3.4`, deprecated by RFC 4291) are
/// deliberately *not* collapsed: they are not how a dual-stack socket reports
/// an IPv4 peer, and treating them as equivalent would let a peer choose which
/// spelling to arrive as.
#[must_use]
pub fn normalise(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Normalise a socket address, keeping its port.
#[must_use]
pub fn normalise_socket(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalise(address.ip()), address.port())
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

    use super::{BACKLOG, KMS_BIND_ADDRESSES, KMS_PORT, normalise, normalise_socket};
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    /// `NET-002` (#151): the port is 1688 and is not negotiable.
    #[test]
    fn the_kms_port_is_1688() {
        assert_eq!(KMS_PORT, 1688);
        for address in KMS_BIND_ADDRESSES {
            assert_eq!(address.port(), KMS_PORT);
        }
    }

    /// `NET-001` (#150): both stacks, as separate sockets.
    #[test]
    fn both_stacks_are_bound_separately() {
        assert_eq!(KMS_BIND_ADDRESSES.len(), 2);
        assert!(KMS_BIND_ADDRESSES.iter().any(SocketAddr::is_ipv6));
        assert!(KMS_BIND_ADDRESSES.iter().any(SocketAddr::is_ipv4));
        // Wildcard on both, so a host with several interfaces serves all of
        // them without anyone having to enumerate them.
        for address in KMS_BIND_ADDRESSES {
            assert!(address.ip().is_unspecified(), "{address}");
        }
    }

    /// `NET-011` (#160): every address is a compile-time constant, so there is
    /// no resolution path to get wrong. This test exists to fail if someone
    /// later makes the list runtime-derived.
    #[test]
    fn bind_addresses_are_compile_time_constants() {
        const _: [SocketAddr; 2] = KMS_BIND_ADDRESSES;
        const _: u16 = KMS_PORT;
        // Usable in a const context, which a resolved address could not be.
        const FIRST_PORT: u16 = KMS_BIND_ADDRESSES[0].port();
        assert_eq!(FIRST_PORT, 1688);
    }

    /// `NET-012` (#161): the same client is never two identities.
    #[test]
    fn an_ipv4_mapped_peer_collapses_to_its_ipv4_form() {
        let mapped = IpAddr::V6(Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped());
        let plain = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert_ne!(mapped, plain, "they differ before normalisation");
        assert_eq!(normalise(mapped), plain, "and not after");
        assert_eq!(normalise(plain), plain, "already normal");

        // Idempotent, since it runs on a path that may see either form.
        assert_eq!(normalise(normalise(mapped)), plain);

        // The port survives.
        let socket = SocketAddr::new(mapped, 50_000);
        assert_eq!(
            normalise_socket(socket),
            SocketAddr::new(plain, 50_000),
            "the port must not be lost"
        );
    }

    /// A genuine IPv6 address is left alone, including loopback — a fork that
    /// got this wrong denied its own loopback once filtering was enabled.
    #[test]
    fn genuine_ipv6_addresses_are_untouched() {
        for address in [
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        ] {
            assert_eq!(normalise(address), address, "{address}");
        }
    }

    /// An IPv4-*compatible* address is deprecated and is not how a dual-stack
    /// socket reports an IPv4 peer. Collapsing it would let a peer choose which
    /// spelling to arrive as, which is the opposite of what normalisation is
    /// for.
    #[test]
    fn deprecated_ipv4_compatible_addresses_are_not_collapsed() {
        let compatible = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0102, 0x0304));
        assert_eq!(
            normalise(compatible),
            compatible,
            "::1.2.3.4 must not become 1.2.3.4"
        );
        assert_ne!(normalise(compatible), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    }

    /// `NET-003` (#152): a backlog sized to the worker pool, not `SOMAXCONN`.
    #[test]
    fn the_backlog_is_bounded_and_not_somaxconn() {
        assert!(BACKLOG > 0);
        assert!(
            BACKLOG <= 1024,
            "a backlog deeper than the pool can drain turns a fast refusal \
             into a slow one"
        );
    }
}
