//! The network, which on this target nobody else configures
//! (`OS-019`, #335; `OS-020`, #336).
//!
//! On Linux-as-a-service and on Windows the address, the routes, the resolver
//! and the clock are somebody else's problem. Here `kmsrs-os` is pid 1 and the
//! only process, so they are this crate's, and there is no `dhcpcd`, no
//! `systemd-networkd` and no `ntpd` to delegate to — adding one would mean a
//! second binary in an image whose contents are currently enumerable in a
//! sentence.
//!
//! | | |
//! |---|---|
//! | [`lease`] | RFC 2131's client state machine, sans-io |
//! | [`link`] | putting a lease on an interface, over netlink |
//! | [`client`] | the task that joins those two to a socket |
//! | [`sntp`] | the clock, from the lease's option 42 or from the pool |
//!
//! The DHCP message format itself is `dhcproto`'s; see the decision in
//! `docs/decisions.md` for why that crate, and why the DNS library it drags in
//! turned out to be the one [`sntp`] needed anyway.
//!
//! # One runtime
//!
//! None of this builds a runtime. [`spawn`] is called from inside
//! [`kmsrs_server::entry::serve_with`]'s `block_on`, so the DHCP timers and the
//! KMS listeners are scheduled by the same tokio current-thread executor
//! (`ARCH-005`, #5, as superseded by `OS-024`, #340).

pub(crate) mod client;
pub(crate) mod lease;
pub(crate) mod link;
pub(crate) mod sntp;

use kmsrs_server::facts::Facts;

/// Start everything pid 1 owns on the network (`OS-019`, #335; `OS-020`, #336).
///
/// Called from inside [`kmsrs_server::entry::serve_with`]'s runtime. The DHCP
/// client publishes what the lease said into a watch channel and the SNTP
/// client reads it, so a renewal that changes the NTP servers is picked up on
/// the next poll rather than needing a restart — and the SNTP client does not
/// have to know that DHCP exists.
pub(crate) fn spawn(facts: Facts, seed: u32) {
    let (sources, watch) = tokio::sync::watch::channel(sntp::Sources::default());
    client::spawn(facts, seed, sources);
    sntp::spawn(watch);
}
