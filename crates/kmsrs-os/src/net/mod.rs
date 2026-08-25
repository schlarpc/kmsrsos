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
//! | [`wire`] | nothing: `dhcproto` does the message format |
//! | [`lease`] | RFC 2131's client state machine, sans-io |
//! | [`link`] | putting a lease on an interface, over netlink |
//! | [`client`] | the task that joins the two to a socket |
//!
//! # One runtime
//!
//! None of this builds a runtime. [`client::spawn`] is called from inside
//! [`kmsrs_server::entry::serve_with`]'s `block_on`, so the DHCP timers and the
//! KMS listeners are scheduled by the same tokio current-thread executor
//! (`ARCH-005`, #5, as superseded by `OS-024`, #340).

pub(crate) mod client;
pub(crate) mod lease;
pub(crate) mod link;
