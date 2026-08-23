//! How the unikernel gets an address, and why nothing here has to know it
//! (`OS-003`, #254).
//!
//! A Hermit guest has two possible sources of an IPv4 address, and they are not
//! alternatives so much as a fallback and a real one:
//!
//! * The `HERMIT_IP` / `HERMIT_GATEWAY` / `HERMIT_MASK` family, which the
//!   kernel reads through its `hermit_var!` macro — the *runtime* environment
//!   first, then `option_env!` of the same name, so a value baked in when the
//!   kernel was compiled is as effective as one passed in boot args. With
//!   `dhcpv4` compiled in the kernel logs a warning when it sees one and treats
//!   it as a pre-DHCP fallback, overwriting it the moment a lease arrives.
//! * **DHCPv4**, which is on in the shipped feature set (`OS-006`, #257) and is
//!   the only addressing path this deployment uses.
//!
//! The failure worth preventing is not "DHCP is off" — that is loud. It is a
//! `HERMIT_IP` baked into the kernel derivation, which makes every guest come
//! up on one address before its lease arrives, and makes two guests on one
//! network collide during that window. Nothing in the build sets one, and this
//! is what notices if something starts to.
//!
//! The other half is that **the server does not care**. It binds a wildcard
//! (`OS-009`, #260), so whatever address the lease carries is an address it is
//! already serving on, and no part of this program reads its own IP to decide
//! anything. That is asserted here too, because it is the reason a lease that
//! changes mid-flight is not an event this host has to handle.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed invariant should abort the test loudly"
)]

use kmsrs_server::net::addr::SINGLE_SOCKET_ADDRESSES;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/<name> is always two levels below the workspace root")
        .to_path_buf()
}

fn flake() -> String {
    let path = workspace_root().join("flake.nix");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

/// `OS-003` (#254): no static address is compiled into the kernel.
///
/// `hermit_var!` falls back to `option_env!`, so setting any of these in the
/// derivation's environment bakes them into `libhermit.a`. The result still
/// boots and still answers — on an address the network did not assign it, until
/// the lease lands.
#[test]
fn no_static_address_is_baked_into_the_kernel() {
    let flake = flake();

    for variable in [
        "HERMIT_IP",
        "HERMIT_GATEWAY",
        "HERMIT_MASK",
        "HERMIT_DNS1",
        "HERMIT_DNS2",
    ] {
        // An *assignment*, in either the Nix or the shell spelling. Naming the
        // variable in prose is how the boot check explains what it is looking
        // for, and forbidding that would only produce a circumlocution.
        for line in flake.lines() {
            let trimmed = line.trim_start();
            let assigns = trimmed.contains(&format!("{variable}="))
                || trimmed.contains(&format!("{variable} ="));
            assert!(
                !assigns || trimmed.starts_with('#'),
                "flake.nix sets {variable}, which the kernel reads through \
                 option_env! and bakes in. DHCPv4 is the addressing path \
                 (OS-003, #254); a compile-time address is a fallback every \
                 guest shares.\n  {trimmed}"
            );
        }
    }
}

/// The boot check proves the lease, rather than only proving the guest answers.
///
/// Both addressing paths produce a guest that answers on a forwarded port, so
/// "it served" does not distinguish them. The check greps the serial console
/// for the lease, and this fails if that stops happening — a boot test that
/// silently stopped testing the thing it was named for is worse than no boot
/// test.
#[test]
fn the_boot_check_asserts_a_lease_was_acquired() {
    let flake = flake();
    assert!(
        flake.contains("DHCP config acquired"),
        "the hermit-boot check no longer looks for a DHCPv4 lease in the \
         guest's serial log (OS-003, #254)"
    );
}

/// `OS-003` (#254) + `OS-009` (#260): whatever the lease says, it is already
/// bound.
///
/// The Hermit bind list is a single `0.0.0.0` socket. That is what makes DHCP a
/// non-event for this program: there is no address to re-bind when a lease
/// arrives, changes or is renewed, and nothing reads the interface address to
/// decide what to serve.
#[test]
fn the_unikernel_serves_whatever_address_the_lease_carries() {
    assert_eq!(SINGLE_SOCKET_ADDRESSES.len(), 1);
    let address = SINGLE_SOCKET_ADDRESSES[0];
    assert!(
        address.ip().is_unspecified(),
        "the Hermit listener binds {address}, so a DHCP lease for any other \
         address would not be served (OS-003, #254)"
    );
    assert!(
        address.is_ipv4(),
        "Hermit speaks DHCPv4 only — no SLAAC, no RA, no DHCPv6 — so an IPv6 \
         entry could never be assigned an address"
    );
}
