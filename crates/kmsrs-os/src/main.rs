//! The bare-metal target: `kmsrsos` as a [Hermit] unikernel (`ARCH-001`, #1;
//! `OS-001`, #252).
//!
//! Hermit is the reason the core crates are `no_std`-capable and sans-io. The
//! platform differs from Linux and Windows in ways that are easy to get wrong
//! and hard to notice (`docs/research-findings.md`, R2):
//!
//! * `cfg(unix)` is **false**, so every `#[cfg(unix)]` branch in our code and in
//!   every dependency silently takes the other path (`ARCH-015`, #15).
//! * `setsockopt` is a stub. Only `TCP_NODELAY` does anything; `SO_REUSEADDR`
//!   is a silent no-op and the timeout options return `EINVAL` (`OS-010`, #261).
//! * `bind()` records the address and ignores it, so one socket already accepts
//!   on every local address and two would race (`OS-009`, #260).
//! * On seeding failure the kernel's `sys_read_entropy` **silently succeeds**,
//!   returning a deterministic LCG stream seeded from a static zero. Every
//!   anti-fingerprinting property would become a constant while the service
//!   kept working, so the entropy self-test refuses to serve (`OS-012`, #263).
//!
//! None of those is handled here. Every one of them is a named capability in
//! [`kmsrs_server::platform`] whose branches compile on all three targets, so
//! the Hermit behaviour is decided — and asserted — by a test suite running on
//! Linux. What is left for this crate is a `main` that calls the same entry
//! point the hosted binary calls, and the reason that is the entire content of
//! the file is the point of `ARCH-005`: one driver, not one per platform.
//!
//! # What the unikernel does not have
//!
//! No signals, so nothing installs a handler and the drain path is reached only
//! by the hypervisor stopping the guest (`OS-015`, #298). No filesystem of any
//! kind, which is what makes axiom A5 structural here rather than a policy
//! (`OS-006`, #257). One IPv4 socket, because `bind()` records an address it
//! then ignores (`OS-009`, #260). And a wall clock that is one CMOS read plus
//! local ticks, which does not matter because it is read exactly once
//! (`OS-007`, #258).
//!
//! [Hermit]: https://github.com/hermit-os

use std::process::ExitCode;

fn main() -> ExitCode {
    kmsrs_server::entry::serve()
}
