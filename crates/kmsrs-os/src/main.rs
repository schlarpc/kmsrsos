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
//! [Hermit]: https://github.com/hermit-os

fn main() {
    eprintln!(
        "{} on Hermit — platform layer not yet implemented (OS-001, #252)",
        kmsrs_server::PRODUCT_NAME
    );
}
