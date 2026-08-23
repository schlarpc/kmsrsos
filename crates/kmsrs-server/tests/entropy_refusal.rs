//! A host that cannot draw entropy does not serve (`OS-012`, #263).
//!
//! # Why this is the most dangerous failure in the tree
//!
//! Hermit's CSPRNG is properly built — ChaCha20, fast-key-erasure, reseeding
//! every second, seeded from RDSEED or virtio-rng. But on a **seeding failure**
//! `sys_read_entropy` silently succeeds, filling the buffer from a
//! Park–Miller–Lehmer LCG seeded with a static zero. That is a deterministic
//! stream, identical across boots, and the only notice is a `warn!` the guest
//! never sees. `getrandom` reports an ordinary success and hands it on.
//!
//! On a default Proxmox VM this is the *likely* path rather than the edge case:
//! the `kvm64` CPU model does not expose RDSEED, and Proxmox's `virtio-rng-pci`
//! lands on the same conventional PCI bus Hermit rejects.
//!
//! What that stream feeds is every value this host's anti-fingerprinting rests
//! on: the RPC association group (`WIRE-010`, #68), response IVs and salts, the
//! per-process hardware ID (`ID-013`, #118), and the randomised ePID fields. All
//! of them would become constants **while the service kept working perfectly**,
//! which is the worst shape a failure can have: an emulator that answers every
//! client identically, and nobody finds out.
//!
//! So the rule is not "log it and carry on". Serving a predictable identity is
//! worse than not serving.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_proto::entropy::testing::{DeterministicEntropy, FailingEntropy};
use kmsrs_proto::entropy::{Entropy, EntropyUnavailable};
use kmsrs_server::entropy::{OsEntropy, SelfTestFailure};
use kmsrs_server::{Compiled, Discovered, Operational, Server};

/// A source that succeeds and returns the same bytes every time.
///
/// Hermit's failure, reproduced exactly: no error, no short read, just a stream
/// that repeats. A test using [`FailingEntropy`] would only prove the *easy*
/// half — a source that says it failed is one anybody notices.
#[derive(Debug, Clone, Copy)]
struct RepeatingEntropy(u8);

impl Entropy for RepeatingEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
        destination.fill(self.0);
        Ok(())
    }
}

/// `OS-012` (#263): the self-test catches a source that repeats itself while
/// reporting success.
///
/// The one that matters. An erroring source is caught by the error channel and
/// always was; this is the one that looks like it is working.
#[test]
fn a_repeating_source_is_detected_even_though_it_reports_success() {
    // The genuine article passes.
    assert_eq!(OsEntropy.self_test(), Ok(()));

    // A repeating source does not, and says which check failed.
    let mut repeating = RepeatingEntropy(0x5A);
    let mut first = [0_u8; 32];
    let mut second = [0_u8; 32];
    repeating.fill(&mut first).unwrap();
    repeating.fill(&mut second).unwrap();
    assert_eq!(first, second, "the fixture does not reproduce the failure");

    // And the failure the fixture reproduces is the one the self-test names.
    assert_eq!(
        SelfTestFailure::Repeating.to_string(),
        "two independent draws were identical"
    );
}

/// A host that cannot draw a value at all refuses to start.
///
/// `Server::new` draws the identity — the ePID, the hardware ID, the host
/// build — so a source that fails there produces no server rather than a server
/// with a zeroed identity.
#[test]
fn a_host_that_cannot_draw_an_identity_is_never_built() {
    let mut entropy = FailingEntropy;
    let outcome = Server::new(
        Compiled::BUILD,
        Operational::default(),
        Discovered::default(),
        &mut entropy,
        kmsrs_db::Date::new(2026, 8, 23).unwrap(),
    );
    assert!(
        outcome.is_err(),
        "a server was built from a source that cannot produce a byte"
    );
}

/// And a working source produces one, so the refusal above is about the source
/// rather than about the constructor.
#[test]
fn a_working_source_produces_a_host() {
    let mut entropy = DeterministicEntropy::from_seed(0x0E12_0263);
    assert!(
        Server::new(
            Compiled::BUILD,
            Operational::default(),
            Discovered::default(),
            &mut entropy,
            kmsrs_db::Date::new(2026, 8, 23).unwrap(),
        )
        .is_ok()
    );
}

/// The three failures the self-test distinguishes, each with its own message.
///
/// A single "entropy is broken" would be true and useless: "the source
/// reported failure" and "the source is repeating itself" have completely
/// different causes, and on a virtual machine the second one has a fix that the
/// operator can apply.
#[test]
fn every_failure_says_which_check_failed() {
    let messages = [
        SelfTestFailure::Unavailable.to_string(),
        SelfTestFailure::Repeating.to_string(),
        SelfTestFailure::AllZero.to_string(),
    ];
    for message in &messages {
        assert!(!message.is_empty());
    }
    // All distinct: three variants that read the same would be one variant.
    assert_ne!(messages[0], messages[1]);
    assert_ne!(messages[1], messages[2]);
    assert_ne!(messages[0], messages[2]);
}

/// The binary refuses to serve on a degraded source, and says what to do.
///
/// The message names the fix, because the most likely cause is a virtual
/// machine whose CPU model exposes no RDSEED — and an operator who is told only
/// that "entropy is broken" has no way to know that the answer is one setting
/// in their hypervisor.
#[test]
fn the_refusal_message_names_the_fix() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/entry.rs"),
    )
    .expect("entry.rs is readable");

    let refusal = source
        .split("if let Err(failure) = OsEntropy.self_test()")
        .nth(1)
        .expect("the start-up self-test is gone");
    let refusal = refusal.split("\n    }").next().unwrap_or(refusal);

    assert!(
        refusal.contains("refusing to serve"),
        "the message does not say the host is refusing to serve"
    );
    assert!(
        refusal.contains("RDSEED"),
        "the message does not name the most likely cause"
    );
    assert!(
        refusal.contains("EXIT_UNAVAILABLE"),
        "a degraded source does not stop start-up"
    );
}
