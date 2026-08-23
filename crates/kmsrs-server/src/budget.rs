//! What this host will hold in memory, asserted at compile time
//! (`OS-011`, #262).
//!
//! # Why a ceiling has to exist at all
//!
//! On Linux and Windows an over-generous allocation is a paragraph in a
//! monitoring dashboard. On Hermit it is the end of the guest: a unikernel has
//! a fixed memory budget decided when the VM is created, there is no swap, and
//! there is no OOM killer to pick a victim — the allocation fails, and a failed
//! allocation in a program compiled with `panic = "abort"` stops the machine.
//! Only the hypervisor can restart it.
//!
//! So the interesting number is not "how much does it use", which varies with
//! load, but **how much can it ever use**, which does not. Every structure that
//! grows is bounded by a constant somewhere else in this workspace, and this
//! module is where those constants are added up and checked against a budget.
//!
//! # `const` assertions rather than a test
//!
//! A test would tell somebody the budget was blown after they had built the
//! binary. These fail the *build*, on every target, which is the only place a
//! Hermit-specific memory ceiling can be checked from a machine that is not
//! Hermit.
//!
//! # What is not counted
//!
//! Two things, deliberately:
//!
//! * **The product database.** It is `static` data in `.rodata`
//!   (`DB-003`, #127) — no allocation, no initialisation, no lazy first use —
//!   so it is part of the image rather than of the heap. `DB-018` (#142) is
//!   where its size is measured against the image budget.
//! * **The allocator's own overhead.** Every figure here is the size of the
//!   data, and a real allocator rounds up and keeps bookkeeping. That is what
//!   [`SLACK`] is for: the budget is set well above the sum rather than at it.

use crate::net::driver::{CONNECTION_STATE_BUDGET, MAX_OUTBOUND};
use kmsrs_policy::counting::{MAX_APPLICATIONS, MAX_CACHED_PER_APPLICATION};
use kmsrs_policy::events::{DEFAULT_CAPACITY, Event};

/// Bytes one cached client machine ID occupies.
///
/// A GUID and an instant. Written as the sum rather than as
/// `size_of::<Cached>()` because that type is private to the counting model,
/// and making it public to be measured would be exposing an implementation
/// detail so that a comment could be checked.
pub const CMID_ENTRY_BYTES: usize = 16 + core::mem::size_of::<kmsrs_proto::time::Instant>();

/// The most the CMID table can hold (`POL-001`, #89; `POL-002`, #90).
///
/// Bounded twice over: per application by `MAX_CACHED_PER_APPLICATION`, and in
/// how many applications exist at all by `MAX_APPLICATIONS`. The second bound
/// is what stops a client sending unrecognised application GUIDs from deciding
/// this number.
pub const CMID_TABLE_BYTES: usize = MAX_APPLICATIONS
    .saturating_mul(MAX_CACHED_PER_APPLICATION)
    .saturating_mul(CMID_ENTRY_BYTES);

/// The most the event log can hold (`OBS-004`, #180).
///
/// Capacity times the size of one record. Bounded in the *other* dimension too
/// — a retention window — but retention only ever makes it smaller, so the
/// ceiling is capacity alone.
pub const EVENT_LOG_BYTES: usize = DEFAULT_CAPACITY.saturating_mul(core::mem::size_of::<Event>());

/// The most in-flight connection state can occupy (`NET-014`, #296).
///
/// Already a budget rather than a consequence: `MAX_CONNECTIONS` is derived by
/// dividing this by the per-connection cost, which is what makes the ceiling
/// derivable rather than picked.
pub const CONNECTION_BYTES: usize = CONNECTION_STATE_BUDGET;

/// Everything that grows, added up.
pub const TOTAL_BYTES: usize = CMID_TABLE_BYTES
    .saturating_add(EVENT_LOG_BYTES)
    .saturating_add(CONNECTION_BYTES);

/// How much room the budget leaves above the sum.
///
/// Not padding for its own sake. Every figure above is the size of the *data*,
/// and a real allocator rounds each allocation up and keeps bookkeeping beside
/// it; a `VecDeque` also over-allocates by design. Two megabytes is comfortably
/// more than any of that and small enough that the budget still means something.
pub const SLACK: usize = 2 * 1024 * 1024;

/// The ceiling this host is built to fit inside.
///
/// Eight mebibytes of *heap*, which is a rounding error on Linux and Windows
/// and the binding constraint on Hermit — where the figure that matters is the
/// VM's memory size, of which this is one part alongside the image, the stacks
/// and the network buffers. A Hermit guest is normally given 64 MiB or more, so
/// this leaves the kernel an order of magnitude more room than it takes.
pub const BUDGET_BYTES: usize = 8 * 1024 * 1024;

// The assertion. A build that would exceed the budget does not link.
const _: () = assert!(
    TOTAL_BYTES.saturating_add(SLACK) <= BUDGET_BYTES,
    "the bounded structures no longer fit the memory budget (OS-011, #262). \
     Either a bound grew or the budget has to; both are decisions, and neither \
     should be made by a build that quietly got bigger."
);

// And the budget is not vacuous: every component is a real number rather than a
// zero that would make the sum trivially fit.
const _: () = assert!(CMID_TABLE_BYTES > 0 && EVENT_LOG_BYTES > 0 && CONNECTION_BYTES > 0);

// One connection's outbound queue is bounded too, and must not be able to
// exceed the whole per-connection budget on its own.
const _: () = assert!(MAX_OUTBOUND < CONNECTION_STATE_BUDGET);

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        BUDGET_BYTES, CMID_TABLE_BYTES, CONNECTION_BYTES, EVENT_LOG_BYTES, SLACK, TOTAL_BYTES,
    };

    /// `OS-011` (#262): the sum fits, with room for an allocator.
    ///
    /// The `const` assertion above is what actually enforces this — it fails
    /// the build rather than a test run. This exists so that the number is
    /// *printed* when it is close, because "it fits" and "it fits by four
    /// kilobytes" want different responses.
    #[test]
    fn the_bounded_structures_fit_the_budget() {
        assert!(
            TOTAL_BYTES + SLACK <= BUDGET_BYTES,
            "{TOTAL_BYTES} bytes of bounded state plus {SLACK} of slack \
             exceeds the {BUDGET_BYTES}-byte budget"
        );
        eprintln!(
            "bounded state: {TOTAL_BYTES} bytes ({CMID_TABLE_BYTES} CMID table, \
             {EVENT_LOG_BYTES} event log, {CONNECTION_BYTES} connections) of \
             {BUDGET_BYTES}"
        );
    }

    /// Every component is bounded by a constant, not by traffic.
    ///
    /// The property that makes a ceiling meaningful. A structure whose size
    /// depended on how many requests had arrived would make this whole module
    /// an estimate.
    #[test]
    fn every_component_is_a_compile_time_constant() {
        const _: usize = CMID_TABLE_BYTES;
        const _: usize = EVENT_LOG_BYTES;
        const _: usize = CONNECTION_BYTES;
        const _: usize = TOTAL_BYTES;
        assert!(CMID_TABLE_BYTES > 0);
        assert!(EVENT_LOG_BYTES > 0);
        assert!(CONNECTION_BYTES > 0);
    }

    /// The connection budget is the largest of the three, which is worth
    /// knowing: it is the one derived from a *chosen* number rather than from
    /// a protocol constraint, so it is the one to move if the budget is ever
    /// tight.
    #[test]
    fn connections_are_the_largest_share() {
        assert!(CONNECTION_BYTES > CMID_TABLE_BYTES);
        assert!(CONNECTION_BYTES > EVENT_LOG_BYTES);
    }
}
