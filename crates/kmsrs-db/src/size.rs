//! How much of the binary the product tables are (`DB-018`, #142).
//!
//! # Why anybody counts
//!
//! On Linux and Windows nobody would. The tables live in `.rodata`, which is
//! mapped rather than allocated, and a few tens of kilobytes in a binary that
//! is already a megabyte is not a number anyone would look up.
//!
//! On Hermit it is the *image*. A unikernel is one binary loaded whole into a
//! VM with a fixed memory size, so every byte of `.rodata` is a byte of the
//! guest's memory, permanently, whether or not anything reads it. That makes
//! the table size a deployment constraint rather than a curiosity — and one
//! that grows silently, because the data is regenerated from Microsoft's
//! artifacts by a pipeline nobody watches the output size of (`DB-002`, #126).
//!
//! # What is counted, and what is not
//!
//! The `static` arrays, exactly: the elements plus their layout. **String
//! contents are not counted** — a `&'static str` is a pointer and a length in
//! the array, and the bytes it points at are elsewhere in `.rodata`. So
//! [`TOTAL_BYTES`] is a floor rather than the whole figure, and
//! `tests/data_integrity.rs` measures the strings separately, where a `const`
//! cannot reach them.
//!
//! # No feature gate
//!
//! `DB-018` allows for making the GVLK and instructions payload a separately
//! gated section if the data does not fit. It does — the whole key table added
//! by `DB-013` (#137) is a few kilobytes of strings — so there is nothing to
//! gate — and a feature that shrinks the database is a
//! feature that changes which products activate, which is the last thing that
//! should be behind a build flag nobody differentially tests (declined item
//! D37).

use crate::tables::{
    APPLICATIONS, COUNTED_IDS, CSVLKS, EPID_HOST_BUILDS, GVLKS, HOST_BUILDS, LCIDS, PRODUCTS,
};

/// Bytes the application table occupies.
pub const APPLICATIONS_BYTES: usize = core::mem::size_of_val(&APPLICATIONS);

/// Bytes the product table occupies. The largest of the seven by far.
pub const PRODUCTS_BYTES: usize = core::mem::size_of_val(&PRODUCTS);

/// Bytes the KMS host key table occupies.
pub const CSVLKS_BYTES: usize = core::mem::size_of_val(&CSVLKS);

/// Bytes the counted-ID table occupies.
pub const COUNTED_IDS_BYTES: usize = core::mem::size_of_val(&COUNTED_IDS);

/// Bytes the host build table occupies.
pub const HOST_BUILDS_BYTES: usize = core::mem::size_of_val(&HOST_BUILDS);

/// Bytes the ePID host-build index occupies.
pub const EPID_HOST_BUILDS_BYTES: usize = core::mem::size_of_val(&EPID_HOST_BUILDS);

/// Bytes the locale table occupies.
pub const LCIDS_BYTES: usize = core::mem::size_of_val(&LCIDS);

/// Bytes the client-setup-key table occupies (`DB-013`, #137).
///
/// Almost all of this table is string contents, which this figure does not
/// reach — see the module documentation. The array itself is three pointers and
/// three lengths per row.
pub const GVLKS_BYTES: usize = core::mem::size_of_val(&GVLKS);

/// Every table, added up.
///
/// A floor: string *contents* are elsewhere in `.rodata` and a `const` cannot
/// reach them. See the module documentation.
pub const TOTAL_BYTES: usize = APPLICATIONS_BYTES
    .saturating_add(PRODUCTS_BYTES)
    .saturating_add(CSVLKS_BYTES)
    .saturating_add(COUNTED_IDS_BYTES)
    .saturating_add(HOST_BUILDS_BYTES)
    .saturating_add(EPID_HOST_BUILDS_BYTES)
    .saturating_add(LCIDS_BYTES)
    .saturating_add(GVLKS_BYTES);

/// The ceiling the tables are built to fit inside (`DB-018`, #142).
///
/// 256 KiB. The issue estimated "roughly 15–20 KB of data" and the arrays alone
/// are a few times that, so this is generous rather than tight — deliberately:
/// a limit set just above today's number is a limit that fails the next time
/// Microsoft ships a product, which is news rather than a defect and should not
/// look like one. What it catches is a *change in kind*: a table that started
/// carrying blobs, or a generator that began emitting one row per key ID.
pub const BUDGET_BYTES: usize = 256 * 1024;

// A build whose tables exceed the budget does not link. Checked here rather
// than in a test because the target it matters for is the one no test runs on.
const _: () = assert!(
    TOTAL_BYTES <= BUDGET_BYTES,
    "the product tables no longer fit the image budget (DB-018, #142). On \
     Hermit every byte of .rodata is a byte of the guest's memory, so this is a \
     deployment constraint rather than a curiosity."
);

// And the budget is not vacuous: an empty table would trivially fit.
const _: () = assert!(PRODUCTS_BYTES > 0 && LCIDS_BYTES > 0 && CSVLKS_BYTES > 0);

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    extern crate std;

    use super::{BUDGET_BYTES, LCIDS_BYTES, PRODUCTS_BYTES, TOTAL_BYTES};

    /// `DB-018` (#142): the tables fit, and the number is printed.
    ///
    /// The `const` assertion is what enforces it. This exists so the figure is
    /// *visible* — "it fits" and "it fits by four kilobytes" want different
    /// responses, and a number nobody ever sees is a number nobody notices
    /// growing.
    #[test]
    fn the_tables_fit_the_image_budget() {
        assert!(TOTAL_BYTES <= BUDGET_BYTES);
        std::eprintln!(
            "product tables: {TOTAL_BYTES} bytes of {BUDGET_BYTES} \
             ({PRODUCTS_BYTES} products, {LCIDS_BYTES} locales, and the rest)"
        );
    }

    /// Every size is a compile-time constant, which is what makes this a
    /// ceiling rather than an estimate.
    #[test]
    fn every_size_is_known_at_compile_time() {
        const _: usize = TOTAL_BYTES;
        assert!(TOTAL_BYTES > 0);
        // The product table is the one that grows when Microsoft ships
        // something, so it should dominate. If it stops dominating, some other
        // table has started carrying data it should not.
        assert!(
            PRODUCTS_BYTES > LCIDS_BYTES,
            "products {PRODUCTS_BYTES} no longer dominates locales {LCIDS_BYTES}"
        );
    }
}
