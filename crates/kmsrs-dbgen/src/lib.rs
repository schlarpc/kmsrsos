//! Extraction of product data from Microsoft `pkeyconfig` artifacts
//! (`ARCH-001`, #1; `DB-001`, #125).
//!
//! # Why this is a separate crate
//!
//! Extraction needs base64, gzip and an XML parser, and the artifacts must be
//! fetched over the network. None of that has any business being reachable from
//! a server that has no disk I/O and parses nothing but its own wire protocol.
//! Keeping the extractor in its own crate, depended on by nothing the binary
//! depends on, makes "unreachable" a property of the dependency graph that CI
//! can check rather than a claim in a comment.
//!
//! The output is a reviewable, provenance-stamped data file that is committed
//! to the tree (`DB-002`, #126). `kmsrs-db`'s `build.rs` compiles that file into
//! `static` tables; it does not run this crate.

/// The generator's own version stamp, recorded in every file it emits so that a
/// regenerated data file can be attributed to the code that produced it
/// (`DB-002`, #126).
pub const GENERATOR_VERSION: &str = env!("CARGO_PKG_VERSION");
