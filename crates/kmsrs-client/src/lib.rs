//! Diagnostic, validation and soak client (`ARCH-001`, #1).
//!
//! This is not a convenience tool that happened to get written. It is the
//! regression suite for the detection-resistance checklist (`CLI-002`, #208):
//! the client sends what a real Windows client sends, then checks the response
//! against every property a genuine KMS host's response has — and warns when
//! one is missing. Per the audit, none of the three existing implementations
//! survives that probe unreconfigured, so a test that only asks "did it
//! activate?" would pass on all of them.

// `SEC-012` (#204): no discarded `Result` anywhere a byte from the wire can
// reach. vlmcsd's `handle_error() -> pass` turns a dozen distinct crash paths
// into one indistinguishable connection reset, invisible at every log level,
// and `let _ =` is the Rust spelling of the same thing. Denied here rather than
// in the workspace lint table because `kmsrs-dbgen` and `kmsrs-db`'s build
// script write into `String`s, where the discarded value is an infallible
// `fmt::Result` and the discipline buys nothing.
#![deny(clippy::let_underscore_untyped)]

pub mod catalog;
pub mod load;
pub mod names;
pub mod probe;
pub mod request;
pub mod session;

pub use catalog::Listing;
pub use load::{Charge, Charged, Soak, SoakReport};
pub use probe::{Finding, Probe, Report};
pub use request::{RequestError, RequestFields};
pub use session::{Exchange, ProbeError, Session};

/// Every response property the client checks, as a bitfield (`CLI-001`, #207).
///
/// A single pass/fail verdict throws away exactly the information that makes
/// the client useful, which is *which* property failed.
pub const CHECK_SUITE_NAME: &str = "kmsrs-client response validation";
