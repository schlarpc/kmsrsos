//! Diagnostic, validation and soak client (`ARCH-001`, #1).
//!
//! This is not a convenience tool that happened to get written. It is the
//! regression suite for the detection-resistance checklist (`CLI-002`, #208):
//! the client sends what a real Windows client sends, then checks the response
//! against every property a genuine KMS host's response has — and warns when
//! one is missing. Per the audit, none of the three existing implementations
//! survives that probe unreconfigured, so a test that only asks "did it
//! activate?" would pass on all of them.

pub mod probe;
pub mod request;

pub use probe::{Finding, Probe, ProbeError, Report};
pub use request::{RequestError, RequestFields};

/// Every response property the client checks, as a bitfield (`CLI-001`, #207).
///
/// A single pass/fail verdict throws away exactly the information that makes
/// the client useful, which is *which* property failed.
pub const CHECK_SUITE_NAME: &str = "kmsrs-client response validation";
