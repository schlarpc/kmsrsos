//! Activation policy, the host-state model, host identity and the event log
//! (`ARCH-001`, #1).
//!
//! Like [`kmsrs_proto`], this crate is sans-io: it is handed a decoded request,
//! a clock reading and a source address, and it returns a decision plus the
//! events that decision produced. It never reads a clock or a socket itself.
//!
//! The central design choice lives here. A request is answered from a *view*
//! computed over the shared world model, and answering it never writes the
//! view back (`POL-001`, #89). An anomalous demand is therefore satisfied for
//! the client that made it and for nobody else, which is what makes the
//! overcharge attack against a genuine host unrepresentable rather than merely
//! mitigated (`POL-005`, #93).

#![no_std]
// `SEC-012` (#204): no discarded `Result` anywhere a byte from the wire can
// reach. vlmcsd's `handle_error() -> pass` turns a dozen distinct crash paths
// into one indistinguishable connection reset, invisible at every log level,
// and `let _ =` is the Rust spelling of the same thing. Denied here rather than
// in the workspace lint table because `kmsrs-dbgen` and `kmsrs-db`'s build
// script write into `String`s, where the discarded value is an infallible
// `fmt::Result` and the discipline buys nothing.
#![deny(clippy::let_underscore_untyped)]

extern crate alloc;

pub mod access;
pub mod counting;
pub mod error;
pub mod events;
pub mod gate;
pub mod identity;

pub use access::{AccessList, Admission, Denial, RateLimiter, Rule, canonical};
pub use counting::{ClientCounts, CountOutcome, CountView};
pub use error::EntropyUnavailable;
pub use events::{Event, EventLog, Outcome, Peer};
pub use gate::{Decision, Grant, Observations, Refusal};
pub use identity::{GroupIdentity, HostIdentity};
