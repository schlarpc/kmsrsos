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

extern crate alloc;

pub mod error;
pub mod identity;

pub use error::EntropyUnavailable;
pub use identity::{GroupIdentity, HostIdentity};
