//! The KMS host emulator's platform layer and wiring (`ARCH-001`, #1).
//!
//! Everything that touches the outside world lives here: sockets, threads,
//! clocks, entropy, the log sink and the in-process web server. The protocol
//! and policy crates below it are sans-io, so this is the only crate that knows
//! what platform it is on — and it is written *once*, not three times: one
//! `mio` event loop runs on Linux, Windows and Hermit, and what differs is
//! socket semantics, named as constants in [`platform`] (`ARCH-005`, #5).
//!
//! [`entry::serve`] is the whole program. Both binaries — `kmsrsos` and the
//! unikernel `kmsrsos-hermit` — are a `main` that calls it (`OS-001`, #252).
//!
//! The web UI is folded in here rather than living in its own crate. It shares
//! the bounded worker budget with the KMS listener (`OBS-014`, #190), which is
//! easier to guarantee when there is one budget and one crate that owns it.

// `SEC-012` (#204): no discarded `Result` anywhere a byte from the wire can
// reach. vlmcsd's `handle_error() -> pass` turns a dozen distinct crash paths
// into one indistinguishable connection reset, invisible at every log level,
// and `let _ =` is the Rust spelling of the same thing. Denied here rather than
// in the workspace lint table because `kmsrs-dbgen` and `kmsrs-db`'s build
// script write into `String`s, where the discarded value is an infallible
// `fmt::Result` and the discipline buys nothing.
#![deny(clippy::let_underscore_untyped)]

pub mod budget;
pub mod clock;
pub mod config;
pub mod entropy;
pub mod entry;
pub mod facts;
pub mod host;
pub mod log;
pub mod net;
pub mod platform;
pub mod server;
pub mod web;

pub use clock::WallClock;
pub use config::{BuildStamp, Compiled, Discovered, Operational};
pub use entropy::OsEntropy;
pub use facts::{Facts, Network};
pub use host::{Host, RequestContext};
pub use log::{Logger, Severity};
pub use server::{Handled, Server};

/// The name the emulator reports for itself. Used by the log sink and the web
/// UI; never sent on the wire, where the only identity that exists is the ePID
/// (`ID-001`, #106).
pub const PRODUCT_NAME: &str = "kmsrsos";
