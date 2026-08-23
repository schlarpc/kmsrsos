//! The KMS host emulator's platform layer and wiring (`ARCH-001`, #1).
//!
//! Everything that touches the outside world lives here: sockets, threads,
//! clocks, entropy, the log sink and the in-process web server. The protocol
//! and policy crates below it are sans-io, so this crate is the only one that
//! has to be written three times over — once for tokio on Linux and Windows,
//! once for blocking `std::net` on Hermit (`ARCH-005`, #5).
//!
//! The web UI is folded in here rather than living in its own crate. It shares
//! the bounded worker budget with the KMS listener (`OBS-014`, #190), which is
//! easier to guarantee when there is one budget and one crate that owns it.

pub mod config;
pub mod entropy;
pub mod host;
pub mod log;
pub mod net;
pub mod server;

pub use config::{Compiled, Discovered, Operational};
pub use entropy::OsEntropy;
pub use host::{Host, RequestContext};
pub use log::{Logger, Severity};
pub use server::{Handled, Server};

/// The name the emulator reports for itself. Used by the log sink and the web
/// UI; never sent on the wire, where the only identity that exists is the ePID
/// (`ID-001`, #106).
pub const PRODUCT_NAME: &str = "kmsrsos";
