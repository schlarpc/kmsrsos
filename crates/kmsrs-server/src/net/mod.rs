//! The platform layer: sockets, threads and the accept loop
//! (`ARCH-005`, #5).
//!
//! Everything here touches the outside world, which is why it is the only part
//! of this workspace that has to be written more than once. The protocol and
//! policy crates below are sans-io — they take bytes, a clock reading and an
//! entropy source and return bytes — so what a driver has to supply is small
//! enough that there is no async abstraction layer between the two
//! implementations. Each simply owns its loop.
//!
//! [`driver`] is the `std::net` and `std::thread` one. It is what runs on
//! Hermit, where the tokio fork is pinned at 1.45.0 with unrebased 2024 commits
//! and where adopting it would mean a workspace-global `[patch.crates-io]`
//! pinning Linux and Windows to that same stale fork.

pub mod addr;
pub mod driver;
pub mod listener;

pub use addr::{KMS_PORT, bind_addresses, normalise, normalise_socket};
pub use driver::{Driver, MAX_CONNECTIONS, ShutdownHandle};
pub use listener::{BindOutcome, Bound, NothingBound, bind_all};
