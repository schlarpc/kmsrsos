//! `kmsrs-server` entry point: the hosted binary, for Linux and Windows.
//!
//! Everything it does lives in [`kmsrs_server::entry`], because every binary in
//! this workspace must do exactly the same thing (`OS-001`, #252) and a start-up
//! sequence written twice is a start-up sequence that is right once.
//!
//! The one thing decided here is *how* it was started. On Windows,
//! [`kmsrs_server::service::run`] asks the operating system whether this process
//! is a service and serves either way (`PKG-008`, #245); on every other target
//! it is `entry::serve` unchanged.

use std::process::ExitCode;

fn main() -> ExitCode {
    kmsrs_server::service::run()
}
