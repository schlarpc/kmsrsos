//! `kmsrs-server` entry point: the hosted binary, for Linux and Windows.
//!
//! Everything it does lives in [`kmsrs_server::entry`], because the Hermit
//! binary must do exactly the same thing (`OS-001`, #252) and a start-up
//! sequence written twice is a start-up sequence that is right once.

use std::process::ExitCode;

fn main() -> ExitCode {
    kmsrs_server::entry::serve()
}
