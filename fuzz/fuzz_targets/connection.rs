//! libFuzzer shim for the `connection` target (`SEC-004`, #196).
//!
//! The body is [`kmsrs_vectors::targets::connection`], which lives in the workspace so
//! that the pinned stable toolchain compiles, lints and runs it. Only this file
//! needs nightly.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| kmsrs_vectors::targets::connection(data));
