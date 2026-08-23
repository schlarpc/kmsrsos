//! libFuzzer shim for the `http_request` target (`SEC-013`, #306).
//!
//! The body is [`kmsrs_vectors::targets::http_request`], which lives in the
//! workspace so that the pinned stable toolchain compiles, lints and runs it.
//! Only this file needs nightly.

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| kmsrs_vectors::targets::http_request(data));
