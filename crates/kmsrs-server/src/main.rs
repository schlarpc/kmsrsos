//! `kmsrsos` entry point.
//!
//! There is no argv processing here and there never will be (`CFG-007`, #172).
//! Configuration is decided when the binary is built; the single runtime knob
//! is the `KMSRSOS_CONFIG` environment variable, which may only touch settings
//! that cannot change a byte on the wire (`CFG-002`, #167).

use kmsrs_server::config::{Compiled, Discovered, Operational};

/// Exit code for a configuration this binary could not understand.
///
/// Distinct from a generic failure so that a supervisor can tell "you told me
/// something wrong" from "something went wrong" without parsing stderr.
const EXIT_BAD_CONFIG: i32 = 78;

/// Exit code for arguments that were passed and should not have been.
const EXIT_BAD_USAGE: i32 = 64;

fn main() {
    // `CFG-007` (#172): this binary takes no arguments. Silently ignoring them
    // is worse than refusing — an operator who typed something expects it to
    // have had an effect. vlmcsd documents `-h` and `-?` that are not in its
    // own optstring, and py-kms has no `--version` at all; both are what
    // happens when argv handling is an afterthought rather than absent.
    let extra: Vec<String> = std::env::args().skip(1).collect();
    if !extra.is_empty() {
        eprintln!(
            "{}: this program takes no arguments, but was given: {}",
            kmsrs_server::PRODUCT_NAME,
            extra.join(" ")
        );
        eprintln!(
            "Configuration is compiled in. The only runtime setting is the \
             {} environment variable, which holds a TOML document.",
            kmsrs_server::config::operational::ENV_VAR
        );
        std::process::exit(EXIT_BAD_USAGE);
    }

    // `CFG-002` (#167): malformed configuration exits non-zero immediately and
    // says what was wrong. Starting degraded would mean running with a
    // configuration nobody wrote.
    let operational = match Operational::from_env() {
        Ok(operational) => operational,
        Err(error) => {
            eprintln!("{}: {error}", kmsrs_server::PRODUCT_NAME);
            std::process::exit(EXIT_BAD_CONFIG);
        }
    };

    let discovered = Discovered::observe();
    let compiled = Compiled::BUILD;

    eprintln!(
        "{} — listener not yet implemented (NET-001, #150)",
        kmsrs_server::PRODUCT_NAME
    );
    eprintln!(
        "  intervals: {} min activation, {} min renewal",
        compiled.intervals.activation, compiled.intervals.renewal
    );
    eprintln!(
        "  log: {:?} as {:?}, colour {}",
        operational.log_level,
        operational.log_format,
        discovered.should_colour(operational.colour)
    );
}
