//! `kmsrsos` entry point.
//!
//! There is no argv processing here and there never will be (`CFG-007`, #172).
//! Configuration is decided when the binary is built; the single runtime knob
//! is the `KMSRSOS_CONFIG` environment variable, which may only touch settings
//! that cannot change a byte on the wire (`CFG-002`, #167).

use core::sync::atomic::{AtomicBool, Ordering};
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::time::Instant;
use kmsrs_server::config::{Compiled, Discovered, Operational};
use kmsrs_server::net::driver::{MAX_CONNECTIONS, Runtime, serve};
use kmsrs_server::net::listener::bind_all;
use kmsrs_server::{OsEntropy, PRODUCT_NAME, Server};
use std::sync::Arc;

/// Exit code for a configuration this binary could not understand.
///
/// Distinct from a generic failure so that a supervisor can tell "you told me
/// something wrong" from "something went wrong" without parsing stderr.
const EXIT_BAD_CONFIG: i32 = 78;

/// Exit code for arguments that were passed and should not have been.
const EXIT_BAD_USAGE: i32 = 64;

/// Exit code for a start-up that could not proceed.
const EXIT_UNAVAILABLE: i32 = 69;

/// Exit code when a second signal cut a drain short.
///
/// 128 + SIGINT, the shell convention for "died of a signal".
const EXIT_INTERRUPTED: i32 = 130;

fn main() {
    // `CFG-007` (#172): this binary takes no arguments. Silently ignoring them
    // is worse than refusing — an operator who typed something expects it to
    // have had an effect. vlmcsd documents `-h` and `-?` that are not in its
    // own optstring, and py-kms has no `--version` at all; both are what
    // happens when argv handling is an afterthought rather than absent.
    let extra: Vec<String> = std::env::args().skip(1).collect();
    if !extra.is_empty() {
        eprintln!(
            "{PRODUCT_NAME}: this program takes no arguments, but was given: {}",
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
            eprintln!("{PRODUCT_NAME}: {error}");
            std::process::exit(EXIT_BAD_CONFIG);
        }
    };

    if let Err(code) = run(operational) {
        std::process::exit(code);
    }
}

/// Start up and serve until asked to stop.
fn run(operational: Operational) -> Result<(), i32> {
    let discovered = Discovered::observe();
    let compiled = Compiled::BUILD;

    // The wall clock is read exactly once, to bound the randomised activation
    // date in the ePID (`ID-007`, #112). Nothing in the request path reads one
    // again, which is why this host needs no accurate clock (`ARCH-004`, #4).
    let today = today().ok_or_else(|| {
        eprintln!("{PRODUCT_NAME}: the system clock is not usable");
        EXIT_UNAVAILABLE
    })?;

    let mut entropy = OsEntropy;
    let server =
        Server::new(compiled, operational, discovered, &mut entropy, today).map_err(|error| {
            // Serving a predictable identity is worse than not serving
            // (`OS-012`, #263).
            eprintln!("{PRODUCT_NAME}: {error}");
            EXIT_UNAVAILABLE
        })?;

    let (bound, failures) = bind_all().map_err(|error| {
        eprintln!("{PRODUCT_NAME}: {error}");
        EXIT_UNAVAILABLE
    })?;

    for (address, error) in &failures {
        // `NET-001` (#150): one stack missing is a fact about the host, not a
        // failure — but it is worth saying out loud, since an operator who
        // expected IPv6 to work should not have to guess.
        eprintln!("{PRODUCT_NAME}: not listening on {address}: {error}");
    }
    for entry in &bound {
        eprintln!("{PRODUCT_NAME}: listening on {}", entry.address);
    }

    let runtime = Arc::new(Runtime::new(server, MAX_CONNECTIONS));

    // `NET-007` (#157): SIGINT and SIGTERM on Unix, `SetConsoleCtrlHandler` on
    // Windows, through a safe wrapper so this crate keeps `forbid(unsafe_code)`.
    // The handler does one thing — set a flag and poke the listeners — rather
    // than vlmcsd's `fopen`/`fprintf` from signal context.
    //
    // The Windows *service* control handler is a separate mechanism and belongs
    // with the rest of the service work (M8).
    {
        let runtime = Arc::clone(&runtime);
        let already_asked = AtomicBool::new(false);
        if let Err(error) = ctrlc::set_handler(move || {
            if already_asked.swap(true, Ordering::AcqRel) {
                // A second signal means the operator is not willing to wait for
                // in-flight connections. Honouring that is more useful than
                // draining twice as politely.
                eprintln!("{PRODUCT_NAME}: exiting without draining");
                #[expect(
                    clippy::exit,
                    reason = "a second signal is an explicit instruction not to \
                              wait for in-flight connections; unwinding out of a \
                              signal handler is not possible, so exiting is the \
                              only way to honour it"
                )]
                std::process::exit(EXIT_INTERRUPTED);
            }
            eprintln!("{PRODUCT_NAME}: draining");
            runtime.shutdown.request();
        }) {
            eprintln!("{PRODUCT_NAME}: no shutdown handler installed: {error}");
        }
    }

    let boot = std::time::Instant::now();
    let clock = move || {
        let elapsed = boot.elapsed();
        Instant::from_nanos(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
    };

    let entropy: Box<dyn Entropy + Send> = Box::new(OsEntropy);
    if let Err(error) = serve(&runtime, bound, entropy, &clock) {
        eprintln!("{PRODUCT_NAME}: {error}");
        return Err(EXIT_UNAVAILABLE);
    }

    eprintln!("{PRODUCT_NAME}: stopped");
    Ok(())
}

/// Today's date in UTC, from the system clock.
///
/// The only wall-clock read in the program.
fn today() -> Option<kmsrs_db::Date> {
    /// Seconds in a day. Leap seconds are not represented in Unix time, so
    /// this conversion is exact.
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    let days = i32::try_from(since_epoch.as_secs().checked_div(SECONDS_PER_DAY)?).ok()?;
    Some(kmsrs_db::Date::from_days_since_epoch(days))
}
