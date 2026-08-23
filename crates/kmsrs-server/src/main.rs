//! `kmsrsos` entry point.
//!
//! There is no argv processing here and there never will be (`CFG-007`, #172).
//! Configuration is decided when the binary is built; the single runtime knob
//! is the `KMSRSOS_CONFIG` environment variable, which may only touch settings
//! that cannot change a byte on the wire (`CFG-002`, #167).

use core::sync::atomic::{AtomicBool, Ordering};
use kmsrs_proto::time::Instant;
use kmsrs_server::config::{Compiled, Discovered, Operational};
use kmsrs_server::log::{Logger, Severity};
use kmsrs_server::net::driver::{Driver, MAX_CONNECTIONS, Role, ShutdownHandle};
use kmsrs_server::net::listener::bind_all;
use kmsrs_server::platform::SignalHandling;
use kmsrs_server::{OsEntropy, PRODUCT_NAME, Server};

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
    // Everything from here on goes through the logger, so it is shaped and
    // filtered the same way a request is (`OBS-001`, #177). The two failures
    // above happen before a logger can exist, since the logger is built from
    // the configuration that failed to parse.
    let logger = Logger::new(&operational, &discovered);

    // The wall clock is read exactly once, to bound the randomised activation
    // date in the ePID (`ID-007`, #112). Nothing in the request path reads one
    // again, which is why this host needs no accurate clock (`ARCH-004`, #4).
    let today = today().ok_or_else(|| {
        logger.message(Severity::Error, "startup", "the system clock is not usable");
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
        logger.message(Severity::Error, "bind", &error.to_string());
        EXIT_UNAVAILABLE
    })?;

    for (address, error) in &failures {
        // `NET-001` (#150): one stack missing is a fact about the host, not a
        // failure — but it is worth saying out loud, since an operator who
        // expected IPv6 to work should not have to guess.
        logger.message(
            Severity::Warn,
            "bind-skipped",
            &format!("{address}: {error}"),
        );
    }
    for entry in &bound {
        logger.message(Severity::Info, "listening", &entry.address.to_string());
    }

    // `OBS-014` (#190): the web UI is another listener on the same loop, not a
    // second server. One loop means one place where a deadline, a capacity
    // check and a shutdown have to be right.
    let mut listeners: Vec<(kmsrs_server::net::listener::Bound, Role)> =
        bound.into_iter().map(|entry| (entry, Role::Kms)).collect();

    if operational.web_ui {
        match kmsrs_server::net::listener::bind_each(&kmsrs_server::net::addr::web_addresses(
            operational.web_ui_port,
        )) {
            Ok((web_bound, web_failures)) => {
                for (address, error) in &web_failures {
                    logger.message(
                        Severity::Warn,
                        "web-bind-skipped",
                        &format!("{address}: {error}"),
                    );
                }
                for entry in &web_bound {
                    logger.message(Severity::Info, "web-listening", &entry.address.to_string());
                }
                listeners.extend(web_bound.into_iter().map(|entry| (entry, Role::Web)));
            }
            // A web port that will not bind is not a reason to refuse to
            // activate anything. Said out loud rather than swallowed
            // (`SEC-012`, #204).
            Err(error) => logger.message(Severity::Warn, "web-bind", &error.to_string()),
        }
    }

    // `OS-012` (#263): a source that has started repeating itself will not
    // stop, so this is read once and reported by `/healthz` thereafter.
    let entropy_healthy = OsEntropy.self_test().is_ok();
    if !entropy_healthy {
        logger.message(
            Severity::Error,
            "entropy",
            "the entropy self-test is failing; /healthz will report unhealthy",
        );
    }

    let mut driver = Driver::with_roles(server, listeners, MAX_CONNECTIONS, entropy_healthy)
        .map_err(|error| {
            logger.message(Severity::Error, "startup", &error.to_string());
            EXIT_UNAVAILABLE
        })?;
    let shutdown = driver.shutdown_handle();

    arrange_to_stop_politely(logger, &shutdown);

    let boot = std::time::Instant::now();
    let clock = move || {
        let elapsed = boot.elapsed();
        Instant::from_nanos(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
    };

    let mut entropy = OsEntropy;
    if let Err(error) = driver.run(&mut entropy, &clock) {
        logger.message(Severity::Error, "serve", &error.to_string());
        return Err(EXIT_UNAVAILABLE);
    }

    logger.message(Severity::Info, "stopped", PRODUCT_NAME);
    Ok(())
}

/// Ask the operating system to drain us when it wants us gone
/// (`NET-007`, #157; `OS-015`, #298).
///
/// SIGINT and SIGTERM on Unix, `SetConsoleCtrlHandler` on Windows, through a
/// safe wrapper so this crate keeps `forbid(unsafe_code)`. The handler does one
/// thing — set a flag and poke the poller's waker — rather than vlmcsd's
/// `fopen`/`fprintf` from signal context.
///
/// On Hermit there is nothing to install: that target has no signals at all, so
/// the drain path is reached only through [`ShutdownHandle`], and
/// [`kmsrs_server::platform::install_shutdown_handler`] reports that rather than
/// a failure to deliver something that does not exist. Not being able to stop
/// politely is never fatal — a host that ignores SIGTERM is still a host that
/// activates — so every outcome here is logged and none returns an error.
///
/// The Windows *service* control handler is a separate mechanism and belongs
/// with the rest of the service work (M8).
fn arrange_to_stop_politely(logger: Logger, shutdown: &ShutdownHandle) {
    let shutdown = shutdown.clone();
    let already_asked = AtomicBool::new(false);

    match kmsrs_server::platform::install_shutdown_handler(move || {
        if already_asked.swap(true, Ordering::AcqRel) {
            // A second signal means the operator is not willing to wait for
            // in-flight connections. Honouring that is more useful than
            // draining twice as politely.
            logger.message(Severity::Warn, "shutdown", "exiting without draining");
            #[expect(
                clippy::exit,
                reason = "a second signal is an explicit instruction not to \
                          wait for in-flight connections; unwinding out of a \
                          signal handler is not possible, so exiting is the \
                          only way to honour it"
            )]
            std::process::exit(EXIT_INTERRUPTED);
        }
        logger.message(Severity::Info, "shutdown", "draining");
        shutdown.request();
    }) {
        Ok(SignalHandling::Installed) => {}
        // Not a warning. A target with no signals has not failed to deliver
        // one, and logging it as a problem would train an operator to ignore
        // the line that does mean something.
        Ok(SignalHandling::Unsupported) => logger.message(
            Severity::Info,
            "shutdown",
            "this target has no signals; stopping is the hypervisor's job",
        ),
        Err(error) => logger.message(
            Severity::Warn,
            "shutdown",
            &format!("no handler installed: {error}"),
        ),
    }
}

/// Today's date in UTC, from the system clock.
///
/// The only wall-clock read in the program (`OS-007`, #258). Everything else
/// that needs time uses the injected monotonic clock, which is why this host
/// works on a target whose `SystemTime` is a CMOS read plus local ticks.
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
