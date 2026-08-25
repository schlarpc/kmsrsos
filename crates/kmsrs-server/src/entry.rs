//! Start-up, wiring and shutdown: the whole program except `fn main`
//! (`ARCH-001`, #1; `OS-001`, #252).
//!
//! This is a module rather than the contents of `main.rs` because there are two
//! binaries that must run *exactly* this: `kmsrsos` on Linux and Windows, and
//! `kmsrsos-hermit` on the unikernel. A second copy of the start-up sequence is
//! a second place where the entropy self-test could be forgotten, and the
//! target it would be forgotten on is the one nobody can attach a debugger to.
//!
//! There is no argv processing here and there never will be (`CFG-007`, #172).
//! Configuration is decided when the binary is built; the single runtime knob
//! is the `KMSRSOS_CONFIG` environment variable, which may only touch settings
//! that cannot change a byte on the wire (`CFG-002`, #167).

use crate::config::{Compiled, Discovered, Operational};
use crate::facts::Facts;
use crate::log::{Logger, Severity};
use crate::net::driver::{Driver, MAX_CONNECTIONS, Role, ShutdownHandle};
use crate::net::listener::bind_all;
use crate::{OsEntropy, PRODUCT_NAME, Server};
use core::sync::atomic::{AtomicBool, Ordering};
use std::process::ExitCode;

/// Exit code for a configuration this binary could not understand.
///
/// Distinct from a generic failure so that a supervisor can tell "you told me
/// something wrong" from "something went wrong" without parsing stderr.
pub const EXIT_BAD_CONFIG: u8 = 78;

/// Exit code for arguments that were passed and should not have been.
pub const EXIT_BAD_USAGE: u8 = 64;

/// Exit code for a start-up that could not proceed.
pub const EXIT_UNAVAILABLE: u8 = 69;

/// Exit code when a second signal cut a drain short.
///
/// 128 + SIGINT, the shell convention for "died of a signal".
pub const EXIT_INTERRUPTED: i32 = 130;

/// Run the emulator until it is asked to stop, and report how that went.
///
/// Every binary in this workspace that serves KMS calls exactly this, so
/// "what the program does at start-up" has one definition (`OS-001`, #252).
#[must_use]
pub fn serve() -> ExitCode {
    serve_with(|_| {})
}

/// The same, with work process 1 wants running alongside (`OS-019`, #335).
///
/// # One runtime, and this is how it stays one
///
/// On the bare-metal target the userland is this process, so DHCP renewal,
/// SNTP polling and the guest-agent channel have nowhere else to live. Each of
/// them is a timer and a socket, and `ARCH-005` (#5) as superseded by `OS-024`
/// (#340) says there is one scheduler deciding when work runs — so they run as
/// tasks on the runtime this function builds, not on a second one `kmsrs-os`
/// builds for itself.
///
/// `housekeeping` is called **inside** `block_on`, after the listeners are bound
/// and before the driver accepts, so it may [`tokio::spawn`] freely. It is
/// handed a [`Facts`] slot to publish what it learns into; the web UI reads the
/// same slot. On Linux and Windows nothing calls this and the slot stays empty,
/// which is what every page already renders.
///
/// Binding does not wait for it. This host binds `0.0.0.0` and reads its own
/// address for nothing (`NET-001`, #150), so there is no ordering requirement
/// between having an address and being able to serve — and making one would
/// mean a DHCP server outage was a KMS outage.
#[must_use]
pub fn serve_with<F>(housekeeping: F) -> ExitCode
where
    F: FnOnce(Facts) + Send + 'static,
{
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
            crate::config::operational::ENV_VAR
        );
        return ExitCode::from(EXIT_BAD_USAGE);
    }

    // `CFG-002` (#167): malformed configuration exits non-zero immediately and
    // says what was wrong. Starting degraded would mean running with a
    // configuration nobody wrote.
    let operational = match Operational::from_env() {
        Ok(operational) => operational,
        Err(error) => {
            eprintln!("{PRODUCT_NAME}: {error}");
            return ExitCode::from(EXIT_BAD_CONFIG);
        }
    };

    match run(operational, housekeeping) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

/// Start up and serve until asked to stop.
fn run<F>(operational: Operational, housekeeping: F) -> Result<(), u8>
where
    F: FnOnce(Facts) + Send + 'static,
{
    let discovered = Discovered::observe();
    let compiled = Compiled::BUILD;

    // `NET-016` (#165), declined as D40: this build does not adopt inherited
    // sockets, and refuses to start rather than binding its own alongside a
    // manager's.
    //
    // Silently ignoring `LISTEN_FDS` is the failure this exists to prevent. A
    // `.socket` unit holds 1688; this process would then try to bind it too and
    // fail with EADDRINUSE — or worse, succeed on a different address and serve
    // nothing anybody reaches. Under `Accept=yes` it would be worse still: one
    // process per connection, which destroys both the stable ePID
    // (`ID-001`, #106) and the CMID table (`POL-001`, #89) while continuing to
    // answer, which is exactly how vlmcsd-under-systemd degrades without
    // telling anyone (declined item D20).
    //
    // Written before the logger exists, because the logger is built from
    // configuration and this is a fact about how the process was started.
    if discovered.listen_fds > 0 {
        eprintln!(
            "{PRODUCT_NAME}: started with LISTEN_FDS={}, but this build does \
             not adopt inherited sockets.",
            discovered.listen_fds
        );
        eprintln!(
            "Remove the .socket unit and let the service bind 1688 itself: it \
             is an unprivileged port, so nothing is gained by having systemd \
             open it. See deploy/systemd/kmsrsos.service."
        );
        return Err(EXIT_BAD_USAGE);
    }
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
    let mut listeners: Vec<(crate::net::listener::Bound, Role)> =
        bound.into_iter().map(|entry| (entry, Role::Kms)).collect();

    if operational.web_ui {
        match crate::net::listener::bind_each(&crate::net::addr::web_addresses(
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

    // `OS-012` (#263): refuse to serve rather than serve a predictable
    // identity.
    //
    // This is not defensive coding. Hermit's `sys_read_entropy` *silently
    // succeeds* on a seeding failure, filling the buffer from a Park-Miller
    // LCG seeded with a static zero — a stream identical across boots — and
    // emitting a warning the guest never sees. `getrandom` reports success and
    // hands it on. On a default Proxmox VM that is the likely path rather than
    // the edge case: the `kvm64` CPU model exposes no RDSEED and Proxmox's
    // virtio-rng lands on a bus Hermit rejects.
    //
    // Every anti-fingerprinting property this host has would become a constant
    // while it kept working perfectly: the association group, response IVs and
    // salts, the hardware ID, the randomised ePID fields. A host that answers
    // every client with the same "random" values is worse than one that does
    // not answer, because nobody finds out.
    if let Err(failure) = OsEntropy.self_test() {
        logger.message(
            Severity::Error,
            "entropy",
            &format!(
                "{failure}; refusing to serve. On a virtual machine, check that                  the CPU model exposes RDSEED — see docs/deployment.md."
            ),
        );
        return Err(EXIT_UNAVAILABLE);
    }

    let runtime = build_runtime().map_err(|error| {
        logger.message(Severity::Error, "startup", &error.to_string());
        EXIT_UNAVAILABLE
    })?;

    let outcome = runtime.block_on(async {
        let mut driver = Driver::with_roles(
            server,
            listeners,
            MAX_CONNECTIONS,
            true,
            Box::new(OsEntropy),
        )
        .map_err(|error| {
            logger.message(Severity::Error, "startup", &error.to_string());
            EXIT_UNAVAILABLE
        })?;
        let shutdown = driver.shutdown_handle();

        arrange_to_stop_politely(logger, &shutdown);

        // Inside `block_on` and before `run`, so anything it spawns is on this
        // runtime and starts before the first connection (`OS-019`, #335).
        housekeeping(driver.facts());

        driver.run().await.map_err(|error| {
            logger.message(Severity::Error, "serve", &error.to_string());
            EXIT_UNAVAILABLE
        })
    });
    outcome?;

    logger.message(Severity::Info, "stopped", PRODUCT_NAME);
    Ok(())
}

/// The runtime the driver runs on (`OS-024`, #340).
///
/// Current-thread, not multi-threaded. This host answers one 384-byte request
/// per client per few hours; the work is a Rijndael CBC-MAC over a few hundred
/// bytes, and the shared server state is serialised behind one mutex anyway, so
/// a worker pool would add threads that contend for it and nothing else. It
/// also keeps the bare-metal target honest: `kmsrs-server` is pid 1 there, and
/// a thread-per-core scheduler on a one-vCPU guest is a scheduler arguing with
/// itself.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the runtime could not be created.
fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
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
/// [`crate::platform::install_shutdown_handler`] reports that rather than a
/// failure to deliver something that does not exist. Not being able to stop
/// politely is never fatal — a host that ignores SIGTERM is still a host that
/// activates — so every outcome here is logged and none returns an error.
///
/// The Windows *service* control handler is a separate mechanism and belongs
/// with the rest of the service work (M8).
fn arrange_to_stop_politely(logger: Logger, shutdown: &ShutdownHandle) {
    let shutdown = shutdown.clone();
    let already_asked = AtomicBool::new(false);

    match crate::platform::install_shutdown_handler(move || {
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
        Ok(()) => {}
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
