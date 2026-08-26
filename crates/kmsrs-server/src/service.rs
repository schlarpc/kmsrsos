//! Running as a Windows service (`PKG-008`, #245).
//!
//! # What this is, and what it deliberately is not
//!
//! Four things: the control dispatcher, a handler for `STOP` and `SHUTDOWN`,
//! honest [`ServiceState`] transitions, and console-versus-service detection.
//!
//! There is **no install or uninstall verb**, and that is the whole design.
//! Under this project's configuration model installation is one documented
//! `sc.exe create` line, and an in-binary installer reintroduces exactly the
//! code that produced both of vlmcsd's service bugs. Without one, both become
//! unrepresentable rather than merely fixed:
//!
//! * there is no argv to embed in the `ImagePath`, so a password cannot be
//!   written into the registry where anyone can read it — this program takes no
//!   arguments at all (`CFG-007`, #172); and
//! * there is no argv concatenation, so the `strcat` overflow has nothing to
//!   overflow.
//!
//! # The consequence, stated plainly
//!
//! **A service has no stderr.** This program logs to stderr and nowhere else
//! (axiom A5: no disk I/O, no log files), so in service mode the request log is
//! visible only through the web UI — which makes the web UI non-optional there
//! rather than a convenience. A start-up failure is worse still: a bind failure
//! or a failed entropy self-test means the HTTP listener never comes up, so
//! there is nothing to browse to. `OBS-016` (#192) is the six-event Windows
//! Event Log that covers exactly that gap.
//!
//! # Detection, not configuration
//!
//! Whether this process is a service is asked of the operating system, not of a
//! flag: `StartServiceCtrlDispatcher` fails with
//! `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (1063) when the caller is not one.
//! A `--service` switch would be a second way to be wrong about it, and would
//! be an argument this program does not take.

use std::process::ExitCode;

/// The service name `sc.exe create` must use, and the name the SCM answers to.
///
/// One constant, because the name in the dispatcher and the name in
/// [`crate::service::platform`]'s handler registration have to agree or the
/// service starts and then cannot be controlled.
pub const SERVICE_NAME: &str = "kmsrsos";

/// Whether this target can run as a service at all (`PKG-008`, #245).
///
/// A `const bool` rather than a `cfg` on an item, so both branches of every
/// caller compile and are tested on every platform — the rule
/// [`crate::platform`] exists to keep.
pub const SERVICE_IS_AVAILABLE: bool = cfg!(windows);

/// Serve, as a service if the operating system started this as one.
///
/// On any other target, and on Windows when started from a console, this is
/// exactly [`crate::entry::serve`] — same start-up sequence, same sandbox, same
/// exit codes (`OS-001`, #252).
#[must_use]
pub fn run() -> ExitCode {
    platform::run()
}

#[cfg(windows)]
mod platform {
    //! The dispatcher, the handler and the state machine.

    use super::SERVICE_NAME;
    use std::ffi::OsString;
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    /// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: not started by the SCM.
    ///
    /// The one error that is not a failure. Anything else from the dispatcher
    /// means this *is* a service and could not become one, which is worth
    /// reporting.
    const NOT_A_SERVICE: i32 = 1063;

    /// How long the SCM should wait before deciding start-up has hung.
    ///
    /// Generous, because the entropy self-test runs before the listeners bind
    /// and a slow or contended machine should not be reported as a hung
    /// service. The checkpoint below is what actually tells the SCM progress is
    /// being made.
    const START_WAIT_HINT: Duration = Duration::from_secs(30);

    /// `ERROR_SERVICE_SPECIFIC_ERROR`-free way to say start-up did not finish.
    ///
    /// `ERROR_PROCESS_ABORTED`. Reported only when the service never reached
    /// `Running`, so the SCM and any recovery policy see a failed start rather
    /// than a clean stop.
    const EXIT_STARTUP_FAILED: u32 = 1067;

    define_windows_service!(ffi_service_main, service_main);

    /// A status record with this service's invariant fields already filled in.
    fn status(
        state: ServiceState,
        controls: ServiceControlAccept,
        wait: Duration,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            // `NO_ERROR` throughout: a service that stops because it was asked
            // to has not failed, and reporting a non-zero code here makes the
            // SCM restart it under a default recovery policy.
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        }
    }

    /// The service's body. Errors have nowhere to go — see the module docs.
    fn service_main(_arguments: Vec<OsString>) {
        drop(run_service());
    }

    fn run_service() -> windows_service::Result<()> {
        let handle =
            service_control_handler::register(SERVICE_NAME, move |control| match control {
                // Both mean the same thing to this program: stop accepting and
                // drain. `crate::platform::request_shutdown` runs the same handler
                // a console Ctrl-C would, so there is one shutdown path.
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    crate::platform::request_shutdown();
                    ServiceControlHandlerResult::NoError
                }
                // Answering `Interrogate` is how the SCM confirms the service is
                // alive; the status it reads is the one last set below.
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;

        // `StartPending` first, and accepting nothing yet: a `STOP` arriving
        // before the listeners exist has nothing to drain, and claiming to
        // accept it would mean acknowledging a control this cannot honour.
        handle.set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            START_WAIT_HINT,
        ))?;

        // `Running` is reported from inside the start-up sequence, at the
        // moment the listeners are bound and before the driver accepts — not
        // when this function was entered. A service that reports `Running`
        // before it can serve is a service whose dependents start too early.
        //
        // Whether that ever happened is also the only thing this can honestly
        // tell the SCM about how the run went: `serve_reporting_ready` returns
        // an `ExitCode`, which cannot be inspected, so "did it reach Running"
        // is the signal available. Not reaching it means start-up failed —
        // nothing bound, the clock was unusable, or the entropy self-test
        // failed — and reporting that as a clean stop would leave an operator
        // looking at a service that says it stopped normally and never served.
        let reached_running = Arc::new(AtomicBool::new(false));
        let ready = handle;
        let announced = Arc::clone(&reached_running);
        let _served: ExitCode = crate::entry::serve_reporting_ready(move |_| {
            announced.store(true, Ordering::Release);
            drop(ready.set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                Duration::default(),
            )));
        });

        // `serve_reporting_ready` returns only once the drain is finished, so
        // `StopPending` would be a state this never occupies for an observable
        // length of time. Reporting it anyway would be theatre.
        let mut stopped = status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            Duration::default(),
        );
        if !reached_running.load(Ordering::Acquire) {
            stopped.exit_code = ServiceExitCode::Win32(EXIT_STARTUP_FAILED);
        }
        handle.set_service_status(stopped)?;

        Ok(())
    }

    pub(super) fn run() -> ExitCode {
        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => ExitCode::SUCCESS,
            Err(windows_service::Error::Winapi(error))
                if error.raw_os_error() == Some(NOT_A_SERVICE) =>
            {
                // Started from a console. This is the ordinary case for anyone
                // running the binary by hand, so it is not logged.
                crate::entry::serve()
            }
            Err(error) => {
                eprintln!(
                    "{}: cannot start as a service: {error}",
                    crate::PRODUCT_NAME
                );
                ExitCode::from(crate::entry::EXIT_UNAVAILABLE)
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    //! A target with no service control manager.

    use std::process::ExitCode;

    pub(super) fn run() -> ExitCode {
        crate::entry::serve()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::assertions_on_constants,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{SERVICE_IS_AVAILABLE, SERVICE_NAME};

    /// `PKG-008` (#245): the name is a valid `sc.exe create` service name.
    ///
    /// The SCM accepts neither a forward slash nor a backslash, and a name that
    /// differs from the one in the documented `sc.exe` line produces a service
    /// that starts and then cannot be controlled.
    #[test]
    fn the_service_name_is_usable() {
        assert!(!SERVICE_NAME.is_empty());
        assert!(SERVICE_NAME.len() < 256, "the SCM limit is 256 characters");
        assert!(
            !SERVICE_NAME.contains('/') && !SERVICE_NAME.contains('\\'),
            "the SCM rejects both slashes in a service name"
        );
        assert!(
            SERVICE_NAME
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "keep the name to what an operator can type without quoting"
        );
    }

    /// The capability constant agrees with the target it describes.
    #[test]
    fn availability_matches_the_target() {
        assert_eq!(SERVICE_IS_AVAILABLE, cfg!(windows));
    }
}
