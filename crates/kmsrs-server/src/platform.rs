//! What differs per target, named once (`NET-007`, #157; `OS-015`, #298).
//!
//! This module used to be large. It carried a named capability for every way
//! Hermit differed from a hosted operating system — one socket instead of two,
//! no signals, a stub `setsockopt`, an unchoosable listen backlog, an untrusted
//! wall clock — together with an executable audit of every socket option that
//! stub mishandled (`OS-010`, #261).
//!
//! `OS-018` (#334) removed Hermit, and every one of those capabilities was
//! `cfg!(target_os = "hermit")` or its negation. With the target gone they are
//! all constants: two sockets, signals exist, `setsockopt` works, the backlog is
//! chosen, the clock is real. A `const bool` that is `true` on every remaining
//! target is not a capability, it is a comment — so they are deleted rather than
//! kept as documentation of a target nobody can build.
//!
//! Linux and Windows are what is left, and they differ in one thing this
//! Linux and Windows are what is left, and they differ in one thing this
//! program can observe: how the operating system asks it to stop. `ctrlc`
//! handles both, so even that is not a branch here — and a Windows service,
//! which is asked through the SCM rather than a console event, reaches the same
//! handler through [`request_shutdown`] (`PKG-008`, #245).

/// The installed handler, kept so a second caller can trigger it.
///
/// `PKG-008` (#245): a Windows service is not asked to stop by a console
/// control event — it is asked through its service control handler, on a thread
/// the SCM owns. That is the same event as `SIGTERM` as far as this program is
/// concerned, so it runs the same handler rather than a parallel shutdown path
/// that could drift from it.
static ASKED_TO_STOP: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);

use std::sync::Mutex;

/// A signal handler that could not be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalError(String);

impl core::fmt::Display for SignalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for SignalError {}

/// Ask the operating system to run `handler` when it is told to stop
/// (`NET-007`, #157; `OS-015`, #298).
///
/// SIGINT and SIGTERM on Unix, `SetConsoleCtrlHandler` on Windows.
///
/// # Why this matters more as PID 1
///
/// On the `OS-017` (#333) target this program *is* process 1, and the kernel
/// applies no default dispositions to pid 1: a signal with no installed handler
/// is discarded rather than acted on. So installing a handler is not a courtesy
/// that makes shutdown tidier — before this call, `SIGTERM` does nothing at all,
/// and the only way to stop the machine is for the hypervisor to pull the power.
///
/// # Errors
///
/// Returns [`SignalError`] if the handler could not be installed. A caller
/// should carry on serving: a host that cannot be stopped politely is still a
/// host that activates.
pub fn install_shutdown_handler<F>(handler: F) -> Result<(), SignalError>
where
    F: FnMut() + Send + 'static,
{
    match ASKED_TO_STOP.lock() {
        Ok(mut slot) => *slot = Some(Box::new(handler)),
        Err(_) => {
            return Err(SignalError(String::from(
                "shutdown handler slot is poisoned",
            )));
        }
    }
    ctrlc::set_handler(request_shutdown).map_err(|error| SignalError(error.to_string()))
}

/// Run the installed shutdown handler, if there is one (`PKG-008`, #245).
///
/// Called by the console control handler on both targets, and by the Windows
/// service control handler when the SCM sends `STOP` or `SHUTDOWN`. Doing
/// nothing when no handler is installed is deliberate: the only window in which
/// that happens is before the listeners exist, and there is nothing to drain.
pub fn request_shutdown() {
    if let Ok(mut slot) = ASKED_TO_STOP.lock()
        && let Some(handler) = slot.as_mut()
    {
        handler();
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::install_shutdown_handler;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The handler is installed once per process, so this asserts the call
    /// succeeds rather than that the signal arrives — raising a real SIGTERM in
    /// a test process would take the test runner with it.
    #[test]
    fn a_handler_installs() {
        static CALLED: AtomicBool = AtomicBool::new(false);
        let result = install_shutdown_handler(|| CALLED.store(true, Ordering::SeqCst));
        assert!(result.is_ok(), "handler should install: {result:?}");
        assert!(!CALLED.load(Ordering::SeqCst), "nothing has signalled yet");
    }
}
