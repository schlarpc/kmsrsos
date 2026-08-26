//! Six lifecycle events, on Windows, and nothing else (`OBS-016`, #192).
//!
//! # Why this exists at all
//!
//! A Windows service has no stderr, and this program logs to stderr and nowhere
//! else — no files, no log database (axiom A5). Under the SCM that output goes
//! nowhere, so a service-mode start-up failure is **completely silent**, which
//! is vlmcsd's documented failure mode.
//!
//! The web UI cannot cover it either, and that is the part worth stating: a bind
//! failure or a failed entropy self-test means the HTTP listener never comes up,
//! so there is nothing to browse to. The window this fills is exactly the one
//! where every other channel is unavailable.
//!
//! # Six, and the request stream is not among them
//!
//! Start, stop, and the four ways start-up can fail. **Not** one event per
//! request: the Event Log is a shared, size-limited, administrator-visible
//! facility, and a KMS host filling it with activation records would be a
//! denial of service against every other thing that logs there. The request
//! stream stays on stderr and the web UI, which is where an operator looks for
//! it and where it can be bounded (`OBS-002`, the ring buffer).
//!
//! # Rendering, and why the binary is its own message file
//!
//! An event carries an identifier, not a string. The viewer resolves it through
//! the `EventMessageFile` registered for the source, and with none registered
//! it renders *"The description for Event ID N cannot be found"* — which looks
//! broken to an operator and is worse than logging nothing.
//!
//! So this binary is its own message file. `build.rs` generates an
//! `RT_MESSAGETABLE` resource and links it in, and
//! `the_message_table_matches_the_events` fails if its identifiers drift from
//! [`Event`]. Registration is one documented `reg add` line next to the
//! `sc.exe create` line — see `docs/deployment.md`, and see
//! [`crate::service`] for why there is no installer to do it automatically.
//!
//! # The second unsafe boundary
//!
//! `SEC-019` (#356) reopened the workspace's unsafe boundary for one call, and
//! this is the second place. `RegisterEventSourceW`, `ReportEventW` and
//! `DeregisterEventSource` are `unsafe extern` in every binding that exists.
//! The one crate that wraps them safely, `eventlog`, pulls in `windows` rather
//! than `windows-sys` — a COM runtime this program has no use for — and is
//! shaped as a `log` backend, which is the wrong shape for six events and would
//! mean adopting a logging facade this project does not use.
//!
//! `unsafe_is_confined_to_the_one_boundary` names both files rather than
//! counting to one, so a third cannot appear without the test being changed
//! deliberately.

/// A lifecycle event, and its identifier in the message table.
///
/// The discriminants are the `MESSAGES` identifiers in `build.rs` and must stay
/// contiguous from 1 — `the_message_table_matches_the_events` checks both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Event {
    /// Listeners are bound and the driver is accepting.
    Started = 1,
    /// A drain finished and the process is exiting normally.
    Stopped = 2,
    /// Nothing could be bound, so nothing is being served.
    BindFailed = 3,
    /// The entropy self-test failed, so no identity can be generated.
    EntropyFailed = 4,
    /// `KMSRSOS_CONFIG` could not be parsed.
    ConfigInvalid = 5,
    /// The process panicked.
    Panicked = 6,
}

impl Event {
    /// Every event, in identifier order.
    pub const ALL: [Self; 6] = [
        Self::Started,
        Self::Stopped,
        Self::BindFailed,
        Self::EntropyFailed,
        Self::ConfigInvalid,
        Self::Panicked,
    ];

    /// The identifier the viewer resolves against the message table.
    #[must_use]
    pub const fn id(self) -> u32 {
        self as u32
    }

    /// Whether this is a failure, which decides the icon an operator sees.
    ///
    /// Only the two normal transitions are informational. Everything else here
    /// is a reason the host is not serving, and an operator scanning for red
    /// should find them.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        !matches!(self, Self::Started | Self::Stopped)
    }
}

/// Whether this target has an event log to write to (`OBS-016`, #192).
///
/// A `const bool` rather than a `cfg` on an item, so both branches of every
/// caller compile and are tested on every platform.
pub const EVENT_LOG_IS_AVAILABLE: bool = cfg!(windows);

/// Record one lifecycle event, if this target has somewhere to record it.
///
/// Never fails and never blocks the caller: this is the channel of last resort
/// for saying why the program is not running, and a program that could not
/// start should not also fail to exit because it could not say so.
pub fn report(event: Event, detail: &str) {
    platform::report(event, detail);
}

#[cfg(windows)]
mod platform {
    //! `advapi32`, through the second documented unsafe boundary.

    use super::Event;
    use crate::service::SERVICE_NAME;
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
        RegisterEventSourceW, ReportEventW,
    };

    /// A NUL-terminated UTF-16 string, owned for as long as it is borrowed.
    fn wide(text: &str) -> Vec<u16> {
        let mut units: Vec<u16> = text.encode_utf16().collect();
        units.push(0);
        units
    }

    pub(super) fn report(event: Event, detail: &str) {
        let source = wide(SERVICE_NAME);
        // The insertion string. Truncated because `ReportEventW` rejects
        // anything over 32 KiB per string, and a detail that long is a bug
        // report rather than a log line.
        let mut shortened = String::new();
        for (index, character) in detail.chars().enumerate() {
            if index >= 2048 {
                shortened.push('…');
                break;
            }
            shortened.push(character);
        }
        let message = wide(&shortened);
        let strings = [message.as_ptr()];

        // SAFETY: `RegisterEventSourceW` reads one NUL-terminated wide string
        // from `source`, which `wide` guarantees, and a null server name means
        // the local machine. It returns a handle or null; null is checked
        // before use and there is nothing to release in that case.
        #[expect(
            unsafe_code,
            reason = "the second documented boundary: advapi32's event log has \
                      no safe wrapper that does not also bring a COM runtime \
                      (`OBS-016`, #192; `SEC-019`, #356)"
        )]
        let handle = unsafe { RegisterEventSourceW(core::ptr::null(), source.as_ptr()) };
        if handle.is_null() {
            return;
        }

        // SAFETY: `handle` is a live event-source handle from the call above.
        // `strings` holds exactly one pointer and `wnumstrings` says 1, so the
        // callee reads one element; the string it points at is NUL-terminated
        // and outlives this call because `message` does. No SID and no raw
        // data are supplied, and both parameters accept null for that, with
        // `dwdatasize` 0 agreeing that `lprawdata` is empty. The call reads
        // these buffers and writes none of them.
        #[expect(
            unsafe_code,
            reason = "the second documented boundary: advapi32's event log has \
                      no safe wrapper that does not also bring a COM runtime \
                      (`OBS-016`, #192; `SEC-019`, #356)"
        )]
        let _reported: i32 = unsafe {
            ReportEventW(
                handle,
                if event.is_failure() {
                    EVENTLOG_ERROR_TYPE
                } else {
                    EVENTLOG_INFORMATION_TYPE
                },
                0,
                event.id(),
                core::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                core::ptr::null(),
            )
        };

        // SAFETY: `handle` came from `RegisterEventSourceW`, has not been
        // closed, and is not used again after this.
        #[expect(
            unsafe_code,
            reason = "the second documented boundary: advapi32's event log has \
                      no safe wrapper that does not also bring a COM runtime \
                      (`OBS-016`, #192; `SEC-019`, #356)"
        )]
        let _released: i32 = unsafe { DeregisterEventSource(handle) };
    }
}

#[cfg(not(windows))]
mod platform {
    //! A target whose service manager reads stderr.

    use super::Event;

    pub(super) fn report(_event: Event, _detail: &str) {}
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{EVENT_LOG_IS_AVAILABLE, Event, report};

    /// `OBS-016` (#192): exactly six, contiguous from 1.
    ///
    /// The message table `build.rs` emits is a single block covering one
    /// contiguous range, so a gap here would render the wrong text for every
    /// identifier after it rather than failing visibly.
    #[test]
    fn the_identifiers_are_six_and_contiguous() {
        assert_eq!(Event::ALL.len(), 6, "OBS-016 says six events and no more");
        for (index, event) in Event::ALL.into_iter().enumerate() {
            let expected = u32::try_from(index).expect("six fits") + 1;
            assert_eq!(event.id(), expected, "{event:?} is out of order");
        }
    }

    /// Only the two normal transitions are informational.
    #[test]
    fn every_failure_is_reported_as_one() {
        assert!(!Event::Started.is_failure());
        assert!(!Event::Stopped.is_failure());
        for event in [
            Event::BindFailed,
            Event::EntropyFailed,
            Event::ConfigInvalid,
            Event::Panicked,
        ] {
            assert!(
                event.is_failure(),
                "{event:?} is a reason not to be serving"
            );
        }
    }

    /// Reporting is infallible on every target, including the ones with no log.
    ///
    /// This is the channel of last resort for saying why the program is not
    /// running; it must not become a second reason it cannot exit.
    #[test]
    fn reporting_never_fails() {
        assert_eq!(EVENT_LOG_IS_AVAILABLE, cfg!(windows));
        for event in Event::ALL {
            report(event, "workspace_invariants self-test");
        }
    }
}
