//! The sans-io contract between the protocol core and the platform layer
//! (`ARCH-002`, #2).
//!
//! A [`SansIo`] implementation is handed bytes, a clock reading and an entropy
//! source, and returns an [`Outcome`] describing what the driver should do with
//! the socket. It does not own the socket, read the clock or hold a generator.
//! That inversion is what makes three otherwise-hard things possible at once
//! (axiom A7):
//!
//! * **Fuzzing** — a fuzz target is a loop over [`SansIo::handle_input`] with no
//!   network involved (`SEC-004`, #196).
//! * **Differential testing** — the same byte sequence can be replayed against
//!   vlmcsd and py-kms and compared, because time and randomness are arguments
//!   rather than ambient state (`TEST-004`, #225).
//! * **Swapping the driver** — the I/O layer can be replaced wholesale without
//!   a second copy of the protocol logic (`ARCH-005`, #5). That is not
//!   hypothetical: this split is what let the bare-metal target change from a
//!   unikernel to Linux (`OS-018`, #334) with no change here at all.
//!
//! # Deviation from the issue text
//!
//! `ARCH-002` sketches `Outcome` as an enum with `Send`, `Close`, `KeepOpen`,
//! `Event` and `Deadline` variants. Events and deadlines are accessors here
//! instead ([`SansIo::next_event`], [`SansIo::deadline`]), because a request
//! that is both answered *and* logged is the normal case, not an edge one — and
//! a single-valued enum cannot express both at once without the driver
//! re-entering the machine to ask what else it wanted. The properties the issue
//! is actually about, that no I/O, clock or generator lives inside the core,
//! are unaffected.

use crate::entropy::Entropy;
use crate::time::Instant;

/// Why an association is being torn down.
///
/// Exhaustive on purpose: a driver that gains a new way to close a connection
/// should stop compiling until it has decided how to log it, since these map
/// directly onto operator-visible event-log entries (`OBS-003`, #179).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The peer closed its side.
    PeerClosed,

    /// The framing was unusable and no fault could be attributed to a call —
    /// for example a PDU shorter than the 16-byte common header, which is
    /// rejected before parsing (`WIRE-025`, #83).
    Malformed,

    /// A fault PDU was emitted and the association cannot continue.
    ///
    /// Distinct from [`CloseReason::Malformed`] because the client received an
    /// answer in this case and did not in the other, which is exactly the
    /// distinction an operator reading the log needs.
    Faulted,

    /// No input arrived before the state machine's deadline.
    ///
    /// The timeout lives in the state machine rather than in a socket option
    /// (`NET-004`, #153) — `SO_RCVTIMEO` is a silent no-op on one of the three
    /// target platforms and returns `EINVAL` on it, which is the worst possible
    /// failure shape for something load-bearing.
    IdleTimeout,

    /// Admission control refused the connection rather than queueing it
    /// (`POL-012`, #100).
    Refused,

    /// The process is shutting down (`NET-008`, #157).
    ShuttingDown,
}

/// What the driver must do with the socket after a call to
/// [`SansIo::handle_input`] (`ARCH-002`, #2).
///
/// `Send` carries a length rather than a slice: the driver owns the output
/// buffer and passes it in, so the machine never allocates and the response
/// path has no failure mode of its own (`KMS-023`, #39).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Nothing to send. Keep the association open and read more.
    ///
    /// This is the normal result of a partial read: DCE/RPC PDUs are
    /// reassembled from however many segments TCP chose to deliver
    /// (`WIRE-022`, #80; `NET-007`, #156).
    KeepOpen,

    /// Send the first `len` bytes of the output buffer, then keep the
    /// association open.
    ///
    /// This is what a successful activation returns. A real KMS host does not
    /// hang up afterwards, and an emulator that does is distinguishable from
    /// one that does not (`WIRE-021`, #79).
    Send {
        /// Number of bytes written to the front of the output buffer. Never
        /// exceeds the buffer's length.
        len: usize,
    },

    /// Send the first `len` bytes, then close.
    SendThenClose {
        /// Number of bytes written to the front of the output buffer.
        len: usize,
        /// Why the association is ending.
        reason: CloseReason,
    },

    /// Close without sending anything.
    Close {
        /// Why the association is ending.
        reason: CloseReason,
    },
}

impl Outcome {
    /// How many bytes of the output buffer the driver should write, if any.
    #[must_use]
    pub const fn bytes_to_send(self) -> usize {
        match self {
            Self::Send { len } | Self::SendThenClose { len, .. } => len,
            Self::KeepOpen | Self::Close { .. } => 0,
        }
    }

    /// Whether the driver should close the connection after sending.
    #[must_use]
    pub const fn closes(self) -> bool {
        match self {
            Self::SendThenClose { .. } | Self::Close { .. } => true,
            Self::KeepOpen | Self::Send { .. } => false,
        }
    }
}

/// A protocol state machine that performs no I/O (`ARCH-002`, #2).
///
/// # Contract
///
/// * `handle_input` is called with a monotonic reading that never decreases
///   between calls, and with the bytes read from the socket. An empty `input`
///   means "no new data" and is how a driver reports a timer expiry.
/// * The output buffer the driver supplies is at least
///   [`SansIo::MAX_OUTPUT_LEN`] bytes. Because every response this protocol can
///   produce has a statically known bound, the machine never has to fail for
///   want of room, and there is no partial-write state to get wrong.
/// * Implementations must not panic on any input. This is enforced rather than
///   requested: `kmsrs-proto` is compiled for a `no_std` target with
///   `panic_immediate_abort` and CI fails on any reference to
///   `core::panicking::panic_fmt` (`ARCH-009`, #9).
pub trait SansIo {
    /// What this machine reports to the event log (`OBS-004`, #180).
    ///
    /// An associated type rather than a concrete one so that the protocol crate
    /// does not have to depend on the policy crate that owns the event log,
    /// which depends on it.
    type Event;

    /// An upper bound on the bytes a single `handle_input` call can produce.
    ///
    /// Stated by the implementation so the driver can size one buffer per
    /// connection up front and never resize it (`ARCH-014`, #14: per-request
    /// state is owned by the request, never a shared mutable map).
    const MAX_OUTPUT_LEN: usize;

    /// Feed input to the machine and learn what to do with the socket.
    ///
    /// `now` and `entropy` are arguments precisely so this crate contains no
    /// clock read and no generator state.
    fn handle_input(
        &mut self,
        now: Instant,
        entropy: &mut dyn Entropy,
        input: &[u8],
        output: &mut [u8],
    ) -> Outcome;

    /// The instant after which the driver should stop waiting for input, if the
    /// machine wants one (`NET-004`, #153).
    ///
    /// Recomputed by the machine on each transition rather than armed once, so
    /// that a slow-loris client that dribbles a byte at a time does not get an
    /// unbounded extension — and, unlike py-kms's, this is a per-connection
    /// deadline rather than a process-lifetime cap computed before the accept
    /// loop (declined item D23).
    fn deadline(&self) -> Option<Instant>;

    /// Take the next event the machine has produced, if any.
    ///
    /// Drained by the driver after each `handle_input`. Events are queued
    /// rather than returned inline because one request routinely produces both
    /// a response and a log entry.
    fn next_event(&mut self) -> Option<Self::Event>;
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: arithmetic is over known-small test values"
    )]

    use super::{CloseReason, Outcome, SansIo};
    use crate::entropy::Entropy;
    use crate::entropy::testing::{DeterministicEntropy, FailingEntropy};
    use crate::time::Instant;
    use arrayvec::ArrayVec;
    use core::time::Duration;

    /// A machine that exercises every part of the contract without being the
    /// real one: it answers a fixed request, reports an event, arms a deadline,
    /// and refuses to serve when its entropy source fails.
    ///
    /// Its purpose is to prove the interface is expressible — that a full
    /// connection lifecycle can be driven with no socket, no clock read and no
    /// ambient generator anywhere in the crate.
    #[derive(Debug, Default)]
    struct ExampleMachine {
        events: ArrayVec<Event, 4>,
        deadline: Option<Instant>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Answered { nonce: u32 },
        EntropyFailed,
    }

    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    impl SansIo for ExampleMachine {
        type Event = Event;
        const MAX_OUTPUT_LEN: usize = 8;

        fn handle_input(
            &mut self,
            now: Instant,
            entropy: &mut dyn Entropy,
            input: &[u8],
            output: &mut [u8],
        ) -> Outcome {
            self.deadline = now.checked_add(IDLE_TIMEOUT);

            if input.is_empty() {
                // How a driver reports a timer expiry: no new bytes.
                return Outcome::KeepOpen;
            }
            if input != b"REQUEST" {
                return Outcome::Close {
                    reason: CloseReason::Malformed,
                };
            }

            let Ok(nonce) = entropy.next_u32() else {
                let _: Result<_, _> = self.events.try_push(Event::EntropyFailed);
                return Outcome::Close {
                    reason: CloseReason::Refused,
                };
            };

            let bytes = nonce.to_le_bytes();
            output[..bytes.len()].copy_from_slice(&bytes);
            let _: Result<_, _> = self.events.try_push(Event::Answered { nonce });
            Outcome::Send { len: bytes.len() }
        }

        fn deadline(&self) -> Option<Instant> {
            self.deadline
        }

        fn next_event(&mut self) -> Option<Event> {
            if self.events.is_empty() {
                None
            } else {
                Some(self.events.remove(0))
            }
        }
    }

    /// Stand-in for the platform driver: owns the buffer, applies the outcome.
    fn drive(
        machine: &mut ExampleMachine,
        now: Instant,
        entropy: &mut dyn Entropy,
        input: &[u8],
    ) -> (Outcome, ArrayVec<u8, { ExampleMachine::MAX_OUTPUT_LEN }>) {
        let mut output = [0_u8; ExampleMachine::MAX_OUTPUT_LEN];
        let outcome = machine.handle_input(now, entropy, input, &mut output);
        let sent = output[..outcome.bytes_to_send()].iter().copied().collect();
        (outcome, sent)
    }

    #[test]
    fn a_full_exchange_needs_no_socket_clock_or_ambient_generator() {
        let mut machine = ExampleMachine::default();
        let mut entropy = DeterministicEntropy::from_seed(7);
        let now = Instant::from_nanos(1_000);

        let (outcome, sent) = drive(&mut machine, now, &mut entropy, b"REQUEST");

        assert_eq!(outcome, Outcome::Send { len: 4 });
        assert!(!outcome.closes(), "a real host keeps the association open");
        assert_eq!(sent.len(), 4);
        assert_eq!(
            machine.next_event(),
            Some(Event::Answered {
                nonce: u32::from_le_bytes([sent[0], sent[1], sent[2], sent[3]]),
            })
        );
        assert_eq!(
            machine.next_event(),
            None,
            "events are drained, not repeated"
        );
    }

    #[test]
    fn the_same_inputs_produce_the_same_bytes_twice() {
        // The property differential testing rests on (TEST-004, #225): with
        // time and randomness as arguments, a replay is exact.
        let replay = || {
            let mut machine = ExampleMachine::default();
            let mut entropy = DeterministicEntropy::from_seed(99);
            drive(
                &mut machine,
                Instant::from_nanos(5),
                &mut entropy,
                b"REQUEST",
            )
            .1
        };
        assert_eq!(replay(), replay());
    }

    #[test]
    fn a_failing_entropy_source_refuses_to_serve_rather_than_answering() {
        // The shape OS-012 (#263) depends on: no response, an event recorded,
        // and no plausible-looking constant handed to the client.
        let mut machine = ExampleMachine::default();
        let (outcome, sent) = drive(&mut machine, Instant::ZERO, &mut FailingEntropy, b"REQUEST");
        assert_eq!(
            outcome,
            Outcome::Close {
                reason: CloseReason::Refused
            }
        );
        assert!(sent.is_empty());
        assert_eq!(machine.next_event(), Some(Event::EntropyFailed));
    }

    #[test]
    fn the_deadline_is_rearmed_on_every_input_not_armed_once() {
        // Against D23: py-kms's timeout is computed once before the accept loop
        // and is really a process-lifetime cap. A per-connection deadline has
        // to move forward as input arrives.
        let mut machine = ExampleMachine::default();
        let mut entropy = DeterministicEntropy::from_seed(1);
        assert_eq!(machine.deadline(), None, "nothing armed before first input");

        let first = Instant::from_nanos(1_000);
        drive(&mut machine, first, &mut entropy, b"");
        let armed = machine.deadline().unwrap();
        assert_eq!(armed, first.checked_add(IDLE_TIMEOUT).unwrap());

        let later = first.checked_add(Duration::from_secs(5)).unwrap();
        drive(&mut machine, later, &mut entropy, b"");
        assert!(machine.deadline().unwrap() > armed, "deadline must advance");
    }

    #[test]
    fn empty_input_means_no_new_data_and_does_not_close() {
        let mut machine = ExampleMachine::default();
        let mut entropy = DeterministicEntropy::from_seed(1);
        let (outcome, sent) = drive(&mut machine, Instant::ZERO, &mut entropy, b"");
        assert_eq!(outcome, Outcome::KeepOpen);
        assert!(sent.is_empty());
    }

    #[test]
    fn outcome_accessors_agree_with_the_variants() {
        assert_eq!(Outcome::KeepOpen.bytes_to_send(), 0);
        assert!(!Outcome::KeepOpen.closes());
        assert_eq!(Outcome::Send { len: 12 }.bytes_to_send(), 12);
        assert!(!Outcome::Send { len: 12 }.closes());
        let ending = Outcome::SendThenClose {
            len: 3,
            reason: CloseReason::Faulted,
        };
        assert_eq!(ending.bytes_to_send(), 3);
        assert!(ending.closes());
        let closed = Outcome::Close {
            reason: CloseReason::ShuttingDown,
        };
        assert_eq!(closed.bytes_to_send(), 0);
        assert!(closed.closes());
    }
}
