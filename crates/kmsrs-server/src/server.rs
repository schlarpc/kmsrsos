//! One host, its configuration, and the byte path through them
//! (`CFG-001`, #166).
//!
//! [`Server`] holds all three configuration categories and the [`Host`]. Its
//! reason for existing beyond convenience is the signature of
//! [`Server::handle`]: the wire path is handed `&Compiled` and never
//! [`Operational`], so an operational setting cannot reach a response byte
//! without someone changing a function signature to let it.
//!
//! That is the mechanism `CFG-001` (#166) asks for — a wire-visible field
//! *cannot* be placed in the runtime layer — and
//! `tests/wire_is_not_configurable.rs` is the test that keeps it honest by
//! driving a full exchange through two servers whose [`Operational`] settings
//! differ in every field and comparing the bytes.

use crate::clock::WallClock;
use crate::config::{Compiled, Discovered, Operational};
use crate::host::{Host, RequestContext};
use crate::log::Logger;
use kmsrs_policy::access::RateLimiter;
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::layout::MAX_RESPONSE_LEN;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::connection::{Connection, SecondaryAddress, Step};

/// A configured host.
#[derive(Debug)]
pub struct Server {
    compiled: Compiled,
    operational: Operational,
    discovered: Discovered,
    host: Host,
    logger: Logger,
    limiter: RateLimiter,
    /// The host's wall clock (`POL-020`, #346).
    ///
    /// Defaults to [`WallClock::unknown`], which is right for a platform
    /// without a usable one and for every test that does not care what time it
    /// is. `entry.rs` replaces it via [`Server::with_wall_clock`].
    wall_clock: WallClock,
}

/// What a driver should do with the socket after a call to [`Server::handle`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handled {
    /// Bytes to write back. Empty means there is nothing to send.
    pub response: Vec<u8>,
    /// Whether the connection should be closed afterwards.
    pub close: bool,
}

impl Server {
    /// Build a server from its three configuration categories.
    ///
    /// # Errors
    ///
    /// Returns [`kmsrs_policy::EntropyUnavailable`] if the identity could not
    /// be drawn. Serving a predictable identity is worse than not serving
    /// (`OS-012`, #263).
    pub fn new(
        compiled: Compiled,
        operational: Operational,
        discovered: Discovered,
        entropy: &mut dyn Entropy,
        today: kmsrs_db::Date,
    ) -> Result<Self, kmsrs_policy::EntropyUnavailable> {
        let host = Host::new(entropy, today)?.with_intervals(compiled.intervals);
        let logger = Logger::new(&operational, &discovered);
        Ok(Self {
            compiled,
            operational,
            discovered,
            host,
            logger,
            limiter: RateLimiter::new(),
            wall_clock: WallClock::unknown(),
        })
    }

    /// Give this server the host's wall clock (`POL-020`, #346).
    ///
    /// A builder rather than a parameter of [`Server::new`], because the clock
    /// is a property of the *process* — one reading, shared with whatever is
    /// disciplining it — while `Server::new` is called by a dozen tests that
    /// have no opinion about the time. Those get [`WallClock::unknown`] and the
    /// `host_time: None` behaviour that has always been correct for a host
    /// without a clock.
    #[must_use]
    pub fn with_wall_clock(mut self, wall_clock: WallClock) -> Self {
        self.wall_clock = wall_clock;
        self
    }

    /// The host's wall clock now (`POL-020`, #346).
    ///
    /// Reads `CLOCK_MONOTONIC` and projects from the anchor; it does **not**
    /// read `CLOCK_REALTIME`, which `OS-007` (#258) permits in only two files.
    /// See [`crate::clock`].
    #[must_use]
    pub fn host_time(&self) -> Option<kmsrs_proto::time::FileTime> {
        self.wall_clock.now()
    }

    /// The clock handle, for whatever is disciplining it (`OS-020`, #336).
    #[must_use]
    pub fn wall_clock(&self) -> WallClock {
        self.wall_clock.clone()
    }

    /// Feed a connection some bytes and collect whatever it wants to send.
    ///
    /// Note what is *not* a parameter: [`Operational`]. The wire path can see
    /// [`Compiled`] and the request, and nothing else (`CFG-001`, #166).
    pub fn handle(
        &mut self,
        connection: &mut Connection,
        input: &[u8],
        context: RequestContext,
        entropy: &mut dyn Entropy,
    ) -> Handled {
        let mut response = Vec::new();
        let mut close = false;
        // The sequence number the next event will get. Used rather than the
        // log's length because the log is bounded and may evict while this
        // call runs — a length would then skip the wrong events, whereas a
        // sequence number is monotonic and never reused (`OBS-004`, #180).
        let logged_through = self.host.events().recorded();

        if connection.receive(input).is_err() {
            // The peer sent more than the framing permits before a complete PDU
            // arrived (`WIRE-023`, #81). There is nothing to answer.
            return Handled {
                response,
                close: true,
            };
        }

        let mut scratch = [0_u8; MAX_RESPONSE_LEN];
        loop {
            let host = &mut self.host;
            let step = connection.step(
                context.now,
                entropy,
                &mut |request| host.activate(request, context),
                &mut scratch,
            );
            match step {
                Step::NeedMore => break,
                Step::Send { len } => {
                    response.extend_from_slice(scratch.get(..len).unwrap_or(&[]));
                }
                Step::SendThenClose { len, .. } => {
                    response.extend_from_slice(scratch.get(..len).unwrap_or(&[]));
                    close = true;
                    break;
                }
                Step::Close { .. } => {
                    close = true;
                    break;
                }
            }
        }

        // `SEC-012` (#204): everything the protocol layer refused, faulted or
        // negotiated. Drained here rather than left in the ring, because a
        // sans-io core that reports and a driver that never listens is the same
        // silence as not reporting — and the ring evicts, so an undrained one
        // eventually loses what it was holding. Draining to `None` is also what
        // collects the `Lost` count, which is emitted last.
        while let Some(event) = connection.next_event() {
            self.logger.connection_event(&event);
        }

        // `OBS-003` (#179): one line per handled request, written after the
        // state machine has finished with the input so that a request split
        // across reads produces one line rather than several.
        for event in self
            .host
            .events()
            .iter()
            .filter(|event| event.sequence >= logged_through)
        {
            self.logger.request(event);
        }

        Handled { response, close }
    }

    /// The per-source token buckets (`POL-014`, #102).
    ///
    /// Owned by the server rather than shared behind a lock: the driver is a
    /// single event loop, so there is no second thread to contend with
    /// (`ARCH-005`, #5).
    pub const fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// The rate limiter, mutably, for the driver.
    pub const fn limiter_mut(&mut self) -> &mut RateLimiter {
        &mut self.limiter
    }

    /// Replace the rate limiter, for tests that need a small burst.
    #[must_use]
    pub fn with_limiter(mut self, limiter: RateLimiter) -> Self {
        self.limiter = limiter;
        self
    }

    /// How this server writes log lines (`OBS-001`, #177).
    #[must_use]
    pub const fn logger(&self) -> &Logger {
        &self.logger
    }

    /// A fresh connection using this build's negotiation settings.
    ///
    /// `accepting_port` is the port of the socket that actually accepted, which
    /// the `bind_ack` advertises (`WIRE-011`, #69). With two listeners each
    /// must report its own — py-kms echoes its configured primary port
    /// regardless, so a client reconnecting to the advertised endpoint can be
    /// sent somewhere the host is not.
    #[must_use]
    pub fn connection(&self, assoc_group: u32, accepting_port: u16) -> Connection {
        Connection::new(assoc_group, self.host.identity().advertises_ndr64())
            .with_secondary_address(SecondaryAddress::for_port(accepting_port))
    }

    /// When an idle connection should be closed (`NET-004`, #153).
    #[must_use]
    pub fn idle_deadline(&self, last_input: Instant) -> Option<Instant> {
        last_input.checked_add(self.compiled.idle_timeout)
    }

    /// Settings that may change a byte on the wire.
    #[must_use]
    pub const fn compiled(&self) -> &Compiled {
        &self.compiled
    }

    /// Settings a running host may be told, none of which may change a byte on
    /// the wire (`CFG-001`, #166).
    #[must_use]
    pub const fn operational(&self) -> &Operational {
        &self.operational
    }

    /// What the environment said about itself.
    #[must_use]
    pub const fn discovered(&self) -> &Discovered {
        &self.discovered
    }

    /// The host.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// The host, mutably, for the driver.
    pub const fn host_mut(&mut self) -> &mut Host {
        &mut self.host
    }
}
