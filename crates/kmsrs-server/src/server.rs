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

use crate::config::{Compiled, Discovered, Operational};
use crate::host::{Host, RequestContext};
use kmsrs_proto::entropy::Entropy;
use kmsrs_proto::kms::layout::MAX_RESPONSE_LEN;
use kmsrs_proto::time::Instant;
use kmsrs_proto::wire::connection::{Connection, Step};

/// A configured host.
#[derive(Debug)]
pub struct Server {
    compiled: Compiled,
    operational: Operational,
    discovered: Discovered,
    host: Host,
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
        Ok(Self {
            compiled,
            operational,
            discovered,
            host,
        })
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

        Handled { response, close }
    }

    /// A fresh connection using this build's negotiation settings.
    #[must_use]
    pub fn connection(&self, assoc_group: u32) -> Connection {
        Connection::new(assoc_group, self.host.identity().advertises_ndr64())
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
