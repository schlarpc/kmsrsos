//! What process 1 learns, and the rest of the program renders
//! (`OS-019`, #335; `DISC-007`, #149).
//!
//! # Why this exists
//!
//! On the bare-metal target `kmsrs-os` is pid 1 and owns the DHCP client, so it
//! is the only part of the system that knows things this program has always had
//! to guess at. The load-bearing one is the **domain**: `/instructions` tells an
//! operator to publish a `_vlmcs._tcp` SRV record and has never been able to say
//! *under which domain*, so it prints `EXAMPLE.COM` and leaves them to
//! substitute. The lease knows — options 15 and 119 — and until `OS-019` (#335)
//! nothing read them, because the kernel's `ip=dhcp` discards both.
//!
//! # The direction of the dependency
//!
//! `kmsrs-os` depends on `kmsrs-server`, not the other way round, so the facts
//! cannot be a parameter to `serve`: they are not known when it is called, and
//! on the two hosted targets they are never known at all. [`Facts`] is a slot
//! the server creates and hands out — pid 1 writes it whenever a lease changes,
//! the web UI reads it whenever it renders.
//!
//! # This is not configuration
//!
//! Nothing here can change a byte on the KMS wire, which is what keeps it clear
//! of `CFG-001` (#166). It is an *observation* about the network, in the same
//! category as [`crate::config::Discovered`], and the only thing it affects is
//! what a human is told on an HTML page. A machine with no lease renders
//! exactly what it rendered before.

use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

/// What pid 1 has learned about this machine's place on the network.
///
/// Every field is optional and empty by default, because on the Linux service
/// build and on Windows nothing ever fills them in and the pages that read this
/// must render the same as they always did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Network {
    /// The domains a client on this network searches, most specific first.
    ///
    /// Option 119 where the server sends it, otherwise the single domain of
    /// option 15. This is what a Windows client appends to `_vlmcs._tcp` when
    /// it goes looking for a KMS host, so it is exactly the zone an operator
    /// must publish the SRV record in (`DISC-007`, #149).
    pub search_domains: Vec<String>,
    /// The address the lease assigned, if there is a lease.
    ///
    /// Reported, never acted on. Nothing in this program reads its own address
    /// to decide anything (`NET-001`, #150), and this is here so the status
    /// page can say what the machine believes its address to be — which is the
    /// first thing an operator wants when clients cannot reach it.
    pub address: Option<Ipv4Addr>,
}

/// A slot pid 1 writes and the web UI reads (`OS-019`, #335).
///
/// A lock rather than a channel: there is one writer, many readers, and the
/// readers want the current value rather than the history. A renewal that
/// changes nothing writes the same bytes and nobody notices, which is the
/// common case.
#[derive(Debug, Clone, Default)]
pub struct Facts(Arc<RwLock<Network>>);

impl Facts {
    /// A slot with nothing in it, which is what the hosted builds use forever.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace what is known. Called by pid 1 when a lease is taken, renewed
    /// into a different answer, or lost.
    pub fn publish(&self, network: Network) {
        // A poisoned lock means a reader panicked while holding it. The value
        // behind it is a list of domain names, so there is no invariant to have
        // been broken and nothing to recover — taking it back and carrying on
        // is strictly better than a host that stops activating because an HTML
        // page panicked. `panic = "abort"` means this cannot happen in a
        // release build at all.
        match self.0.write() {
            Ok(mut slot) => *slot = network,
            Err(poisoned) => *poisoned.into_inner() = network,
        }
    }

    /// What is known now.
    #[must_use]
    pub fn read(&self) -> Network {
        match self.0.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
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

    use super::{Facts, Network};
    use std::net::Ipv4Addr;

    /// The default is what the Linux service build and the Windows build see
    /// for the life of the process, so it has to be the "nothing known" case
    /// rather than a guess.
    #[test]
    fn nothing_is_known_until_something_publishes() {
        assert_eq!(Facts::new().read(), Network::default());
    }

    #[test]
    fn a_clone_sees_what_the_original_published() {
        let facts = Facts::new();
        let reader = facts.clone();
        facts.publish(Network {
            search_domains: vec!["corp.example.net".to_owned()],
            address: Some(Ipv4Addr::new(10, 0, 0, 5)),
        });
        assert_eq!(reader.read().search_domains, ["corp.example.net"]);
        assert_eq!(reader.read().address, Some(Ipv4Addr::new(10, 0, 0, 5)));
    }

    /// A renewal that returns a different address replaces the old one rather
    /// than accumulating — the page must show where the machine *is*, not
    /// everywhere it has been.
    #[test]
    fn a_later_publish_replaces_an_earlier_one() {
        let facts = Facts::new();
        facts.publish(Network {
            search_domains: vec!["old.example.net".to_owned()],
            address: Some(Ipv4Addr::new(10, 0, 0, 5)),
        });
        facts.publish(Network {
            search_domains: vec!["new.example.net".to_owned()],
            address: Some(Ipv4Addr::new(10, 0, 0, 6)),
        });
        assert_eq!(facts.read().search_domains, ["new.example.net"]);
        assert_eq!(facts.read().address, Some(Ipv4Addr::new(10, 0, 0, 6)));
    }
}
