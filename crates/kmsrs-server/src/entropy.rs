//! The operating system's CSPRNG (`CRY-013`, #52; `ARCH-003`, #3).
//!
//! One implementation of [`Entropy`] over `getrandom`, which is `getrandom(2)`
//! on Linux, `BCryptGenRandom` on Windows and `sys_read_entropy` on Hermit.
//! Every random value this program puts on the wire comes through here.
//!
//! # What both existing implementations use instead
//!
//! * **vlmcsd** reseeds libc `rand()` with `srand(tv_sec ^ tv_usec)` at the
//!   start of **every connection**. That is roughly 20 bits of seed entropy, so
//!   an observer who knows roughly when a connection was made can enumerate the
//!   seeds and reproduce every "random" value in the response.
//! * **py-kms** uses Python's Mersenne Twister, which is not a CSPRNG and whose
//!   internal state is recoverable from 624 outputs. Its one `os.urandom` call
//!   sits in dead code.
//!
//! This matters because everything drawn here is *visible*: the RPC association
//! group, response IVs and salts, RPC padding, the per-process hardware ID and
//! the ePID's randomised fields. A predictable pattern in any of them is a way
//! to identify an emulator without sending it anything unusual.
//!
//! # Failure is reported, never papered over
//!
//! [`OsEntropy::fill`] returns [`EntropyUnavailable`] rather than falling back
//! to anything. There is no fallback that would be safe: a weaker source here
//! is worse than not serving, because the service keeps *working* while every
//! value it emits becomes predictable — which is precisely Hermit's failure
//! mode (`OS-012`, #263), where a seeding failure silently fills the buffer
//! from an LCG seeded with a static zero and reports success.

use kmsrs_proto::entropy::{Entropy, EntropyUnavailable};

/// The operating system's CSPRNG.
///
/// Zero-sized: there is no generator state here, because the state belongs to
/// the OS. That is deliberate — a userspace generator would have to be seeded,
/// and seeding is the step both existing implementations get wrong.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
        getrandom::fill(destination).map_err(|_| EntropyUnavailable)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::OsEntropy;
    use kmsrs_proto::entropy::Entropy;
    use std::collections::HashSet;

    #[test]
    fn it_fills_the_whole_buffer() {
        let mut entropy = OsEntropy;
        for len in [0_usize, 1, 8, 16, 64, 1024] {
            let mut buffer = vec![0_u8; len];
            entropy.fill(&mut buffer).unwrap();
            assert_eq!(buffer.len(), len);
        }
    }

    /// Not a test of randomness quality — that belongs to the OS — but of the
    /// failure this module exists to prevent: a source that returns the same
    /// bytes every time while reporting success. That is exactly what Hermit
    /// does on a seeding failure (`OS-012`, #263) and what vlmcsd's
    /// `srand(tv_sec ^ tv_usec)` approximates.
    #[test]
    fn successive_draws_differ() {
        let mut entropy = OsEntropy;
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for _ in 0..256 {
            let mut buffer = [0_u8; 32];
            entropy.fill(&mut buffer).unwrap();
            assert!(
                seen.insert(buffer),
                "a 32-byte draw repeated within 256 attempts, which for a \
                 working CSPRNG is impossible"
            );
        }
        assert_eq!(seen.len(), 256);
    }

    /// Two independently constructed sources must not agree, which they would
    /// if this type held seeded state rather than deferring to the OS.
    #[test]
    fn two_sources_do_not_produce_the_same_stream() {
        let mut first = OsEntropy;
        let mut second = OsEntropy;
        let mut a = [0_u8; 64];
        let mut b = [0_u8; 64];
        first.fill(&mut a).unwrap();
        second.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    /// A zero-sized type cannot carry a seed, which is the property that makes
    /// vlmcsd's per-connection reseed unrepresentable here.
    #[test]
    fn the_source_holds_no_state() {
        assert_eq!(core::mem::size_of::<OsEntropy>(), 0);
    }
}
