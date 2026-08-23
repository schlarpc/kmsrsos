//! Randomness as an injected capability (`ARCH-003`, #3).
//!
//! Linux, Windows, Hermit and the fuzzer each supply their own implementation.
//! The core never opens `/dev/urandom`, never calls `getrandom`, and holds no
//! generator state of its own — a request handler is *handed* a source.
//!
//! Two things depend on that inversion, and neither is cosmetic:
//!
//! * The Hermit entropy self-test (`OS-012`, #263) can refuse to serve. On a
//!   seeding failure Hermit's `sys_read_entropy` **silently succeeds**, filling
//!   the buffer from a Park–Miller LCG seeded from a static zero — a stream
//!   identical across boots — and `getrandom` reports success. Every value in
//!   the list below would silently become a constant while the service kept
//!   working perfectly. A source that can report failure is what makes refusing
//!   possible; [`EntropyUnavailable`] is that channel.
//! * Differential testing against vlmcsd and py-kms (`TEST-004`, #225) needs
//!   the same request to produce the same bytes twice.
//!
//! Everything drawn from here is visible to a client, which is why an emulator
//! that gets it wrong is detectable: the RPC association group, response IVs
//! and salts, RPC padding (`WIRE-017`, #75), the per-process HWID (`ID-012`,
//! #117) and the ePID's randomised fields.

use core::num::NonZeroU32;

/// The source could not produce randomness.
///
/// There is deliberately no detail field. A caller's only correct response is
/// to stop serving (`OS-012`, #263) — no variant of this error is one to
/// recover from and continue, and a `reason` string would invite a `match` that
/// tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyUnavailable;

impl core::fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the entropy source failed; refusing to serve")
    }
}

/// A cryptographically secure source of random bytes (`ARCH-003`, #3;
/// `CRY-013`, #52).
///
/// Implementations must be CSPRNGs. Every value drawn here ends up on the wire
/// where a client can see it, and the pattern that makes an emulator
/// identifiable is a predictable one.
pub trait Entropy {
    /// Fill `destination` completely with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EntropyUnavailable`] if the underlying source failed. On
    /// failure the contents of `destination` are unspecified and must not be
    /// used; callers stop serving rather than continue with what is there.
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable>;

    /// Draw a `u32`.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn next_u32(&mut self) -> Result<u32, EntropyUnavailable> {
        let mut bytes = [0_u8; 4];
        self.fill(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Draw a `u64`.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn next_u64(&mut self) -> Result<u64, EntropyUnavailable> {
        let mut bytes = [0_u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Draw uniformly from `0 .. bound`.
    ///
    /// Uses rejection sampling against a power-of-two mask rather than a
    /// modulo. The modulo version is shorter and is biased towards the low end
    /// of the range whenever `bound` is not a power of two — which is exactly
    /// the kind of skew the ePID statistical tests look for (`TEST-008`, #229)
    /// and exactly the kind a detection probe could look for too. It also
    /// performs no division at all, so the ID-015 (#120) divide-by-zero
    /// question does not arise: `bound` is a [`NonZeroU32`], and there is
    /// nothing to divide by anyway.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn uniform_below(&mut self, bound: NonZeroU32) -> Result<u32, EntropyUnavailable> {
        let bound = bound.get();
        let significant_bits = 32_u32.saturating_sub(bound.saturating_sub(1).leading_zeros());
        let mask = if significant_bits >= 32 {
            u32::MAX
        } else {
            (1_u32 << significant_bits).saturating_sub(1)
        };
        loop {
            let candidate = self.next_u32()? & mask;
            if candidate < bound {
                return Ok(candidate);
            }
        }
    }

    /// Draw uniformly from `low ..= high`.
    ///
    /// Returns `low` when `high < low`, which cannot arise from a validated
    /// range type and is the one answer that is always inside the caller's
    /// intent.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn uniform_in_inclusive_range(
        &mut self,
        low: u32,
        high: u32,
    ) -> Result<u32, EntropyUnavailable> {
        let Some(span) = high.checked_sub(low) else {
            return Ok(low);
        };
        let Some(bound) = NonZeroU32::new(span.saturating_add(1)) else {
            // `span + 1` is zero only when span is u32::MAX, i.e. the range is
            // the whole of u32 — in which case every draw is in range.
            return self.next_u32();
        };
        Ok(low.saturating_add(self.uniform_below(bound)?))
    }
}

impl<T: Entropy + ?Sized> Entropy for &mut T {
    fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
        (**self).fill(destination)
    }
}

/// Generic conveniences over an [`Entropy`] source.
///
/// Separate from the trait itself because a method with a const generic
/// parameter has no place in a vtable, and every handler signature in this
/// codebase takes `&mut dyn Entropy` — the platform owns one generator and
/// lends it out, rather than each layer being generic over the source. The
/// blanket implementation covers `dyn Entropy` as well as concrete sources.
pub trait EntropyExt: Entropy {
    /// Draw a fixed-size array.
    ///
    /// # Errors
    ///
    /// As [`Entropy::fill`].
    fn array<const N: usize>(&mut self) -> Result<[u8; N], EntropyUnavailable> {
        let mut bytes = [0_u8; N];
        self.fill(&mut bytes)?;
        Ok(bytes)
    }
}

impl<T: Entropy + ?Sized> EntropyExt for T {}

/// Deterministic entropy sources for tests, fuzzing and differential runs.
///
/// Behind a Cargo feature that the shipped binary never enables, so that a
/// predictable generator cannot reach production by an ordinary `use`
/// statement. Under resolver 3, a dev-dependency enabling `testing` does not
/// turn it on for the binary's own build.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::{Entropy, EntropyUnavailable};

    /// A reproducible, **non-cryptographic** source for tests.
    ///
    /// This is deliberately not a CSPRNG. Making it one would let it be
    /// mistaken for a usable implementation; being visibly a toy counter means
    /// a reviewer who finds it outside a test knows immediately that something
    /// is wrong. It exists so a differential run can replay the same request
    /// against two implementations and compare bytes (`TEST-004`, #225).
    #[derive(Debug, Clone)]
    pub struct DeterministicEntropy {
        state: u64,
    }

    impl DeterministicEntropy {
        /// Create a source from a seed. The same seed always yields the same
        /// stream.
        #[must_use]
        pub const fn from_seed(seed: u64) -> Self {
            Self { state: seed }
        }
    }

    impl Entropy for DeterministicEntropy {
        fn fill(&mut self, destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
            for byte in destination.iter_mut() {
                // SplitMix64. Chosen because it is eight lines and passes
                // enough of BigCrush that a statistical test written for the
                // real generator does not fail against this one for the wrong
                // reason.
                self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                *byte = u8::try_from(z & 0xFF).unwrap_or(0);
            }
            Ok(())
        }
    }

    /// A source that always fails, for exercising the refuse-to-serve path
    /// (`OS-012`, #263).
    #[derive(Debug, Clone, Copy, Default)]
    pub struct FailingEntropy;

    impl Entropy for FailingEntropy {
        fn fill(&mut self, _destination: &mut [u8]) -> Result<(), EntropyUnavailable> {
            Err(EntropyUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "test code: arithmetic is over known-small test values"
    )]

    use super::testing::{DeterministicEntropy, FailingEntropy};
    use super::{Entropy, EntropyExt, EntropyUnavailable, NonZeroU32};

    fn seeded() -> DeterministicEntropy {
        DeterministicEntropy::from_seed(0x0123_4567_89AB_CDEF)
    }

    #[test]
    fn a_failing_source_fails_every_helper_rather_than_returning_zeroes() {
        // The whole point of the error channel: a caller must not be able to
        // get a plausible-looking value out of a broken source (OS-012, #263).
        let mut source = FailingEntropy;
        assert_eq!(source.fill(&mut [0; 8]), Err(EntropyUnavailable));
        assert_eq!(source.array::<16>(), Err(EntropyUnavailable));
        assert_eq!(source.next_u32(), Err(EntropyUnavailable));
        assert_eq!(source.next_u64(), Err(EntropyUnavailable));
        assert_eq!(
            source.uniform_below(NonZeroU32::new(10).unwrap()),
            Err(EntropyUnavailable)
        );
        assert_eq!(
            source.uniform_in_inclusive_range(1, 10),
            Err(EntropyUnavailable)
        );
    }

    #[test]
    fn the_deterministic_source_is_deterministic() {
        let first = seeded().array::<64>().unwrap();
        let second = seeded().array::<64>().unwrap();
        assert_eq!(first, second);
        let different = DeterministicEntropy::from_seed(1).array::<64>().unwrap();
        assert_ne!(first, different);
    }

    #[test]
    fn uniform_below_stays_in_range_including_the_degenerate_bounds() {
        let mut source = seeded();
        for bound in [1_u32, 2, 3, 255, 256, 257, 1000, u32::MAX] {
            let bound = NonZeroU32::new(bound).unwrap();
            for _ in 0..200 {
                let value = source.uniform_below(bound).unwrap();
                assert!(value < bound.get(), "{value} not below {bound}");
            }
        }
    }

    #[test]
    fn uniform_below_one_is_always_zero() {
        let mut source = seeded();
        for _ in 0..100 {
            assert_eq!(
                source.uniform_below(NonZeroU32::new(1).unwrap()).unwrap(),
                0
            );
        }
    }

    /// The reason `uniform_below` rejects rather than taking a modulo. With a
    /// bound just over a power of two, the modulo version hands the bottom
    /// `2^32 mod bound` values an extra chance each — here roughly a 2:1 skew
    /// towards the low third. A detection probe that collected enough ePIDs
    /// could see that; this test fails if the implementation regresses to it.
    #[test]
    fn uniform_below_is_not_biased_towards_the_low_end() {
        // A bound of 3 is the classic case: 2^32 mod 3 == 1.
        let bound = NonZeroU32::new(3).unwrap();
        let mut source = seeded();
        let mut counts = [0_u32; 3];
        let draws = 60_000;
        for _ in 0..draws {
            counts[source.uniform_below(bound).unwrap() as usize] += 1;
        }
        // Each bucket should be near draws/3 = 20,000. A 5% band is far tighter
        // than the ~33% excess a modulo would give the low bucket for a bound
        // near 2^31, and comfortably looser than sampling noise at this count.
        for (value, count) in counts.iter().enumerate() {
            let expected = draws / 3;
            let deviation = i64::from(*count) - i64::from(expected);
            assert!(
                deviation.abs() < i64::from(expected) / 20,
                "bucket {value} got {count}, expected about {expected}"
            );
        }
    }

    #[test]
    fn inclusive_range_covers_both_endpoints_and_nothing_outside() {
        let mut source = seeded();
        let (low, high) = (10_u32, 13_u32);
        let mut seen = [false; 4];
        for _ in 0..500 {
            let value = source.uniform_in_inclusive_range(low, high).unwrap();
            assert!(
                (low..=high).contains(&value),
                "{value} outside {low}..={high}"
            );
            seen[(value - low) as usize] = true;
        }
        assert!(seen.iter().all(|hit| *hit), "some endpoint never drawn");
    }

    #[test]
    fn inclusive_range_handles_the_degenerate_and_full_width_cases() {
        let mut source = seeded();
        // Empty span: one legal answer.
        assert_eq!(source.uniform_in_inclusive_range(7, 7).unwrap(), 7);
        // Inverted, which a validated range type cannot produce: answer inside
        // the caller's intent rather than a panic or a wrapped span.
        assert_eq!(source.uniform_in_inclusive_range(7, 3).unwrap(), 7);
        // Full u32 width: `span + 1` overflows, and the fallback must not.
        let _ = source.uniform_in_inclusive_range(0, u32::MAX).unwrap();
    }

    #[test]
    fn the_blanket_impl_lets_a_borrowed_source_be_passed_on() {
        fn takes_source(mut source: impl Entropy) -> u32 {
            source.next_u32().unwrap_or(0)
        }
        let mut source = seeded();
        // This is the shape every handler signature uses: `&mut dyn Entropy`
        // handed down without moving the platform's generator.
        let first = takes_source(&mut source);
        let second = takes_source(&mut source);
        assert_ne!(first, second, "the borrow must advance the shared stream");
    }
}
