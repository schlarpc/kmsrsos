//! The ePID container and its wire encoding (`KMS-011`, #27; `ID-014`, #119).
//!
//! An ePID is the host identity a response carries. Generating one is a policy
//! concern and lives in `kmsrs-policy` (`ID-003`, #108); this module is only
//! about holding one and putting it on the wire correctly.
//!
//! # Bounded in code units, not in bytes
//!
//! The response field is 64 UCS-2 code units, one of which is the terminating
//! NUL. Bounding an ePID at 128 *bytes* looks equivalent and is not: it lets a
//! 64-unit name through, which then has nowhere to put its NUL. vlmcsd checks
//! this on the client side and never bounds what its server emits, so a
//! misconfigured ePID produces a response no client can parse and no log line
//! saying why.

use crate::kms::layout::PID_BUFFER_UNITS;
use crate::types::PidSize;
use arrayvec::ArrayVec;

/// The most UCS-2 code units an ePID can hold, excluding its NUL.
pub const MAX_EPID_UNITS: usize = PID_BUFFER_UNITS - 1;

/// A host identity, as UCS-2 code units without a terminating NUL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EPid {
    units: ArrayVec<u16, MAX_EPID_UNITS>,
}

/// Why an ePID could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EPidError {
    /// The name needs more code units than the field holds.
    TooLong {
        /// Units the name needs.
        units: usize,
        /// Units available, excluding the terminating NUL.
        limit: usize,
    },

    /// The name contains an interior NUL, which would truncate it on the wire
    /// and make the declared size disagree with the content.
    InteriorNul,

    /// The name contains a character outside the basic multilingual plane.
    ///
    /// A real ePID is digits and hyphens, so this cannot arise from a generated
    /// one. It is refused rather than encoded as a surrogate pair because a
    /// pair costs two units and would make a length check in characters
    /// disagree with the field's length in units.
    NotBasicMultilingualPlane,
}

impl core::fmt::Display for EPidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong { units, limit } => {
                write!(
                    f,
                    "an ePID of {units} code units exceeds the {limit}-unit field"
                )
            }
            Self::InteriorNul => f.write_str("an ePID may not contain an interior NUL"),
            Self::NotBasicMultilingualPlane => {
                f.write_str("an ePID may only contain basic multilingual plane characters")
            }
        }
    }
}

impl EPid {
    /// Build an ePID from text.
    ///
    /// # Errors
    ///
    /// Returns [`EPidError`] if the text is too long for the field, contains an
    /// interior NUL, or contains a character outside the basic multilingual
    /// plane.
    pub fn parse(text: &str) -> Result<Self, EPidError> {
        let mut units = ArrayVec::new();
        for character in text.chars() {
            if character == '\0' {
                return Err(EPidError::InteriorNul);
            }
            let mut encoded = [0_u16; 2];
            let encoded = character.encode_utf16(&mut encoded);
            if encoded.len() != 1 {
                return Err(EPidError::NotBasicMultilingualPlane);
            }
            for unit in encoded.iter() {
                units.try_push(*unit).map_err(|_| EPidError::TooLong {
                    units: text.chars().count(),
                    limit: MAX_EPID_UNITS,
                })?;
            }
        }
        Ok(Self { units })
    }

    /// The code units, without the terminating NUL.
    #[must_use]
    pub fn units(&self) -> &[u16] {
        &self.units
    }

    /// The value the response's `PIDSize` field declares, including the NUL.
    #[must_use]
    pub fn pid_size(&self) -> PidSize {
        // The constructor cannot build a name longer than the field, so this is
        // total; the fallback is unreachable and exists because "cannot happen"
        // is not something this codebase asserts at runtime.
        PidSize::for_units(self.units.len()).unwrap_or(PidSize::MAX)
    }

    /// Bytes this ePID occupies on the wire, including the terminating NUL.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.units.len().saturating_add(1).saturating_mul(2)
    }

    /// Write the ePID to `out` as little-endian UCS-2 with a terminating NUL.
    ///
    /// Returns the number of bytes written, or `None` if `out` is too small.
    #[must_use]
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let needed = self.encoded_len();
        let region = out.get_mut(..needed)?;
        for (slot, unit) in region
            .chunks_exact_mut(2)
            .zip(self.units.iter().copied().chain(core::iter::once(0_u16)))
        {
            if let Some(pair) = slot.first_chunk_mut::<2>() {
                *pair = unit.to_le_bytes();
            }
        }
        Some(needed)
    }
}

impl core::fmt::Display for EPid {
    /// Lossy, for logging. A generated ePID is ASCII digits and hyphens, so the
    /// lossy path is unreachable for one we produced — but one read back from
    /// another host is not ours to trust.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for character in char::decode_utf16(self.units.iter().copied()) {
            f.write_fmt(format_args!(
                "{}",
                character.unwrap_or(char::REPLACEMENT_CHARACTER)
            ))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{EPid, EPidError, MAX_EPID_UNITS};
    use alloc::string::String;

    /// A realistic ePID, in the shape `ID-003` (#108) will generate.
    const SAMPLE: &str = "03612-00206-591-000000-03-1033-26100.0000-2412024";

    #[test]
    fn a_realistic_epid_encodes_as_ucs2_with_a_terminating_nul() {
        let epid = EPid::parse(SAMPLE).unwrap();
        assert_eq!(epid.units().len(), SAMPLE.len());
        assert_eq!(epid.encoded_len(), (SAMPLE.len() + 1) * 2);
        assert_eq!(
            epid.pid_size().get(),
            u32::try_from(epid.encoded_len()).unwrap()
        );

        let mut out = [0xAA_u8; 256];
        let written = epid.encode(&mut out).unwrap();
        assert_eq!(written, epid.encoded_len());

        // ASCII in UCS-2 little-endian: every second byte is zero.
        assert_eq!(out[0], b'0');
        assert_eq!(out[1], 0);
        assert_eq!(out[2], b'3');
        // The NUL, and nothing written past it.
        assert_eq!(&out[written - 2..written], &[0, 0]);
        assert_eq!(out[written], 0xAA);
    }

    /// `ID-014` (#119): the bound is in code units. A 63-unit name fits with its
    /// NUL; a 64-unit one does not, even though 64 units is 128 bytes and 128 is
    /// what the field holds.
    #[test]
    fn the_bound_is_in_code_units_not_bytes() {
        let at_limit: String = core::iter::repeat_n('9', MAX_EPID_UNITS).collect();
        let epid = EPid::parse(&at_limit).unwrap();
        assert_eq!(epid.pid_size().get(), 128);
        assert_eq!(epid.encoded_len(), 128);

        let past_limit: String = core::iter::repeat_n('9', MAX_EPID_UNITS + 1).collect();
        assert_eq!(
            EPid::parse(&past_limit),
            Err(EPidError::TooLong {
                units: MAX_EPID_UNITS + 1,
                limit: MAX_EPID_UNITS
            })
        );
    }

    /// A three-byte character is one code unit, so the limit is not a byte
    /// count in disguise.
    #[test]
    fn a_multibyte_character_still_costs_one_unit() {
        let wide: String = core::iter::repeat_n('\u{4E00}', MAX_EPID_UNITS).collect();
        assert_eq!(wide.len(), MAX_EPID_UNITS * 3, "three bytes each");
        let epid = EPid::parse(&wide).unwrap();
        assert_eq!(epid.units().len(), MAX_EPID_UNITS);
        assert_eq!(epid.encoded_len(), 128);
    }

    /// A surrogate pair costs two units, so a length check in characters would
    /// disagree with the field. Refused rather than silently costing double.
    #[test]
    fn characters_outside_the_basic_plane_are_refused() {
        assert_eq!(
            EPid::parse("\u{1F600}"),
            Err(EPidError::NotBasicMultilingualPlane)
        );
    }

    #[test]
    fn an_interior_nul_is_refused() {
        assert_eq!(EPid::parse("03612-\0-1033"), Err(EPidError::InteriorNul));
        // A trailing one too: the encoder adds the terminator itself, so an
        // explicit one would make the declared size disagree with the content.
        assert_eq!(EPid::parse("03612\0"), Err(EPidError::InteriorNul));
    }

    #[test]
    fn an_undersized_buffer_is_refused_rather_than_truncating() {
        let epid = EPid::parse(SAMPLE).unwrap();
        let needed = epid.encoded_len();
        for len in [0_usize, 1, needed - 1] {
            let mut out = alloc::vec![0_u8; len];
            assert_eq!(epid.encode(&mut out), None, "{len} bytes must not suffice");
        }
        let mut exact = alloc::vec![0_u8; needed];
        assert_eq!(epid.encode(&mut exact), Some(needed));
    }

    #[test]
    fn display_round_trips_the_text() {
        assert_eq!(alloc::format!("{}", EPid::parse(SAMPLE).unwrap()), SAMPLE);
        assert_eq!(alloc::format!("{}", EPid::parse("").unwrap()), "");
    }

    #[test]
    fn an_empty_epid_still_declares_its_nul() {
        let empty = EPid::parse("").unwrap();
        assert_eq!(empty.encoded_len(), 2);
        assert_eq!(empty.pid_size().get(), 2);
        let mut out = [0xAA_u8; 4];
        assert_eq!(empty.encode(&mut out), Some(2));
        assert_eq!(&out[..2], &[0, 0]);
    }
}
