//! A GUID, as it appears in Microsoft's licensing artifacts (`DB-005`, #129).
//!
//! Deliberately separate from `kmsrs-db`'s equivalent. `kmsrs-db` is `no_std`
//! with no allocator and holds GUIDs as compile-time constants; this one parses
//! and formats strings. Making `kmsrs-dbgen` depend on `kmsrs-db` would also
//! create a bootstrapping hazard, because `kmsrs-db`'s `build.rs` consumes the
//! file this program writes — a malformed data file would then stop the only
//! tool that can regenerate it from building.

use core::fmt;

/// A 128-bit GUID in RFC 4122 byte order.
///
/// The mixed-endian layout Microsoft uses on the wire is a *wire* concern and
/// lives in `kmsrs-proto`. Storing the canonical order here keeps the database
/// independent of how any particular protocol version frames it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid([u8; 16]);

/// Why a GUID string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseGuidError(String);

impl fmt::Display for ParseGuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a GUID: {}", self.0)
    }
}

impl std::error::Error for ParseGuidError {}

impl Guid {
    /// The raw bytes, in RFC 4122 order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse a GUID, with or without surrounding braces, in any case.
    ///
    /// # The version nibble is not checked (`DB-005`, #129)
    ///
    /// Office LTSC 2024's genuine KMS counted ID is
    /// `a8973cb5-bf03-0a4c-9cef-703099645ab3`. Its version nibble is `0`, which
    /// no RFC 4122 version defines — and it is nonetheless what Microsoft ships
    /// and what every real client sends. vlmcsd's `CheckVersion4Uuid` emits a
    /// spurious warning for it.
    ///
    /// The heuristic is not merely useless here, it is inverted: the two values
    /// py-kms fabricated for Server 2025 and Office LTSC 2024 are *valid*
    /// UUIDv5, and the genuine one is not. A validator would have rejected the
    /// real data and accepted the invented data.
    ///
    /// # Errors
    ///
    /// Returns [`ParseGuidError`] if the string is not 32 hexadecimal digits in
    /// the canonical 8-4-4-4-12 grouping.
    pub fn parse(text: &str) -> Result<Self, ParseGuidError> {
        let trimmed = text.trim().trim_start_matches('{').trim_end_matches('}');
        let groups: Vec<&str> = trimmed.split('-').collect();
        let widths = [8_usize, 4, 4, 4, 12];
        if groups.len() != widths.len()
            || !groups
                .iter()
                .zip(widths.iter())
                .all(|(group, width)| group.len() == *width)
        {
            return Err(ParseGuidError(text.to_owned()));
        }

        let digits: String = groups.concat();
        let mut bytes = [0_u8; 16];
        hex::decode_to_slice(&digits, &mut bytes).map_err(|_| ParseGuidError(text.to_owned()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Guid {
    /// Canonical lowercase form, without braces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = hex::encode(self.0);
        for (index, boundary) in [8_usize, 12, 16, 20].into_iter().enumerate() {
            let start = [0_usize, 8, 12, 16].get(index).copied().unwrap_or(0);
            if let Some(part) = hex.get(start..boundary) {
                write!(f, "{part}-")?;
            }
        }
        if let Some(tail) = hex.get(20..) {
            write!(f, "{tail}")?;
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
        clippy::arithmetic_side_effects,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::Guid;

    #[test]
    fn parses_every_form_microsoft_writes() {
        let canonical = "84e331f6-4279-48c4-ab10-b75139181351";
        for text in [
            canonical,
            "{84e331f6-4279-48c4-ab10-b75139181351}",
            "{84E331F6-4279-48C4-AB10-B75139181351}",
            "  {84E331F6-4279-48C4-AB10-B75139181351}  ",
        ] {
            assert_eq!(Guid::parse(text).unwrap().to_string(), canonical, "{text}");
        }
    }

    /// `DB-005` (#129). Office LTSC 2024's real counted ID has a version nibble
    /// of `0`, which is not a valid RFC 4122 version — and it is what Microsoft
    /// ships. A parser that checked would reject the genuine value.
    #[test]
    fn accepts_the_office_2024_counted_id_with_its_invalid_version_nibble() {
        let genuine = "a8973cb5-bf03-0a4c-9cef-703099645ab3";
        let parsed = Guid::parse(genuine).unwrap();
        assert_eq!(parsed.to_string(), genuine);
        // The nibble in question, for the avoidance of doubt.
        assert_eq!(parsed.as_bytes()[6] >> 4, 0);
    }

    #[test]
    fn rejects_what_is_not_a_guid() {
        for text in [
            "",
            "84e331f6",
            "84e331f6-4279-48c4-ab10",
            "84e331f6-4279-48c4-ab10-b7513918135",
            "84e331f6-4279-48c4-ab10-b751391813511",
            "84e331f6427948c4ab10b75139181351",
            "84e331f6-4279-48c4-ab10-b7513918135z",
        ] {
            assert!(Guid::parse(text).is_err(), "{text:?} should not parse");
        }
    }

    #[test]
    fn display_round_trips_through_parse() {
        for text in [
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "55c92734-d682-4d71-983e-d6ec3f16059f",
            "0ff1ce15-a989-479d-af46-f275c6370663",
        ] {
            let parsed = Guid::parse(text).unwrap();
            assert_eq!(parsed.to_string(), text);
            assert_eq!(Guid::parse(&parsed.to_string()).unwrap(), parsed);
        }
    }
}
