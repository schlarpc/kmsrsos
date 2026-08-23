//! A GUID as the database stores it (`ARCH-007`, #7).
//!
//! Bytes are held in RFC 4122 order — the order they are written in, and the
//! order that makes byte-wise comparison agree with string comparison, which is
//! what lets the generated tables be binary-searched.
//!
//! The mixed-endian layout Microsoft puts on the wire, where the first three
//! fields are little-endian, is a *wire* concern and is converted in
//! `kmsrs-proto`. Keeping it out of here means a change to the framing cannot
//! silently reorder the database.

use core::fmt;

/// A 128-bit GUID in RFC 4122 byte order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid([u8; 16]);

impl Guid {
    /// The all-zero GUID.
    ///
    /// Meaningful on the wire: a client that has never changed its machine ID
    /// sends all zeros in the previous-CMID field.
    pub const ZERO: Self = Self([0; 16]);

    /// Construct from bytes in RFC 4122 order.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes, in RFC 4122 order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The bytes, by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Lowercase hexadecimal digits.
const HEX: [u8; 16] = *b"0123456789abcdef";

impl fmt::Display for Guid {
    /// Canonical lowercase form, without braces, and without allocating.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            let high = usize::from(byte >> 4);
            let low = usize::from(byte & 0x0F);
            let digits = [
                HEX.get(high).copied().unwrap_or(b'?'),
                HEX.get(low).copied().unwrap_or(b'?'),
            ];
            // Two ASCII hex digits are always valid UTF-8.
            f.write_str(core::str::from_utf8(&digits).unwrap_or("??"))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
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

    use super::Guid;
    use alloc::format;

    #[test]
    fn display_is_the_canonical_lowercase_form() {
        let guid = Guid::from_bytes([
            0x84, 0xe3, 0x31, 0xf6, 0x42, 0x79, 0x48, 0xc4, 0xab, 0x10, 0xb7, 0x51, 0x39, 0x18,
            0x13, 0x51,
        ]);
        assert_eq!(format!("{guid}"), "84e331f6-4279-48c4-ab10-b75139181351");
        assert_eq!(
            format!("{guid:?}"),
            "Guid(84e331f6-4279-48c4-ab10-b75139181351)"
        );
        assert_eq!(
            format!("{}", Guid::ZERO),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            format!("{}", Guid::from_bytes([0xFF; 16])),
            "ffffffff-ffff-ffff-ffff-ffffffffffff"
        );
    }

    /// The version nibble is not special (`DB-005`, #129): Office LTSC 2024's
    /// genuine counted ID has an invalid one and must round-trip unchanged.
    #[test]
    fn a_guid_with_an_invalid_version_nibble_is_ordinary() {
        let office = Guid::from_bytes([
            0xa8, 0x97, 0x3c, 0xb5, 0xbf, 0x03, 0x0a, 0x4c, 0x9c, 0xef, 0x70, 0x30, 0x99, 0x64,
            0x5a, 0xb3,
        ]);
        assert_eq!(format!("{office}"), "a8973cb5-bf03-0a4c-9cef-703099645ab3");
    }

    /// Byte order matters: the tables are binary-searched, so `Ord` on the
    /// bytes must agree with `Ord` on the canonical string.
    #[test]
    fn byte_order_agrees_with_string_order() {
        let mut previous = Guid::ZERO;
        for byte in 1..=255_u8 {
            let mut bytes = [0_u8; 16];
            bytes[0] = byte;
            let current = Guid::from_bytes(bytes);
            assert!(previous < current);
            assert!(format!("{previous}") < format!("{current}"));
            previous = current;
        }
    }
}
