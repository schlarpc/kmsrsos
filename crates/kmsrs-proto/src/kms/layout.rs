//! Byte-exact layouts for the KMS request and response (`KMS-001`, #17;
//! `KMS-002`, #18; `KMS-003`, #19; `KMS-004`, #20).
//!
//! # Endianness lives in the type (`ARCH-012`, #12)
//!
//! Every multi-byte field is a `zerocopy` little-endian integer, so there is no
//! per-field byte-order call to forget and no macro to get backwards. Reading a
//! field is `.get()` and the compiler will not let you read it any other way
//! (`ARCH-011`, #11).
//!
//! # The response is written forward, not laid out as a struct
//!
//! A response's ePID field is emitted at its *declared* size, not at the full
//! 64 units, so the bytes after it move. `RESPONSE_V6` as a C struct is
//! therefore only useful for `sizeof()`, which is exactly how vlmcsd uses it —
//! it builds the whole struct and then compacts it with a `memmove`. Here the
//! layout is split into the segments the builder actually writes: a head, the
//! ePID, a tail, and the per-version proof fields (`KMS-023`, #39).
//!
//! # Sizes are derived, never transcribed
//!
//! Every constant below is computed from `size_of`, and each is asserted
//! against the number in the issue. A hand-written 236 that drifts from the
//! struct is the bug those assertions exist to catch.

use kmsrs_db::Guid;
use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::types::WORKSTATION_NAME_UNITS;

/// A GUID as Microsoft frames it: the first three fields little-endian, the
/// last eight bytes in order.
///
/// This mixed layout is why the wire form is a separate type from
/// [`kmsrs_db::Guid`]. Storing the database in wire order would make the
/// database's sort order depend on the protocol's framing, and a table sorted
/// one way and searched another fails silently for some keys.
#[derive(
    FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(C)]
pub struct WireGuid {
    /// First four bytes, little-endian.
    pub data1: U32,
    /// Next two bytes, little-endian.
    pub data2: U16,
    /// Next two bytes, little-endian.
    pub data3: U16,
    /// Final eight bytes, in order.
    pub data4: [u8; 8],
}

impl WireGuid {
    /// Convert to the database's RFC 4122 byte order.
    #[must_use]
    pub fn to_guid(self) -> Guid {
        let first = self.data1.get().to_be_bytes();
        let second = self.data2.get().to_be_bytes();
        let third = self.data3.get().to_be_bytes();
        Guid::from_bytes([
            first[0],
            first[1],
            first[2],
            first[3],
            second[0],
            second[1],
            third[0],
            third[1],
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        ])
    }

    /// Convert from the database's RFC 4122 byte order.
    #[must_use]
    pub fn from_guid(guid: Guid) -> Self {
        let bytes = guid.to_bytes();
        Self {
            data1: U32::new(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            data2: U16::new(u16::from_be_bytes([bytes[4], bytes[5]])),
            data3: U16::new(u16::from_be_bytes([bytes[6], bytes[7]])),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        }
    }
}

/// The KMS request body, 236 bytes (`KMS-001`, #17).
///
/// Field order is exactly as it appears on the wire. The one that catches
/// people out is that the *previous* client machine ID precedes the workstation
/// name rather than following it.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct RequestBody {
    /// Offset 0. Major in the high half, minor in the low.
    pub version: U32,
    /// Offset 4. 0 for bare metal, 1 for a virtual machine.
    pub is_client_vm: U32,
    /// Offset 8. The client's self-reported licensing state.
    pub license_status: U32,
    /// Offset 12. Minutes remaining in that state.
    pub grace_time: U32,
    /// Offset 16. Windows, Office 2010, or Office 2013 and later.
    pub application_id: WireGuid,
    /// Offset 32. The most detailed product identifier, which a host ignores.
    pub sku_id: WireGuid,
    /// Offset 48. What the host actually decides on.
    pub kms_counted_id: WireGuid,
    /// Offset 64. The identity the host counts.
    pub client_machine_id: WireGuid,
    /// Offset 80. Minimum clients this product's policy requires.
    pub required_clients: U32,
    /// Offset 84. `FILETIME`, 100 ns ticks since 1601.
    pub client_time: U64,
    /// Offset 92. All zeros if the machine ID has never changed.
    pub previous_client_machine_id: WireGuid,
    /// Offset 108. 64 UCS-2 code units, NUL-terminated.
    pub workstation_name: [U16; WORKSTATION_NAME_UNITS],
}

/// The fixed head of a response: version and the declared ePID size
/// (`KMS-002`, #18).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct ResponseHead {
    /// Echoed from the request (`KMS-012`, #28).
    pub version: U32,
    /// Bytes of ePID that follow, including the terminating NUL.
    pub pid_size: U32,
}

/// The fixed tail of a response, after the variable-length ePID
/// (`KMS-002`, #18).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct ResponseTail {
    /// Echoed from the request verbatim (`KMS-012`, #28).
    pub client_machine_id: WireGuid,
    /// Echoed from the request verbatim, and the input to the v6 key
    /// derivation.
    pub client_time: U64,
    /// The count this host reports (`POL-001`, #89).
    pub count: U32,
    /// Minutes before a failed client retries (`KMS-021`, #37).
    pub activation_interval: U32,
    /// Minutes before a successful client renews.
    pub renewal_interval: U32,
}

/// The proof-of-decryption fields both v5 and v6 carry (`CRY-008`, #47).
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct SaltProof {
    /// A random salt, XORed with the decrypted request IV.
    pub random_xored_ivs: [u8; 16],
    /// SHA-256 of the salt before the XOR. Recovering one and checking the
    /// other is what proves the responder could decrypt the request.
    pub hash: [u8; 32],
}

/// The extra fields only v6 carries.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned, Debug, Clone, Copy)]
#[repr(C)]
pub struct V6Trailer {
    /// The host's hardware ID (`ID-012`, #117). v6 only (`ID-018`, #123).
    pub hardware_id: [u8; 8],
    /// The decrypted request IV, which the client recomputes and compares.
    pub xored_ivs: [u8; 16],
    /// The last 16 bytes of the response HMAC (`CRY-010`, #49).
    pub hmac: [u8; 16],
}

/// Bytes in a KMS request body.
pub const REQUEST_BODY_LEN: usize = size_of::<RequestBody>();

/// Bytes in the fixed head of a response.
pub const RESPONSE_HEAD_LEN: usize = size_of::<ResponseHead>();

/// Bytes in the fixed tail of a response.
pub const RESPONSE_TAIL_LEN: usize = size_of::<ResponseTail>();

/// Bytes in the salt-proof fields.
pub const SALT_PROOF_LEN: usize = size_of::<SaltProof>();

/// Bytes in the v6-only trailer.
pub const V6_TRAILER_LEN: usize = size_of::<V6Trailer>();

/// UCS-2 code units the ePID field can hold, including its terminating NUL.
pub const PID_BUFFER_UNITS: usize = 64;

/// Bytes in the ePID field when it is emitted at full width.
pub const PID_BUFFER_LEN: usize = PID_BUFFER_UNITS * 2;

/// Bytes in a message authentication code, for v4.
pub const MAC_LEN: usize = 16;

/// Bytes in an initialisation vector.
pub const IV_LEN: usize = 16;

/// Bytes of a v5/v6 request that are not encrypted: the version word.
pub const UNENCRYPTED_PREFIX_LEN: usize = 4;

/// Bytes of a v5/v6 response before the encrypted region: version and IV.
///
/// vlmcsd's `V6_UNENCRYPTED_SIZE`.
pub const V6_UNENCRYPTED_LEN: usize = UNENCRYPTED_PREFIX_LEN + IV_LEN;

/// Fixed padding on a v5/v6 request.
///
/// The request body is 236 bytes and 236 mod 16 is 12, so the inclusive
/// padding is always exactly four bytes of `0x04` (`CRY-011`, #50). Because the
/// body is fixed-size this never varies, which is why vlmcsd can declare it as
/// `BYTE Pad[4]`.
pub const REQUEST_PAD_LEN: usize = 4;

/// A complete v4 request: body plus MAC.
pub const REQUEST_V4_LEN: usize = REQUEST_BODY_LEN + MAC_LEN;

/// A complete v5 request: version, IV, encrypted body, padding.
pub const REQUEST_V5_LEN: usize =
    UNENCRYPTED_PREFIX_LEN + IV_LEN + REQUEST_BODY_LEN + REQUEST_PAD_LEN;

/// A complete v6 request. Identical to v5.
pub const REQUEST_V6_LEN: usize = REQUEST_V5_LEN;

/// The largest request this protocol defines.
pub const MAX_REQUEST_LEN: usize = REQUEST_V6_LEN;

/// The region a v5/v6 server decrypts, starting at the request's IV
/// (`CRY-005`, #44).
///
/// Sixteen blocks: the IV itself, then the body and its padding. Decrypting
/// from the IV with a null IV is what recovers `D_k(IV_req)` in the first
/// block.
pub const V6_DECRYPT_LEN: usize = IV_LEN + REQUEST_BODY_LEN + REQUEST_PAD_LEN;

/// Bytes of a response before the ePID field, for v4.
///
/// vlmcsd's `V4_PRE_EPID_SIZE`.
pub const V4_PRE_EPID_LEN: usize = RESPONSE_HEAD_LEN;

/// Bytes of a response after the ePID field, for v4.
///
/// vlmcsd's `V4_POST_EPID_SIZE`. Excludes the MAC.
pub const V4_POST_EPID_LEN: usize = RESPONSE_TAIL_LEN;

/// Bytes of a response before the ePID field, for v5 and v6.
///
/// vlmcsd's `V6_PRE_EPID_SIZE`.
pub const V6_PRE_EPID_LEN: usize = V6_UNENCRYPTED_LEN + RESPONSE_HEAD_LEN;

/// Bytes of a response after the ePID field, for v5.
///
/// vlmcsd's `V5_POST_EPID_SIZE`.
pub const V5_POST_EPID_LEN: usize = RESPONSE_TAIL_LEN + SALT_PROOF_LEN;

/// Bytes of a response after the ePID field, for v6.
///
/// vlmcsd's `V6_POST_EPID_SIZE`.
pub const V6_POST_EPID_LEN: usize = V5_POST_EPID_LEN + V6_TRAILER_LEN;

/// A v4 response with a full-width ePID.
pub const RESPONSE_V4_LEN: usize = V4_PRE_EPID_LEN + PID_BUFFER_LEN + V4_POST_EPID_LEN + MAC_LEN;

/// A v5 response with a full-width ePID, before padding.
pub const RESPONSE_V5_LEN: usize = V6_PRE_EPID_LEN + PID_BUFFER_LEN + V5_POST_EPID_LEN;

/// A v6 response with a full-width ePID, before padding.
pub const RESPONSE_V6_LEN: usize = V6_PRE_EPID_LEN + PID_BUFFER_LEN + V6_POST_EPID_LEN;

/// The buffer a response is built in (`KMS-023`, #39).
///
/// vlmcsd's `MAX_RESPONSE_SIZE`. Large enough for the widest response plus its
/// inclusive padding, so the builder never has to grow, fail, or compact.
pub const MAX_RESPONSE_LEN: usize = 384;

// The sizes in `KMS-003` (#19) and `KMS-004` (#20), asserted against what the
// structs actually are. Transcribing them would make the numbers agree with the
// issue and not necessarily with the layout.
const _: () = {
    assert!(REQUEST_BODY_LEN == 236, "REQUEST is 236 bytes");
    assert!(
        RESPONSE_HEAD_LEN + PID_BUFFER_LEN + RESPONSE_TAIL_LEN == 172,
        "RESPONSE is 172 bytes"
    );

    assert!(REQUEST_V4_LEN == 252);
    assert!(RESPONSE_V4_LEN == 188);
    assert!(REQUEST_V5_LEN == 260);
    assert!(REQUEST_V6_LEN == 260);
    assert!(MAX_REQUEST_LEN == 260);
    assert!(RESPONSE_V5_LEN == 240);
    assert!(RESPONSE_V6_LEN == 280);

    assert!(V4_PRE_EPID_LEN == 8);
    assert!(V4_POST_EPID_LEN == 36);
    assert!(V6_UNENCRYPTED_LEN == 20);
    assert!(V6_PRE_EPID_LEN == 28);
    assert!(V5_POST_EPID_LEN == 84);
    assert!(V6_POST_EPID_LEN == 124);
    assert!(V6_DECRYPT_LEN == 256);
    assert!(PID_BUFFER_UNITS == 64);

    // The response buffer must hold the widest response plus the extra block
    // inclusive padding adds when the length is already aligned.
    assert!(MAX_RESPONSE_LEN >= RESPONSE_V6_LEN + 16);

    // `size_of` on a `repr(C)` struct includes padding. These types are all
    // `Unaligned`, so there is none — but if a field were ever given a type
    // with an alignment requirement, the struct would silently gain padding
    // and stop matching the wire.
    assert!(size_of::<WireGuid>() == 16);
    assert!(align_of::<RequestBody>() == 1);
    assert!(align_of::<ResponseTail>() == 1);
    assert!(align_of::<WireGuid>() == 1);
};

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{MAX_RESPONSE_LEN, REQUEST_BODY_LEN, RESPONSE_V6_LEN, RequestBody, WireGuid};
    use kmsrs_db::Guid;
    use zerocopy::{FromBytes, IntoBytes};

    /// `KMS-001` (#17): every field at the offset the issue names. Computed
    /// from the parsed struct rather than asserted about the source, so a
    /// reordered field fails here.
    #[test]
    fn every_request_field_is_at_its_documented_offset() {
        // A body whose every field is a distinct byte pattern, so a field read
        // from the wrong offset cannot coincidentally match.
        let mut bytes = [0_u8; REQUEST_BODY_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(index & 0xFF).unwrap_or(0);
        }
        let body = RequestBody::read_from_bytes(&bytes).unwrap();

        assert_eq!(body.version.get(), u32::from_le_bytes([0, 1, 2, 3]));
        assert_eq!(body.is_client_vm.get(), u32::from_le_bytes([4, 5, 6, 7]));
        assert_eq!(
            body.license_status.get(),
            u32::from_le_bytes([8, 9, 10, 11])
        );
        assert_eq!(body.grace_time.get(), u32::from_le_bytes([12, 13, 14, 15]));

        // The four GUIDs, at 16, 32, 48 and 64.
        assert_eq!(
            body.application_id.data1.get(),
            u32::from_le_bytes([16, 17, 18, 19])
        );
        assert_eq!(
            body.sku_id.data1.get(),
            u32::from_le_bytes([32, 33, 34, 35])
        );
        assert_eq!(
            body.kms_counted_id.data1.get(),
            u32::from_le_bytes([48, 49, 50, 51])
        );
        assert_eq!(
            body.client_machine_id.data1.get(),
            u32::from_le_bytes([64, 65, 66, 67])
        );

        assert_eq!(
            body.required_clients.get(),
            u32::from_le_bytes([80, 81, 82, 83])
        );
        assert_eq!(
            body.client_time.get(),
            u64::from_le_bytes([84, 85, 86, 87, 88, 89, 90, 91])
        );

        // The previous machine ID *precedes* the workstation name, which is the
        // ordering that catches people out.
        assert_eq!(
            body.previous_client_machine_id.data1.get(),
            u32::from_le_bytes([92, 93, 94, 95])
        );
        assert_eq!(
            body.workstation_name[0].get(),
            u16::from_le_bytes([108, 109])
        );
        assert_eq!(
            body.workstation_name[63].get(),
            u16::from_le_bytes([234, 235])
        );
    }

    /// A request must survive a round trip byte for byte: a field whose
    /// endianness was declared wrong would still round-trip, but the offset
    /// test above would catch that.
    #[test]
    fn a_request_round_trips_through_bytes() {
        let mut bytes = [0_u8; REQUEST_BODY_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from((index * 7) & 0xFF).unwrap_or(0);
        }
        let body = RequestBody::read_from_bytes(&bytes).unwrap();
        assert_eq!(body.as_bytes(), bytes.as_slice());
    }

    /// A truncated or over-long buffer must be refused rather than read
    /// (`KMS-009`, #25; `SEC-003`, #195).
    #[test]
    fn a_wrongly_sized_buffer_does_not_parse() {
        for len in [0_usize, 1, REQUEST_BODY_LEN - 1, REQUEST_BODY_LEN + 1] {
            let bytes = alloc::vec![0_u8; len];
            assert!(
                RequestBody::read_from_bytes(&bytes).is_err(),
                "{len} bytes must not parse as a request body"
            );
        }
    }

    /// The wire GUID's mixed-endian layout, against a value whose bytes are
    /// visibly rearranged. Getting this backwards produces a server that looks
    /// up the wrong product for every request.
    #[test]
    fn wire_guids_convert_to_and_from_canonical_order() {
        // 84e331f6-4279-48c4-ab10-b75139181351, Windows Server 2025.
        let canonical = Guid::from_bytes([
            0x84, 0xe3, 0x31, 0xf6, 0x42, 0x79, 0x48, 0xc4, 0xab, 0x10, 0xb7, 0x51, 0x39, 0x18,
            0x13, 0x51,
        ]);
        let wire = WireGuid::from_guid(canonical);

        // The first three fields are byte-swapped on the wire; the last eight
        // are not.
        assert_eq!(
            wire.as_bytes(),
            &[
                0xf6, 0x31, 0xe3, 0x84, // data1, reversed
                0x79, 0x42, // data2, reversed
                0xc4, 0x48, // data3, reversed
                0xab, 0x10, 0xb7, 0x51, 0x39, 0x18, 0x13, 0x51, // data4, in order
            ]
        );
        assert_eq!(wire.to_guid(), canonical);
    }

    #[test]
    fn wire_guid_conversion_round_trips_for_every_byte_position() {
        for position in 0..16_usize {
            let mut bytes = [0_u8; 16];
            bytes[position] = 0xFF;
            let guid = Guid::from_bytes(bytes);
            assert_eq!(WireGuid::from_guid(guid).to_guid(), guid, "byte {position}");
        }
        assert_eq!(WireGuid::from_guid(Guid::ZERO).to_guid(), Guid::ZERO);
        let all_ones = Guid::from_bytes([0xFF; 16]);
        assert_eq!(WireGuid::from_guid(all_ones).to_guid(), all_ones);
    }

    /// `KMS-023` (#39): the response buffer is big enough for anything the
    /// builder can produce, so there is no failure path and nothing to compact.
    #[test]
    fn the_response_buffer_holds_the_widest_response_and_its_padding() {
        const { assert!(MAX_RESPONSE_LEN >= RESPONSE_V6_LEN + 16) };
        assert_eq!(MAX_RESPONSE_LEN, 384);
        assert_eq!(RESPONSE_V6_LEN, 280);
    }
}
