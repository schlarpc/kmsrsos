//! The NDR32 and NDR64 stub layouts (`WIRE-019`, #77; `WIRE-020`, #78;
//! `WIRE-030`, #88).
//!
//! The KMS payload is carried as a conformant array of bytes. NDR32 declares
//! its lengths in 32-bit fields and NDR64 in 64-bit ones, which moves the data
//! from offset 16 to 24 on the way in and from 20 to 32 on the way out.
//!
//! # Two fields that are not what they look like
//!
//! * The response's `DataSizeMax` is **`0x00020000`**, and it is not a size. It
//!   is an NDR *referent identifier* — the pointer-valued placeholder a
//!   conformant array's referent gets. py-kms calls the field `unknown`
//!   (`KMS-005`, #21); it is not unknown, and naming it correctly is the
//!   difference between a reader understanding the layout and copying it.
//! * The four bytes after the payload are the **RPC return code**, not padding.
//!   py-kms's `getPadding()` returns `4 + align` and zeroes all of it, which is
//!   why it structurally cannot return a non-zero `HRESULT` on the success path
//!   (`KMS-013`, #29). The padding is the *next* thing, and it is cosmetic —
//!   Windows RPC aligns to 32 bits here even though nothing requires it, and
//!   `vlmcs` warns when a server omits it (`WIRE-018`, #76).

use crate::wire::syntax::TransferSyntax;

/// The referent identifier a conformant array's `DataSizeMax` carries.
///
/// Not a maximum, not a size. `0x00020000` little-endian, which is
/// `0x00 00 02 00` big-endian — the form py-kms's comment quotes.
pub const CONFORMANT_ARRAY_REFERENT: u64 = 0x0002_0000;

/// The only operation this interface defines.
pub const KMS_OPNUM: u16 = 0;

/// Bytes before the NDR fields in a request stub: alloc hint, context, opnum.
const REQUEST_PREFIX_LEN: usize = 8;

/// Bytes before the NDR fields in a response stub: alloc hint, context, cancel
/// count, reserved.
const RESPONSE_PREFIX_LEN: usize = 8;

/// How wide this syntax's NDR length fields are.
#[must_use]
const fn length_field_width(syntax: TransferSyntax) -> usize {
    match syntax {
        // NDR64 is supported on 32-bit targets too (`WIRE-030`, #88). vlmcsd
        // does this; Microsoft's own implementation does not. In Rust it costs
        // nothing, because `u64` is a type rather than a platform capability.
        TransferSyntax::Ndr64 => 8,
        TransferSyntax::Ndr32 | TransferSyntax::FeatureNegotiation(_) | TransferSyntax::Unknown => {
            4
        }
    }
}

/// Offset of the payload within a request stub.
#[must_use]
pub const fn request_data_offset(syntax: TransferSyntax) -> usize {
    // Two length fields: `DataLength` and `DataSizeIs`.
    REQUEST_PREFIX_LEN.saturating_add(length_field_width(syntax).saturating_mul(2))
}

/// Offset of the payload within a response stub.
#[must_use]
pub const fn response_data_offset(syntax: TransferSyntax) -> usize {
    // Three length fields: `DataLength`, `DataSizeMax`, `DataSizeIs`.
    RESPONSE_PREFIX_LEN.saturating_add(length_field_width(syntax).saturating_mul(3))
}

/// A parsed request stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestStub<'a> {
    /// What the client says the whole stub is.
    pub alloc_hint: u32,
    /// Which presentation context this call belongs to.
    pub context_id: u16,
    /// Which operation. Must be [`KMS_OPNUM`] (`WIRE-009`, #67).
    pub opnum: u16,
    /// The NDR conformant-array length the client declared.
    pub declared_length: u64,
    /// The NDR `size_is` the client declared.
    pub declared_size_is: u64,
    /// The KMS payload.
    pub data: &'a [u8],
}

/// Why a request stub could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubError {
    /// The stub ended before a field it declared.
    Truncated {
        /// Bytes present.
        actual: usize,
        /// Bytes the layout needs before the payload.
        needed: usize,
    },

    /// The operation number was not [`KMS_OPNUM`] (`WIRE-009`, #67).
    UnknownOperation {
        /// What the client asked for.
        opnum: u16,
    },

    /// The NDR length fields disagree with each other or with the payload
    /// (`WIRE-020`, #78).
    ///
    /// `vlmcs` warns on a mismatch in a *response*, so a real detection tool is
    /// watching this field. Accepting an inconsistent request would mean
    /// answering one, and the answer's lengths would have to be invented.
    InconsistentLength {
        /// The declared conformant-array length.
        declared_length: u64,
        /// The declared `size_is`.
        declared_size_is: u64,
        /// Bytes actually present.
        actual: usize,
    },
}

impl core::fmt::Display for StubError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { actual, needed } => {
                write!(f, "a stub of {actual} bytes cannot hold {needed} of header")
            }
            Self::UnknownOperation { opnum } => write!(f, "opnum {opnum} is not implemented"),
            Self::InconsistentLength {
                declared_length,
                declared_size_is,
                actual,
            } => write!(
                f,
                "NDR declares {declared_length}/{declared_size_is} bytes but {actual} are present"
            ),
        }
    }
}

/// Parse a request stub in the syntax the association negotiated.
///
/// # Errors
///
/// Returns [`StubError`] if the stub is truncated, names an operation this
/// interface does not implement, or declares lengths that disagree with what it
/// carries.
pub fn parse_request(body: &[u8], syntax: TransferSyntax) -> Result<RequestStub<'_>, StubError> {
    let width = length_field_width(syntax);
    let needed = request_data_offset(syntax);
    let (header, data) = body.split_at_checked(needed).ok_or(StubError::Truncated {
        actual: body.len(),
        needed,
    })?;

    let alloc_hint = read_u32(header, 0).unwrap_or(0);
    let context_id = read_u16(header, 4).unwrap_or(0);
    let opnum = read_u16(header, 6).unwrap_or(0);

    if opnum != KMS_OPNUM {
        return Err(StubError::UnknownOperation { opnum });
    }

    let declared_length = read_len(header, REQUEST_PREFIX_LEN, width).unwrap_or(0);
    let declared_size_is =
        read_len(header, REQUEST_PREFIX_LEN.saturating_add(width), width).unwrap_or(0);

    let actual = data.len();
    // `usize` may be narrower than the declared `u64`, which is exactly the
    // case NDR64-on-a-32-bit-target has to survive (`WIRE-030`, #88): a length
    // that does not fit `usize` cannot match what is present, so it is a
    // mismatch rather than a truncation.
    let matches_payload = u64::try_from(actual).is_ok_and(|actual| actual == declared_length);
    if declared_length != declared_size_is || !matches_payload {
        return Err(StubError::InconsistentLength {
            declared_length,
            declared_size_is,
            actual,
        });
    }

    Ok(RequestStub {
        alloc_hint,
        context_id,
        opnum,
        declared_length,
        declared_size_is,
        data,
    })
}

/// Bytes a response stub occupies for a payload of `payload_len` bytes.
///
/// Includes the RPC return code and the cosmetic alignment padding
/// (`WIRE-018`, #76).
#[must_use]
pub fn response_stub_len(syntax: TransferSyntax, payload_len: usize) -> usize {
    let unpadded = response_data_offset(syntax)
        .saturating_add(payload_len)
        .saturating_add(4);
    unpadded.saturating_add(unpadded.wrapping_neg() & 3)
}

/// Bytes an *error* response stub occupies.
///
/// On the error path the length fields are zeroed and `size_is` is omitted, so
/// the return code takes its place — which is what makes the `HRESULT` a field
/// of its own rather than something folded into padding (`KMS-013`, #29).
#[must_use]
pub fn error_stub_len(syntax: TransferSyntax) -> usize {
    let width = length_field_width(syntax);
    let unpadded = RESPONSE_PREFIX_LEN
        .saturating_add(width.saturating_mul(2))
        .saturating_add(4);
    unpadded.saturating_add(unpadded.wrapping_neg() & 3)
}

/// Write a response stub around `payload`.
///
/// `result` is the RPC return code: zero on success, the `HRESULT` otherwise.
/// A non-zero result means the payload is omitted entirely.
///
/// Returns the number of bytes written.
///
/// # Errors
///
/// Returns `None` if `out` is too small.
#[must_use]
pub fn write_response(
    out: &mut [u8],
    syntax: TransferSyntax,
    context_id: u16,
    result: u32,
    payload: &[u8],
) -> Option<usize> {
    let width = length_field_width(syntax);
    let failed = result != 0;
    let total = if failed {
        error_stub_len(syntax)
    } else {
        response_stub_len(syntax, payload.len())
    };
    let region = out.get_mut(..total)?;

    // `AllocHint` counts from the NDR fields onwards, matching what the peer
    // measures (`WIRE-020`, #78).
    let alloc_hint = u32::try_from(total.checked_sub(RESPONSE_PREFIX_LEN)?).ok()?;
    write_u32(region, 0, alloc_hint)?;
    write_u16(region, 4, context_id)?;
    // Cancel count and its reserved byte, both zero.
    write_u16(region, 6, 0)?;

    let mut cursor = RESPONSE_PREFIX_LEN;
    if failed {
        // Zeroed length fields, no `size_is`, and the return code in its place.
        write_len(region, cursor, width, 0)?;
        cursor = cursor.checked_add(width)?;
        write_len(region, cursor, width, 0)?;
        cursor = cursor.checked_add(width)?;
    } else {
        let payload_len = u64::try_from(payload.len()).ok()?;
        write_len(region, cursor, width, payload_len)?;
        cursor = cursor.checked_add(width)?;
        write_len(region, cursor, width, CONFORMANT_ARRAY_REFERENT)?;
        cursor = cursor.checked_add(width)?;
        write_len(region, cursor, width, payload_len)?;
        cursor = cursor.checked_add(width)?;

        let end = cursor.checked_add(payload.len())?;
        region.get_mut(cursor..end)?.copy_from_slice(payload);
        cursor = end;
    }

    write_u32(region, cursor, result)?;
    cursor = cursor.checked_add(4)?;

    // The cosmetic pad. Windows RPC aligns to 32 bits here even though nothing
    // requires it, and `vlmcs` warns when a server omits it.
    for byte in region.get_mut(cursor..)? {
        *byte = 0;
    }

    Some(total)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    bytes
        .get(offset..end)?
        .first_chunk::<2>()
        .map(|pair| u16::from_le_bytes(*pair))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    bytes
        .get(offset..end)?
        .first_chunk::<4>()
        .map(|quad| u32::from_le_bytes(*quad))
}

fn read_len(bytes: &[u8], offset: usize, width: usize) -> Option<u64> {
    if width == 8 {
        let end = offset.checked_add(8)?;
        bytes
            .get(offset..end)?
            .first_chunk::<8>()
            .map(|eight| u64::from_le_bytes(*eight))
    } else {
        read_u32(bytes, offset).map(u64::from)
    }
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Option<()> {
    let end = offset.checked_add(2)?;
    bytes
        .get_mut(offset..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let end = offset.checked_add(4)?;
    bytes
        .get_mut(offset..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

fn write_len(bytes: &mut [u8], offset: usize, width: usize, value: u64) -> Option<()> {
    if width == 8 {
        let end = offset.checked_add(8)?;
        bytes
            .get_mut(offset..end)?
            .copy_from_slice(&value.to_le_bytes());
        Some(())
    } else {
        write_u32(bytes, offset, u32::try_from(value).ok()?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        CONFORMANT_ARRAY_REFERENT, KMS_OPNUM, StubError, error_stub_len, parse_request,
        request_data_offset, response_data_offset, response_stub_len, write_response,
    };
    use crate::wire::syntax::TransferSyntax;
    use alloc::vec;
    use alloc::vec::Vec;

    fn request_stub(syntax: TransferSyntax, payload: &[u8]) -> Vec<u8> {
        let width = if syntax == TransferSyntax::Ndr64 {
            8
        } else {
            4
        };
        let mut stub = Vec::new();
        stub.extend_from_slice(&0_u32.to_le_bytes());
        stub.extend_from_slice(&0_u16.to_le_bytes());
        stub.extend_from_slice(&KMS_OPNUM.to_le_bytes());
        for _ in 0..2 {
            let value = u64::try_from(payload.len()).unwrap();
            if width == 8 {
                stub.extend_from_slice(&value.to_le_bytes());
            } else {
                stub.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
            }
        }
        stub.extend_from_slice(payload);
        stub
    }

    /// `WIRE-019` (#77): the four offsets the issue names.
    #[test]
    fn the_payload_offsets_are_the_documented_ones() {
        assert_eq!(request_data_offset(TransferSyntax::Ndr32), 16);
        assert_eq!(request_data_offset(TransferSyntax::Ndr64), 24);
        assert_eq!(response_data_offset(TransferSyntax::Ndr32), 20);
        assert_eq!(response_data_offset(TransferSyntax::Ndr64), 32);
    }

    #[test]
    fn a_request_stub_parses_in_both_syntaxes() {
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            let payload = vec![0xAB_u8; 260];
            let stub = request_stub(syntax, &payload);
            assert_eq!(stub.len(), request_data_offset(syntax) + payload.len());

            let parsed = parse_request(&stub, syntax).unwrap();
            assert_eq!(parsed.opnum, KMS_OPNUM);
            assert_eq!(parsed.context_id, 0);
            assert_eq!(parsed.declared_length, 260);
            assert_eq!(parsed.declared_size_is, 260);
            assert_eq!(parsed.data, payload.as_slice());
        }
    }

    /// `WIRE-009` (#67): only opnum 0 exists.
    #[test]
    fn an_unknown_operation_is_refused() {
        let mut stub = request_stub(TransferSyntax::Ndr32, &[0; 260]);
        stub[6..8].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            parse_request(&stub, TransferSyntax::Ndr32),
            Err(StubError::UnknownOperation { opnum: 1 })
        );
    }

    /// `WIRE-020` (#78): the NDR lengths must agree with each other and with
    /// what is present. Accepting an inconsistent request would mean inventing
    /// the lengths in the answer, and `vlmcs` warns on exactly that field.
    #[test]
    fn inconsistent_ndr_lengths_are_refused() {
        // `DataLength` disagrees with what is carried.
        let mut stub = request_stub(TransferSyntax::Ndr32, &[0; 260]);
        stub[8..12].copy_from_slice(&259_u32.to_le_bytes());
        assert!(matches!(
            parse_request(&stub, TransferSyntax::Ndr32),
            Err(StubError::InconsistentLength { .. })
        ));

        // `size_is` disagrees with `DataLength`.
        let mut stub = request_stub(TransferSyntax::Ndr32, &[0; 260]);
        stub[12..16].copy_from_slice(&259_u32.to_le_bytes());
        assert!(matches!(
            parse_request(&stub, TransferSyntax::Ndr32),
            Err(StubError::InconsistentLength { .. })
        ));

        // A length far larger than anything present, which is the shape of an
        // attempt to make a server read past its buffer.
        let mut stub = request_stub(TransferSyntax::Ndr64, &[0; 260]);
        stub[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            parse_request(&stub, TransferSyntax::Ndr64),
            Err(StubError::InconsistentLength { .. })
        ));
    }

    #[test]
    fn a_truncated_stub_is_refused_rather_than_read_past() {
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            let needed = request_data_offset(syntax);
            for len in 0..needed {
                assert_eq!(
                    parse_request(&vec![0_u8; len], syntax),
                    Err(StubError::Truncated {
                        actual: len,
                        needed
                    }),
                    "{syntax:?} with {len} bytes"
                );
            }
        }
    }

    /// `WIRE-019` (#77) and `KMS-013` (#29): the referent identifier is written
    /// as `0x00020000`, and the RPC return code is a field of its own that
    /// carries a real value on the error path.
    #[test]
    fn a_response_stub_carries_the_referent_and_a_separate_return_code() {
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            let payload = vec![0xCD_u8; 240];
            let mut out = vec![0_u8; 512];
            let written = write_response(&mut out, syntax, 1, 0, &payload).unwrap();
            assert_eq!(written, response_stub_len(syntax, payload.len()));

            let data_at = response_data_offset(syntax);
            let width = if syntax == TransferSyntax::Ndr64 {
                8
            } else {
                4
            };

            // `DataLength`, then the referent, then `size_is`.
            let read = |offset: usize| -> u64 {
                if width == 8 {
                    u64::from_le_bytes(out[offset..offset + 8].try_into().unwrap())
                } else {
                    u64::from(u32::from_le_bytes(
                        out[offset..offset + 4].try_into().unwrap(),
                    ))
                }
            };
            assert_eq!(read(8), 240);
            assert_eq!(read(8 + width), CONFORMANT_ARRAY_REFERENT);
            assert_eq!(read(8 + 2 * width), 240);
            assert_eq!(&out[data_at..data_at + 240], payload.as_slice());

            // The return code sits after the payload and is zero on success.
            let code_at = data_at + 240;
            assert_eq!(
                u32::from_le_bytes(out[code_at..code_at + 4].try_into().unwrap()),
                0
            );
            assert_eq!(u16::from_le_bytes(out[4..6].try_into().unwrap()), 1);
        }
    }

    /// The error path: lengths zeroed, `size_is` omitted, the `HRESULT` in its
    /// place. py-kms cannot express this at all, because its padding helper
    /// always writes zeros there.
    #[test]
    fn an_error_response_puts_the_hresult_where_size_is_would_be() {
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            let width = if syntax == TransferSyntax::Ndr64 {
                8
            } else {
                4
            };
            let mut out = vec![0xFF_u8; 512];
            let written = write_response(&mut out, syntax, 1, 0x8007_000D, &[0xAA; 240]).unwrap();
            assert_eq!(written, error_stub_len(syntax));
            assert!(
                written < response_stub_len(syntax, 240),
                "the payload must be omitted"
            );

            // Both remaining length fields are zero...
            assert!(out[8..8 + 2 * width].iter().all(|byte| *byte == 0));
            // ...and the return code takes the place `size_is` would occupy.
            let code_at = 8 + 2 * width;
            assert_eq!(
                u32::from_le_bytes(out[code_at..code_at + 4].try_into().unwrap()),
                0x8007_000D
            );
        }
    }

    /// `WIRE-018` (#76): the cosmetic pad. Windows aligns to 32 bits here even
    /// though nothing requires it, and `vlmcs` warns when a server omits it.
    #[test]
    fn the_response_is_padded_to_a_thirty_two_bit_boundary() {
        for syntax in [TransferSyntax::Ndr32, TransferSyntax::Ndr64] {
            for payload_len in 0..8_usize {
                let total = response_stub_len(syntax, payload_len);
                assert_eq!(total % 4, 0, "{syntax:?} with {payload_len} bytes");

                let mut out = vec![0xFF_u8; 128];
                let written =
                    write_response(&mut out, syntax, 0, 0, &vec![0xCD; payload_len]).unwrap();
                assert_eq!(written, total);

                // Every padding byte is zero, including where the buffer held
                // 0xFF before.
                let unpadded = response_data_offset(syntax) + payload_len + 4;
                assert!(
                    out[unpadded..total].iter().all(|byte| *byte == 0),
                    "padding not zeroed"
                );
            }
            assert_eq!(error_stub_len(syntax) % 4, 0);
        }
    }

    /// A real v5 exchange, end to end through the stub layer, so the offsets
    /// are checked against a realistic size rather than a contrived one.
    #[test]
    fn a_realistic_v5_response_has_the_expected_wire_size() {
        // 240 bytes of KMS payload over NDR32: 20 + 240 + 4 = 264, already
        // aligned.
        assert_eq!(response_stub_len(TransferSyntax::Ndr32, 240), 264);
        // Over NDR64: 32 + 240 + 4 = 276, which needs no padding either.
        assert_eq!(response_stub_len(TransferSyntax::Ndr64, 240), 276);
        // A v6 payload of 280 bytes: 20 + 280 + 4 = 304.
        assert_eq!(response_stub_len(TransferSyntax::Ndr32, 280), 304);
    }

    #[test]
    fn an_undersized_output_buffer_is_refused() {
        let needed = response_stub_len(TransferSyntax::Ndr32, 240);
        for len in [0_usize, 20, needed - 1] {
            let mut out = vec![0_u8; len];
            assert_eq!(
                write_response(&mut out, TransferSyntax::Ndr32, 0, 0, &[0; 240]),
                None
            );
        }
    }
}
