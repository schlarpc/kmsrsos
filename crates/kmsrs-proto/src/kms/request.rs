//! Parsing a KMS request body into typed values (`KMS-009`, #25).
//!
//! # Exact lengths, not minimums
//!
//! The stub length must **equal** the declared version's fixed size. Every KMS
//! request is fixed-size — 252 bytes for v4, 260 for v5 and v6 — so a length
//! check has no reason to be an inequality.
//!
//! This is MM18, the one case where neither existing implementation is right.
//! vlmcsd checks `>=` against a floor that wrongly includes the RPC prologue,
//! so a v6 request of 268–275 bytes over NDR32, or 276–283 over NDR64, passes
//! the check and then reads up to eight bytes past what the client actually
//! sent — uninitialised stack, returned to the peer. An equality check makes
//! that unrepresentable rather than bounded.
//!
//! Whether over-long requests occur in practice at all is `KMS-010` (#26),
//! which is an experiment against a real Wine client rather than a guess.
//! Until it is answered, the strict rule holds: refusing a request no genuine
//! client sends costs nothing, and vlmcsd's "allow bigger requests to support
//! buggy RPC clients" comment is how the over-read got in.

use crate::kms::layout::{REQUEST_V4_LEN, REQUEST_V5_LEN, REQUEST_V6_LEN, RequestBody};
use crate::kms::status::LicenseStatus;
use crate::kms::version::{ProtocolVersion, Version};
use crate::time::FileTime;
use crate::types::{
    ApplicationId, ClientKind, ClientMachineId, ClientTime, GraceMinutes, KmsCountedId,
    RequiredClients, SkuId, WorkstationName,
};

/// A parsed KMS request.
///
/// Every field is a named type, so a handler cannot confuse the SKU ID with the
/// counted ID (`ARCH-007`, #7). The raw bytes are not retained: the input
/// buffer belongs to the caller and is never modified (`ARCH-013`, #13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Exactly what the client declared, echoed back verbatim
    /// (`KMS-012`, #28).
    pub version: ProtocolVersion,

    /// Whether the client says it is virtualised. Logged, never a decision
    /// (`KMS-017`, #33).
    pub client_kind: ClientKind,

    /// The client's self-reported licensing state (`KMS-016`, #32).
    pub license_status: LicenseStatus,

    /// Minutes the client says remain in that state. Logged, never a decision.
    pub grace: GraceMinutes,

    /// Windows, Office 2010, or Office 2013 and later. Selects the counting
    /// bucket (`POL-002`, #90).
    pub application: ApplicationId,

    /// The detailed product identifier, which a host ignores (`KMS-018`, #34).
    pub sku: SkuId,

    /// What the host actually decides on.
    pub counted: KmsCountedId,

    /// The identity the host counts.
    pub client_machine_id: ClientMachineId,

    /// The minimum client count this product's policy requires.
    pub required_clients: RequiredClients,

    /// The client's timestamp, echoed back and used to derive the v6 key.
    pub client_time: ClientTime,

    /// The machine's previous identity, if it has ever changed.
    pub previous_client_machine_id: Option<ClientMachineId>,

    /// The client's workstation name, decoded lossily for logging and never
    /// trusted (`KMS-019`, #35).
    pub workstation_name: WorkstationName,
}

impl Request {
    /// Interpret a request body.
    ///
    /// Total: every field is either fixed-width or has a defined reading for
    /// every bit pattern, so there is no failure mode once the length is right.
    /// That is the point of checking the length first.
    #[must_use]
    pub fn from_body(body: &RequestBody) -> Self {
        Self {
            version: ProtocolVersion::from_wire(body.version.get()),
            client_kind: ClientKind::from_wire(body.is_client_vm.get()),
            license_status: LicenseStatus::from_wire(body.license_status.get()),
            grace: GraceMinutes(body.grace_time.get()),
            application: ApplicationId(body.application_id.to_guid()),
            sku: SkuId(body.sku_id.to_guid()),
            counted: KmsCountedId(body.kms_counted_id.to_guid()),
            client_machine_id: ClientMachineId(body.client_machine_id.to_guid()),
            required_clients: RequiredClients(body.required_clients.get()),
            // Checked by construction: any `u64` is a representable `FileTime`,
            // and every operation on one is checked or saturating
            // (`KMS-020`, #36). py-kms raises `OSError`, `ValueError` or
            // `OverflowError` here depending on the value.
            client_time: ClientTime(FileTime::from_ticks(body.client_time.get())),
            previous_client_machine_id: ClientMachineId::previous(
                body.previous_client_machine_id.to_guid(),
            ),
            workstation_name: WorkstationName::decode(&read_units(&body.workstation_name)),
        }
    }
}

/// Copy the workstation-name field out of its little-endian wire form.
fn read_units(
    field: &[zerocopy::byteorder::little_endian::U16; crate::types::WORKSTATION_NAME_UNITS],
) -> [u16; crate::types::WORKSTATION_NAME_UNITS] {
    let mut units = [0_u16; crate::types::WORKSTATION_NAME_UNITS];
    for (slot, wire) in units.iter_mut().zip(field.iter()) {
        *slot = wire.get();
    }
    units
}

/// Why a request could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// The declared version is not one this host implements.
    ///
    /// Answered with a well-formed response carrying `0x8007000D`, not a
    /// dropped connection (`KMS-014`, #30).
    UnsupportedVersion {
        /// What the client declared.
        declared: ProtocolVersion,
    },

    /// The stub was not the exact length the declared version requires
    /// (`KMS-009`, #25).
    WrongLength {
        /// The version the client declared.
        declared: Version,
        /// The only length that version accepts.
        expected: usize,
        /// What arrived.
        actual: usize,
    },

    /// The stub was too short to hold even a version word.
    TooShortToDispatch {
        /// What arrived.
        actual: usize,
    },
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedVersion { declared } => {
                write!(f, "unsupported protocol version {declared}")
            }
            Self::WrongLength {
                declared,
                expected,
                actual,
            } => write!(
                f,
                "a {declared:?} request is exactly {expected} bytes, not {actual}"
            ),
            Self::TooShortToDispatch { actual } => {
                write!(f, "{actual} bytes is too short to read a version")
            }
        }
    }
}

/// The exact framed length a version's request has (`KMS-003`, #19).
#[must_use]
pub const fn framed_request_len(version: Version) -> usize {
    match version {
        Version::V4 => REQUEST_V4_LEN,
        Version::V5 => REQUEST_V5_LEN,
        Version::V6 => REQUEST_V6_LEN,
    }
}

/// Read the version word from the front of a stub and check its length.
///
/// The version word is the first four bytes of every request in every version,
/// which is what makes dispatch possible before anything is decrypted.
///
/// # Errors
///
/// Returns [`RequestError::TooShortToDispatch`] if there is no version word,
/// [`RequestError::UnsupportedVersion`] if it names a version this host does not
/// implement, and [`RequestError::WrongLength`] if the stub is any length other
/// than that version's exact size.
pub fn dispatch(stub: &[u8]) -> Result<(Version, ProtocolVersion), RequestError> {
    let Some(word) = stub.first_chunk::<4>() else {
        return Err(RequestError::TooShortToDispatch { actual: stub.len() });
    };
    let declared = ProtocolVersion::from_wire(u32::from_le_bytes(*word));
    let Some(version) = declared.supported() else {
        return Err(RequestError::UnsupportedVersion { declared });
    };

    let expected = framed_request_len(version);
    if stub.len() == expected {
        Ok((version, declared))
    } else {
        Err(RequestError::WrongLength {
            declared: version,
            expected,
            actual: stub.len(),
        })
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

    use super::{Request, RequestError, dispatch, framed_request_len};
    use crate::kms::layout::{REQUEST_BODY_LEN, RequestBody};
    use crate::kms::status::LicenseStatus;
    use crate::kms::version::{ProtocolVersion, Version};
    use crate::types::{ClientKind, WORKSTATION_NAME_UNITS};
    use alloc::vec;
    use zerocopy::{FromBytes, IntoBytes};

    /// A request body with plausible field values, built through the wire type
    /// so the test exercises the same path the server does.
    fn sample_body() -> RequestBody {
        let mut bytes = [0_u8; REQUEST_BODY_LEN];
        let mut body = RequestBody::read_from_bytes(&bytes).unwrap();

        body.version.set(0x0006_0000);
        body.is_client_vm.set(1);
        body.license_status.set(2);
        body.grace_time.set(43_200);
        body.required_clients.set(25);
        body.client_time.set(133_000_000_000_000_000);
        body.application_id.data1.set(0x55c9_2734);
        body.kms_counted_id.data1.set(0x907f_1f65);
        body.client_machine_id.data1.set(0x1111_2222);
        for (slot, unit) in body.workstation_name.iter_mut().zip("host".encode_utf16()) {
            slot.set(unit);
        }

        bytes.copy_from_slice(body.as_bytes());
        RequestBody::read_from_bytes(&bytes).unwrap()
    }

    #[test]
    fn a_request_parses_into_named_types() {
        let request = Request::from_body(&sample_body());

        assert_eq!(request.version, ProtocolVersion { major: 6, minor: 0 });
        assert_eq!(request.client_kind, ClientKind::VirtualMachine);
        assert_eq!(request.license_status, LicenseStatus::OutOfBoxGrace);
        assert_eq!(request.grace.0, 43_200);
        assert_eq!(request.required_clients.0, 25);
        assert_eq!(request.client_time.0.as_ticks(), 133_000_000_000_000_000);
        assert_eq!(request.workstation_name.as_str(), "host");
        assert_eq!(
            request.previous_client_machine_id, None,
            "an all-zero previous ID means it never changed"
        );
        assert_ne!(request.application.0, request.counted.0);
    }

    /// `KMS-020` (#36): any `u64` a client can send must parse. py-kms raises
    /// `OSError`, `ValueError` or `OverflowError` here depending on the value.
    #[test]
    fn any_client_timestamp_parses_without_failing() {
        for ticks in [0_u64, 1, u64::MAX, u64::MAX - 1, 116_444_736_000_000_000] {
            let mut body = sample_body();
            body.client_time.set(ticks);
            let request = Request::from_body(&body);
            assert_eq!(request.client_time.0.as_ticks(), ticks);
        }
    }

    /// Every bit pattern in the fixed-width fields must parse, because the
    /// length check is the only gate in front of them (`SEC-003`, #195).
    #[test]
    fn a_body_of_arbitrary_bytes_parses_rather_than_failing() {
        for fill in [0x00_u8, 0xFF, 0xAA, 0x80] {
            let bytes = [fill; REQUEST_BODY_LEN];
            let body = RequestBody::read_from_bytes(&bytes).unwrap();
            let request = Request::from_body(&body);
            // The workstation name is the field with the most ways to go wrong.
            assert!(request.workstation_name.as_str().chars().count() <= WORKSTATION_NAME_UNITS);
        }
    }

    /// `KMS-009` (#25), MM18. The lengths in the middle of these ranges are
    /// exactly the ones vlmcsd accepts and then over-reads.
    #[test]
    fn only_the_exact_framed_length_is_accepted() {
        for version in Version::ALL {
            let expected = framed_request_len(version);
            let word = version.to_protocol_version().to_wire().to_le_bytes();

            let mut exact = vec![0_u8; expected];
            exact[..4].copy_from_slice(&word);
            assert_eq!(dispatch(&exact).unwrap().0, version);

            // One byte either side, and the whole band vlmcsd's `>=` admits.
            for actual in [
                expected.saturating_sub(1),
                expected + 1,
                expected + 8,
                expected + 15,
                expected + 16,
                expected + 23,
            ] {
                let mut wrong = vec![0_u8; actual];
                wrong[..4].copy_from_slice(&word);
                assert_eq!(
                    dispatch(&wrong),
                    Err(RequestError::WrongLength {
                        declared: version,
                        expected,
                        actual
                    }),
                    "{version:?} must reject {actual} bytes"
                );
            }
        }
    }

    /// The specific NDR32 and NDR64 bands the audit names for v6.
    #[test]
    fn the_mm18_over_read_band_is_refused() {
        let word = 0x0006_0000_u32.to_le_bytes();
        // 260 is the real length; NDR32 adds an 8-byte prologue to vlmcsd's
        // floor and NDR64 a 16-byte one, which is where 268 and 276 come from.
        for actual in (268..=283_usize).chain([261, 262, 267]) {
            let mut stub = vec![0_u8; actual];
            stub[..4].copy_from_slice(&word);
            assert!(
                matches!(dispatch(&stub), Err(RequestError::WrongLength { .. })),
                "a {actual}-byte v6 stub must be refused"
            );
        }
    }

    #[test]
    fn an_unsupported_version_is_named_rather_than_length_checked() {
        // 6.1 — py-kms services this as v6.
        let mut stub = vec![0_u8; 260];
        stub[..4].copy_from_slice(&0x0006_0001_u32.to_le_bytes());
        assert_eq!(
            dispatch(&stub),
            Err(RequestError::UnsupportedVersion {
                declared: ProtocolVersion { major: 6, minor: 1 }
            })
        );

        // A version that does not exist at all.
        let mut stub = vec![0_u8; 260];
        stub[..4].copy_from_slice(&0x0009_0000_u32.to_le_bytes());
        assert!(matches!(
            dispatch(&stub),
            Err(RequestError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_stub_too_short_to_hold_a_version_is_refused_first() {
        for actual in 0..4_usize {
            assert_eq!(
                dispatch(&vec![0_u8; actual]),
                Err(RequestError::TooShortToDispatch { actual })
            );
        }
    }

    #[test]
    fn the_framed_lengths_are_the_documented_ones() {
        assert_eq!(framed_request_len(Version::V4), 252);
        assert_eq!(framed_request_len(Version::V5), 260);
        assert_eq!(framed_request_len(Version::V6), 260);
    }
}
