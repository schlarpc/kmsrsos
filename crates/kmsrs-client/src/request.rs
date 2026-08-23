//! What the client sends, and what it refuses to send
//! (`CLI-009`, #215; `CLI-013`, #219).
//!
//! # Every field is overridable
//!
//! The defaults are what a real Windows client sends, because the client's job
//! is to be indistinguishable from one. But every field can be replaced, since
//! probing a host means sending things a real client would not — a retail
//! activation ID, an absurd `N_Policy`, a clock four hours out.
//!
//! # Over-long input is an error, never a truncation
//!
//! `vlmcs` truncates a workstation name over 63 characters after printing a
//! BEL-prefixed warning, and accepts a licence status anywhere in
//! `0..=0x7fffffff` with only a warning above 6. Both are the same mistake:
//! the operator asked for one thing and the program did another, and the only
//! notice was a line that scrolled past.
//!
//! Here an over-long name is [`RequestError::WorkstationNameTooLong`] and
//! nothing is sent. A probe that silently became a *different* probe is worse
//! than one that refused to run.

use core::time::Duration;
use kmsrs_db::Guid;
use kmsrs_proto::kms::layout::{REQUEST_BODY_LEN, RequestBody, WireGuid};
use kmsrs_proto::kms::version::Version;
use kmsrs_proto::types::WORKSTATION_NAME_UNITS;
use zerocopy::FromBytes;

/// Windows' application GUID, which is what a Windows client sends.
pub const WINDOWS_APPLICATION: &str = "55c92734-d682-4d71-983e-d6ec3f16059f";

/// Windows Server 2025's counted ID — the genuine one (`DB-008`, #132).
pub const DEFAULT_KMS_ID: &str = "907f1f65-adcd-4a2e-95bc-4bf500bc6e58";

/// How long to wait for a reply before giving up (`CLI-012`, #218).
///
/// `vlmcs` hardcodes ten seconds and offers no option at all, which makes it
/// unusable for probing a host across a slow link and unusable for a soak test
/// that wants to fail fast.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a request could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The workstation name does not fit the wire field.
    ///
    /// The field is 64 UTF-16 code units including its terminator, so at most
    /// 63 units of name — and a name of 63 *characters* may still not fit,
    /// because anything outside the basic multilingual plane costs two units.
    WorkstationNameTooLong {
        /// How many UTF-16 code units the name needs.
        units: usize,
        /// How many are available.
        limit: usize,
    },
    /// A GUID could not be parsed.
    MalformedGuid {
        /// Which field.
        field: &'static str,
        /// What was given.
        value: alloc_text::Text,
    },
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WorkstationNameTooLong { units, limit } => write!(
                f,
                "the workstation name needs {units} UTF-16 code units and the \
                 field holds {limit}; refusing to truncate it"
            ),
            Self::MalformedGuid { field, value } => {
                write!(f, "{field} is not a GUID: {}", value.as_str())
            }
        }
    }
}

impl core::error::Error for RequestError {}

/// A short owned string, so an error can quote what it was given.
pub mod alloc_text {
    /// An owned string.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Text(String);

    impl Text {
        /// Wrap a string.
        #[must_use]
        pub fn new(value: &str) -> Self {
            Self(value.to_owned())
        }

        /// The text.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }
}

/// Everything a client puts in a request (`CLI-009`, #215).
///
/// Defaults are what a real Windows client sends; every field is replaceable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFields {
    /// Which protocol version to speak.
    pub version: Version,
    /// The application GUID.
    pub application: Guid,
    /// The SKU ID, which a host reads and ignores (`KMS-018`, #34).
    pub sku: Guid,
    /// The counted ID, which is what a host actually decides on.
    pub kms_id: Guid,
    /// This machine's identity.
    pub client_machine_id: Guid,
    /// The previous machine ID, or all zeros if it has never changed.
    pub previous_client_machine_id: Guid,
    /// How many clients this product's policy requires.
    pub required_clients: u32,
    /// The client's self-reported licensing state.
    pub license_status: u32,
    /// Minutes remaining in that state.
    pub grace_minutes: u32,
    /// Whether to claim to be a virtual machine.
    pub virtual_machine: bool,
    /// The workstation name.
    pub workstation_name: String,
    /// The timestamp to send, as a `FILETIME`.
    pub client_time: u64,
}

impl Default for RequestFields {
    fn default() -> Self {
        Self {
            version: Version::V6,
            application: parse_guid(WINDOWS_APPLICATION).unwrap_or(Guid::ZERO),
            sku: parse_guid(DEFAULT_KMS_ID).unwrap_or(Guid::ZERO),
            kms_id: parse_guid(DEFAULT_KMS_ID).unwrap_or(Guid::ZERO),
            client_machine_id: Guid::ZERO,
            previous_client_machine_id: Guid::ZERO,
            required_clients: 25,
            license_status: 0,
            grace_minutes: 0,
            virtual_machine: false,
            workstation_name: String::from("kmsrs-client"),
            client_time: 0,
        }
    }
}

impl RequestFields {
    /// Encode these fields into a wire request body.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::WorkstationNameTooLong`] rather than truncating
    /// (`CLI-013`, #219).
    pub fn to_body(&self) -> Result<RequestBody, RequestError> {
        let units: Vec<u16> = self.workstation_name.encode_utf16().collect();
        // One unit is reserved for the terminating NUL.
        let limit = WORKSTATION_NAME_UNITS.saturating_sub(1);
        if units.len() > limit {
            return Err(RequestError::WorkstationNameTooLong {
                units: units.len(),
                limit,
            });
        }

        // `RequestBody` is all integers, so a zeroed buffer is a valid one and
        // this cannot fail — but it is written as a `?` rather than an unwrap
        // so the crate keeps its no-panic posture (`ARCH-008`, #8).
        let mut body = RequestBody::read_from_bytes(&[0_u8; REQUEST_BODY_LEN]).map_err(|_| {
            RequestError::MalformedGuid {
                field: "body",
                value: alloc_text::Text::new("a zeroed request body was not readable"),
            }
        })?;

        body.version
            .set(self.version.to_protocol_version().to_wire());
        body.is_client_vm.set(u32::from(self.virtual_machine));
        body.license_status.set(self.license_status);
        body.grace_time.set(self.grace_minutes);
        body.application_id = WireGuid::from_guid(self.application);
        body.sku_id = WireGuid::from_guid(self.sku);
        body.kms_counted_id = WireGuid::from_guid(self.kms_id);
        body.client_machine_id = WireGuid::from_guid(self.client_machine_id);
        body.required_clients.set(self.required_clients);
        body.client_time.set(self.client_time);
        body.previous_client_machine_id = WireGuid::from_guid(self.previous_client_machine_id);
        for (slot, unit) in body.workstation_name.iter_mut().zip(units.iter()) {
            slot.set(*unit);
        }

        Ok(body)
    }
}

/// Parse a canonical GUID string.
///
/// The shipped *server* never parses a GUID from text, because nothing on the
/// wire is text. A diagnostic client does, because an operator types them.
#[must_use]
pub fn parse_guid(text: &str) -> Option<Guid> {
    let mut digits = [0_u8; 32];
    let mut count = 0_usize;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        let value = match byte {
            b'0'..=b'9' => byte.checked_sub(b'0')?,
            b'a'..=b'f' => byte.checked_sub(b'a')?.checked_add(10)?,
            b'A'..=b'F' => byte.checked_sub(b'A')?.checked_add(10)?,
            _ => return None,
        };
        *digits.get_mut(count)? = value;
        count = count.checked_add(1)?;
    }
    if count != 32 {
        return None;
    }

    let mut bytes = [0_u8; 16];
    for (index, slot) in bytes.iter_mut().enumerate() {
        let high = *digits.get(index.checked_mul(2)?)?;
        let low = *digits.get(index.checked_mul(2)?.checked_add(1)?)?;
        *slot = high.checked_shl(4)?.checked_add(low)?;
    }
    Some(Guid::from_bytes(bytes))
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

    use super::{DEFAULT_KMS_ID, RequestError, RequestFields, WINDOWS_APPLICATION, parse_guid};
    use kmsrs_proto::kms::version::Version;

    /// `CLI-009` (#215): every field the issue lists can be replaced.
    #[test]
    fn every_field_is_overridable() {
        let fields = RequestFields {
            version: Version::V4,
            application: parse_guid("0ff1ce15-a989-479d-af46-f275c6370663").unwrap(),
            sku: parse_guid("11111111-2222-3333-4444-555555555555").unwrap(),
            kms_id: parse_guid("66666666-7777-8888-9999-aaaaaaaaaaaa").unwrap(),
            client_machine_id: parse_guid("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").unwrap(),
            previous_client_machine_id: parse_guid("12345678-1234-1234-1234-123456789abc").unwrap(),
            required_clients: 4242,
            license_status: 3,
            grace_minutes: 43_200,
            virtual_machine: true,
            workstation_name: String::from("probe-host"),
            client_time: 133_000_000_000_000_000,
        };

        let body = fields.to_body().expect("it encodes");
        assert_eq!(
            body.version.get(),
            Version::V4.to_protocol_version().to_wire()
        );
        assert_eq!(body.is_client_vm.get(), 1);
        assert_eq!(body.license_status.get(), 3);
        assert_eq!(body.grace_time.get(), 43_200);
        assert_eq!(body.required_clients.get(), 4242);
        assert_eq!(body.client_time.get(), 133_000_000_000_000_000);
        assert_eq!(body.application_id.to_guid(), fields.application);
        assert_eq!(body.sku_id.to_guid(), fields.sku);
        assert_eq!(body.kms_counted_id.to_guid(), fields.kms_id);
        assert_eq!(body.client_machine_id.to_guid(), fields.client_machine_id);
        assert_eq!(
            body.previous_client_machine_id.to_guid(),
            fields.previous_client_machine_id
        );
        assert_eq!(body.workstation_name[0].get(), u16::from(b'p'));
    }

    /// The defaults are what a real Windows client sends, because the client's
    /// job is to be indistinguishable from one.
    #[test]
    fn the_defaults_are_a_real_windows_client() {
        let fields = RequestFields::default();
        assert_eq!(fields.version, Version::V6);
        assert_eq!(fields.application, parse_guid(WINDOWS_APPLICATION).unwrap());
        assert_eq!(fields.kms_id, parse_guid(DEFAULT_KMS_ID).unwrap());
        assert_eq!(fields.required_clients, 25, "a Windows client SKU asks 25");
        assert!(!fields.virtual_machine);
        assert!(fields.to_body().is_ok());
    }

    /// `CLI-013` (#219): over-long input is refused, never truncated.
    ///
    /// `vlmcs` truncates a name over 63 characters after a BEL-prefixed
    /// warning — so the operator asked for one probe and got a different one,
    /// and the only notice was a line that scrolled past.
    #[test]
    fn an_over_long_workstation_name_is_refused_not_truncated() {
        let fields = RequestFields {
            workstation_name: "x".repeat(64),
            ..RequestFields::default()
        };
        let failure = fields.to_body().unwrap_err();
        assert!(
            matches!(
                failure,
                RequestError::WorkstationNameTooLong {
                    units: 64,
                    limit: 63
                }
            ),
            "{failure:?}"
        );
        // And the message says what to do about it.
        assert!(failure.to_string().contains("refusing to truncate"));

        // Exactly at the limit is fine: 63 units plus a terminator.
        let fields = RequestFields {
            workstation_name: "x".repeat(63),
            ..RequestFields::default()
        };
        assert!(fields.to_body().is_ok());
    }

    /// The limit is in UTF-16 code units, not characters. A name of 40
    /// astral-plane characters is 80 units and does not fit, and counting
    /// characters would have let it through to be truncated on the wire.
    #[test]
    fn the_length_limit_counts_code_units_not_characters() {
        let fields = RequestFields {
            // Each of these is two UTF-16 code units.
            workstation_name: "\u{1F600}".repeat(40),
            ..RequestFields::default()
        };
        let failure = fields.to_body().unwrap_err();
        assert!(
            matches!(
                failure,
                RequestError::WorkstationNameTooLong { units: 80, .. }
            ),
            "{failure:?}"
        );

        // 31 of them is 62 units, which fits.
        let fields = RequestFields {
            workstation_name: "\u{1F600}".repeat(31),
            ..RequestFields::default()
        };
        assert!(fields.to_body().is_ok());
    }

    /// An out-of-range licence status is *sent*, not refused. Unlike a name
    /// that would be silently shortened, an unusual status is exactly the kind
    /// of thing a probe exists to send — the client's job is to be able to ask
    /// impolite questions.
    #[test]
    fn an_unusual_licence_status_is_sent_rather_than_refused() {
        for status in [0_u32, 6, 7, 0x7fff_ffff, u32::MAX] {
            let fields = RequestFields {
                license_status: status,
                ..RequestFields::default()
            };
            let body = fields.to_body().expect("a probe may send anything");
            assert_eq!(body.license_status.get(), status);
        }
    }

    #[test]
    fn guid_parsing_accepts_canonical_text_and_rejects_the_rest() {
        let guid = parse_guid("907f1f65-adcd-4a2e-95bc-4bf500bc6e58").unwrap();
        assert_eq!(guid.to_bytes()[0], 0x90);
        assert_eq!(guid.to_bytes()[15], 0x58);

        // Case-insensitive, and dashes are optional.
        assert_eq!(
            parse_guid("907F1F65ADCD4A2E95BC4BF500BC6E58"),
            Some(guid),
            "dashes are cosmetic"
        );

        for bad in [
            "",
            "907f1f65",
            "907f1f65-adcd-4a2e-95bc-4bf500bc6e5",
            "907f1f65-adcd-4a2e-95bc-4bf500bc6e588",
            "907f1f65-adcd-4a2e-95bc-4bf500bc6e5g",
        ] {
            assert!(parse_guid(bad).is_none(), "{bad} was accepted");
        }
    }
}
