//! The HRESULT vocabulary a KMS exchange can carry (`KMS-015`, #31).
//!
//! An `HRESULT` is a bare `u32` on the wire, and treating it as one is how both
//! existing implementations end up unable to return an error at all:
//!
//! * py-kms **structurally cannot** return a non-zero result on the success
//!   path, because its `getPadding()` returns `4 + align` and those four bytes
//!   are always zero (`KMS-013`, #29).
//! * py-kms's unsupported-version path calls
//!   `finalResponse.decode('utf-8').encode('utf-8')` on bytes that begin
//!   `42 F0 04 C0`, which raises `UnicodeDecodeError` every single time. That
//!   error path has never once executed successfully in either version of the
//!   program (`KMS-014`, #30).
//!
//! Each variant carries the text `vlmcs` prints for it, so a diagnostic client
//! can say what happened rather than printing a hexadecimal number
//! (`CLI-014`, #220).

/// A KMS-relevant `HRESULT`.
///
/// Exhaustive over the values this protocol produces (`ARCH-010`, #10), with
/// [`HResult::Other`] for anything read back from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HResult {
    /// `S_OK` — the request succeeded.
    Ok,

    /// `0xC004F042` — the KMS host declined to activate this product.
    ///
    /// Notably **not** what an unsupported protocol version returns. Both are
    /// refusals; only this one means "I understood you and said no".
    NotSupportedByKmsServer,

    /// `0x8007000D` — the data is invalid.
    ///
    /// The answer to an unsupported protocol version (`KMS-014`, #30).
    InvalidData,

    /// `0xC004F06C` — the client's timestamp is too far from the host's.
    TimestampDiffers,

    /// `0xC004D104` — invalid activation data was used.
    ///
    /// A genuine host returns this when its client-count table is poisoned.
    /// Ours evicts instead, so it is never emitted (`POL-007`, #95) — but a
    /// diagnostic client must still be able to name it when a real host sends
    /// one.
    InvalidActivationData,

    /// `0x80070005` — access denied.
    AccessDenied,

    /// `0xC004B005` — authorization failed.
    AuthorizationFailed,

    /// `0xC004F050` — the product key is invalid.
    InvalidProductKey,

    /// `1` — an RPC protocol error, which is not really an HRESULT at all.
    RpcProtocolError,

    /// A value this vocabulary does not name.
    ///
    /// Reachable only when reading a response from some other host. Kept as-is
    /// so a diagnostic client reports the number rather than losing it.
    Other(u32),
}

impl HResult {
    /// Decode a wire value.
    #[must_use]
    pub const fn from_wire(raw: u32) -> Self {
        match raw {
            0x0000_0000 => Self::Ok,
            0xC004_F042 => Self::NotSupportedByKmsServer,
            0x8007_000D => Self::InvalidData,
            0xC004_F06C => Self::TimestampDiffers,
            0xC004_D104 => Self::InvalidActivationData,
            0x8007_0005 => Self::AccessDenied,
            0xC004_B005 => Self::AuthorizationFailed,
            0xC004_F050 => Self::InvalidProductKey,
            0x0000_0001 => Self::RpcProtocolError,
            other => Self::Other(other),
        }
    }

    /// Encode to a wire value.
    #[must_use]
    pub const fn to_wire(self) -> u32 {
        match self {
            Self::Ok => 0x0000_0000,
            Self::NotSupportedByKmsServer => 0xC004_F042,
            Self::InvalidData => 0x8007_000D,
            Self::TimestampDiffers => 0xC004_F06C,
            Self::InvalidActivationData => 0xC004_D104,
            Self::AccessDenied => 0x8007_0005,
            Self::AuthorizationFailed => 0xC004_B005,
            Self::InvalidProductKey => 0xC004_F050,
            Self::RpcProtocolError => 0x0000_0001,
            Self::Other(raw) => raw,
        }
    }

    /// Whether this indicates success.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// The text `vlmcs` prints for this result (`CLI-014`, #220).
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Ok => "success",
            Self::NotSupportedByKmsServer => {
                "the requested product is not supported by this KMS server"
            }
            Self::InvalidData => "the data is invalid",
            Self::TimestampDiffers => {
                "the client and server timestamps differ by more than the allowed tolerance"
            }
            Self::InvalidActivationData => "invalid activation data was used",
            Self::AccessDenied => "access denied",
            Self::AuthorizationFailed => "authorization failed",
            Self::InvalidProductKey => "the product key is invalid",
            Self::RpcProtocolError => "an RPC protocol error occurred",
            Self::Other(_) => "an unrecognised error",
        }
    }
}

impl core::fmt::Display for HResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:08X} ({})", self.to_wire(), self.description())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::HResult;

    /// Every named value, so a transposed digit in one of the constants shows
    /// up as a failing test rather than as a client that reports the wrong
    /// reason.
    const NAMED: [(HResult, u32); 9] = [
        (HResult::Ok, 0x0000_0000),
        (HResult::NotSupportedByKmsServer, 0xC004_F042),
        (HResult::InvalidData, 0x8007_000D),
        (HResult::TimestampDiffers, 0xC004_F06C),
        (HResult::InvalidActivationData, 0xC004_D104),
        (HResult::AccessDenied, 0x8007_0005),
        (HResult::AuthorizationFailed, 0xC004_B005),
        (HResult::InvalidProductKey, 0xC004_F050),
        (HResult::RpcProtocolError, 0x0000_0001),
    ];

    #[test]
    fn every_named_result_round_trips_through_its_wire_value() {
        for (result, wire) in NAMED {
            assert_eq!(result.to_wire(), wire, "{result:?}");
            assert_eq!(HResult::from_wire(wire), result, "{wire:#010X}");
        }
    }

    /// `KMS-014` (#30): the unsupported-version answer is `0x8007000D`, and is
    /// specifically *not* `0xC004F042`. Both are refusals; only the second one
    /// means "I understood you and declined".
    #[test]
    fn an_unsupported_version_is_invalid_data_not_a_decline() {
        assert_eq!(HResult::InvalidData.to_wire(), 0x8007_000D);
        assert_ne!(HResult::InvalidData, HResult::NotSupportedByKmsServer);
    }

    #[test]
    fn an_unknown_value_survives_rather_than_being_lost() {
        let unknown = HResult::from_wire(0xDEAD_BEEF);
        assert_eq!(unknown, HResult::Other(0xDEAD_BEEF));
        assert_eq!(unknown.to_wire(), 0xDEAD_BEEF);
        assert!(!unknown.is_ok());
    }

    #[test]
    fn only_zero_is_success() {
        assert!(HResult::Ok.is_ok());
        for (result, _) in NAMED {
            assert_eq!(result.is_ok(), result == HResult::Ok, "{result:?}");
        }
    }

    #[test]
    fn every_result_has_text_a_person_can_read() {
        for (result, _) in NAMED {
            assert!(!result.description().is_empty(), "{result:?}");
            let rendered = alloc::format!("{result}");
            assert!(rendered.starts_with("0x"), "{rendered}");
            assert!(rendered.contains(result.description()), "{rendered}");
        }
        assert_eq!(
            alloc::format!("{}", HResult::InvalidData),
            "0x8007000D (the data is invalid)"
        );
    }

    /// The whole `u32` range must decode rather than panic: an HRESULT read
    /// back from a peer is attacker-controlled (`SEC-003`, #195).
    #[test]
    fn every_wire_value_decodes() {
        for raw in [0_u32, 1, u32::MAX, 0x8000_0000, 0xC004_0000] {
            let _ = HResult::from_wire(raw).description();
        }
    }
}
