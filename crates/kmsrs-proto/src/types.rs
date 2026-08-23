//! Parse-don't-validate newtypes for every wire value (`ARCH-007`, #7).
//!
//! The KMS request carries four GUIDs in a row and two more values that are
//! both `u32`. Passing them around as `Guid` and `u32` means the compiler
//! cannot tell you when two of them are swapped, and swapping the SKU ID with
//! the KMS counted ID produces a server that answers plausibly and wrongly —
//! which is the shape of most of the defects in the audits.
//!
//! So each is its own type. The cost is a wrapper; what it buys is that the
//! only way to get a [`KmsCountedId`] is to read the field that holds one.
//!
//! # The one that matters most
//!
//! [`CsvlkSelection`] distinguishes `Resolved` from `Fallback` as separate
//! variants. vlmcsd conflates them — its unknown-product fallback *is* CSVLK
//! index 0 — and the consequence is that nobody, including its maintainers, can
//! tell whether its Office 2013 Preview mapping is deliberate or vestigial. A
//! value that means both "this is the right answer" and "I had no answer"
//! destroys the information needed to review it later.

use crate::time::FileTime;
use arrayvec::ArrayString;
use kmsrs_db::Guid;

/// Maximum UCS-2 code units in a workstation name, as the request field holds.
pub const WORKSTATION_NAME_UNITS: usize = 64;

/// Bytes of UTF-8 a [`WorkstationName`] can need.
///
/// Every BMP code point encodes in at most three UTF-8 bytes, and an unpaired
/// surrogate becomes U+FFFD, which is also three. A surrogate *pair* is two
/// units producing at most four bytes, so it cannot exceed this bound either.
pub const WORKSTATION_NAME_BYTES: usize = WORKSTATION_NAME_UNITS * 3;

/// Which application a request is about: Windows, Office 2010, or Office 2013
/// and later.
///
/// This is what selects the counting bucket (`POL-002`, #90). It is also half
/// of the product gate: an application that does not match the counted ID's is
/// refused, because no legitimate client sends that combination
/// (`POL-010`, #98).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApplicationId(pub Guid);

/// The request's `ActID`: the most detailed product identifier there is, one
/// per product key.
///
/// **A KMS host reads this and ignores it** (`KMS-018`, #34). It is here for
/// the event log, so an operator sees *Windows Server 2025 Datacenter* rather
/// than a raw GUID, and for nothing else. A genuine host activates SKUs it has
/// never heard of, and a policy that read this field would not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkuId(pub Guid);

/// The request's `KMSID`.
///
/// This is what a KMS host actually decides on: it drives grant or refuse and
/// it drives which host key's ePID comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KmsCountedId(pub Guid);

/// A client machine ID — the identity a host counts.
///
/// Client-chosen and freely regenerated: `vlmcs` makes a fresh one per request
/// by default. Anything that tries to use this as a durable identity is
/// building on sand, which is why per-client quotas were declined (D14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientMachineId(pub Guid);

impl ClientMachineId {
    /// The previous-CMID field, which is all zeros when it has never changed.
    ///
    /// Returning `Option` rather than a zero GUID means a caller cannot
    /// accidentally treat "never changed" as a machine that identifies itself
    /// as all zeros.
    #[must_use]
    pub fn previous(guid: Guid) -> Option<Self> {
        if guid == Guid::ZERO {
            None
        } else {
            Some(Self(guid))
        }
    }
}

/// The minimum client count a product's policy requires.
///
/// 25 for Windows client SKUs, 5 for server and Office. It arrives *from the
/// client*, which is why the reported count is computed per request and never
/// written back (`POL-001`, #89).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequiredClients(pub u32);

/// A Windows locale identifier, as it appears in an ePID.
///
/// Emitted unpadded (`ID-005`, #110). Practically moot — every LCID a real host
/// can report is at least 1025 — but License Manager's ePID parser accepts
/// `^[0-9]{1,5}$`, so padding it would be a difference from a genuine host for
/// no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lcid(pub u32);

/// A Windows build number, as it appears in an ePID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BuildNumber(pub u32);

/// The platform identifier an ePID reports for a build.
///
/// 3612 for every build from 10240 onwards, corroborated by two genuine ePIDs
/// from real machines (`DB-011`, #135).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlatformId(pub u32);

/// A CSVLK group identifier, as it appears in an ePID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub u32);

/// A key identifier drawn from a host key's blocks, as it appears in an ePID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(pub u32);

/// The eight-byte hardware identifier a v6 response carries (`ID-012`, #117).
///
/// Only v6 carries it (`ID-018`, #123). Shipping a constant here is one of the
/// canonical detection tests, so it is drawn from the CSPRNG once per process
/// (`ID-013`, #118).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HardwareId(pub [u8; 8]);

/// The size a response declares for its ePID field, in bytes.
///
/// `(units + 1) * 2`, counting the terminating NUL, capped at 128 — the field
/// is 64 UCS-2 units and there is no way to say otherwise (`KMS-011`, #27).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PidSize(u32);

impl PidSize {
    /// The largest value the field can legally carry: 64 units, including NUL.
    pub const MAX: Self = Self(128);

    /// The size a name of `units` UCS-2 code units declares, including its NUL.
    ///
    /// Returns `None` if the name does not fit the field. vlmcsd validates this
    /// on the *client* side and never bounds what its server emits, so a
    /// misconfigured ePID produces a response no client can parse.
    #[must_use]
    pub fn for_units(units: usize) -> Option<Self> {
        // The terminating NUL counts, so 63 units is the practical maximum.
        if units >= WORKSTATION_NAME_UNITS {
            return None;
        }
        let with_nul = units.checked_add(1)?;
        let bytes = with_nul.checked_mul(2)?;
        // `bytes` is at most 128 here, so the conversion is total; `as` is
        // unavailable in this crate by design.
        u32::try_from(bytes).ok().map(Self)
    }

    /// The value as it goes on the wire.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Which host key an ePID was generated from (`ARCH-007`, #7).
///
/// The distinction between the two variants is the whole point. vlmcsd's
/// unknown-product fallback *is* CSVLK index 0, so `Resolved(0)` and `Fallback`
/// are the same value there — and once they are the same value, no later reader
/// can tell a deliberate mapping from a vestigial one. Its Office 2013 Preview
/// entry is the case where that ambiguity actually bit: the audit could only
/// record that nobody knows which it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CsvlkSelection {
    /// The database named a host key for this product.
    Resolved {
        /// Index into `kmsrs_db::CSVLKS`.
        index: u16,
    },

    /// No host key in the database counts this product, so one was chosen by
    /// policy.
    ///
    /// This is the normal answer for a product newer than the build's data, and
    /// it must stay an activation rather than a refusal — refusing an unknown
    /// KMS ID is why py-kms fails on GUIDs it has not seen, and not refusing it
    /// is why a 2019-era vlmcsd still activates Windows 11 (`POL-010`, #98).
    Fallback {
        /// Index into `kmsrs_db::CSVLKS` of the key actually used.
        index: u16,
    },
}

impl CsvlkSelection {
    /// The host key index, whichever way it was arrived at.
    #[must_use]
    pub const fn index(self) -> u16 {
        match self {
            Self::Resolved { index } | Self::Fallback { index } => index,
        }
    }

    /// Whether the database actually knew this product.
    ///
    /// The event log records this, because "activated, product unknown to this
    /// build" is a different operational fact from "activated" and an operator
    /// deciding whether to update should be able to see it.
    #[must_use]
    pub const fn was_resolved(self) -> bool {
        matches!(self, Self::Resolved { .. })
    }
}

/// A client's workstation name, decoded for logging (`KMS-019`, #35).
///
/// Bounded and lossy, and **never trusted**. It is client-supplied text with no
/// authentication behind it, so it may not be used for access control — the two
/// forks that tried produced a v6-bypassable gate and a `sys.exit(0)` from
/// inside a request handler that took the whole server down while logging a
/// bind failure (declined item D28).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkstationName(ArrayString<WORKSTATION_NAME_BYTES>);

impl WorkstationName {
    /// Decode the request's fixed 64-unit UCS-2 field.
    ///
    /// Total by construction: it stops at the first NUL, replaces unpaired
    /// surrogates with U+FFFD, and cannot run past the field. py-kms's
    /// equivalent computes a negative length for a name longer than 126 bytes
    /// and hands it to `struct.unpack`, and vlmcsd's `ServiceInstaller` shows
    /// the other half of the same mistake — `strcat` into a fixed buffer with
    /// no bound (`SEC-002`, #194). A field that arrives full and unterminated
    /// is the wire equivalent, and it stops at the field.
    #[must_use]
    pub fn decode(units: &[u16; WORKSTATION_NAME_UNITS]) -> Self {
        let terminated = units.split(|unit| *unit == 0).next().unwrap_or(&[]);
        let mut decoded = ArrayString::new();
        for character in char::decode_utf16(terminated.iter().copied()) {
            let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
            // The capacity is computed to fit the worst case, so this cannot
            // fail. Stopping keeps the function total if it ever does, and is
            // written out rather than discarded so the discarded form can be
            // forbidden outright (`SEC-012`, #204).
            if decoded.try_push(character).is_err() {
                break;
            }
        }
        Self(decoded)
    }

    /// The decoded name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether the client sent an empty name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Display for WorkstationName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the client says it is running in a virtual machine
/// (`KMS-017`, #33).
///
/// Parsed and surfaced in the event log; **no policy path reads it**. A genuine
/// host does not refuse virtual machines, and a host that did would be trivially
/// distinguishable from one that did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKind {
    /// The client reports bare metal.
    BareMetal,
    /// The client reports a virtual machine.
    VirtualMachine,
    /// The client sent something other than 0 or 1.
    ///
    /// Kept rather than normalised, because an unexpected value here is worth
    /// seeing in a log and is never worth refusing over.
    Unrecognised(u32),
}

impl ClientKind {
    /// Decode the wire value.
    #[must_use]
    pub const fn from_wire(value: u32) -> Self {
        match value {
            0 => Self::BareMetal,
            1 => Self::VirtualMachine,
            other => Self::Unrecognised(other),
        }
    }
}

/// How long the client says remains in its current licensing state, in minutes
/// (`KMS-017`, #33).
///
/// Logged, never a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GraceMinutes(pub u32);

/// The two intervals a response tells a client to use (`KMS-021`, #37).
///
/// The one place all three implementations agree, and it matches Microsoft's
/// documented defaults: two hours to retry a failed activation, seven days to
/// renew a successful one. Modern clients — 8.1 and later — ignore both and use
/// their own schedule, which is why getting them wrong has gone unnoticed
/// elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Intervals {
    /// Minutes before a client that failed should try again.
    pub activation: u32,
    /// Minutes before a client that succeeded should renew.
    pub renewal: u32,
}

impl Intervals {
    /// Microsoft's documented defaults: 120 and 10,080 minutes.
    pub const DEFAULT: Self = Self {
        activation: 120,
        renewal: 10_080,
    };
}

/// A request's timestamp, and the response's, which is the same value.
///
/// Echoed verbatim (`KMS-012`, #28). It is also the input to the v6 key
/// derivation, which is why the server needs no accurate clock of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientTime(pub FileTime);

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        ClientKind, ClientMachineId, CsvlkSelection, Intervals, PidSize, WORKSTATION_NAME_UNITS,
        WorkstationName,
    };
    use kmsrs_db::Guid;

    fn units(text: &str) -> [u16; WORKSTATION_NAME_UNITS] {
        let mut field = [0_u16; WORKSTATION_NAME_UNITS];
        for (slot, unit) in field.iter_mut().zip(text.encode_utf16()) {
            *slot = unit;
        }
        field
    }

    #[test]
    fn a_workstation_name_stops_at_the_first_nul() {
        let mut field = units("host-a");
        field[10] = u16::from(b'X');
        assert_eq!(WorkstationName::decode(&field).as_str(), "host-a");
    }

    #[test]
    fn a_full_length_workstation_name_is_kept_whole() {
        let long: alloc::string::String =
            core::iter::repeat_n('w', WORKSTATION_NAME_UNITS).collect();
        let decoded = WorkstationName::decode(&units(&long));
        assert_eq!(decoded.as_str().chars().count(), WORKSTATION_NAME_UNITS);
    }

    /// `KMS-019` (#35). py-kms computes a negative length here and hands it to
    /// `struct.unpack`; the field is fixed-size, so there is nothing to compute.
    #[test]
    fn a_hostile_workstation_name_decodes_rather_than_failing() {
        // An unpaired high surrogate, which is not valid UTF-16.
        let mut field = [0_u16; WORKSTATION_NAME_UNITS];
        field[0] = 0xD800;
        field[1] = u16::from(b'a');
        let decoded = WorkstationName::decode(&field);
        assert_eq!(decoded.as_str(), "\u{FFFD}a");

        // Every unit set, no NUL anywhere: the field must still terminate.
        let decoded = WorkstationName::decode(&[0xFFFF; WORKSTATION_NAME_UNITS]);
        assert_eq!(decoded.as_str().chars().count(), WORKSTATION_NAME_UNITS);

        // Three-byte characters at full length: the worst case for capacity.
        let decoded = WorkstationName::decode(&[0x4E00; WORKSTATION_NAME_UNITS]);
        assert_eq!(decoded.as_str().len(), WORKSTATION_NAME_UNITS * 3);

        // A surrogate pair, which is two units and one character.
        let mut field = [0_u16; WORKSTATION_NAME_UNITS];
        field[0] = 0xD83D;
        field[1] = 0xDE00;
        assert_eq!(WorkstationName::decode(&field).as_str(), "\u{1F600}");

        assert!(WorkstationName::decode(&[0; WORKSTATION_NAME_UNITS]).is_empty());
    }

    /// `ARCH-007` (#7): the distinction vlmcsd cannot make.
    #[test]
    fn a_fallback_selection_is_not_the_same_value_as_resolving_to_index_zero() {
        let resolved = CsvlkSelection::Resolved { index: 0 };
        let fallback = CsvlkSelection::Fallback { index: 0 };

        assert_ne!(resolved, fallback);
        assert_eq!(resolved.index(), fallback.index());
        assert!(resolved.was_resolved());
        assert!(!fallback.was_resolved());
    }

    /// `KMS-011` (#27): the response's PID size counts the terminating NUL and
    /// cannot exceed the field.
    #[test]
    fn pid_size_counts_the_nul_and_refuses_to_overflow_the_field() {
        assert_eq!(PidSize::for_units(0).unwrap().get(), 2);
        assert_eq!(PidSize::for_units(1).unwrap().get(), 4);
        assert_eq!(PidSize::for_units(48).unwrap().get(), 98);
        assert_eq!(PidSize::for_units(63).unwrap().get(), 128);
        assert_eq!(PidSize::for_units(63).unwrap(), PidSize::MAX);

        // 64 units plus a NUL does not fit a 64-unit field.
        assert_eq!(PidSize::for_units(64), None);
        assert_eq!(PidSize::for_units(usize::MAX), None);
    }

    #[test]
    fn a_zero_previous_machine_id_means_it_never_changed() {
        assert_eq!(ClientMachineId::previous(Guid::ZERO), None);
        let changed = Guid::from_bytes([1; 16]);
        assert_eq!(
            ClientMachineId::previous(changed),
            Some(ClientMachineId(changed))
        );
    }

    /// `KMS-017` (#33): an unexpected value is kept for the log, not refused.
    #[test]
    fn an_unrecognised_client_kind_is_kept_rather_than_normalised() {
        assert_eq!(ClientKind::from_wire(0), ClientKind::BareMetal);
        assert_eq!(ClientKind::from_wire(1), ClientKind::VirtualMachine);
        assert_eq!(
            ClientKind::from_wire(0xFFFF_FFFF),
            ClientKind::Unrecognised(0xFFFF_FFFF)
        );
    }

    /// `KMS-021` (#37): Microsoft's documented defaults, which is also the one
    /// value all three implementations agree on.
    #[test]
    fn the_default_intervals_are_two_hours_and_seven_days() {
        assert_eq!(Intervals::DEFAULT.activation, 120);
        assert_eq!(Intervals::DEFAULT.renewal, 10_080);
        assert_eq!(Intervals::DEFAULT.renewal, 7 * 24 * 60);
    }
}
