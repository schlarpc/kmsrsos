//! The generated product tables and the types they are made of
//! (`DB-003`, #127; `DB-015`, #139).
//!
//! Everything here is `static` data in the binary's read-only section. There is
//! no initialisation, no lock, no lazy first-use cost, and no parsing on the
//! request path — py-kms parses an 88 KB XML catalogue twice per activation,
//! which is about 4 ms of pure parsing before it has looked at anything.

use crate::date::Date;
use crate::guid::Guid;

/// What kind of product key a configuration describes.
///
/// Microsoft's own strings are preserved in [`Product::key_type`]; this is the
/// classification the policy layer actually branches on. An unrecognised string
/// stops the build rather than becoming an `Other` nobody notices — see
/// `key_kind` in `build.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// `Volume:CSVLK` — a KMS *host* key. This is what a host installs, and
    /// what an ePID is generated from.
    KmsHost,

    /// `Volume:GVLK` — a KMS *client* key. The generic key every volume-licensed
    /// installation ships with, and the only kind a legitimate KMS client has.
    KmsClient,

    /// `Volume:MAK` — a multiple activation key, activated against Microsoft
    /// rather than against a KMS host.
    MultipleActivation,

    /// `Retail`.
    Retail,

    /// `OEM:DM`, `OEM:NONSLP`, `OEM:SLP`, `OEM:COA`.
    OriginalEquipment,

    /// `Retail:TB:Eval` — a timebombed evaluation edition.
    Evaluation,

    /// A key type this codebase does not model, with the raw string kept in
    /// [`Product::key_type`].
    ///
    /// Currently `VT:IA` and `PGS:TB`, seen on some Windows Server entries.
    /// Neither appears in any KMS counted-ID list, so nothing in the protocol
    /// turns on them and guessing at their meaning would be worse than saying
    /// so.
    Other,
}

impl KeyKind {
    /// Whether this is a volume-licensing key type.
    ///
    /// The distinction the product gate is built on (`POL-010`, #98): a retail
    /// or OEM SKU has no GVLK, so no legitimate client can present one to a KMS
    /// host.
    #[must_use]
    pub const fn is_volume(self) -> bool {
        matches!(
            self,
            Self::KmsHost | Self::KmsClient | Self::MultipleActivation
        )
    }
}

/// A KMS application: Windows, Office 2010, or Office 2013 and later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Application {
    /// The GUID a client sends in the request's `AppID` field.
    pub guid: Guid,
    /// A human-readable name (`DB-014`, #138).
    ///
    /// vlmcsd's stock build links a compact database with `SkuItemCount = 0`,
    /// where every name points at one shared "Unknown" string — so every SKU
    /// logs as `Unknown` and the log is useless for the one thing an operator
    /// wants from it.
    pub name: &'static str,
}

/// One block of a key-ID range (`ID-019`, #124).
///
/// Blocks, not a min/max pair. Windows Server 2022's host key has two valid
/// blocks with an invalid hole between them, and Windows 10's have as many as
/// three; a min/max model draws key IDs that no genuine host would ever emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBlock {
    /// First key ID in the block, inclusive.
    pub start: u32,
    /// Last key ID in the block, inclusive.
    pub end: u32,
}

impl KeyBlock {
    /// How many key IDs the block contains.
    ///
    /// Never zero, because `start <= end` is asserted at build time — which is
    /// what stops the ePID key-ID draw dividing by zero (`ID-015`, #120). Named
    /// `key_count` rather than `len` for exactly that reason: a block has no
    /// empty case, so the `len`/`is_empty` pairing would be misleading.
    #[must_use]
    pub const fn key_count(self) -> u32 {
        // `end >= start` is a build-time invariant, so the subtraction cannot
        // wrap; saturating rather than checked keeps this `const`.
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Whether a key ID falls inside this block.
    #[must_use]
    pub const fn contains(self, key_id: u32) -> bool {
        self.start <= key_id && key_id <= self.end
    }
}

/// One product key configuration, as Microsoft's `pkeyconfig` describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    /// `ActConfigId`. A client sends this as the request's `ActID`, and a KMS
    /// host reads it and then ignores it (`KMS-018`, #34).
    pub activation_id: Guid,
    /// `RefGroupId`, which appears in a generated ePID (`ID-003`, #108).
    pub group_id: u32,
    /// The classification the policy layer branches on.
    pub kind: KeyKind,
    /// Microsoft's own key-type string, kept verbatim for logging.
    pub key_type: &'static str,
    /// Microsoft's edition identifier.
    pub edition_id: &'static str,
    /// Microsoft's product description — the human-readable name.
    pub description: &'static str,
    /// The application this product belongs to, where the source said so.
    pub application: Option<Guid>,
}

impl Product {
    /// Whether this SKU is a server edition (`DB-012`, #136).
    ///
    /// Derived from Microsoft's own `EditionId` rather than carried as a
    /// column, because it is a *function* of data already here and a column
    /// would be a second place for it to be wrong. Every server edition
    /// identifier Microsoft ships begins with `Server` — `ServerDatacenter`,
    /// `ServerStandard`, `ServerRdsh`, `ServerSolution` — and a multi-edition
    /// row lists them separated by semicolons.
    ///
    /// vlmcsd calls the equivalent flag `MayBeServer` and the name is apt: it
    /// says a request for this SKU *may* come from a server, not that it did.
    /// Nothing refuses on it; it selects the client count a real client would
    /// declare (see [`crate::required_clients`]).
    #[must_use]
    pub fn may_be_server(&self) -> bool {
        self.edition_id
            .split(';')
            .any(|edition| edition.trim_start().starts_with("Server"))
    }

    /// Whether this SKU is a pre-release build (`DB-012`, #136;
    /// `POL-010`, #98).
    ///
    /// Derived from Microsoft's `ProductDescription`, which marks them in
    /// plain text — `Windows Server Next Beta ServerRdsh`, and so on.
    ///
    /// py-kms carries this as a hand-entered `IsPreview` attribute on nine of
    /// its several hundred rows, which is both incomplete and unverifiable.
    /// Reading Microsoft's own description instead means the flag tracks
    /// whatever the pipeline extracts, with no catalogue to fall out of date.
    #[must_use]
    pub fn is_preview(&self) -> bool {
        const MARKERS: [&str; 4] = ["Beta", "Pre-Release", "Prerelease", "Preview"];
        MARKERS
            .iter()
            .any(|marker| contains_ignoring_case(self.description, marker))
    }
}

/// Whether `haystack` contains `needle`, ignoring ASCII case.
///
/// `core` has no case-insensitive substring search and this crate has no
/// dependencies, so it is written out. The inputs are short and this runs at
/// most a few hundred times.
fn contains_ignoring_case(haystack: &str, needle: &str) -> bool {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    let Some(last_start) = haystack.len().checked_sub(needle.len()) else {
        return false;
    };
    (0..=last_start).any(|start| {
        haystack
            .get(start..start.saturating_add(needle.len()))
            .is_some_and(|window| {
                window
                    .iter()
                    .zip(needle.iter())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
    })
}

/// A KMS host key, with what it can activate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Csvlk {
    /// `ActConfigId`, matching a [`Product`] with [`KeyKind::KmsHost`].
    pub activation_id: Guid,
    /// The group ID that appears in a generated ePID.
    pub group_id: u32,
    /// The human-readable name.
    pub description: &'static str,
    /// The application this host key serves.
    pub application: Option<Guid>,
    /// Valid key-ID blocks, sorted and non-overlapping.
    pub key_blocks: &'static [KeyBlock],
    /// The KMS counted IDs a host holding this key will count
    /// (`DB-008`, #132).
    pub counted_ids: &'static [Guid],
}

/// A KMS counted ID, and the host keys that count it.
///
/// This is the value a request's `KMSID` field carries, and it is what a KMS
/// host actually decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CountedId {
    /// The GUID a client sends.
    pub guid: Guid,
    /// Indices into [`CSVLKS`] of every host key that counts this product.
    pub csvlks: &'static [u16],
}

/// A Windows build a generated ePID may claim (`DB-011`, #135).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostBuild {
    /// The build number, as it appears in an ePID.
    pub build: u32,
    /// The platform identifier this build reports (`ID-009`, #114).
    ///
    /// 3612 for every build from 10240 onwards — a finding corroborated by two
    /// genuine ePIDs from real machines, and one that appears in no published
    /// Microsoft document.
    pub platform_id: u32,
    /// Release date, the lower bound for a randomised activation date
    /// (`ID-007`, #112).
    ///
    /// Present exactly where [`Self::use_for_epid`] is set; the build asserts
    /// that pairing, because a build with no date cannot produce an ePID.
    pub release_date: Option<Date>,
    /// Whether an ePID may claim this build.
    pub use_for_epid: bool,
    /// Whether this build speaks NDR64 (`ID-010`, #115).
    ///
    /// Advertising a build and then refusing its transfer syntax is a
    /// combination no real host produces — py-kms claims build 17763 while
    /// rejecting NDR64 — so the two travel together rather than being
    /// configured separately.
    pub ndr64: bool,
    /// What the build is, for the log and the web UI.
    pub description: &'static str,
}

/// A locale identifier a generated ePID may carry (`ID-008`, #113).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lcid {
    /// The numeric identifier, emitted **unpadded** (`ID-005`, #110).
    pub value: u32,
    /// The BCP 47 language tag, for the log.
    pub tag: &'static str,
    /// The language name.
    pub language: &'static str,
    /// The region name.
    pub location: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/tables.rs"));
