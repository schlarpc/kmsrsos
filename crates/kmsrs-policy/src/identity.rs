//! Host identity: the ePID and hardware ID a response carries
//! (`ID-001`, #106 … `ID-019`, #124).
//!
//! # Generated once, at start-up
//!
//! Every value here is drawn when [`HostIdentity::generate`] runs and never
//! again. There is no path that regenerates one, because the generator is a
//! constructor and the accessors take `&self`.
//!
//! That is MM01, "the canonical emulator-detection test". py-kms regenerates on
//! every response, so two byte-identical requests on one TCP connection come
//! back with different ePIDs — something no real host has ever done. The same
//! property is why this service cannot be deployed with more than one replica:
//! each pod would draw its own identity and a client load-balanced across them
//! would see the test fail at the infrastructure layer instead (`PKG-011`,
//! #248).
//!
//! # What is shared and what is per-group
//!
//! The locale and the host build are drawn **once and shared** across every
//! host key (`ID-008`, #113; `ID-009`, #114). That is what makes a set of ePIDs
//! from one host look self-consistent: a machine has one locale and one build,
//! and a host whose Office ePID claimed a different Windows build from its
//! Windows ePID would be visibly two machines. vlmcsd's `-r1` does this
//! deliberately.
//!
//! The key ID, the activation date and the hardware ID are **per host key**,
//! because a real deployment installs each host key separately and each was
//! issued its own key ID.

use crate::error::EntropyUnavailable;
use alloc::format;
use alloc::vec::Vec;
use core::num::NonZeroU32;
use kmsrs_db::{Csvlk, Date, HostBuild, Lcid};
use kmsrs_proto::entropy::{Entropy, EntropyExt as _};
use kmsrs_proto::kms::epid::EPid;
use kmsrs_proto::types::{ApplicationId, CsvlkSelection, HardwareId, KmsCountedId};

/// The licence channel every genuine ePID carries (`ID-006`, #111).
///
/// `00` and `01` are retail, `02` is OEM, `03` is volume — and a KMS host is by
/// definition activating volume-licensed clients, so nothing else can appear
/// here. A literal rather than a computed value, because there is no input that
/// could change it.
pub const LICENSE_CHANNEL: &str = "03";

/// The identity a single host key presents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupIdentity {
    /// The ePID for this host key, generated once.
    pub epid: EPid,
    /// The hardware ID for this host key (`ID-012`, #117).
    pub hardware_id: HardwareId,
    /// The key ID drawn from the host key's blocks.
    pub key_id: u32,
    /// The activation date this identity claims.
    pub activated: Date,
}

/// Everything this host claims about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    lcid: &'static Lcid,
    build: &'static HostBuild,
    /// One entry per host key, in `kmsrs_db::CSVLKS` order.
    groups: Vec<GroupIdentity>,
}

impl HostIdentity {
    /// Draw an identity for this process.
    ///
    /// `today` is the upper bound for the randomised activation date, and comes
    /// from the platform's wall clock — the only place in the request path that
    /// reads one, and one whose accuracy nothing depends on (`ARCH-004`, #4).
    ///
    /// # Errors
    ///
    /// Returns [`EntropyUnavailable`] if the source failed. A host that cannot
    /// draw randomness must not serve: every value here would otherwise be a
    /// constant, and constants are what the detection tests look for
    /// (`OS-012`, #263).
    pub fn generate(entropy: &mut dyn Entropy, today: Date) -> Result<Self, EntropyUnavailable> {
        let lcid = draw_lcid(entropy)?;
        let build = draw_host_build(entropy)?;

        let mut groups = Vec::with_capacity(kmsrs_db::CSVLKS.len());
        for csvlk in &kmsrs_db::CSVLKS {
            groups.push(generate_group(entropy, csvlk, build, lcid, today)?);
        }

        Ok(Self {
            lcid,
            build,
            groups,
        })
    }

    /// The locale every ePID from this host reports.
    #[must_use]
    pub const fn lcid(&self) -> &'static Lcid {
        self.lcid
    }

    /// The Windows build every ePID from this host claims.
    #[must_use]
    pub const fn host_build(&self) -> &'static HostBuild {
        self.build
    }

    /// Whether this host advertises NDR64 (`ID-010`, #115).
    ///
    /// Derived from the claimed build rather than configured beside it, so
    /// "build 26100 but no NDR64" — a combination no real host produces, and
    /// one py-kms emits — cannot be expressed.
    #[must_use]
    pub const fn advertises_ndr64(&self) -> bool {
        self.build.ndr64
    }

    /// The identity to answer a request with (`ID-002`, #107).
    ///
    /// # How the host key is chosen
    ///
    /// Among the host keys that count this product, the one that counts the
    /// **fewest** products wins. That is the most specific key for the request:
    /// Office LTSC 2024's host key counts exactly one product, while Windows
    /// Server 2025's counts twenty-two, so an Office request gets the Office
    /// key. It also settles the Azure-only and Internal-Lab variants for free —
    /// they count *more* products than the general key, so the general key is
    /// always preferred.
    ///
    /// py-kms instead appends a Server 2019 fallback for every **non**-matching
    /// entry and then `random.choice`s over the whole list. Measured at
    /// 4887/5000 wrong for Office 2010 — a rate only counting can find, which
    /// is why `TEST-008` (#229) asserts it statistically rather than by
    /// example, and it can emit impossible combinations
    /// such as group 00096 with build 17763. The audit calls fixing this the
    /// highest-value single finding in the fork network, and it is still
    /// unfixed upstream.
    #[must_use]
    pub fn select(
        &self,
        application: ApplicationId,
        counted: KmsCountedId,
    ) -> (CsvlkSelection, &GroupIdentity) {
        let candidates = kmsrs_db::csvlks_counting(counted.0);

        let resolved = candidates
            .iter()
            .filter_map(|index| {
                let csvlk = kmsrs_db::csvlk_at(*index)?;
                Some((*index, csvlk))
            })
            .min_by_key(|(index, csvlk)| (csvlk.counted_ids.len(), *index));

        if let Some((index, _)) = resolved
            && let Some(identity) = self.groups.get(usize::from(index))
        {
            return (CsvlkSelection::Resolved { index }, identity);
        }

        // Unknown product. Answering anyway is the whole point of the
        // permissive half of the product gate (`POL-010`, #98): refusing an
        // unknown KMS ID is why py-kms fails on GUIDs it has not seen, and not
        // refusing it is why a 2019-era vlmcsd still activates Windows 11.
        let (index, identity) = self.fallback(application);
        (CsvlkSelection::Fallback { index }, identity)
    }

    /// The host key to answer with when the product is unknown.
    ///
    /// The most general key for the request's application: among that
    /// application's host keys, the one counting the most products, which is
    /// the one a real deployment would have installed to cover the widest
    /// range. Falling back within the right application matters — an Office
    /// client handed a Windows group ID would be visibly wrong.
    fn fallback(&self, application: ApplicationId) -> (u16, &GroupIdentity) {
        let best = kmsrs_db::CSVLKS
            .iter()
            .enumerate()
            .filter(|(_, csvlk)| csvlk.application == Some(application.0))
            .max_by_key(|(index, csvlk)| (csvlk.counted_ids.len(), core::cmp::Reverse(*index)))
            .or_else(|| kmsrs_db::CSVLKS.iter().enumerate().next());

        match best {
            Some((index, _)) => {
                let index = u16::try_from(index).unwrap_or(0);
                match self.groups.get(usize::from(index)) {
                    Some(identity) => (index, identity),
                    // Unreachable: `groups` has one entry per host key, and the
                    // build asserts the table is non-empty.
                    None => (0, self.any_group()),
                }
            }
            None => (0, self.any_group()),
        }
    }

    /// The first group, for the paths a non-empty table makes unreachable.
    fn any_group(&self) -> &GroupIdentity {
        self.groups.first().unwrap_or_else(|| unreachable_group())
    }
}

/// A `const`-promoted placeholder for a case the database's build-time
/// non-emptiness assertion makes unreachable.
fn unreachable_group() -> &'static GroupIdentity {
    // `CSVLKS` is asserted non-empty at compile time, so `groups` is never
    // empty and this is never called. It exists so the accessor is total
    // without an `unwrap`.
    static EMPTY: &[GroupIdentity] = &[];
    #[expect(
        clippy::indexing_slicing,
        reason = "unreachable: the database asserts CSVLKS is non-empty at compile time"
    )]
    &EMPTY[0]
}

/// Draw the locale, once (`ID-008`, #113).
fn draw_lcid(entropy: &mut dyn Entropy) -> Result<&'static Lcid, EntropyUnavailable> {
    let count = u32::try_from(kmsrs_db::lcid_count()).unwrap_or(1);
    let bound = NonZeroU32::new(count).ok_or(EntropyUnavailable)?;
    let index = entropy
        .uniform_below(bound)
        .map_err(|_| EntropyUnavailable)?;
    kmsrs_db::lcid_at(index.try_into().unwrap_or(0)).ok_or(EntropyUnavailable)
}

/// Draw the host build, once (`ID-009`, #114; `ID-011`, #116).
///
/// The set is non-empty by construction — the database's build fails if it
/// would be empty — which is why this cannot loop. vlmcsd's equivalent is a
/// `while (TRUE)` that hangs at start-up when no build matches its
/// configuration.
/// Draw the build this host claims to be running.
///
/// Uniform over the whole table, which is the property `TEST-008` (#229)
/// counts: the Organization fork emits 17763 in 2000 of 2000 generations, and
/// every ePID it produces is individually well-formed. What gives it away is
/// the distribution, which no single sample can show.
fn draw_host_build(entropy: &mut dyn Entropy) -> Result<&'static HostBuild, EntropyUnavailable> {
    let count = u32::try_from(kmsrs_db::epid_host_build_count()).unwrap_or(1);
    let bound = NonZeroU32::new(count).ok_or(EntropyUnavailable)?;
    let index = entropy
        .uniform_below(bound)
        .map_err(|_| EntropyUnavailable)?;
    kmsrs_db::epid_host_build_at(index.try_into().unwrap_or(0)).ok_or(EntropyUnavailable)
}

/// Draw one host key's identity.
fn generate_group(
    entropy: &mut dyn Entropy,
    csvlk: &'static Csvlk,
    build: &'static HostBuild,
    lcid: &'static Lcid,
    today: Date,
) -> Result<GroupIdentity, EntropyUnavailable> {
    let key_id = draw_key_id(entropy, csvlk)?;
    let activated = draw_activation_date(entropy, build, today)?;
    let hardware_id = HardwareId(entropy.array::<8>().map_err(|_| EntropyUnavailable)?);

    let epid = format_epid(build, csvlk, key_id, lcid, activated);
    let epid = EPid::parse(&epid).map_err(|_| EntropyUnavailable)?;

    Ok(GroupIdentity {
        epid,
        hardware_id,
        key_id,
        activated,
    })
}

/// Draw a key ID uniformly across the union of a host key's blocks
/// (`ID-019`, #124).
///
/// Across the *union*, not within a single block: Windows Server 2022's host
/// key has two valid blocks with an invalid hole between them, and Windows 10's
/// have as many as three. Drawing between a minimum and a maximum — which is
/// what py-kms does — emits key IDs inside the hole, values no genuine host can
/// produce.
fn draw_key_id(
    entropy: &mut dyn Entropy,
    csvlk: &'static Csvlk,
) -> Result<u32, EntropyUnavailable> {
    let total: u64 = csvlk
        .key_blocks
        .iter()
        .map(|block| u64::from(block.key_count()))
        .sum();

    // Every real host key's blocks total well under `u32::MAX`; the conversion
    // failing would mean a database far outside anything Microsoft ships.
    let total = u32::try_from(total).unwrap_or(u32::MAX);
    let bound = NonZeroU32::new(total).ok_or(EntropyUnavailable)?;
    let mut offset = entropy
        .uniform_below(bound)
        .map_err(|_| EntropyUnavailable)?;

    for block in csvlk.key_blocks {
        let width = block.key_count();
        if offset < width {
            return Ok(block.start.saturating_add(offset));
        }
        offset = offset.saturating_sub(width);
    }

    // Unreachable: `offset` is below the total, so some block claims it.
    csvlk
        .key_blocks
        .first()
        .map(|block| block.start)
        .ok_or(EntropyUnavailable)
}

/// Draw an activation date between the build's release and today
/// (`ID-007`, #112).
///
/// In UTC, because [`Date`] has no other option — py-kms uses `time.mktime` on
/// local time, so its day-of-year depends on the server's timezone and on
/// whether daylight saving was in effect.
///
/// A release date in the future — a stale build, or a clock that has not been
/// set — collapses the span to a single day rather than dividing by zero, which
/// is what vlmcsd does when a release date equals now (`ID-015`, #120).
fn draw_activation_date(
    entropy: &mut dyn Entropy,
    build: &'static HostBuild,
    today: Date,
) -> Result<Date, EntropyUnavailable> {
    let Some(release) = build.release_date else {
        // The database asserts that every drawable build has one.
        return Err(EntropyUnavailable);
    };

    let span = today
        .days_since_epoch()
        .saturating_sub(release.days_since_epoch());
    let span = u32::try_from(span).unwrap_or(0);

    let offset = entropy
        .uniform_in_inclusive_range(0, span)
        .map_err(|_| EntropyUnavailable)?;
    let days = release
        .days_since_epoch()
        .saturating_add(i32::try_from(offset).unwrap_or(0));
    Ok(Date::from_days_since_epoch(days))
}

/// Render an ePID (`ID-003`, #108).
///
/// `PPPPP-GGGGG-KKK-KKKKKK-CC-LLLL-BBBBB.0000-DDDYYYY`, with the field widths
/// the issue specifies:
///
/// * `PlatformId` and `GroupId` zero-padded to five digits.
/// * The key ID split into `keyId / 1000000` at three digits and
///   `keyId % 1000000` at six.
/// * The licence channel a literal `03` (`ID-006`, #111).
/// * The **LCID unpadded** (`ID-005`, #110) — three implementations agree, and
///   License Manager's parser accepts `^[0-9]{1,5}$`. Moot in practice, since
///   every LCID a real host reports is at least 1025, but padding it would
///   differ from a genuine host for no reason.
/// * The build unpadded with a literal `.0000`.
/// * The day of year at three digits, **1-based** (`ID-004`, #109), and the
///   year at four.
fn format_epid(
    build: &'static HostBuild,
    csvlk: &'static Csvlk,
    key_id: u32,
    lcid: &'static Lcid,
    activated: Date,
) -> alloc::string::String {
    let key_high = key_id.checked_div(1_000_000).unwrap_or(0);
    let key_low = key_id.checked_rem(1_000_000).unwrap_or(0);
    format!(
        "{:05}-{:05}-{:03}-{:06}-{}-{}-{}.0000-{:03}{:04}",
        build.platform_id,
        csvlk.group_id,
        key_high,
        key_low,
        LICENSE_CHANNEL,
        lcid.value,
        build.build,
        activated.day_of_year(),
        activated.year()
    )
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

    use super::{HostIdentity, LICENSE_CHANNEL};
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use kmsrs_db::{Date, Guid};
    use kmsrs_proto::entropy::testing::{DeterministicEntropy, FailingEntropy};
    use kmsrs_proto::types::{ApplicationId, CsvlkSelection, KmsCountedId};

    const WINDOWS: &str = "55c92734-d682-4d71-983e-d6ec3f16059f";
    const OFFICE: &str = "0ff1ce15-a989-479d-af46-f275c6370663";
    const SERVER_2025_COUNTED: &str = "907f1f65-adcd-4a2e-95bc-4bf500bc6e58";
    const OFFICE_2024_COUNTED: &str = "a8973cb5-bf03-0a4c-9cef-703099645ab3";

    /// The two hardware IDs published as cross-deployment fingerprints
    /// (`ID-013`, #118). `3A1C049600B60076` is "HwId from the Ratiborus VM".
    const RATIBORUS: [u8; 8] = [0x3A, 0x1C, 0x04, 0x96, 0x00, 0xB6, 0x00, 0x76];
    const OTHER: [u8; 8] = [0x36, 0x4F, 0x46, 0x3A, 0x88, 0x63, 0xD3, 0x5F];

    fn guid(text: &str) -> Guid {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| *byte != b'-')
            .map(|byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                other => panic!("not hex: {other}"),
            })
            .collect();
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (digits[index * 2] << 4) | digits[index * 2 + 1];
        }
        Guid::from_bytes(bytes)
    }

    fn today() -> Date {
        Date::new(2026, 8, 22).unwrap()
    }

    fn identity(seed: u64) -> HostIdentity {
        HostIdentity::generate(&mut DeterministicEntropy::from_seed(seed), today()).unwrap()
    }

    /// `ID-003` (#108): the format, checked field by field rather than against
    /// a whole string, so a failure says which field is wrong.
    #[test]
    fn an_epid_has_the_documented_shape() {
        let host = identity(1);
        let (_, group) = host.select(
            ApplicationId(guid(WINDOWS)),
            KmsCountedId(guid(SERVER_2025_COUNTED)),
        );
        let text = group.epid.to_string();
        let fields: Vec<&str> = text.split('-').collect();

        assert_eq!(fields.len(), 8, "{text}");
        assert_eq!(fields[0].len(), 5, "PlatformId is %05u: {text}");
        assert_eq!(
            fields[0],
            format!("{:05}", host.host_build().platform_id),
            "{text}"
        );
        assert_eq!(fields[1].len(), 5, "GroupId is %05u: {text}");
        assert_eq!(fields[2].len(), 3, "keyId/1000000 is %03u: {text}");
        assert_eq!(fields[3].len(), 6, "keyId%1000000 is %06u: {text}");
        assert_eq!(fields[4], LICENSE_CHANNEL, "the channel is a literal 03");
        assert_eq!(fields[5], host.lcid().value.to_string(), "LCID is unpadded");
        assert!(fields[6].ends_with(".0000"), "{text}");
        assert_eq!(
            fields[6],
            format!("{}.0000", host.host_build().build),
            "{text}"
        );
        assert_eq!(fields[7].len(), 7, "DDDYYYY: {text}");
    }

    /// `ID-005` (#110): unpadded. Every LCID a real host reports is at least
    /// 1025, so this is moot in practice — but padding it would differ from a
    /// genuine host for no reason, and License Manager's parser accepts
    /// `^[0-9]{1,5}$`.
    #[test]
    fn the_lcid_is_not_zero_padded() {
        for seed in 0..16_u64 {
            let host = identity(seed);
            let (_, group) = host.select(
                ApplicationId(guid(WINDOWS)),
                KmsCountedId(guid(SERVER_2025_COUNTED)),
            );
            let text = group.epid.to_string();
            let lcid_field = text.split('-').nth(5).unwrap();
            assert!(!lcid_field.starts_with('0'), "{text}");
            assert_eq!(lcid_field, host.lcid().value.to_string());
        }
    }

    /// `ID-004` (#109): the day of year is 1-based, so `000` never appears.
    /// License Manager's validator treats a zero as malformed.
    #[test]
    fn the_day_of_year_is_never_zero() {
        for seed in 0..64_u64 {
            let host = identity(seed);
            for group in &host.groups {
                let text = group.epid.to_string();
                let tail = text.split('-').next_back().unwrap();
                let day = &tail[..3];
                assert_ne!(day, "000", "{text}");
                assert_eq!(
                    day,
                    format!("{:03}", group.activated.day_of_year()),
                    "{text}"
                );
                assert_eq!(
                    &tail[3..],
                    format!("{:04}", group.activated.year()),
                    "{text}"
                );
            }
        }
    }

    /// `ID-001` (#106), MM01 — "the canonical emulator-detection test". py-kms
    /// regenerates on every response, so two byte-identical requests on one
    /// connection come back with different ePIDs.
    #[test]
    fn the_same_product_always_gets_the_same_epid() {
        let host = identity(2);
        let application = ApplicationId(guid(WINDOWS));
        let counted = KmsCountedId(guid(SERVER_2025_COUNTED));

        let first = host.select(application, counted).1.clone();
        for _ in 0..100 {
            let (_, again) = host.select(application, counted);
            assert_eq!(*again, first);
        }
    }

    /// `ID-008` (#113) and `ID-009` (#114): one locale and one build across
    /// every host key. A host whose Office ePID claimed a different Windows
    /// build from its Windows ePID would be visibly two machines.
    #[test]
    fn the_locale_and_build_are_shared_across_every_host_key() {
        let host = identity(3);
        let expected_platform = format!("{:05}", host.host_build().platform_id);
        let expected_build = format!("{}.0000", host.host_build().build);
        let expected_lcid = host.lcid().value.to_string();

        for group in &host.groups {
            let text = group.epid.to_string();
            let fields: Vec<&str> = text.split('-').collect();
            assert_eq!(fields[0], expected_platform, "{text}");
            assert_eq!(fields[5], expected_lcid, "{text}");
            assert_eq!(fields[6], expected_build, "{text}");
        }
    }

    /// `ID-002` (#107): the most specific host key wins. py-kms measures
    /// 4887/5000 wrong for Office 2010 because it random-choices over a list
    /// that includes a fallback for every non-matching entry.
    #[test]
    fn a_known_product_resolves_to_its_own_host_key() {
        let host = identity(4);

        // Office LTSC 2024's counted ID is counted by exactly one host key.
        let (selection, group) = host.select(
            ApplicationId(guid(OFFICE)),
            KmsCountedId(guid(OFFICE_2024_COUNTED)),
        );
        assert!(selection.was_resolved());
        let office_csvlk = kmsrs_db::csvlk_at(selection.index()).unwrap();
        assert!(
            office_csvlk.description.contains("Office24"),
            "{}",
            office_csvlk.description
        );
        assert_eq!(office_csvlk.group_id, 206);
        assert!(group.epid.to_string().contains("-00206-"));

        // Server 2025's is counted by three: the general key, the Azure-only
        // key and the internal-lab key. The general one counts the fewest
        // products, so it wins — which settles the variants for free.
        let (selection, _) = host.select(
            ApplicationId(guid(WINDOWS)),
            KmsCountedId(guid(SERVER_2025_COUNTED)),
        );
        assert!(selection.was_resolved());
        let windows_csvlk = kmsrs_db::csvlk_at(selection.index()).unwrap();
        assert_eq!(
            windows_csvlk.group_id, 4919,
            "the general key, not Azure-only (4918) or lab (4920)"
        );
    }

    /// `POL-010` (#98): an unknown product still activates, and gets a host key
    /// for the right *application* — an Office client handed a Windows group ID
    /// would be visibly wrong.
    #[test]
    fn an_unknown_product_falls_back_within_its_application() {
        let host = identity(5);

        let (selection, group) = host.select(
            ApplicationId(guid(OFFICE)),
            KmsCountedId(Guid::from_bytes([0x5A; 16])),
        );
        assert!(
            !selection.was_resolved(),
            "unknown products are not resolved"
        );
        assert!(matches!(selection, CsvlkSelection::Fallback { .. }));
        let csvlk = kmsrs_db::csvlk_at(selection.index()).unwrap();
        assert_eq!(
            csvlk.application,
            Some(guid(OFFICE)),
            "an Office request must not get a Windows host key"
        );
        assert!(!group.epid.to_string().is_empty());

        let (selection, _) = host.select(
            ApplicationId(guid(WINDOWS)),
            KmsCountedId(Guid::from_bytes([0x5A; 16])),
        );
        let csvlk = kmsrs_db::csvlk_at(selection.index()).unwrap();
        assert_eq!(csvlk.application, Some(guid(WINDOWS)));
    }

    /// `ID-019` (#124): every drawn key ID falls inside a real block, never in
    /// a hole between two of them.
    #[test]
    fn every_key_id_falls_inside_a_real_block() {
        for seed in 0..48_u64 {
            let host = identity(seed);
            for (index, group) in host.groups.iter().enumerate() {
                let csvlk = &kmsrs_db::CSVLKS[index];
                assert!(
                    csvlk
                        .key_blocks
                        .iter()
                        .any(|block| block.contains(group.key_id)),
                    "key {} is in a hole for {}",
                    group.key_id,
                    csvlk.description
                );
            }
        }
    }

    /// `ID-012` (#117) and `ID-013` (#118): a per-host-key hardware ID, drawn
    /// rather than constant. `3A1C049600B60076` and `364F463A8863D35F` are both
    /// published cross-deployment fingerprints.
    #[test]
    fn hardware_ids_are_drawn_per_host_key_and_per_process() {
        let first = identity(6);
        let second = identity(7);

        let ids: Vec<[u8; 8]> = first
            .groups
            .iter()
            .map(|group| group.hardware_id.0)
            .collect();
        assert!(
            ids.iter()
                .collect::<alloc::collections::BTreeSet<_>>()
                .len()
                > 1,
            "host keys must not share one hardware id"
        );
        assert_ne!(
            ids[0], second.groups[0].hardware_id.0,
            "two processes must not agree"
        );
        assert!(ids.iter().all(|id| *id != [0; 8]));

        // Neither published constant.
        assert!(ids.iter().all(|id| *id != RATIBORUS && *id != OTHER));
    }

    /// `ID-007` (#112): the activation date is between the claimed build's
    /// release and today, so a host never claims to have been activated before
    /// its own build existed.
    #[test]
    fn the_activation_date_is_between_release_and_today() {
        for seed in 0..32_u64 {
            let host = identity(seed);
            let release = host.host_build().release_date.unwrap();
            for group in &host.groups {
                assert!(
                    group.activated >= release,
                    "{} is before build {} was released",
                    group.activated,
                    host.host_build().build
                );
                assert!(group.activated <= today(), "{}", group.activated);
            }
        }
    }

    /// `ID-015` (#120): a release date equal to or later than today collapses
    /// the span rather than dividing by zero, which is what vlmcsd does.
    #[test]
    fn a_release_date_in_the_future_does_not_divide_by_zero() {
        for date in [
            Date::new(2009, 5, 26).unwrap(),
            Date::new(2026, 10, 1).unwrap(),
            Date::new(1970, 1, 1).unwrap(),
        ] {
            let host =
                HostIdentity::generate(&mut DeterministicEntropy::from_seed(8), date).unwrap();
            assert!(!host.groups.is_empty());
            for group in &host.groups {
                assert!(!group.epid.to_string().is_empty());
            }
        }
    }

    /// `ID-010` (#115): NDR64 comes from the claimed build, so "build 26100 but
    /// no NDR64" — which py-kms emits — is not expressible.
    #[test]
    fn ndr64_follows_the_claimed_build() {
        for seed in 0..32_u64 {
            let host = identity(seed);
            assert_eq!(host.advertises_ndr64(), host.host_build().build >= 9200);
            assert!(host.host_build().use_for_epid);
        }
    }

    /// `OS-012` (#263): a host that cannot draw randomness must not serve.
    #[test]
    fn a_failing_entropy_source_produces_no_identity() {
        assert!(HostIdentity::generate(&mut FailingEntropy, today()).is_err());
    }

    /// Two processes must not agree on anything. A shared ePID across
    /// deployments is the fingerprint the whole module exists to avoid.
    #[test]
    fn two_processes_produce_different_identities() {
        let first = identity(9);
        let second = identity(10);
        let epids = |host: &HostIdentity| -> Vec<String> {
            host.groups.iter().map(|g| g.epid.to_string()).collect()
        };
        assert_ne!(epids(&first), epids(&second));
    }
}
