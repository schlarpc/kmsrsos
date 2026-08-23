//! Lookups over the generated tables.
//!
//! Every one is a binary search over a `static` array whose sortedness is
//! asserted at compile time. There is no map to build, nothing to initialise,
//! and no allocation — which is what makes the database usable unchanged on the
//! bare-metal target.

use crate::guid::Guid;
use crate::tables::{
    APPLICATIONS, Application, COUNTED_IDS, CSVLKS, Csvlk, EPID_HOST_BUILDS, HOST_BUILDS,
    HostBuild, LCIDS, Lcid, PRODUCTS, Product,
};

/// The application a GUID names, if it is one of the three.
#[must_use]
pub fn application(guid: Guid) -> Option<&'static Application> {
    let index = APPLICATIONS
        .binary_search_by(|candidate| candidate.guid.cmp(&guid))
        .ok()?;
    APPLICATIONS.get(index)
}

/// The product key configuration an activation ID names.
///
/// A KMS host does not decide on this — the request's `ActID` is read and
/// ignored (`KMS-018`, #34). It is here so the event log can say
/// *Windows Server 2025 Datacenter* rather than a raw GUID (`DB-014`, #138),
/// and so the client can enumerate products (`CLI-008`, #214).
#[must_use]
pub fn product(activation_id: Guid) -> Option<&'static Product> {
    let index = PRODUCTS
        .binary_search_by(|candidate| candidate.activation_id.cmp(&activation_id))
        .ok()?;
    PRODUCTS.get(index)
}

/// The host key an activation ID names, if it is a host key.
#[must_use]
pub fn csvlk(activation_id: Guid) -> Option<&'static Csvlk> {
    let index = CSVLKS
        .binary_search_by(|candidate| candidate.activation_id.cmp(&activation_id))
        .ok()?;
    CSVLKS.get(index)
}

/// The host key at an index, as stored in [`crate::tables::CountedId::csvlks`].
#[must_use]
pub fn csvlk_at(index: u16) -> Option<&'static Csvlk> {
    CSVLKS.get(usize::from(index))
}

/// Every host key that counts a given KMS counted ID.
///
/// The mapping is many-to-many, and that is a fact about how volume licensing
/// works rather than an artefact of the extraction: a Windows Server 2025 host
/// key counts 22 products, and a single product is counted by as many as ten
/// different host keys. Both existing emulators model one host key per product,
/// which cannot represent it — so *which* host key to answer as is a policy
/// decision (`ID-002`, #107), and this function deliberately returns all the
/// candidates rather than picking one.
///
/// Returns an empty slice for an unknown counted ID. That is the common case
/// for a product this build's sources did not cover, and it must not be an
/// error: refusing an unknown KMS ID is why a 2019-era vlmcsd still activates
/// Windows 11, and refusing it is exactly what py-kms's crash-on-unknown-GUID
/// does instead (`POL-010`, #98).
#[must_use]
pub fn csvlks_counting(counted_id: Guid) -> &'static [u16] {
    COUNTED_IDS
        .binary_search_by(|candidate| candidate.guid.cmp(&counted_id))
        .ok()
        .and_then(|index| COUNTED_IDS.get(index))
        .map_or(&[], |entry| entry.csvlks)
}

/// Whether any host key in the database counts this product.
#[must_use]
pub fn is_known_counted_id(counted_id: Guid) -> bool {
    !csvlks_counting(counted_id).is_empty()
}

/// Every host build an ePID may claim (`ID-009`, #114; `ID-011`, #116).
///
/// Non-empty by construction: the build fails if the table would be empty, so
/// callers do not have to handle "no build to claim". vlmcsd's equivalent
/// coupling is a `while (TRUE)` loop that hangs at start-up instead.
pub fn epid_host_builds() -> impl Iterator<Item = &'static HostBuild> {
    EPID_HOST_BUILDS
        .iter()
        .filter_map(|index| HOST_BUILDS.get(usize::from(*index)))
}

/// How many host builds an ePID may draw from.
///
/// Never zero: the build fails if the table would be empty, which is what
/// makes [`epid_host_build_at`] a lookup rather than a search.
#[must_use]
pub const fn epid_host_build_count() -> usize {
    EPID_HOST_BUILDS.len()
}

/// How many locales an ePID may draw from. Never zero.
#[must_use]
pub const fn lcid_count() -> usize {
    LCIDS.len()
}

/// The host build at an index in [`EPID_HOST_BUILDS`].
#[must_use]
pub fn epid_host_build_at(position: usize) -> Option<&'static HostBuild> {
    EPID_HOST_BUILDS
        .get(position)
        .and_then(|index| HOST_BUILDS.get(usize::from(*index)))
}

/// The locale at an index in [`LCIDS`].
#[must_use]
pub fn lcid_at(position: usize) -> Option<&'static Lcid> {
    LCIDS.get(position)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::expect_used,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::{
        application, csvlk, csvlk_at, csvlks_counting, epid_host_build_at, epid_host_builds,
        is_known_counted_id, lcid_at, product,
    };
    use crate::guid::Guid;
    use crate::tables::{APPLICATIONS, COUNTED_IDS, CSVLKS, HOST_BUILDS, KeyKind, LCIDS, PRODUCTS};
    use alloc::format;
    use alloc::vec::Vec;

    /// Parse a canonical GUID string. Test-only: the shipped code never parses
    /// a GUID from text, because nothing on the wire is text.
    fn guid(text: &str) -> Guid {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| *byte != b'-')
            .map(|byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                other => panic!("not hex: {other}"),
            })
            .collect();
        assert_eq!(digits.len(), 32, "not a GUID: {text}");
        let mut bytes = [0_u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (digits[index * 2] << 4) | digits[index * 2 + 1];
        }
        Guid::from_bytes(bytes)
    }

    #[test]
    fn the_two_application_guids_resolve_to_their_names() {
        assert_eq!(
            application(guid("55c92734-d682-4d71-983e-d6ec3f16059f"))
                .unwrap()
                .name,
            "Windows"
        );
        assert_eq!(
            application(guid("0ff1ce15-a989-479d-af46-f275c6370663"))
                .unwrap()
                .name,
            "Office 2013 and later"
        );
        assert!(application(Guid::ZERO).is_none());
    }

    /// `DB-007` (#131): the Server 2025 host key, with the group ID and the two
    /// key blocks that py-kms gets wrong in three separate ways.
    #[test]
    fn the_server_2025_host_key_matches_the_artifact() {
        let entry = csvlk(guid("84e331f6-4279-48c4-ab10-b75139181351")).unwrap();
        assert_eq!(entry.group_id, 4919, "py-kms has 4918 and 4919 swapped");
        assert_eq!(entry.key_blocks.len(), 2);
        assert_eq!(
            (entry.key_blocks[0].start, entry.key_blocks[0].end),
            (0, 19_999)
        );
        assert_eq!(
            (entry.key_blocks[1].start, entry.key_blocks[1].end),
            (20_000, 20_019_999),
            "py-kms uses Server 2022's range here"
        );

        // The Azure-only key is the *other* group, not the same one.
        let azure = csvlk(guid("82fcf64d-f9dd-4411-9c79-f2eed16d4eb8")).unwrap();
        assert_eq!(azure.group_id, 4918);
        assert_ne!(azure.activation_id, entry.activation_id);
    }

    /// `DB-007` (#131): Office LTSC 2024's key range, which py-kms fills with
    /// Office 2019's verbatim.
    #[test]
    fn the_office_ltsc_2024_host_key_has_its_own_range() {
        let office_2024 = csvlk(guid("f3d89bbf-c0ec-47ce-a8fa-e5a5f97e447f")).unwrap();
        let office_2019 = csvlk(guid("70512334-47b4-44db-a233-be5ea33b914c")).unwrap();
        assert_eq!(
            (
                office_2024.key_blocks[0].start,
                office_2024.key_blocks[0].end
            ),
            (591_000_000, 610_999_999)
        );
        assert_eq!(
            (
                office_2019.key_blocks[0].start,
                office_2019.key_blocks[0].end
            ),
            (666_000_000, 685_999_999)
        );
        assert_ne!(office_2024.key_blocks, office_2019.key_blocks);
    }

    /// `DB-008` (#132): Server 2025's genuine counted ID, against the value
    /// py-kms fabricated.
    #[test]
    fn the_server_2025_counted_id_is_the_genuine_one() {
        let genuine = guid("907f1f65-adcd-4a2e-95bc-4bf500bc6e58");
        assert!(is_known_counted_id(genuine));

        let fabricated = guid("4b83307d-0000-0000-0000-000000000000");
        assert!(!is_known_counted_id(fabricated));

        // The host keys that count it must include Server 2025's own.
        let hosts: Vec<&str> = csvlks_counting(genuine)
            .iter()
            .filter_map(|index| csvlk_at(*index))
            .map(|entry| entry.description)
            .collect();
        assert!(
            hosts
                .iter()
                .any(|name| name.contains("Windows Server 2025")),
            "{hosts:?}"
        );
    }

    /// `DB-005` (#129) end to end: Office LTSC 2024's counted ID has an invalid
    /// version nibble and is nonetheless in the table, because it is what
    /// Microsoft ships.
    #[test]
    fn the_office_2024_counted_id_survives_its_invalid_version_nibble() {
        let genuine = guid("a8973cb5-bf03-0a4c-9cef-703099645ab3");
        assert_eq!(genuine.as_bytes()[6] >> 4, 0, "the nibble in question");
        assert!(is_known_counted_id(genuine));
        assert_eq!(format!("{genuine}"), "a8973cb5-bf03-0a4c-9cef-703099645ab3");
    }

    /// `POL-010` (#98): an unknown counted ID is an empty answer, not an error.
    /// Refusing one is why py-kms crashes on GUIDs it has never seen, and why a
    /// 2019-era vlmcsd still activates Windows 11.
    #[test]
    fn an_unknown_counted_id_is_empty_rather_than_an_error() {
        assert!(csvlks_counting(Guid::ZERO).is_empty());
        assert!(csvlks_counting(Guid::from_bytes([0xFF; 16])).is_empty());
        assert!(!is_known_counted_id(Guid::ZERO));
    }

    /// The mapping is many-to-many in both directions, which is the fact that
    /// makes host-key selection a policy decision rather than a lookup.
    #[test]
    fn counted_ids_and_host_keys_are_many_to_many() {
        let shared = COUNTED_IDS
            .iter()
            .find(|entry| entry.csvlks.len() > 1)
            .expect("some product is counted by more than one host key");
        assert!(shared.csvlks.len() > 1);

        let generous = CSVLKS
            .iter()
            .find(|entry| entry.counted_ids.len() > 1)
            .expect("some host key counts more than one product");
        assert!(generous.counted_ids.len() > 1);
    }

    /// `DB-014` (#138): a product resolves to a readable name, not to
    /// "Unknown". vlmcsd's stock build points every SKU name at one shared
    /// "Unknown" string.
    #[test]
    fn products_have_readable_names() {
        let entry = product(guid("84e331f6-4279-48c4-ab10-b75139181351")).unwrap();
        assert!(
            entry.description.contains("Windows Server 2025"),
            "{entry:?}"
        );
        assert_eq!(entry.kind, KeyKind::KmsHost);

        for candidate in &PRODUCTS {
            assert!(!candidate.description.is_empty());
            assert_ne!(candidate.description, "Unknown");
        }
    }

    /// `POL-010` (#98) needs the volume/non-volume split, so the table must
    /// actually contain both sides of it.
    #[test]
    fn the_table_distinguishes_volume_from_retail() {
        let volume = PRODUCTS
            .iter()
            .filter(|entry| entry.kind.is_volume())
            .count();
        let other = PRODUCTS.len().saturating_sub(volume);
        assert!(volume > 0 && other > 0, "{volume} volume, {other} other");

        assert!(KeyKind::KmsClient.is_volume());
        assert!(KeyKind::KmsHost.is_volume());
        assert!(KeyKind::MultipleActivation.is_volume());
        assert!(!KeyKind::Retail.is_volume());
        assert!(!KeyKind::OriginalEquipment.is_volume());
        assert!(!KeyKind::Evaluation.is_volume());
        assert!(!KeyKind::Other.is_volume());
    }

    /// Every host key must be able to produce an ePID: a group and at least one
    /// key block. Asserted at compile time too, but a test says what it is for.
    #[test]
    fn every_host_key_can_produce_an_epid() {
        assert!(!CSVLKS.is_empty());
        for entry in &CSVLKS {
            assert!(entry.group_id > 0, "{entry:?}");
            assert!(!entry.key_blocks.is_empty(), "{entry:?}");
            for block in entry.key_blocks {
                assert!(block.key_count() > 0, "{block:?}");
                assert!(block.contains(block.start) && block.contains(block.end));
            }
        }
    }

    /// Lookups must actually find every row. A table that was sorted with a
    /// different comparator than the search uses fails only for some keys, so
    /// checking every one is the only convincing version of this test.
    #[test]
    fn every_row_is_findable_by_its_key() {
        for entry in &APPLICATIONS {
            assert_eq!(application(entry.guid).unwrap().guid, entry.guid);
        }
        for entry in &PRODUCTS {
            assert_eq!(
                product(entry.activation_id).unwrap().activation_id,
                entry.activation_id
            );
        }
        for entry in &CSVLKS {
            assert_eq!(
                csvlk(entry.activation_id).unwrap().activation_id,
                entry.activation_id
            );
        }
        for entry in &COUNTED_IDS {
            assert!(is_known_counted_id(entry.guid));
        }
    }

    /// `DB-011` (#135): the host build table, against the research it came
    /// from. PlatformId appears in no published Microsoft document, so these
    /// are the values the two genuine ePIDs corroborate.
    #[test]
    fn the_host_build_table_matches_the_research() {
        assert!(HOST_BUILDS.len() >= 20);

        // PlatformId is 3612 for every build from 10240 onwards.
        for entry in &HOST_BUILDS {
            if entry.build >= 10_240 {
                assert_eq!(entry.platform_id, 3612, "build {}", entry.build);
            }
        }

        // Sorted, and the pre-NDR64 builds carry their own platform ids.
        let mut previous = 0;
        for entry in &HOST_BUILDS {
            assert!(entry.build > previous, "not sorted at {}", entry.build);
            previous = entry.build;
        }
        assert_eq!(
            HOST_BUILDS
                .iter()
                .find(|entry| entry.build == 7601)
                .unwrap()
                .platform_id,
            55_041
        );

        // Build 28000 is real — KB5077179, 2026-02-10 — not speculation.
        assert!(HOST_BUILDS.iter().any(|entry| entry.build == 28_000));
    }

    /// `ID-010` (#115): the build and its transfer syntax travel together, so
    /// a host cannot claim build 26100 while refusing NDR64 — a combination no
    /// real host produces and one py-kms emits.
    #[test]
    fn no_build_claims_a_syntax_its_era_did_not_have() {
        for entry in &HOST_BUILDS {
            assert_eq!(
                entry.ndr64,
                entry.build >= 9200,
                "build {} says ndr64={}",
                entry.build,
                entry.ndr64
            );
        }
    }

    /// `ID-011` (#116): non-empty by construction, and every drawable build
    /// carries the release date an activation date is drawn from.
    #[test]
    fn every_drawable_build_can_actually_produce_an_epid() {
        let builds: alloc::vec::Vec<u32> = epid_host_builds().map(|entry| entry.build).collect();
        assert_eq!(
            builds,
            [6002, 7601, 9200, 9600, 14_393, 17_763, 20_348, 26_100]
        );

        for entry in epid_host_builds() {
            assert!(entry.use_for_epid);
            let date = entry.release_date.expect("a drawable build has a date");
            assert!(date.year() >= 2009, "{date} for build {}", entry.build);
            assert!(date.day_of_year() >= 1, "the day-of-year is 1-based");
        }

        assert!(epid_host_build_at(0).is_some());
        assert!(epid_host_build_at(builds.len()).is_none());
    }

    /// `ID-008` (#113): the locale pool. Every entry is a specific culture, so
    /// none is below 1025 — which is the research note restated.
    #[test]
    fn the_locale_table_holds_only_specific_cultures() {
        assert!(LCIDS.len() > 100, "{} locales", LCIDS.len());

        let mut previous = 0;
        for entry in &LCIDS {
            assert!(
                entry.value >= 1025,
                "{} is a primary language id",
                entry.value
            );
            assert!(entry.value > previous, "not sorted at {}", entry.value);
            previous = entry.value;
            assert!(entry.tag.contains('-'), "{} has no region", entry.tag);
        }

        // en-US, the one every reader can check by eye.
        let american_english = LCIDS.iter().find(|entry| entry.value == 1033).unwrap();
        assert_eq!(american_english.tag, "en-US");
        assert_eq!(lcid_at(0).map(|entry| entry.value), Some(LCIDS[0].value));
        assert!(lcid_at(LCIDS.len()).is_none());
    }
}
