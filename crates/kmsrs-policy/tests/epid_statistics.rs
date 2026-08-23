//! Statistical properties of generated ePIDs (`TEST-008`, #229).
//!
//! # Why statistics rather than examples
//!
//! Both properties here are ones an example-based test passes by accident. The
//! two defects they pin were each found by *counting*, not by reading one
//! output:
//!
//! * **py-kms picks the wrong host key 97.7% of the time.** For every host key
//!   that does *not* count the requested product it appends a Server 2019
//!   fallback, then `random.choice`s over the whole list. Measured at 4887 of
//!   5000 wrong for Office 2010. Any single sample has a 2.3% chance of looking
//!   right, so one example would have found nothing — and it can emit
//!   impossible combinations such as group 00096 with build 17763.
//! * **The Organization fork's host build is degenerate.** It emits 17763 in
//!   2000 of 2000 generations. Every individual ePID is well-formed; what is
//!   wrong is the distribution, and a distribution is not visible from one
//!   sample.
//!
//! Both are exactly the shape `CLI-002` (#208) cares about: a host that is
//! individually plausible and collectively distinguishable.
//!
//! # Determinism
//!
//! Every draw comes from [`DeterministicEntropy`] with a fixed seed, so a
//! failure here is reproducible and CI cannot flake. The tests are still
//! statistical — they count over many generations — but they count over the
//! *same* generations every time.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::{Date, Guid};
use kmsrs_policy::identity::HostIdentity;
use kmsrs_proto::entropy::testing::DeterministicEntropy;
use kmsrs_proto::types::{ApplicationId, CsvlkSelection, KmsCountedId};
use std::collections::BTreeMap;

/// How many independent hosts each test generates.
///
/// Chosen to be the same order as the measurements the defects were found at —
/// py-kms's 4887/5000, the Organization fork's 2000/2000 — so a regression of
/// the same magnitude is unmissable rather than marginal. Each generation
/// builds one identity per host key, so this is a few hundred thousand ePIDs.
const HOSTS: u64 = 512;

fn today() -> Date {
    Date::new(2026, 8, 23).expect("a real date")
}

/// Every counted ID in the database, with the application that owns it.
fn every_counted_id() -> Vec<(ApplicationId, KmsCountedId, u16)> {
    let mut out = Vec::new();
    for index in 0..kmsrs_db::CSVLKS.len() {
        let Ok(index) = u16::try_from(index) else {
            continue;
        };
        let Some(csvlk) = kmsrs_db::csvlk_at(index) else {
            continue;
        };
        // A host key with no application is one the extractor could not tie
        // to one; it cannot be the subject of an application-matching claim.
        let Some(application) = csvlk.application else {
            continue;
        };
        for counted in csvlk.counted_ids {
            out.push((ApplicationId(application), KmsCountedId(*counted), index));
        }
    }
    out
}

/// `TEST-008` (#229): the host key answering a request always counts the
/// product that was asked for.
///
/// py-kms manages 2.3%. The bar here is 100%, and it is reachable because the
/// selection is a lookup rather than a choice: `csvlks_counting` returns the
/// keys that count the ID, and the most specific of those is taken.
#[test]
fn the_selected_host_key_always_counts_the_requested_product() {
    let catalogue = every_counted_id();
    assert!(
        catalogue.len() > 50,
        "only {} counted IDs in the database, so this test is measuring almost \
         nothing",
        catalogue.len()
    );

    let mut checked = 0_u64;
    let mut wrong = Vec::new();

    for seed in 0..8_u64 {
        let mut entropy = DeterministicEntropy::from_seed(0xE91D_0000 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");

        for (application, counted, _) in &catalogue {
            let (selection, _) = identity.select(*application, *counted);
            checked += 1;

            let index = match selection {
                CsvlkSelection::Resolved { index } => index,
                CsvlkSelection::Fallback { index } => {
                    wrong.push(format!(
                        "{counted:?} fell back to host key {index} even though the \
                         database says which key counts it"
                    ));
                    continue;
                }
            };

            let Some(csvlk) = kmsrs_db::csvlk_at(index) else {
                wrong.push(format!(
                    "{counted:?} selected host key {index}, which is not in the database"
                ));
                continue;
            };
            if !csvlk.counted_ids.contains(&counted.0) {
                wrong.push(format!(
                    "{counted:?} was answered by host key {index} ({}), which does \
                     not count it",
                    csvlk.group_id
                ));
            }
        }
    }

    assert!(
        wrong.is_empty(),
        "{} of {checked} selections named a host key that does not count the \
         requested product; py-kms gets 4887 of 5000 wrong. First few: {:#?}",
        wrong.len(),
        &wrong[..wrong.len().min(5)]
    );
}

/// And the application matches too, which is the half that produces py-kms's
/// visibly impossible combinations: an Office client handed a Windows group ID.
#[test]
fn the_selected_host_key_always_belongs_to_the_requesting_application() {
    let catalogue = every_counted_id();
    let mut entropy = DeterministicEntropy::from_seed(0xE91D_0001);
    let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");

    let mut mismatched = Vec::new();
    for (application, counted, _) in &catalogue {
        let (selection, _) = identity.select(*application, *counted);
        let index = match selection {
            CsvlkSelection::Resolved { index } | CsvlkSelection::Fallback { index } => index,
        };
        let Some(csvlk) = kmsrs_db::csvlk_at(index) else {
            continue;
        };
        if csvlk.application != Some(application.0) {
            mismatched.push(format!(
                "{counted:?} from application {} was answered by a host key for \
                 application {:?}",
                application.0, csvlk.application
            ));
        }
    }

    assert!(
        mismatched.is_empty(),
        "{} selections crossed application boundaries: {:#?}",
        mismatched.len(),
        &mismatched[..mismatched.len().min(5)]
    );
}

/// An unknown product still gets an answer, and it gets one from the right
/// application (`POL-010`, #98).
///
/// The permissive half of the product gate. Refusing here is why py-kms fails
/// on GUIDs it has not seen; answering from the wrong application is why its
/// fallback is visible.
#[test]
fn an_unknown_counted_id_falls_back_within_its_own_application() {
    let mut entropy = DeterministicEntropy::from_seed(0xE91D_0002);
    let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");

    let applications: Vec<ApplicationId> = {
        let mut seen: Vec<Guid> = Vec::new();
        for index in 0..kmsrs_db::CSVLKS.len() {
            if let Ok(index) = u16::try_from(index)
                && let Some(csvlk) = kmsrs_db::csvlk_at(index)
                && let Some(application) = csvlk.application
                && !seen.contains(&application)
            {
                seen.push(application);
            }
        }
        seen.into_iter().map(ApplicationId).collect()
    };
    assert!(applications.len() >= 2, "the database has one application");

    // A counted ID no database will ever hold.
    let unknown = KmsCountedId(Guid::from_bytes([0xFF; 16]));

    for application in applications {
        let (selection, _) = identity.select(application, unknown);
        let index = match selection {
            CsvlkSelection::Fallback { index } => index,
            CsvlkSelection::Resolved { index } => {
                panic!("an all-0xFF counted ID resolved to host key {index}")
            }
        };
        let csvlk = kmsrs_db::csvlk_at(index).expect("the fallback names a real key");
        assert_eq!(
            csvlk.application,
            Some(application.0),
            "an unknown product from application {} fell back to a host key for \
             application {:?}, which is visibly wrong to the client",
            application.0,
            csvlk.application
        );
    }
}

/// `TEST-008` (#229): the host build is not degenerate.
///
/// The Organization fork emits 17763 in 2000 of 2000 generations. Every ePID it
/// produces is well-formed; the distribution is what gives it away, and a
/// deployment of several replicas makes that visible from outside
/// (`CLI-002`, #208).
///
/// The bar is deliberately not "uniform": the draw is uniform over the build
/// table, but a fixed seed over a finite sample will not produce exactly equal
/// counts and asserting that it does would be a flake waiting for a table
/// change. What is asserted is that the distribution is nowhere near collapsed.
#[test]
fn the_host_build_distribution_is_not_degenerate() {
    let available = kmsrs_db::epid_host_build_count();
    assert!(
        available > 1,
        "the build table has {available} entries, so degeneracy is not a \
         property this test can detect"
    );

    let mut counts: BTreeMap<u32, u64> = BTreeMap::new();
    for seed in 0..HOSTS {
        let mut entropy = DeterministicEntropy::from_seed(0xB11D_0000 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");
        *counts.entry(identity.host_build().build).or_default() += 1;
    }

    let distinct = counts.len();
    let most = counts.values().copied().max().unwrap_or(0);

    // Half the table, at minimum. A uniform draw over `available` builds in
    // `HOSTS` samples covers essentially all of them; half is a floor no
    // healthy generator approaches and a collapsed one cannot reach.
    assert!(
        distinct * 2 >= available,
        "only {distinct} of {available} host builds appeared in {HOSTS} \
         generations. Counts: {counts:#?}"
    );

    // And no single build dominates: at most a quarter of the sample, against
    // a uniform expectation of one eighth. The Organization fork scores the
    // whole sample.
    assert!(
        most * 4 <= HOSTS,
        "one host build accounted for {most} of {HOSTS} generations; the \
         Organization fork's degenerate generator accounts for all of them. \
         Counts: {counts:#?}"
    );
}

/// The platform ID travels with the build, so a degenerate build would show
/// here too — and a build paired with the *wrong* platform ID is the impossible
/// combination py-kms emits.
#[test]
fn every_generated_epid_pairs_its_build_with_that_builds_platform_id() {
    for seed in 0..64_u64 {
        let mut entropy = DeterministicEntropy::from_seed(0xB11D_0100 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");
        let build = identity.host_build();

        let sample = every_counted_id();
        let (application, counted, _) = sample[0];
        let epid = identity.select(application, counted).1.epid.to_string();

        let expected_platform = format!("{:05}", build.platform_id);
        assert!(
            epid.starts_with(&expected_platform),
            "the ePID {epid} does not start with the platform ID {expected_platform} \
             of the build {} it claims",
            build.build
        );
        assert!(
            epid.contains(&format!("-{}.0000-", build.build)),
            "the ePID {epid} does not carry the build {} it was generated from",
            build.build
        );
    }
}

/// One host draws one build and uses it for every host key, because a genuine
/// KMS host is one machine (`ID-002`, #107).
///
/// The opposite failure to degeneracy, and just as visible: a host whose ePIDs
/// disagree about what machine they came from.
#[test]
fn one_host_reports_one_build_across_every_host_key() {
    let catalogue = every_counted_id();
    for seed in 0..32_u64 {
        let mut entropy = DeterministicEntropy::from_seed(0xB11D_0200 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");
        let expected = format!("-{}.0000-", identity.host_build().build);

        for (application, counted, _) in &catalogue {
            let epid = identity.select(*application, *counted).1.epid.to_string();
            assert!(
                epid.contains(&expected),
                "one host emitted {epid}, which disagrees with the build \
                 {expected} its other ePIDs claim"
            );
        }
    }
}

/// The key ID is drawn across the union of a host key's blocks, never from the
/// hole between them (`ID-019`, #124).
///
/// py-kms draws between a minimum and a maximum, which emits key IDs inside the
/// invalid hole in Windows Server 2022's key — values no genuine host can
/// produce. Statistical because the hole is a minority of the range: a handful
/// of samples would sit outside it by luck.
#[test]
fn no_generated_key_id_falls_in_a_hole_between_blocks() {
    let mut checked = 0_u64;
    let mut holed = Vec::new();

    for seed in 0..HOSTS {
        let mut entropy = DeterministicEntropy::from_seed(0xC01D_0000 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");

        for (application, counted, _) in every_counted_id() {
            let (selection, group) = identity.select(application, counted);
            // The *selected* key, not the one the catalogue happened to list
            // the ID under: `select` takes the most specific among the
            // candidates, and the key ID belongs to whichever it chose.
            let index = match selection {
                CsvlkSelection::Resolved { index } | CsvlkSelection::Fallback { index } => index,
            };
            let Some(csvlk) = kmsrs_db::csvlk_at(index) else {
                continue;
            };
            checked += 1;
            let inside = csvlk
                .key_blocks
                .iter()
                .any(|block| group.key_id >= block.start && group.key_id <= block.end);
            if !inside {
                holed.push(format!(
                    "host key {index} produced key ID {} which is in none of its \
                     {} blocks",
                    group.key_id,
                    csvlk.key_blocks.len()
                ));
            }
        }
        // One identity covers every host key, so a few seeds already sample the
        // whole table; the loop is bounded to keep the test quick.
        if seed > 16 {
            break;
        }
    }

    assert!(checked > 500, "only {checked} key IDs examined");
    assert!(
        holed.is_empty(),
        "{} of {checked} key IDs fell outside every valid block: {:#?}",
        holed.len(),
        &holed[..holed.len().min(5)]
    );
}

/// Two hosts do not share an identity.
///
/// The canonical detection test at the infrastructure layer: several replicas
/// behind one address must each look like a different machine, or they look
/// like one emulator (`CLI-002`, #208).
#[test]
fn independently_generated_hosts_do_not_collide() {
    let mut epids: BTreeMap<String, u64> = BTreeMap::new();
    let catalogue = every_counted_id();
    let (application, counted, _) = catalogue[0];

    for seed in 0..HOSTS {
        let mut entropy = DeterministicEntropy::from_seed(0xD01D_0000 ^ seed);
        let identity = HostIdentity::generate(&mut entropy, today()).expect("entropy never fails");
        let epid = identity.select(application, counted).1.epid.to_string();
        *epids.entry(epid).or_default() += 1;
    }

    let collisions: Vec<(&String, &u64)> = epids.iter().filter(|(_, count)| **count > 1).collect();
    assert!(
        collisions.is_empty(),
        "{} of {HOSTS} independently generated hosts share an ePID: {:#?}",
        collisions.len(),
        &collisions[..collisions.len().min(5)]
    );
}
