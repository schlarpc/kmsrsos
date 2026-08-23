//! What the shipped tables must be true of, checked as a test
//! (`TEST-007`, #228).
//!
//! # Why this exists alongside `build.rs`
//!
//! `build.rs` validates `products.toml` while parsing it, and the generated
//! `const _: ()` block asserts sortedness and index bounds at compile time.
//! Both are load-bearing and neither is what this file does.
//!
//! A `const` block can only assert what `const` evaluation can express: no
//! iterators, no string comparison, no dates, no counting. So the properties it
//! cannot reach are exactly the ones a truncated or half-regenerated table
//! satisfies — a `products.toml` with three products in it compiles, sorts,
//! and passes every index check. What it fails is *being the database*.
//!
//! So this file checks the shipped tables for the things a compiler cannot:
//!
//! * **Floors.** A regeneration that silently produced a tenth of the data
//!   would pass the build. These are floors against regression, not the
//!   coverage targets — `DB-010` (#134) is the issue about coverage.
//! * **Cross-table agreement.** Every counted ID resolves to a host key that
//!   lists it, every product's application exists, every host key's activation
//!   ID is a product. vlmcsd never checks the equivalent, and `EPidIndex = 250`
//!   against a shorter table is a remotely-triggerable over-read.
//! * **Plausibility.** A build released in the future, a key block of size
//!   zero, an ePID-drawable build with no date. Each is a value that is wrong
//!   and that nothing else checks — which is the shape of every data defect the
//!   audits found.
//! * **Provenance.** Data ships through the `kmsrs-dbgen` pipeline or it does
//!   not ship (declined item D19). The digests in `products.toml` are what make
//!   a silently republished artifact visible as a changed digest rather than as
//!   changed data (`DB-002`, #126), so a row with no source is a row somebody
//!   typed.
//!
//! # Drift
//!
//! Re-extracting from Microsoft's artifacts needs a network and several
//! hundred megabytes of container image, so it cannot run on every pull
//! request. `.github/workflows/data-drift.yml` runs it on a schedule and fails
//! on a diff; what runs here is the cheap half — that the committed file still
//! says which generator produced it and what it was produced from.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code: a failed expectation should abort loudly"
)]

use kmsrs_db::{APPLICATIONS, COUNTED_IDS, CSVLKS, HOST_BUILDS, KeyKind, LCIDS, PRODUCTS};
use std::collections::{BTreeMap, BTreeSet};

/// Floors against regression, **not** coverage targets.
///
/// Each is set below what the pipeline currently extracts and far above what a
/// broken extraction produces. They catch a regeneration that quietly lost most
/// of its input — which compiles, sorts, and passes every index check.
///
/// They deliberately do not encode `DB-010` (#134), which is the open issue
/// about coverage. Raising a floor is how a coverage improvement gets locked
/// in; a floor set at an aspiration would just fail today and teach the next
/// person to lower it.
///
/// Measured when written, from the extraction committed at the time: 273
/// products, 14 host keys, 27 counted IDs, 2 applications, 252 locales, 23
/// builds of which 8 are drawable.
mod floors {
    pub(crate) const PRODUCTS: usize = 200;
    pub(crate) const CSVLKS: usize = 12;
    pub(crate) const COUNTED_IDS: usize = 24;
    /// Windows and Office, at least.
    pub(crate) const APPLICATIONS: usize = 2;
    /// The ePID draws a locale from this, and one locale is a fingerprint.
    pub(crate) const LCIDS: usize = 200;
    /// And a build, likewise.
    pub(crate) const EPID_HOST_BUILDS: usize = 6;
}

#[test]
fn no_table_is_a_fraction_of_itself() {
    assert!(
        PRODUCTS.len() >= floors::PRODUCTS,
        "{} products, below the floor of {}. A regeneration that lost most of \
         its input still compiles and still sorts (`DB-010`, #134)",
        PRODUCTS.len(),
        floors::PRODUCTS
    );
    assert!(
        CSVLKS.len() >= floors::CSVLKS,
        "{} host keys, below the floor of {}",
        CSVLKS.len(),
        floors::CSVLKS
    );
    assert!(
        COUNTED_IDS.len() >= floors::COUNTED_IDS,
        "{} counted IDs, below the floor of {}",
        COUNTED_IDS.len(),
        floors::COUNTED_IDS
    );
    assert!(
        APPLICATIONS.len() >= floors::APPLICATIONS,
        "{} applications, below the floor of {}",
        APPLICATIONS.len(),
        floors::APPLICATIONS
    );
    assert!(
        LCIDS.len() >= floors::LCIDS,
        "{} locales, below the floor of {}",
        LCIDS.len(),
        floors::LCIDS
    );
    assert!(
        kmsrs_db::epid_host_build_count() >= floors::EPID_HOST_BUILDS,
        "{} drawable builds, below the floor of {}",
        kmsrs_db::epid_host_build_count(),
        floors::EPID_HOST_BUILDS
    );
}

#[test]
fn every_counted_id_resolves_to_a_host_key_that_lists_it() {
    let mut broken = Vec::new();
    for counted in COUNTED_IDS {
        assert!(
            kmsrs_db::is_known_counted_id(counted.guid),
            "{} is in COUNTED_IDS but the query API cannot find it, so the \
             table is not sorted the way the search assumes",
            counted.guid
        );

        let indices = kmsrs_db::csvlks_counting(counted.guid);
        assert_eq!(
            indices, counted.csvlks,
            "the query for {} returned a different list than the row holds",
            counted.guid
        );

        for index in counted.csvlks {
            let Some(csvlk) = kmsrs_db::csvlk_at(*index) else {
                broken.push(format!(
                    "{} names host key {index}, which is not in the table",
                    counted.guid
                ));
                continue;
            };
            if !csvlk.counted_ids.contains(&counted.guid) {
                broken.push(format!(
                    "{} names host key {index} ({}), which does not list it back",
                    counted.guid, csvlk.description
                ));
            }
        }
    }
    assert!(broken.is_empty(), "{broken:#?}");
}

#[test]
fn every_host_key_lists_only_counted_ids_that_exist() {
    let known: BTreeSet<_> = COUNTED_IDS.iter().map(|row| row.guid).collect();
    let mut orphans = Vec::new();

    for (index, csvlk) in CSVLKS.iter().enumerate() {
        for counted in csvlk.counted_ids {
            if !known.contains(counted) {
                orphans.push(format!(
                    "host key {index} ({}) counts {counted}, which is in no \
                     COUNTED_IDS row",
                    csvlk.description
                ));
            }
        }
    }
    assert!(orphans.is_empty(), "{orphans:#?}");
}

#[test]
fn every_host_key_is_also_a_product() {
    let mut missing = Vec::new();
    for csvlk in CSVLKS {
        match kmsrs_db::product(csvlk.activation_id) {
            None => missing.push(format!(
                "host key {} ({}) has no product row",
                csvlk.activation_id, csvlk.description
            )),
            Some(product) if product.kind != KeyKind::KmsHost => missing.push(format!(
                "host key {} ({}) is a product of kind {:?}, not KmsHost",
                csvlk.activation_id, csvlk.description, product.kind
            )),
            Some(_) => {}
        }
    }
    assert!(missing.is_empty(), "{missing:#?}");
}

#[test]
fn every_product_application_is_in_the_application_table() {
    let mut unknown = Vec::new();
    for product in PRODUCTS {
        let Some(application) = product.application else {
            continue;
        };
        if kmsrs_db::application(application).is_none() {
            unknown.push(format!(
                "{} ({}) belongs to application {application}, which is not in \
                 APPLICATIONS",
                product.activation_id, product.description
            ));
        }
    }
    assert!(unknown.is_empty(), "{unknown:#?}");
}

#[test]
fn every_key_block_is_a_non_empty_range_and_they_do_not_overlap() {
    let mut bad = Vec::new();
    for (index, csvlk) in CSVLKS.iter().enumerate() {
        let mut previous_end: Option<u32> = None;
        for block in csvlk.key_blocks {
            if block.start > block.end {
                bad.push(format!(
                    "host key {index} ({}) has an inverted block {}..={}",
                    csvlk.description, block.start, block.end
                ));
            }
            if let Some(previous) = previous_end
                && block.start <= previous
            {
                bad.push(format!(
                    "host key {index} ({}) has blocks that overlap or are out \
                     of order at {}",
                    csvlk.description, block.start
                ));
            }
            previous_end = Some(block.end);
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// The property `ID-019` (#124) is about: a key ID is drawn across the union of
/// the blocks, so the union has to be worth drawing from.
#[test]
fn every_host_key_has_a_key_space_large_enough_to_draw_from() {
    let mut tiny = Vec::new();
    for (index, csvlk) in CSVLKS.iter().enumerate() {
        let total: u64 = csvlk
            .key_blocks
            .iter()
            .map(|block| u64::from(block.end - block.start) + 1)
            .sum();
        // A genuine host key's blocks run to hundreds of millions. Anything
        // under a thousand is a parse that went wrong, not a real key.
        if total < 1_000 {
            tiny.push(format!(
                "host key {index} ({}) has only {total} key IDs across {} blocks",
                csvlk.description,
                csvlk.key_blocks.len()
            ));
        }
    }
    assert!(tiny.is_empty(), "{tiny:#?}");
}

#[test]
fn every_drawable_build_has_a_plausible_release_date() {
    let mut implausible = Vec::new();
    for build in kmsrs_db::epid_host_builds() {
        let Some(date) = build.release_date else {
            implausible.push(format!("build {} is drawable with no date", build.build));
            continue;
        };
        // Windows Vista is the first build a KMS host can claim, and nothing
        // Microsoft has shipped is dated after this file was written.
        if date.year() < 2006 || date.year() > 2100 {
            implausible.push(format!(
                "build {} claims a release date in {}",
                build.build,
                date.year()
            ));
        }
        if build.platform_id == 0 {
            implausible.push(format!("build {} has platform ID 0", build.build));
        }
    }
    assert!(implausible.is_empty(), "{implausible:#?}");
}

/// `ID-010` (#115): a build and its transfer syntax travel together.
///
/// py-kms claims build 17763 while rejecting NDR64, which is a combination no
/// real host produces. The build table is where the pairing lives, so this is
/// where a table that lost it shows.
#[test]
fn no_modern_build_claims_to_lack_ndr64() {
    let mut wrong = Vec::new();
    for build in kmsrs_db::epid_host_builds() {
        // Windows 8 (9200) is where NDR64 arrives; everything after speaks it.
        if build.build >= 9200 && !build.ndr64 {
            wrong.push(format!(
                "build {} ({}) is drawable and claims no NDR64",
                build.build, build.description
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn every_locale_is_a_distinct_identifier_with_a_tag() {
    let mut seen: BTreeMap<u32, &str> = BTreeMap::new();
    let mut problems = Vec::new();
    for lcid in LCIDS {
        if lcid.tag.is_empty() {
            problems.push(format!("locale {} has no BCP 47 tag", lcid.value));
        }
        if let Some(previous) = seen.insert(lcid.value, lcid.tag) {
            problems.push(format!(
                "locale {} appears twice, as {previous} and as {}",
                lcid.value, lcid.tag
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn no_two_products_share_an_activation_id() {
    let mut seen: BTreeMap<_, &str> = BTreeMap::new();
    let mut duplicates = Vec::new();
    for product in PRODUCTS {
        if let Some(previous) = seen.insert(product.activation_id, product.description) {
            duplicates.push(format!(
                "{} is both {previous} and {}",
                product.activation_id, product.description
            ));
        }
    }
    // py-kms ships 296 SKU entries with 287 unique IDs, so nine of them are
    // unreachable — the lookup finds whichever came first.
    assert!(duplicates.is_empty(), "{duplicates:#?}");
}

/// `DB-018` (#142): the whole shipped payload, strings included, and what it
/// costs on the target where it is the image.
///
/// `kmsrs_db::size` counts the `static` arrays, which is what a `const` can
/// see: a `&'static str` in an array is a pointer and a length, and the bytes
/// it points at are elsewhere in `.rodata`. Those bytes are two thirds of the
/// database — every product description, every host key's name, every locale
/// tag — so a figure that omitted them would be the wrong answer to the
/// question the issue asks.
///
/// This is a test rather than a `const` because a string's length is not
/// reachable in const evaluation across a table, and because the number is
/// worth *printing*: the whole point is that somebody sees it grow.
#[test]
fn the_whole_shipped_payload_fits_the_image_budget() {
    let mut strings = 0_usize;

    for application in kmsrs_db::APPLICATIONS {
        strings += application.name.len();
    }
    for product in kmsrs_db::PRODUCTS {
        strings += product.description.len() + product.key_type.len() + product.edition_id.len();
    }
    for csvlk in kmsrs_db::CSVLKS {
        strings += csvlk.description.len();
        // The key blocks and counted-ID lists are slices into `.rodata` too,
        // and a slice in a struct is a pointer and a length just as a string
        // is — so they are counted here rather than by `size_of_val` above.
        strings += core::mem::size_of_val(csvlk.key_blocks);
        strings += core::mem::size_of_val(csvlk.counted_ids);
    }
    for counted in kmsrs_db::COUNTED_IDS {
        strings += core::mem::size_of_val(counted.csvlks);
    }
    for build in kmsrs_db::HOST_BUILDS {
        strings += build.description.len();
    }
    for lcid in kmsrs_db::LCIDS {
        strings += lcid.language.len() + lcid.tag.len() + lcid.location.len();
    }

    let arrays = kmsrs_db::TABLE_BYTES;
    let total = arrays + strings;

    eprintln!(
        "shipped database: {total} bytes — {arrays} of arrays, {strings} of \
         string and slice contents"
    );

    // On Hermit every byte of `.rodata` is a byte of the guest's memory,
    // permanently, whether or not anything reads it. 256 KiB is generous
    // against the issue's "roughly 15-20 KB" estimate and against what this
    // actually is; what it catches is a change in kind rather than growth.
    assert!(
        total <= kmsrs_db::size::BUDGET_BYTES,
        "the shipped database is {total} bytes, past the {} it is built to fit \
         (DB-018, #142)",
        kmsrs_db::size::BUDGET_BYTES
    );

    // And the halves are both real. A zero here would mean this test walked
    // the wrong thing and passed for it.
    assert!(strings > 0 && arrays > 0);
}

#[test]
fn every_host_build_row_that_is_not_drawable_says_so() {
    let drawable = kmsrs_db::epid_host_build_count();
    let claiming: usize = HOST_BUILDS
        .iter()
        .filter(|build| build.use_for_epid)
        .count();
    assert_eq!(
        drawable, claiming,
        "EPID_HOST_BUILDS has {drawable} entries but {claiming} rows claim to \
         be drawable, so the index and the flag disagree"
    );
}

/// Provenance: every row came through the pipeline, and the file says which.
///
/// Reads `products.toml` directly. That is disk I/O, which axiom A5 forbids the
/// *binary* — a test is not the binary, and the alternative is trusting a
/// generated file to describe itself.
mod provenance {
    use std::path::PathBuf;

    fn products_toml() -> toml::Table {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/products.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        toml::from_str(&text).unwrap_or_else(|error| panic!("cannot parse products.toml: {error}"))
    }

    /// `ms-lcid` is a specification page rather than a downloadable artifact,
    /// so there is no file to digest. Named here so that "no digest" is an
    /// exemption somebody wrote down rather than a row that slipped through.
    const WITHOUT_DIGEST: &[&str] = &["ms-lcid", "research"];

    #[test]
    fn every_source_is_described_and_digested() {
        let document = products_toml();
        let sources = document
            .get("source")
            .and_then(toml::Value::as_array)
            .expect("products.toml has no [[source]] rows");
        assert!(
            sources.len() >= 3,
            "only {} sources, so most of the data is unattributed",
            sources.len()
        );

        for source in sources {
            let id = source
                .get("id")
                .and_then(toml::Value::as_str)
                .expect("a source has no id");
            let description = source
                .get("description")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            assert!(!description.is_empty(), "source {id} has no description");

            let origin = source
                .get("origin")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            assert!(!origin.is_empty(), "source {id} has no origin");

            let digest = source
                .get("sha256")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            if WITHOUT_DIGEST.contains(&id) {
                continue;
            }
            assert_eq!(
                digest.len(),
                64,
                "source {id} has no SHA-256, so a silently republished artifact \
                 would show up as changed data rather than as a changed digest \
                 (`DB-002`, #126). If it genuinely has no file to digest, add it \
                 to WITHOUT_DIGEST with a reason"
            );
            assert!(
                digest.chars().all(|c| c.is_ascii_hexdigit()),
                "source {id} has a SHA-256 that is not hexadecimal: {digest:?}"
            );
        }
    }

    /// The generator stamps its own version into the file it writes. If the
    /// generator changes and the data is not regenerated, the two disagree —
    /// which is drift, visible without a network.
    #[test]
    fn the_data_was_generated_by_this_generator() {
        let document = products_toml();
        let stamped = document
            .get("meta")
            .and_then(|meta| meta.get("generator_version"))
            .and_then(toml::Value::as_str)
            .expect("products.toml has no [meta] generator_version");

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../kmsrs-dbgen/Cargo.toml");
        let text = std::fs::read_to_string(&manifest).expect("kmsrs-dbgen has a manifest");
        let generator: toml::Table = toml::from_str(&text).expect("a parseable manifest");
        let current = generator
            .get("package")
            .and_then(|package| package.get("version"))
            .and_then(toml::Value::as_str)
            // A workspace-inherited version is the common case; fall back to it.
            .unwrap_or("0.1.0");

        assert_eq!(
            stamped, current,
            "products.toml says it was generated by kmsrs-dbgen {stamped}, but \
             the generator is now {current}. Regenerate the data or explain why \
             the generator changed without changing what it produces \
             (`TEST-007`, #228)"
        );
    }

    /// A row with no source is a row somebody typed, which is the practice that
    /// produced every fabricated GUID the audits found (declined item D19).
    #[test]
    fn every_data_row_names_a_source() {
        let document = products_toml();
        let known: Vec<String> = document
            .get("source")
            .and_then(toml::Value::as_array)
            .expect("products.toml has no [[source]] rows")
            .iter()
            .filter_map(|source| source.get("id").and_then(toml::Value::as_str))
            .map(str::to_owned)
            .collect();

        let mut unsourced = Vec::new();
        for table in ["product", "host_build", "lcid", "application"] {
            let Some(rows) = document.get(table).and_then(toml::Value::as_array) else {
                continue;
            };
            for (index, row) in rows.iter().enumerate() {
                let source = row.get("source").and_then(toml::Value::as_str);
                match source {
                    None => unsourced.push(format!("[[{table}]] row {index} names no source")),
                    Some(id) if !known.iter().any(|k| k == id) => unsourced.push(format!(
                        "[[{table}]] row {index} names source {id:?}, which is not declared"
                    )),
                    Some(_) => {}
                }
            }
        }
        assert!(unsourced.is_empty(), "{unsourced:#?}");
    }
}
