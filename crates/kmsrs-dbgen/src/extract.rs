//! Turning a directory of artifacts into a [`Database`] (`DB-001`, #125).
//!
//! An input directory is one *source*: its name is the source identifier, and a
//! `SOURCE` file beside the artifacts records what it is and where it came from.
//! A directory without one is an error rather than a source with a blank
//! provenance stamp — unprovenanced data is exactly what this pipeline exists to
//! prevent (`DB-002`, #126).

use crate::error::{Context, Error, Result};
use crate::guid::Guid;
use crate::model::{Application, Database, KeyBlock, Product, Source};
use crate::xrm::{Artifact, Licence, parse_licence, parse_pkeyconfig, pkeyconfig_payload};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The three KMS application GUIDs, with the names we give them.
///
/// The GUIDs are extracted from the artifacts; only the labels are ours, because
/// the artifacts carry no display name for an application (`DB-014`, #138).
const APPLICATION_NAMES: [(&str, &str); 3] = [
    ("55c92734-d682-4d71-983e-d6ec3f16059f", "Windows"),
    ("59a52881-a989-479d-af46-f275c6370663", "Office 2010"),
    (
        "0ff1ce15-a989-479d-af46-f275c6370663",
        "Office 2013 and later",
    ),
];

/// Extract every artifact directory under `roots` into one database.
///
/// # Errors
///
/// Returns an error if a directory has no `SOURCE` file, if an artifact is
/// malformed, or if two sources disagree about the same CSVLK.
pub fn extract(roots: &[&Path]) -> Result<Database> {
    let mut database = Database::default();
    let mut licences_by_activation: BTreeMap<Guid, (Licence, String)> = BTreeMap::new();
    let mut ranges_by_activation: BTreeMap<Guid, Vec<KeyBlock>> = BTreeMap::new();
    let mut applications: BTreeMap<Guid, (String, String)> = BTreeMap::new();

    for root in roots {
        let mut source = read_source(root)?;
        let mut artifacts = collect_artifacts(root)?;
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        if artifacts.is_empty() {
            return Err(Error::new(format!(
                "{} contains no .xrm-ms artifacts",
                root.display()
            )));
        }

        let mut source_applications: BTreeSet<Guid> = BTreeSet::new();
        for artifact in &artifacts {
            absorb_pkeyconfig(
                artifact,
                &source.id,
                &mut database,
                &mut ranges_by_activation,
            )?;
            absorb_licence(
                artifact,
                &source.id,
                &mut source_applications,
                &mut applications,
                &mut licences_by_activation,
            )?;
        }

        // The one inference the pipeline makes, and the check that keeps it
        // sound: a source whose licences name two applications cannot have its
        // product table attributed to either (`DB-006`, #130).
        if source_applications.len() > 1 {
            return Err(Error::new(format!(
                "{} names {} applications, so its products cannot be attributed to one",
                source.id,
                source_applications.len()
            )));
        }
        source.application = source_applications.into_iter().next();
        database.sources.push(source);
    }

    let application_by_source: BTreeMap<String, Option<Guid>> = database
        .sources
        .iter()
        .map(|source| (source.id.clone(), source.application))
        .collect();

    for product in &mut database.products {
        if let Some(blocks) = ranges_by_activation.remove(&product.activation_id) {
            product.key_blocks = blocks;
        }
        if let Some((licence, licence_source)) = licences_by_activation.get(&product.activation_id)
        {
            product.counted_ids.clone_from(&licence.counted_ids);
            product.application = licence.application_id;
            product.cmid_expiration_minutes = licence.cmid_expiration_minutes;
            product.licence_source = Some(licence_source.clone());
        }
        if product.application.is_none() {
            product.application = application_by_source
                .get(&product.source)
                .copied()
                .flatten();
        }
    }

    database.applications = applications
        .into_iter()
        .map(|(guid, (name, source))| Application { guid, name, source })
        .collect();

    database.sort();
    Ok(database)
}

/// Absorb one artifact's licence fields, if it is a licence.
fn absorb_licence(
    artifact: &Artifact,
    source_id: &str,
    source_applications: &mut BTreeSet<Guid>,
    applications: &mut BTreeMap<Guid, (String, String)>,
    licences_by_activation: &mut BTreeMap<Guid, (Licence, String)>,
) -> Result<()> {
    let licence = parse_licence(&artifact.text).context(format!("in {}", artifact.name()))?;
    let Some(activation) = licence.product_sku_id else {
        return Ok(());
    };

    if let Some(application) = licence.application_id {
        source_applications.insert(application);
        applications.entry(application).or_insert_with(|| {
            let name = APPLICATION_NAMES
                .iter()
                .find(|(guid, _)| *guid == application.to_string())
                .map_or_else(
                    || "Unknown application".to_owned(),
                    |(_, name)| (*name).to_owned(),
                );
            (name, source_id.to_owned())
        });
    }

    // A CSVLK has several licence files (public, out-of-box, phone, store) and
    // they carry the same counted-ID list. Keep the first with a non-empty
    // list, so an empty placeholder does not displace real data.
    match licences_by_activation.entry(activation) {
        std::collections::btree_map::Entry::Vacant(slot) => {
            slot.insert((licence, source_id.to_owned()));
        }
        std::collections::btree_map::Entry::Occupied(mut slot) => {
            if slot.get().0.counted_ids.is_empty() && !licence.counted_ids.is_empty() {
                slot.insert((licence, source_id.to_owned()));
            }
        }
    }
    Ok(())
}

/// Absorb one artifact's pkeyconfig payload, if it has one.
///
/// Key ranges are collected separately from configurations because they are
/// siblings in the document rather than children, and a range may name a
/// configuration that appears later in the same file.
fn absorb_pkeyconfig(
    artifact: &Artifact,
    source_id: &str,
    database: &mut Database,
    ranges_by_activation: &mut BTreeMap<Guid, Vec<KeyBlock>>,
) -> Result<()> {
    let Some(payload) =
        pkeyconfig_payload(&artifact.text).context(format!("in {}", artifact.name()))?
    else {
        return Ok(());
    };
    let (configurations, ranges) =
        parse_pkeyconfig(&payload).context(format!("in {}", artifact.name()))?;

    for range in ranges {
        if !range.is_valid {
            continue;
        }
        ranges_by_activation
            .entry(range.activation_id)
            .or_default()
            .push(KeyBlock {
                part_number: range.part_number,
                start: range.start,
                end: range.end,
            });
    }

    for configuration in configurations {
        let existing = database
            .products
            .iter()
            .find(|product| product.activation_id == configuration.activation_id);
        if let Some(existing) = existing {
            // Two artifacts describing the same CSVLK must agree. Where py-kms
            // would take whichever it read last, a disagreement here means one
            // artifact is stale, and stopping is the only safe response
            // (`DB-006`, #130).
            if existing.group_id != configuration.group_id {
                return Err(Error::new(format!(
                    "{} gives group {} for CSVLK {}, but {} gave group {}",
                    artifact.name(),
                    configuration.group_id,
                    configuration.activation_id,
                    existing.source,
                    existing.group_id
                )));
            }
            continue;
        }
        database.products.push(Product {
            activation_id: configuration.activation_id,
            group_id: configuration.group_id,
            edition_id: configuration.edition_id,
            description: configuration.description,
            key_type: configuration.key_type,
            key_blocks: Vec::new(),
            application: None,
            counted_ids: Vec::new(),
            cmid_expiration_minutes: None,
            source: source_id.to_owned(),
            licence_source: None,
        });
    }

    Ok(())
}

/// Read the `SOURCE` file that stamps a directory's provenance.
fn read_source(root: &Path) -> Result<Source> {
    let id = root
        .file_name()
        .context(format!("{} has no directory name", root.display()))?
        .to_string_lossy()
        .into_owned();
    let path = root.join("SOURCE");
    let text = std::fs::read_to_string(&path).context(format!(
        "{} has no SOURCE file; every artifact directory must record what it is \
         and where it came from (DB-002, #126)",
        root.display()
    ))?;
    let mut lines = text.lines();
    let description = lines
        .next()
        .context(format!("{} is empty", path.display()))?
        .trim()
        .to_owned();
    let origin = lines
        .next()
        .context(format!("{} has no origin line", path.display()))?
        .trim()
        .to_owned();
    Ok(Source {
        id,
        description,
        origin,
        sha256: String::new(),
        application: None,
    })
}

/// Every `.xrm-ms` file under `root`, recursively.
fn collect_artifacts(root: &Path) -> Result<Vec<Artifact>> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries =
            std::fs::read_dir(&directory).context(format!("reading {}", directory.display()))?;
        for entry in entries {
            let entry = entry.context(format!("reading an entry of {}", directory.display()))?;
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("xrm-ms"))
            {
                found.push(Artifact::read(&path)?);
            }
        }
    }
    Ok(found)
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

    use super::extract;
    use std::path::Path;

    fn write(directory: &Path, name: &str, contents: &str) {
        std::fs::write(directory.join(name), contents).unwrap();
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join("kmsrs-dbgen-tests").join(name);
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn pkeyconfig_artifact(payload: &str) -> String {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
        format!(
            r#"<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2"><tm:infoBin name="pkeyConfigData">{encoded}</tm:infoBin></r:license>"#
        )
    }

    const CONFIG: &str = r#"<ProductKeyConfiguration xmlns="http://www.microsoft.com/DRM/PKEY/Configuration/2.0">
<Configurations><Configuration>
<ActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</ActConfigId>
<RefGroupId>4919</RefGroupId>
<EditionId>ServerDatacenter</EditionId>
<ProductDescription>Windows Server 2025</ProductDescription>
<ProductKeyType>Volume:CSVLK</ProductKeyType>
</Configuration></Configurations>
<KeyRanges>
<KeyRange><RefActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</RefActConfigId>
<PartNumber>A</PartNumber><IsValid>true</IsValid><Start>20000</Start><End>20019999</End></KeyRange>
<KeyRange><RefActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</RefActConfigId>
<PartNumber>B</PartNumber><IsValid>true</IsValid><Start>0</Start><End>19999</End></KeyRange>
<KeyRange><RefActConfigId>{84e331f6-4279-48c4-ab10-b75139181351}</RefActConfigId>
<PartNumber>C</PartNumber><IsValid>false</IsValid><Start>900000</Start><End>999999</End></KeyRange>
</KeyRanges></ProductKeyConfiguration>"#;

    const LICENCE: &str = r##"<r:license xmlns:r="urn:mpeg:mpeg21:2003:01-REL-R-NS"
 xmlns:sl="http://www.microsoft.com/DRM/XrML2/SL/v2" xmlns:tm="http://www.microsoft.com/DRM/XrML2/TM/v2">
<tm:infoTables><tm:infoList tag="#global">
<tm:infoStr name="productSkuId">{84e331f6-4279-48c4-ab10-b75139181351}</tm:infoStr>
<tm:infoStr name="applicationId">{55c92734-d682-4d71-983e-d6ec3f16059f}</tm:infoStr>
</tm:infoList></tm:infoTables>
<sl:productPolicies>
<sl:policyInt name="Security-SPP-CMIDExpirationPeriod">43200</sl:policyInt>
<sl:policyStr name="Security-SPP-KmsCountedIdList">{907f1f65-adcd-4a2e-95bc-4bf500bc6e58}</sl:policyStr>
</sl:productPolicies></r:license>"##;

    #[test]
    fn a_pkeyconfig_and_its_licence_are_joined_on_the_activation_id() {
        let directory = scratch("join");
        write(
            &directory,
            "SOURCE",
            "Windows Server 2025\nmcr.microsoft.com/...\n",
        );
        write(
            &directory,
            "pkeyconfig-csvlk.xrm-ms",
            &pkeyconfig_artifact(CONFIG),
        );
        write(&directory, "csvlk-2-pl-rtm.xrm-ms", LICENCE);

        let database = extract(&[&directory]).unwrap();
        assert_eq!(database.products.len(), 1);
        let product = &database.products[0];

        assert_eq!(product.group_id, 4919);
        assert_eq!(
            product.application.unwrap().to_string(),
            "55c92734-d682-4d71-983e-d6ec3f16059f"
        );
        assert_eq!(product.counted_ids.len(), 1);
        assert_eq!(
            product.counted_ids[0].to_string(),
            "907f1f65-adcd-4a2e-95bc-4bf500bc6e58"
        );
        assert_eq!(product.cmid_expiration_minutes, Some(43200));

        // The join is on productSkuId, not on the file name: "csvlk-2" means
        // nothing and the number is not stable between images.
        assert_eq!(product.source, "join");
        assert_eq!(product.licence_source.as_deref(), Some("join"));

        // Applications come from the artifacts, with our labels.
        assert_eq!(database.applications.len(), 1);
        assert_eq!(database.applications[0].name, "Windows");
    }

    /// `ID-019` (#124): blocks are kept separate and sorted, and an invalid
    /// range is dropped rather than merged in.
    #[test]
    fn key_blocks_are_sorted_and_invalid_ranges_are_dropped() {
        let directory = scratch("blocks");
        write(&directory, "SOURCE", "d\no\n");
        write(
            &directory,
            "pkeyconfig-csvlk.xrm-ms",
            &pkeyconfig_artifact(CONFIG),
        );

        let database = extract(&[&directory]).unwrap();
        let blocks = &database.products[0].key_blocks;
        assert_eq!(blocks.len(), 2, "the IsValid=false range must not appear");
        assert_eq!((blocks[0].start, blocks[0].end), (0, 19999));
        assert_eq!((blocks[1].start, blocks[1].end), (20_000, 20_019_999));
    }

    /// `DB-002` (#126): a directory with no provenance stamp is an error.
    #[test]
    fn an_unprovenanced_directory_is_refused() {
        let directory = scratch("unprovenanced");
        write(
            &directory,
            "pkeyconfig-csvlk.xrm-ms",
            &pkeyconfig_artifact(CONFIG),
        );
        let failure = extract(&[&directory]).unwrap_err().to_string();
        assert!(failure.contains("SOURCE"), "{failure}");
    }

    #[test]
    fn a_directory_with_no_artifacts_is_refused() {
        let directory = scratch("empty");
        write(&directory, "SOURCE", "d\no\n");
        assert!(extract(&[&directory]).is_err());
    }

    /// `DB-006` (#130): two artifacts that disagree about a CSVLK stop the
    /// pipeline. Taking whichever was read last is how a stale artifact silently
    /// overwrites current data.
    #[test]
    fn sources_that_disagree_about_a_csvlk_stop_the_pipeline() {
        let first = scratch("agree-a");
        write(&first, "SOURCE", "d\no\n");
        write(
            &first,
            "pkeyconfig-csvlk.xrm-ms",
            &pkeyconfig_artifact(CONFIG),
        );

        let second = scratch("agree-b");
        write(&second, "SOURCE", "d\no\n");
        write(
            &second,
            "pkeyconfig-csvlk.xrm-ms",
            &pkeyconfig_artifact(&CONFIG.replace("4919", "9194")),
        );

        let failure = extract(&[&first, &second]).unwrap_err().to_string();
        assert!(failure.contains("group"), "{failure}");
    }
}
