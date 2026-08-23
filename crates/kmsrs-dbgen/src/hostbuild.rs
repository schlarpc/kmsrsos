//! The curated host-build table (`DB-011`, #135).
//!
//! This is the one table in the database that no Microsoft artifact carries.
//! `PlatformId` appears in no published document and is not in `pkeyconfig`; it
//! was established by the research in `docs/research-findings.md` and
//! corroborated against two genuine ePIDs captured from real machines.
//!
//! It is a committed input rather than an extraction, and it goes through the
//! same pipeline so that it arrives in the generated file with a provenance
//! stamp saying exactly that — rather than appearing there from nowhere, which
//! is how every fabricated value in the fork catalogues got in.

use crate::error::{Context, Error, Result};
use crate::model::HostBuild;
use std::path::Path;

/// Read and validate the curated table.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed, if a build appears
/// twice, or if a build usable for an ePID has no release date.
pub fn load(path: &Path) -> Result<Vec<HostBuild>> {
    let text = std::fs::read_to_string(path).context(format!("reading {}", path.display()))?;
    let document: toml::Table =
        toml::from_str(&text).context(format!("parsing {}", path.display()))?;

    let rows = document
        .get("host_build")
        .and_then(toml::Value::as_array)
        .context(format!("{} has no [[host_build]] rows", path.display()))?;

    let mut builds = Vec::new();
    for row in rows {
        let number = row
            .get("build")
            .and_then(toml::Value::as_integer)
            .and_then(|value| u32::try_from(value).ok())
            .context("a [[host_build]] row has no usable build number")?;
        let platform_id = row
            .get("platform_id")
            .and_then(toml::Value::as_integer)
            .and_then(|value| u32::try_from(value).ok())
            .context(format!("build {number} has no usable platform_id"))?;
        let release_date = row
            .get("release_date")
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
        let use_for_epid = row
            .get("use_for_epid")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        let ndr64 = row
            .get("ndr64")
            .and_then(toml::Value::as_bool)
            .context(format!(
                "build {number} does not say whether it speaks NDR64"
            ))?;
        let description = row
            .get("description")
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_owned();

        if let Some(date) = &release_date {
            validate_date(date, number)?;
        } else if use_for_epid {
            // The release date is the lower bound for the randomised
            // activation date (`ID-007`, #112), so a build without one cannot
            // produce an ePID. Catching it here rather than at generation time
            // means the failure is a build failure with a name in it.
            return Err(Error::new(format!(
                "build {number} is marked use_for_epid but has no release_date"
            )));
        }

        builds.push(HostBuild {
            build: number,
            platform_id,
            release_date,
            use_for_epid,
            ndr64,
            description,
        });
    }

    builds.sort_by_key(|entry| entry.build);
    let mut previous: Option<u32> = None;
    for entry in &builds {
        if previous == Some(entry.build) {
            return Err(Error::new(format!("build {} appears twice", entry.build)));
        }
        previous = Some(entry.build);
    }

    // `ID-011` (#116): the set of builds an ePID may claim must be non-empty by
    // construction. vlmcsd achieves the same coupling with a `while (TRUE)`
    // loop that simply hangs at start-up when no build matches.
    if !builds.iter().any(|entry| entry.use_for_epid) {
        return Err(Error::new(
            "no host build is marked use_for_epid, so no ePID could ever be generated",
        ));
    }

    Ok(builds)
}

/// Check an ISO 8601 date.
///
/// Upstream shipped one with a colon where the `T` belongs, which is the class
/// of defect a shape check catches for nothing.
fn validate_date(date: &str, build: u32) -> Result<()> {
    let parts: Vec<&str> = date.split('-').collect();
    let widths = [4_usize, 2, 2];
    let shaped = parts.len() == widths.len()
        && parts
            .iter()
            .zip(widths.iter())
            .all(|(part, width)| part.len() == *width && part.chars().all(|c| c.is_ascii_digit()));
    if !shaped {
        return Err(Error::new(format!(
            "build {build} has release_date {date:?}, which is not YYYY-MM-DD"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code: a failed expectation should abort loudly"
    )]

    use super::load;
    use std::path::PathBuf;

    fn scratch(name: &str, contents: &str) -> PathBuf {
        let base = std::env::temp_dir().join("kmsrs-dbgen-hostbuild");
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    const GOOD: &str = r#"
[[host_build]]
build = 26100
platform_id = 3612
release_date = "2024-10-01"
use_for_epid = true
ndr64 = true
description = "Windows 11 24H2"

[[host_build]]
build = 7601
platform_id = 55041
release_date = "2011-02-22"
use_for_epid = true
ndr64 = false
description = "Windows 7 SP1"

[[host_build]]
build = 19041
platform_id = 3612
use_for_epid = false
ndr64 = true
description = "Windows 10 2004"
"#;

    #[test]
    fn a_well_formed_table_loads_sorted() {
        let builds = load(&scratch("good.toml", GOOD)).unwrap();
        assert_eq!(builds.len(), 3);
        assert_eq!(builds[0].build, 7601, "sorted by build number");
        assert_eq!(builds[0].platform_id, 55041);
        assert!(!builds[0].ndr64, "7601 predates NDR64");
        assert_eq!(builds[2].build, 26100);
        assert!(builds[2].ndr64);
        // A build not usable for an ePID may omit its date, and does.
        assert_eq!(builds[1].release_date, None);
        assert!(!builds[1].use_for_epid);
    }

    /// `ID-007` (#112): the release date is the lower bound for the randomised
    /// activation date, so a build that may produce an ePID must have one.
    #[test]
    fn a_build_usable_for_an_epid_must_have_a_release_date() {
        let broken = GOOD.replace("use_for_epid = false", "use_for_epid = true");
        let failure = load(&scratch("nodate.toml", &broken))
            .unwrap_err()
            .to_string();
        assert!(failure.contains("19041"), "{failure}");
        assert!(failure.contains("release_date"), "{failure}");
    }

    /// `ID-011` (#116). vlmcsd's equivalent coupling is a `while (TRUE)` loop
    /// that hangs at start-up when nothing matches; this is a build failure
    /// with a sentence in it.
    #[test]
    fn a_table_with_no_epid_build_is_refused() {
        let broken = GOOD.replace("use_for_epid = true", "use_for_epid = false");
        let failure = load(&scratch("noepid.toml", &broken))
            .unwrap_err()
            .to_string();
        assert!(failure.contains("use_for_epid"), "{failure}");
    }

    /// Upstream shipped a release date with a colon where the `T` belongs.
    #[test]
    fn a_malformed_release_date_is_refused() {
        for bad in ["2024:10-01", "2024-10", "24-10-01", "2024-1-1", "tomorrow"] {
            let broken = GOOD.replace("2024-10-01", bad);
            assert!(
                load(&scratch("baddate.toml", &broken)).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn a_duplicate_build_is_refused() {
        let broken = GOOD.replace("build = 7601", "build = 26100");
        let failure = load(&scratch("dup.toml", &broken)).unwrap_err().to_string();
        assert!(failure.contains("twice"), "{failure}");
    }

    #[test]
    fn a_missing_ndr64_column_is_refused() {
        let broken = GOOD.replace("ndr64 = true\ndescription = \"Windows 11 24H2\"", "");
        assert!(load(&scratch("nondr.toml", &broken)).is_err());
    }

    /// The table this project actually ships must load, and must agree with
    /// the research it came from.
    #[test]
    fn the_committed_table_loads() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/host-builds.toml");
        let builds = load(&path).unwrap();

        assert!(builds.len() >= 20, "{} builds", builds.len());

        let epid_builds: Vec<u32> = builds
            .iter()
            .filter(|entry| entry.use_for_epid)
            .map(|entry| entry.build)
            .collect();
        assert_eq!(
            epid_builds,
            [6002, 7601, 9200, 9600, 14393, 17763, 20348, 26100],
            "the UseForEpid rows from the research"
        );

        // PlatformId is 3612 for every build from 10240 onwards, which is the
        // finding the two genuine ePIDs corroborate.
        for entry in &builds {
            if entry.build >= 10240 {
                assert_eq!(entry.platform_id, 3612, "build {}", entry.build);
            }
        }

        // NDR64 begins at 9200, and the two builds before it must not claim it
        // — that pairing is what ID-010 (#115) makes unrepresentable.
        for entry in &builds {
            assert_eq!(entry.ndr64, entry.build >= 9200, "build {}", entry.build);
        }

        // Build 28000 is real, not speculation.
        assert!(builds.iter().any(|entry| entry.build == 28000));
    }
}
