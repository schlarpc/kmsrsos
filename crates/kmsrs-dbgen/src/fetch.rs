//! Fetching the artifacts (`DB-001`, #125).
//!
//! Both sources are public and need no credentials, which is what makes the
//! pipeline reproducible rather than a story about what somebody once did on
//! their own machine:
//!
//! * **Windows** — `pkeyconfig-csvlk.xrm-ms` and the `spp\tokens\skus` tree,
//!   streamed out of a `mcr.microsoft.com/windows/servercore` image. The
//!   registry serves these anonymously.
//! * **Office** — `pkeyconfig-office-kmshost.xrm-ms` and the KMS host licences,
//!   from the freely downloadable Volume License Pack, which is a
//!   self-extracting executable wrapped around a CAB.
//!
//! The Windows layer is about 1.5 GB. It is streamed through gzip and tar
//! without ever being written to disk, and only the hundred or so licensing
//! artifacts are kept.

use crate::error::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read as _;
use std::path::Path;

/// Media types a Docker/OCI registry may answer a manifest request with.
const MANIFEST_ACCEPT: &str = "application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.oci.image.manifest.v1+json";

/// Whether a path inside a Windows image is a licensing artifact worth keeping.
fn is_licensing_artifact(path: &str) -> bool {
    let lowered = path.to_ascii_lowercase();
    if !lowered.ends_with(".xrm-ms") {
        return false;
    }
    lowered.contains("pkeyconfig")
        || lowered.contains("/spp/tokens/")
        || lowered.contains("\\spp\\tokens\\")
}

/// Stream a `servercore` image's layers and keep the licensing artifacts.
///
/// # Errors
///
/// Returns an error if the registry cannot be reached, the manifest has no
/// Windows/amd64 entry, or a layer cannot be decompressed.
pub fn fetch_windows_image(registry_reference: &str, into: &Path) -> Result<usize> {
    let (host, repository, tag) = split_reference(registry_reference)?;

    let index = get_json(&format!("https://{host}/v2/{repository}/manifests/{tag}"))?;
    let manifest_digest = if let Some(manifests) = index.get("manifests").and_then(|v| v.as_array())
    {
        manifests
            .iter()
            .find(|entry| {
                entry
                    .get("platform")
                    .and_then(|platform| platform.get("os"))
                    .and_then(|os| os.as_str())
                    == Some("windows")
            })
            .and_then(|entry| entry.get("digest"))
            .and_then(|digest| digest.as_str())
            .map(str::to_owned)
            .context("manifest list has no windows entry")?
    } else {
        tag.to_owned()
    };

    let manifest = get_json(&format!(
        "https://{host}/v2/{repository}/manifests/{manifest_digest}"
    ))?;
    let layers = manifest
        .get("layers")
        .and_then(|layers| layers.as_array())
        .context("manifest has no layers")?;

    std::fs::create_dir_all(into).context(format!("creating {}", into.display()))?;

    let mut kept = 0_usize;
    for layer in layers {
        let digest = layer
            .get("digest")
            .and_then(|digest| digest.as_str())
            .context("layer without a digest")?;
        let url = format!("https://{host}/v2/{repository}/blobs/{digest}");
        eprintln!("fetching layer {digest}");

        let body = ureq::get(&url)
            .call()
            .context(format!("fetching {url}"))?
            .into_body()
            .into_reader();
        let decoder = flate2::read::GzDecoder::new(body);
        let mut archive = tar::Archive::new(decoder);
        let entries = archive.entries().context("reading layer tar")?;

        for entry in entries {
            let mut entry = entry.context("reading a tar entry")?;
            // A Windows layer is full of hardlink and directory entries. They
            // carry no data, so reading one yields an empty file that later
            // fails to parse as XML — a confusing way to discover a tar detail.
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path().context("tar entry with an unreadable path")?;
            let path = path.to_string_lossy().into_owned();
            if !is_licensing_artifact(&path) {
                continue;
            }
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .context(format!("reading {path}"))?;

            // The directory structure is preserved rather than flattened to
            // base names: `client-issuance-ul.xrm-ms` exists in more than one
            // token directory, and flattening silently lets one overwrite the
            // other.
            let destination = into.join(relative_destination(&path));
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)
                    .context(format!("creating {}", parent.display()))?;
            }
            std::fs::write(&destination, &bytes)
                .context(format!("writing {}", destination.display()))?;
            kept = kept.saturating_add(1);
        }
    }

    Ok(kept)
}

/// Download a Volume License Pack and extract its `.xrm-ms` files.
///
/// The download is a self-extracting executable: a PE with a CAB appended. The
/// CAB is located by its `MSCF` magic rather than by a hardcoded offset, because
/// the offset moves whenever the stub is rebuilt.
///
/// # Errors
///
/// Returns an error if the download fails, no CAB is found, or the CAB cannot be
/// read.
pub fn fetch_office_pack(url: &str, into: &Path) -> Result<(usize, String)> {
    let mut bytes = Vec::new();
    ureq::get(url)
        .call()
        .context(format!("fetching {url}"))?
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .context("reading the download body")?;
    let digest = hex::encode(Sha256::digest(&bytes));

    let start = find_cabinet(&bytes).context("no CAB found in the downloaded executable")?;
    let cabinet_bytes = bytes.get(start..).unwrap_or_default().to_vec();
    let mut cabinet =
        cab::Cabinet::new(std::io::Cursor::new(cabinet_bytes)).context("opening the CAB")?;

    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|file| file.name().to_owned())
        .filter(|name| name.to_ascii_lowercase().ends_with(".xrm-ms"))
        .collect();

    std::fs::create_dir_all(into).context(format!("creating {}", into.display()))?;
    let mut kept = 0_usize;
    for name in names {
        let mut reader = cabinet
            .read_file(&name)
            .context(format!("reading {name} from the CAB"))?;
        let mut contents = Vec::new();
        reader
            .read_to_end(&mut contents)
            .context(format!("decompressing {name}"))?;
        std::fs::write(into.join(name.to_ascii_lowercase()), &contents)
            .context(format!("writing {name}"))?;
        kept = kept.saturating_add(1);
    }

    Ok((kept, digest))
}

/// Turn an in-image path into a safe relative path under the artifact
/// directory.
///
/// Components are lowercased for stability across image revisions, and `.` and
/// `..` are dropped so that a hostile archive cannot write outside the
/// destination.
fn relative_destination(path: &str) -> std::path::PathBuf {
    path.split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != "." && *component != "..")
        // Windows layers root everything under `Files/`, which adds a level of
        // nesting to every path and tells a reader nothing.
        .skip_while(|component| component.eq_ignore_ascii_case("Files"))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Find the offset of the `MSCF` cabinet header.
fn find_cabinet(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"MSCF")
}

/// Split `host/repository:tag` into its parts.
fn split_reference(reference: &str) -> Result<(&str, &str, &str)> {
    let (host, rest) = reference
        .split_once('/')
        .context(format!("{reference} is not host/repository:tag"))?;
    let (repository, tag) = rest
        .split_once(':')
        .context(format!("{reference} is not host/repository:tag"))?;
    Ok((host, repository, tag))
}

/// Fetch a URL and parse the body as JSON.
fn get_json(url: &str) -> Result<serde_json::Value> {
    let body = ureq::get(url)
        .header("Accept", MANIFEST_ACCEPT)
        .call()
        .context(format!("fetching {url}"))?
        .into_body()
        .read_to_string()
        .context(format!("reading {url}"))?;
    serde_json::from_str(&body).context(format!("parsing {url} as JSON"))
}

/// Compute the digest of every artifact in a directory, combined.
///
/// One digest per source rather than per file: the source is what a reviewer
/// reasons about, and a per-file list would be a hundred lines of noise in the
/// committed data file.
///
/// # Errors
///
/// Returns an error if the directory cannot be read.
pub fn directory_digest(directory: &Path) -> Result<String> {
    let mut paths = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in
            std::fs::read_dir(&current).context(format!("reading {}", current.display()))?
        {
            let path = entry
                .context(format!("reading an entry of {}", current.display()))?
                .path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("xrm-ms"))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();

    let mut hasher = Sha256::new();
    for path in paths {
        // The path relative to the source directory is part of the digest: two
        // artifacts with the same base name in different token directories are
        // different artifacts.
        let relative = path.strip_prefix(directory).unwrap_or(&path);
        hasher.update(relative.to_string_lossy().as_bytes());
        hasher.update(std::fs::read(&path).context(format!("reading {}", path.display()))?);
    }
    Ok(hex::encode(hasher.finalize()))
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

    use super::{find_cabinet, is_licensing_artifact, split_reference};

    #[test]
    fn only_licensing_artifacts_are_kept() {
        assert!(is_licensing_artifact(
            "Files/Windows/System32/spp/tokens/pkeyconfig/pkeyconfig-csvlk.xrm-ms"
        ));
        assert!(is_licensing_artifact(
            "Files/Windows/System32/spp/tokens/skus/csvlk-pack/csvlk-pack-volume-csvlk-2-pl-rtm.xrm-ms"
        ));
        assert!(is_licensing_artifact(
            r"Files\Windows\System32\spp\tokens\x.xrm-ms"
        ));

        assert!(!is_licensing_artifact(
            "Files/Windows/System32/kernel32.dll"
        ));
        assert!(!is_licensing_artifact(
            "Files/Windows/spp/tokens/readme.txt"
        ));
        // An .xrm-ms outside the licensing trees: there are thousands of
        // unrelated ones in a Windows image, and keeping them all would turn a
        // 4 MB extract into something unreviewable.
        assert!(!is_licensing_artifact(
            "Files/Windows/Something/other.xrm-ms"
        ));
    }

    /// Base names collide across token directories, so the structure is kept.
    /// The traversal filter matters because a tar is an untrusted archive even
    /// when it came from Microsoft.
    #[test]
    fn destinations_keep_their_structure_and_cannot_escape() {
        use std::path::PathBuf;

        assert_eq!(
            super::relative_destination(
                "Files/Windows/System32/spp/tokens/skus/csvlk-pack/CSVLK-2-PL.xrm-ms"
            ),
            PathBuf::from("windows/system32/spp/tokens/skus/csvlk-pack/csvlk-2-pl.xrm-ms")
        );
        assert_eq!(
            super::relative_destination(r"Files\Windows\System32\spp\tokens\x.xrm-ms"),
            PathBuf::from("windows/system32/spp/tokens/x.xrm-ms")
        );
        assert_eq!(
            super::relative_destination("../../etc/passwd"),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(
            super::relative_destination("/absolute/./path"),
            PathBuf::from("absolute/path")
        );
    }

    #[test]
    fn the_cab_is_located_by_magic_not_by_offset() {
        let mut file = vec![0x4D_u8, 0x5A]; // "MZ", a PE stub
        file.extend_from_slice(&[0_u8; 64]);
        file.extend_from_slice(b"MSCF");
        file.extend_from_slice(&[1_u8; 8]);
        assert_eq!(find_cabinet(&file), Some(66));
        assert_eq!(find_cabinet(b"no cabinet here"), None);
    }

    #[test]
    fn registry_references_split_into_host_repository_and_tag() {
        assert_eq!(
            split_reference("mcr.microsoft.com/windows/servercore:ltsc2025").unwrap(),
            ("mcr.microsoft.com", "windows/servercore", "ltsc2025")
        );
        assert!(split_reference("servercore").is_err());
        assert!(split_reference("mcr.microsoft.com/windows/servercore").is_err());
    }
}
