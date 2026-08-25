//! `kmsrs-dbgen` command-line entry point (`DB-001`, #125).
//!
//! Three commands, run by hand or on a schedule — never during a build
//! (`DB-002`, #126). A build that reached out to a registry would not be
//! hermetic, and a data change that appeared without a pull request would not be
//! reviewable.
//!
//! ```text
//! kmsrs-dbgen fetch      [--into <dir>]
//! kmsrs-dbgen extract    [--from <dir>] [--out <file>]
//! kmsrs-dbgen regenerate [--into <dir>] [--out <file>]
//! ```
//!
//! Argument parsing here is deliberately unlike the server's, which has none at
//! all (`CFG-007`, #172). This is a host-only development tool; the no-argv rule
//! is about a service whose configuration must be decided when it is built.

use kmsrs_dbgen::error::{Context, Error, Result};
use kmsrs_dbgen::{
    GENERATOR_VERSION, Origin, SOURCES, emit, extract, fetch, gvlk, hostbuild, lcid,
};
use sha2::Digest as _;
use std::path::{Path, PathBuf};

/// Where artifacts are cached, relative to the workspace root.
const DEFAULT_ARTIFACT_DIR: &str = "crates/kmsrs-dbgen/artifacts";

/// Where the generated data file is written, relative to the workspace root.
const DEFAULT_OUTPUT: &str = "crates/kmsrs-db/data/products.toml";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kmsrs-dbgen: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map_or("help", String::as_str);
    let artifact_dir = PathBuf::from(option(&arguments, "--into").unwrap_or(DEFAULT_ARTIFACT_DIR));
    let output = PathBuf::from(option(&arguments, "--out").unwrap_or(DEFAULT_OUTPUT));
    let from = option(&arguments, "--from").map(PathBuf::from);

    match command {
        "fetch" => fetch_all(&artifact_dir, option(&arguments, "--only")),
        "extract" => extract_all(from.as_deref().unwrap_or(&artifact_dir), &output),
        "regenerate" => {
            fetch_all(&artifact_dir, option(&arguments, "--only"))?;
            extract_all(&artifact_dir, &output)
        }
        "help" | "--help" | "-h" => {
            println!(
                "kmsrs-dbgen {GENERATOR_VERSION}\n\n\
                   fetch      [--into <dir>] [--only <id>]    download the artifacts\n\
                   extract    [--from <dir>] [--out <file>]  parse them into products.toml\n\
                   regenerate [--into <dir>] [--out <file>]  both\n"
            );
            Ok(())
        }
        other => Err(Error::new(format!(
            "unknown command {other:?}; try `kmsrs-dbgen help`"
        ))),
    }
}

/// The value following `flag`, if present.
fn option<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    let position = arguments.iter().position(|argument| argument == flag)?;
    arguments.get(position.checked_add(1)?).map(String::as_str)
}

/// Download every source into its own directory and stamp its provenance.
///
/// `only` narrows it to one source id. Adding an image to [`SOURCES`] otherwise
/// means re-downloading every other one — about 1.5 GB each — to get the one
/// that changed, which is enough friction to discourage adding any
/// (`DB-018`, #286).
fn fetch_all(into: &Path, only: Option<&str>) -> Result<()> {
    if let Some(id) = only
        && !SOURCES.iter().any(|source| source.id == id)
    {
        return Err(Error::new(format!(
            "no source called {id:?}; SOURCES has {}",
            SOURCES
                .iter()
                .map(|source| source.id)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    for source in SOURCES {
        if only.is_some_and(|id| id != source.id) {
            continue;
        }
        let directory = into.join(source.id);
        eprintln!("fetching {} into {}", source.id, directory.display());
        std::fs::create_dir_all(&directory).context(format!("creating {}", directory.display()))?;

        let kept = match source.origin {
            Origin::ContainerImage { reference } => {
                fetch::fetch_windows_image(reference, &directory)?
            }
            Origin::Download { url } => fetch::fetch_office_pack(url, &directory)?.0,
            // Fetched during extraction rather than here: neither produces
            // `.xrm-ms` artifacts, so there is nothing to cache in a directory.
            Origin::Specification { .. } | Origin::Curated { .. } => {
                let _ = std::fs::remove_dir(&directory);
                continue;
            }
        };
        if kept == 0 {
            return Err(Error::new(format!(
                "{} yielded no artifacts; the source has probably moved",
                source.id
            )));
        }

        // The SOURCE file is what `extract` reads to stamp every row. Writing it
        // here, rather than expecting a human to, is what stops an
        // unprovenanced directory existing in the first place (`DB-002`, #126).
        std::fs::write(
            directory.join("SOURCE"),
            format!("{}\n{}\n", source.description, source.origin.as_text()),
        )
        .context("writing the SOURCE stamp")?;

        eprintln!("  kept {kept} artifacts");
    }
    Ok(())
}

/// Parse every artifact directory and write the data file.
fn extract_all(from: &Path, output: &Path) -> Result<()> {
    // Ordered by [`SOURCES`], oldest image first, **not** by directory name.
    //
    // The order decides which artifact wins when two describe the same product,
    // because `absorb_pkeyconfig` keeps the first and errors on a disagreement
    // it cannot reconcile (`DB-006`, #130). Sorting by name made that
    // `windows-server-2019` before `windows-server-2025` — the right answer, by
    // accident of the digits. Naming the next image `win2012` would silently
    // reverse it.
    //
    // Oldest-first is the rule because it makes a product's `source` mean *the
    // earliest image that contained it*, which is exactly the bound `DB-018`
    // (#286) needs: a key that first appears in the 2019 image cannot have been
    // installed on a host older than that build.
    let mut directories: Vec<PathBuf> = std::fs::read_dir(from)
        .context(format!("reading {}", from.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    directories.sort_by_key(|path| {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Position in `SOURCES`, then the name, so a directory the list does
        // not know about is still ordered deterministically rather than
        // wherever the filesystem put it.
        (
            SOURCES
                .iter()
                .position(|source| source.id == name)
                .unwrap_or(usize::MAX),
            name,
        )
    });
    if directories.is_empty() {
        return Err(Error::new(format!(
            "{} has no artifact directories; run `kmsrs-dbgen fetch` first",
            from.display()
        )));
    }

    let borrowed: Vec<&Path> = directories.iter().map(PathBuf::as_path).collect();
    let mut database = extract::extract(&borrowed)?;

    // The two sources that are not artifact directories. Both are recorded as
    // sources so every row they produce is stamped (`DB-002`, #126).
    for source in SOURCES {
        match source.origin {
            Origin::Specification { url } => {
                eprintln!("fetching {}", source.id);
                // Dispatched on the source id rather than on the order of this
                // list. There is more than one specification page now
                // (`DB-013`, #137), and a positional assumption is the kind
                // that keeps compiling after a source is inserted above it.
                match source.id {
                    "ms-lcid" => database.lcids = lcid::fetch(url)?,
                    "ms-gvlk-windows" | "ms-gvlk-office" => {
                        database.gvlks.extend(gvlk::fetch(url, source.id)?);
                    }
                    other => {
                        return Err(Error::new(format!(
                            "no parser is wired up for the specification source \
                             {other:?}; add one in `extract_all`"
                        )));
                    }
                }
                database.sources.push(kmsrs_dbgen::model::Source {
                    id: source.id.to_owned(),
                    description: source.description.to_owned(),
                    origin: url.to_owned(),
                    sha256: String::new(),
                    application: None,
                });
            }
            Origin::Curated { path } => {
                let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
                database.host_builds = hostbuild::load(&path)?;
                database.sources.push(kmsrs_dbgen::model::Source {
                    id: source.id.to_owned(),
                    description: source.description.to_owned(),
                    origin: format!(
                        "committed at crates/kmsrs-dbgen/{}",
                        path.file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    ),
                    sha256: hex::encode(sha2::Sha256::digest(
                        std::fs::read(&path).context("reading the curated table")?,
                    )),
                    application: None,
                });
            }
            Origin::ContainerImage { .. } | Origin::Download { .. } => {}
        }
    }

    for source in &mut database.sources {
        if source.sha256.is_empty() && from.join(&source.id).is_dir() {
            source.sha256 = fetch::directory_digest(&from.join(&source.id))?;
        }
    }
    database.sort();

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).context(format!("creating {}", parent.display()))?;
    }
    let rendered = emit::to_toml(&database, GENERATOR_VERSION);
    std::fs::write(output, &rendered).context(format!("writing {}", output.display()))?;

    eprintln!(
        "wrote {} ({} sources, {} applications, {} products, {} counted IDs, \
         {} host builds, {} locales, {} GVLKs)",
        output.display(),
        database.sources.len(),
        database.applications.len(),
        database.products.len(),
        database
            .products
            .iter()
            .map(|product| product.counted_ids.len())
            .sum::<usize>(),
        database.host_builds.len(),
        database.lcids.len(),
        database.gvlks.len()
    );
    Ok(())
}
