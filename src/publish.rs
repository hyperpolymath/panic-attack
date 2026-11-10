// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! PROTOTYPE: publish a set of report files as one generation.
//!
//! Status: experimental, not wired into any subcommand. It exists to test
//! the design in `docs/design/GENERATION-PUBLISH.adoc` before anything uses
//! it. The design note records the open questions; the stress harness in
//! `examples/publish_stress.rs` holds the experiments.
//!
//! # Layout
//!
//! For a report named `S.json` in directory `D`:
//!
//! ```text
//! D/S.json, D/S.kyaml, ...       mirrors: regular files, hard links into the
//!                                current generation (copies where links fail)
//! D/S.gen/lock                   advisory lock taken by publishers
//! D/S.gen/CURRENT                JCS manifest naming the current generation
//!                                and the SHA-256 of each of its files
//! D/S.gen/<id>/S.json, ...       one complete generation per directory
//! D/S.gen/<id>.partial/          a generation still being written
//! ```
//!
//! # Protocol
//!
//! 1. `begin`: create `<id>.partial/`, `id` ordered by the run's start time.
//! 2. `write`: each file is created new inside it and synced.
//! 3. `publish`: sync the directory, rename it to `<id>` (complete), then
//!    under the lock: refuse if `CURRENT` names a newer generation, else
//!    write `CURRENT` by temp-file + rename, sync `S.gen`, refresh the
//!    mirrors by link + rename, and collect old generations.
//!
//! The invariants the protocol is meant to keep are stated in the design
//! note and model-checked with TLC in
//! `verification/proofs/tlaplus/GenerationPublish.tla` and, independently, by
//! the explicit-state checker in `tests/publish_model.rs`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Name of the pointer file inside the generation root.
pub const CURRENT: &str = "CURRENT";
const LOCK: &str = "lock";
const PARTIAL: &str = ".partial";

/// The `CURRENT` manifest: which generation is current, and what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The generation's directory name, which orders generations.
    pub generation: String,
    /// File name → lowercase hex SHA-256 of its bytes.
    pub files: BTreeMap<String, String>,
}

/// A current generation read whole: its manifest and each file's bytes.
pub type Snapshot = (Manifest, BTreeMap<String, Vec<u8>>);

/// What `publish` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This generation is now current.
    Published,
    /// A newer generation was already current; this one was not published.
    Superseded { current: String },
}

/// Options for `publish`.
#[derive(Debug, Clone)]
pub struct Options {
    /// Complete generations kept besides the current one.
    pub keep: usize,
    /// Partial generations older than this are treated as abandoned.
    pub partial_grace: Duration,
    /// Refresh the top-level mirrors after moving the pointer.
    pub mirror: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            keep: 1,
            partial_grace: Duration::from_secs(3600),
            mirror: true,
        }
    }
}

/// A generation being written.
#[derive(Debug)]
pub struct Generation {
    base_dir: PathBuf,
    root: PathBuf,
    id: String,
    partial: PathBuf,
    files: BTreeMap<String, String>,
}

/// The generation root for a report at `report`: `<stem>.gen` beside it.
pub fn root_for(report: &Path) -> PathBuf {
    let stem = report.file_stem().unwrap_or_default().to_string_lossy();
    parent_dir(report).join(format!("{stem}.gen"))
}

/// A new generation id: 16 hex digits of Unix nanoseconds at the run's
/// start, then 16 random hex digits. Ids sort by start time as strings.
pub fn new_id() -> io::Result<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos() as u64;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    Ok(format!("{nanos:016x}{}", hex::encode(random)))
}

impl Generation {
    /// Start a generation for the report at `report`, with id `id` (from
    /// [`new_id`], taken when the run started).
    pub fn begin(report: &Path, id: String) -> io::Result<Self> {
        let base_dir = parent_dir(report).to_path_buf();
        let root = root_for(report);
        fs::create_dir_all(&root)?;
        let partial = root.join(format!("{id}{PARTIAL}"));
        fs::create_dir(&partial)?;
        Ok(Self {
            base_dir,
            root,
            id,
            partial,
            files: BTreeMap::new(),
        })
    }

    /// The generation id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Write one file of the generation. `name` is a bare file name.
    pub fn write(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        if name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad file name"));
        }
        let path = self.partial.join(name);
        let mut file = new_file(&path, self.mode_of_current(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.files
            .insert(name.to_owned(), hex::encode(Sha256::digest(bytes)));
        Ok(())
    }

    /// The permission bits of `name` in the current generation, so a report
    /// made private stays private in the next one.
    fn mode_of_current(&self, name: &str) -> Option<u32> {
        let current = read_current(&self.root).ok()??;
        mode_of(&self.root.join(&current.generation).join(name))
    }

    /// Complete the generation and make it current unless a newer one is.
    pub fn publish(self, options: &Options) -> io::Result<Outcome> {
        sync_dir(&self.partial)?;
        let complete = self.root.join(&self.id);
        fs::rename(&self.partial, &complete)?;
        sync_dir(&self.root)?;

        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.root.join(LOCK))?;
        lock.lock()?;

        let outcome: io::Result<Outcome> = (|| {
            if let Some(current) = read_current(&self.root)? {
                if current.generation > self.id {
                    return Ok(Outcome::Superseded {
                        current: current.generation,
                    });
                }
            }
            let manifest = Manifest {
                generation: self.id.clone(),
                files: self.files.clone(),
            };
            let bytes = crate::json::to_canonical_string(&manifest).map_err(io::Error::other)?;
            replace_file(&self.root, CURRENT, bytes.as_bytes())?;
            if options.mirror {
                for name in self.files.keys() {
                    mirror(&complete.join(name), &self.base_dir, name)?;
                }
                sync_dir(&self.base_dir)?;
            }
            Ok(Outcome::Published)
        })();
        if let Ok(Outcome::Superseded { .. }) = &outcome {
            let _ = fs::remove_dir_all(&complete);
        }
        let collected = collect(&self.root, options);
        let _ = lock.unlock();
        let outcome = outcome?;
        collected?;
        Ok(outcome)
    }
}

/// Read the `CURRENT` manifest, or `None` before the first publish.
pub fn read_current(root: &Path) -> io::Result<Option<Manifest>> {
    match fs::read(root.join(CURRENT)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Read the whole current generation and check it against its manifest.
/// A reader that wants one consistent set of files uses this, not the
/// mirrors.
///
/// Readers take no lock. A generation can be collected between reading
/// `CURRENT` and opening its files, but only after a newer one became
/// current, so on "not found" the read starts again from `CURRENT`. It
/// gives up when `CURRENT` has not moved, since then the loss is real.
pub fn read_consistent(root: &Path) -> io::Result<Option<Snapshot>> {
    const ATTEMPTS: usize = 16;
    let mut last_error = None;
    for _ in 0..ATTEMPTS {
        let Some(manifest) = read_current(root)? else {
            return Ok(None);
        };
        match read_generation(root, &manifest) {
            Ok(files) => return Ok(Some((manifest, files))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let moved =
                    read_current(root)?.map(|m| m.generation) != Some(manifest.generation.clone());
                if !moved {
                    return Err(e);
                }
                last_error = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("generation kept moving")))
}

fn read_generation(root: &Path, manifest: &Manifest) -> io::Result<BTreeMap<String, Vec<u8>>> {
    let dir = root.join(&manifest.generation);
    let mut files = BTreeMap::new();
    for (name, digest) in &manifest.files {
        let mut bytes = Vec::new();
        File::open(dir.join(name))?.read_to_end(&mut bytes)?;
        if hex::encode(Sha256::digest(&bytes)) != *digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name} does not match the manifest"),
            ));
        }
        files.insert(name.clone(), bytes);
    }
    Ok(files)
}

/// Point `dir/name` at `target` by hard link + rename; copy + rename where
/// the filesystem refuses the link.
fn mirror(target: &Path, dir: &Path, name: &str) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.mirror", new_id()?));
    if fs::hard_link(target, &tmp).is_err() {
        fs::copy(target, &tmp)?;
        File::open(&tmp)?.sync_all()?;
    }
    fs::rename(&tmp, dir.join(name)).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Replace `dir/name` with `bytes` by temp file + rename, then sync `dir`.
fn replace_file(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", new_id()?));
    let result: io::Result<()> = (|| {
        let mut file = new_file(&tmp, None)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, dir.join(name))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    sync_dir(dir)
}

/// Remove complete generations beyond `keep` older ones, and partial ones
/// past the grace period. Never removes the current generation. Called
/// with the lock held, but other writers create and rename their own
/// generations without it, so an entry can vanish between listing and use:
/// that is treated as already gone, not as an error.
fn collect(root: &Path, options: &Options) -> io::Result<()> {
    let current = read_current(root)?.map(|m| m.generation);
    let mut complete = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let Some(file_type) = unless_gone(entry.file_type())? else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = name.strip_suffix(PARTIAL) {
            let Some(meta) = unless_gone(entry.metadata())? else {
                continue;
            };
            let age = meta.modified()?.elapsed().unwrap_or(Duration::ZERO);
            if age > options.partial_grace && Some(id) != current.as_deref() {
                unless_gone(fs::remove_dir_all(entry.path()))?;
            }
        } else {
            complete.push(name);
        }
    }
    complete.sort();
    let Some(current) = current else {
        return Ok(());
    };
    // Keep the current generation and the `keep` newest older than it.
    // Newer complete generations belong to writers waiting for the lock and
    // are left alone. An older one not yet published can only be superseded
    // (the pointer never moves backwards), so removing it is safe.
    let older: Vec<_> = complete.iter().filter(|g| **g < current).collect();
    let keep_from = older.len().saturating_sub(options.keep);
    for (i, g) in older.iter().enumerate() {
        if i < keep_from {
            unless_gone(fs::remove_dir_all(root.join(g)))?;
        }
    }
    Ok(())
}

/// `Ok(None)` for "not found", so a vanished entry is skipped.
fn unless_gone<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn new_file(path: &Path, mode: Option<u32>) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode.unwrap_or(0o666) & 0o777);
    }
    #[cfg(not(unix))]
    let _ = mode;
    options.open(path)
}

fn mode_of(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path).ok()?;
        meta.is_file().then(|| meta.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish_set(report: &Path, tag: &str) -> Outcome {
        let mut generation = Generation::begin(report, new_id().unwrap()).unwrap();
        generation
            .write("S.json", format!("{{\"run\":\"{tag}\"}}\n").as_bytes())
            .unwrap();
        generation
            .write("S.kyaml", format!("{{run: \"{tag}\"}}\n").as_bytes())
            .unwrap();
        generation.publish(&Options::default()).unwrap()
    }

    #[test]
    fn publishes_mirrors_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("S.json");
        assert_eq!(publish_set(&report, "a"), Outcome::Published);
        assert_eq!(fs::read_to_string(&report).unwrap(), "{\"run\":\"a\"}\n");
        let (manifest, files) = read_consistent(&root_for(&report)).unwrap().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(manifest.files.len(), 2);
        assert!(fs::symlink_metadata(&report).unwrap().is_file());
    }

    #[test]
    fn a_stale_generation_is_superseded() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("S.json");
        let old_id = new_id().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        publish_set(&report, "new");
        let mut stale = Generation::begin(&report, old_id).unwrap();
        stale.write("S.json", b"{\"run\":\"old\"}\n").unwrap();
        let outcome = stale.publish(&Options::default()).unwrap();
        assert!(matches!(outcome, Outcome::Superseded { .. }));
        assert_eq!(fs::read_to_string(&report).unwrap(), "{\"run\":\"new\"}\n");
    }

    #[test]
    fn keeps_current_and_one_older_generation() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("S.json");
        for tag in ["a", "b", "c", "d"] {
            publish_set(&report, tag);
        }
        let root = root_for(&report);
        let gens = fs::read_dir(&root)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_type().unwrap().is_dir())
            .count();
        assert_eq!(gens, 2);
    }

    #[cfg(unix)]
    #[test]
    fn a_private_report_stays_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("S.json");
        publish_set(&report, "a");
        fs::set_permissions(&report, fs::Permissions::from_mode(0o600)).unwrap();
        publish_set(&report, "b");
        let mode = fs::metadata(&report).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn collect_skips_generations_renamed_while_it_lists() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("S.json");
        publish_set(&report, "seed");
        let root = root_for(&report);
        let options = Options {
            partial_grace: Duration::ZERO,
            ..Options::default()
        };
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let renamer = {
            let (root, stop) = (root.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let id = new_id().unwrap();
                    let partial = root.join(format!("{id}{PARTIAL}"));
                    if fs::create_dir(&partial).is_ok() {
                        let _ = fs::rename(&partial, root.join(format!("{id}x")));
                        let _ = fs::remove_dir(root.join(format!("{id}x")));
                    }
                }
            })
        };
        let result = (0..20_000).try_for_each(|_| collect(&root, &options));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        renamer.join().unwrap();
        result.unwrap();
    }

    #[test]
    fn rejects_path_names() {
        let dir = tempfile::tempdir().unwrap();
        let mut generation =
            Generation::begin(&dir.path().join("S.json"), new_id().unwrap()).unwrap();
        assert!(generation.write("../x", b"").is_err());
        assert!(generation.write("..", b"").is_err());
    }
}
