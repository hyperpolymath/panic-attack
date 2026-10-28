// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Lockfile parsers — extracts locked dependencies from Cargo.lock, mix.lock,
//! package-lock.json, and requirements.txt for CVE feed queries.

use super::LockedDependency;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ============================================================================
// Discovery
// ============================================================================

/// A lockfile name the bridge understands, paired with its parser.
type LockfileParser = fn(&Path) -> Result<Vec<LockedDependency>>;

/// Every lockfile kind the bridge reads, in parse order. The base name is the
/// only thing discovery keys on — a `Cargo.lock` by any other name is not
/// parsed, even when passed explicitly via `--lockfile`.
const LOCKFILE_KINDS: &[(&str, LockfileParser)] = &[
    ("Cargo.lock", parse_cargo_lock),
    ("mix.lock", parse_mix_lock),
    ("package-lock.json", parse_package_lock_json),
    ("requirements.txt", parse_requirements_txt),
];

/// Human-readable list of supported lockfiles, for error messages.
pub const SUPPORTED_LOCKFILES: &str =
    "Cargo.lock (Rust), mix.lock (Elixir), package-lock.json (npm), requirements.txt (Python)";

/// Directories the recursive search does not descend into.
///
/// A lockfile under one of these describes somebody else's dependency graph
/// (a vendored or installed copy) or a stale duplicate of this project's own,
/// so reading it would report vulnerabilities the project cannot ship. Kept
/// aligned with `bridge::reachability`'s scan exclusions, plus the build and
/// package caches that are known to hold copied lockfiles.
const LOCKFILE_SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".yarn",
    "vendor",
    "deps",
    "_deps",
    "_build",
    "build",
    "dist",
    "out",
    "obj",
    "zig-cache",
    ".zig-cache",
    "zig-out",
    ".stack-work",
    "dist-newstyle",
    "__pycache__",
    ".venv",
    "venv",
    ".elixir_ls",
    ".lexical",
    ".machine_readable",
    "external_corpora",
    "third_party",
    "corpus",
];

/// What lockfile discovery found for one project.
///
/// The two empty-dependency states are kept apart on purpose:
///
/// - `lockfiles` empty → nothing was found, so the project's dependency
///   surface is **unknown** (callers report an error).
/// - `lockfiles` non-empty, `dependencies` empty → the project has a lockfile
///   that declares no external dependencies, which is a **complete answer**
///   for a dependency-free project (see `BridgeReport::empty`).
#[derive(Debug, Clone, Default)]
pub struct LockfileDiscovery {
    /// Lockfiles found on disk (or named with `--lockfile`), sorted by path so
    /// a run is reproducible.
    pub lockfiles: Vec<PathBuf>,
    /// The union of the dependencies those lockfiles declare, de-duplicated by
    /// `(ecosystem, name, version)`. `declared_by` on each entry holds the
    /// lockfile paths as supplied by the walker or explicit command-line input.
    pub dependencies: Vec<LockedDependency>,
    /// Lockfiles that exist but could not be parsed.
    ///
    /// Discovery treats these as warnings — one malformed lockfile should not
    /// abort triage of a whole project — but a caller that needs full coverage
    /// must check this list: a lockfile that failed to parse contributes
    /// nothing to `dependencies`, so a zero count here is not "clean".
    pub unreadable: Vec<PathBuf>,
}

impl LockfileDiscovery {
    /// Whether any recognised lockfile was found at all.
    pub fn has_lockfiles(&self) -> bool {
        !self.lockfiles.is_empty()
    }

    /// Whether no external dependency was declared by any readable lockfile.
    ///
    /// Also true when no lockfiles were found or all failed to parse; check
    /// `lockfiles` and `unreadable` before treating this as dependency-free.
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty()
    }

    /// Number of distinct locked dependencies.
    pub fn len(&self) -> usize {
        self.dependencies.len()
    }
}

/// Discover and parse every lockfile under `dir`, recursively.
///
/// Lockfiles in workspace or monorepo member directories
/// (`src/rust/Cargo.lock`, `frontend/package-lock.json`) are discovered without
/// any flag. Use [`parse_lockfiles`] (the `--lockfile` flag) to name files
/// explicitly, or [`discover_and_parse_root_only`] to pin the search to `dir`.
///
/// Uses the exclusions of [`lockfile_paths`]. Successful parses are merged by
/// ecosystem, name and version. Parse errors are logged as warnings and
/// recorded in [`LockfileDiscovery::unreadable`] rather than returned; callers
/// must inspect that list before treating an empty result as complete.
///
/// # Errors
/// Returns directory traversal errors because an incomplete walk cannot
/// establish dependency coverage.
pub fn discover_and_parse(dir: &Path) -> Result<LockfileDiscovery> {
    discover_from(dir, true)
}

/// As [`discover_and_parse`], but `dir` alone is searched — the pre-0.3
/// behaviour. Kept for callers that must not pick up a nested sub-project.
pub fn discover_and_parse_root_only(dir: &Path) -> Result<LockfileDiscovery> {
    discover_from(dir, false)
}

/// Collect dependencies and parse failures from [`lockfile_paths`].
fn discover_from(dir: &Path, recursive: bool) -> Result<LockfileDiscovery> {
    Ok(parse_found(lockfile_paths(dir, recursive)?))
}

/// Paths of the lockfiles under `dir`, sorted and de-duplicated.
///
/// With `recursive = false`, checks only `dir` itself. Recursive searches skip
/// nested build, vendor and cache names in `LOCKFILE_SKIP_DIRS`. Only recognised
/// base names are included.
///
/// # Errors
/// Returns directory traversal or file metadata errors rather than reporting
/// an incomplete search as an empty result.
pub fn lockfile_paths(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let names: Vec<&str> = LOCKFILE_KINDS.iter().map(|(name, _)| *name).collect();
    let mut found: Vec<PathBuf> = Vec::new();

    if recursive {
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| e.depth() == 0 || !is_skipped_dir(e.path()))
        {
            let entry = entry.with_context(|| format!("Failed to traverse {}", dir.display()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| names.contains(&n))
            {
                continue;
            }
            found.push(path.to_path_buf());
        }
    } else {
        for name in names {
            let path = dir.join(name);
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => found.push(path),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("Failed to inspect {}", path.display()))
                }
            }
        }
    }

    found.sort();
    found.dedup();
    Ok(found)
}

/// Parse exactly these lockfiles, with no searching.
///
/// This is the `--lockfile` path, and it is deliberately stricter than
/// discovery: a lockfile the user named that is missing, unrecognised, or
/// unparseable is an error. Silently dropping it would turn "could not read"
/// into "no dependencies", which is the failure mode this API exists to avoid.
///
/// Dependencies are merged by ecosystem, name and version and tagged with the
/// supplied paths. The returned `lockfiles` list retains those paths, including
/// files with no external dependencies.
///
/// # Errors
/// Returns an error if a path is missing, is not a file, has an unsupported base
/// name, or its parser fails to read or parse it.
pub fn parse_lockfiles(paths: &[PathBuf]) -> Result<LockfileDiscovery> {
    let mut discovery = LockfileDiscovery::default();

    for path in paths {
        if !path.is_file() {
            anyhow::bail!(
                "lockfile not found or not a file: {} (supported: {})",
                path.display(),
                SUPPORTED_LOCKFILES
            );
        }
        let Some(deps) = parse_one(path)? else {
            anyhow::bail!(
                "unsupported lockfile: {} (recognised base names: {})",
                path.display(),
                SUPPORTED_LOCKFILES
            );
        };
        discovery.push(path, deps);
    }

    discovery.finish();
    Ok(discovery)
}

/// Merge parsed dependencies, retaining all supplied paths in `lockfiles` and
/// recording parser errors in `unreadable` rather than returning them.
fn parse_found(paths: Vec<PathBuf>) -> LockfileDiscovery {
    let mut discovery = LockfileDiscovery::default();

    for path in paths {
        discovery.lockfiles.push(path.clone());
        match parse_one(&path) {
            Ok(Some(deps)) => discovery.push(&path, deps),
            // Do not count a discovered file as valid if no parser handled it.
            Ok(None) => discovery.unreadable.push(path),
            Err(e) => {
                log::warn!("[bridge] Failed to parse {}: {}", path.display(), e);
                discovery.unreadable.push(path);
            }
        }
    }

    discovery.finish();
    discovery
}

impl LockfileDiscovery {
    /// Build Cargo reachability context using the root manifest and each
    /// discovered Cargo.lock's neighbouring manifest/workspace. Parent graphs
    /// use their own direct dependencies so independent workspaces do not
    /// accidentally create dependency paths across lockfiles.
    pub(super) fn cargo_context(
        &self,
        project_dir: &Path,
    ) -> (
        std::collections::HashSet<String>,
        std::collections::HashMap<String, String>,
    ) {
        let mut direct = collect_direct_cargo_dependencies(project_dir);
        let mut parents = std::collections::HashMap::new();
        for path in &self.lockfiles {
            if path.file_name().is_none_or(|name| name != "Cargo.lock") {
                continue;
            }
            let Some(dir) = path.parent() else {
                continue;
            };
            let local_direct = collect_direct_cargo_dependencies(dir);
            for (child, parent) in collect_cargo_parents(dir, &local_direct) {
                parents.entry(child).or_insert(parent);
            }
            direct.extend(local_direct);
        }
        (direct, parents)
    }

    /// Record one parsed lockfile's dependencies, each tagged with the lockfile
    /// it came from.
    fn push(&mut self, lockfile: &Path, deps: Vec<LockedDependency>) {
        self.lockfiles.push(lockfile.to_path_buf());
        for mut dep in deps {
            dep.declared_by = vec![lockfile.to_path_buf()];
            self.dependencies.push(dep);
        }
    }

    /// Merge lockfiles that declare the same package version in an ecosystem,
    /// so a dependency shared by several members of a workspace is queried once
    /// and lists every lockfile that declares it.
    /// Sort and de-duplicate the `lockfiles` and `unreadable` path lists.
    fn finish(&mut self) {
        let mut seen: std::collections::HashMap<(String, String, String), usize> =
            std::collections::HashMap::new();
        let mut merged: Vec<LockedDependency> = Vec::with_capacity(self.dependencies.len());

        for dep in self.dependencies.drain(..) {
            let key = (dep.ecosystem.clone(), dep.name.clone(), dep.version.clone());
            match seen.get(&key) {
                Some(&at) => {
                    for path in dep.declared_by {
                        if !merged[at].declared_by.contains(&path) {
                            merged[at].declared_by.push(path);
                        }
                    }
                }
                None => {
                    seen.insert(key, merged.len());
                    merged.push(dep);
                }
            }
        }

        self.dependencies = merged;
        self.lockfiles.sort();
        self.lockfiles.dedup();
        self.unreadable.sort();
        self.unreadable.dedup();
    }
}

/// Whether a lockfile name is one we read, and which parser handles it.
fn parser_for(path: &Path) -> Option<LockfileParser> {
    let name = path.file_name().and_then(|n| n.to_str())?;
    LOCKFILE_KINDS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, parser)| *parser)
}

/// Parse a supported base name, returning `Ok(None)` for an unrecognised name.
///
/// # Errors
/// Propagates the selected parser's read and format errors.
fn parse_one(path: &Path) -> Result<Option<Vec<LockedDependency>>> {
    match parser_for(path) {
        Some(parser) => parser(path).map(Some),
        None => Ok(None),
    }
}

/// Whether the final component of `path` matches an excluded directory name.
fn is_skipped_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    LOCKFILE_SKIP_DIRS.contains(&name)
}

// ============================================================================
// Cargo.lock (Rust / crates.io)
// ============================================================================

/// Parse a Cargo.lock file into a list of locked dependencies.
///
/// Reads Cargo.lock v3/v4 package entries whose source contains `registry`.
/// Returns an empty list if no such packages are present.
///
/// # Errors
/// Returns file-read, UTF-8 or TOML parse errors, or an error if the top-level
/// version is unsupported, the package structure is invalid, or a package lacks
/// a non-empty string name or version, even if it is skipped. An invalid source
/// field is also an error.
pub fn parse_cargo_lock(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let document: toml_edit::DocumentMut = content
        .parse()
        .with_context(|| format!("Parsing {}", path.display()))?;
    if !matches!(
        document.get("version").and_then(|v| v.as_integer()),
        Some(3 | 4)
    ) {
        anyhow::bail!(
            "{} is not a supported Cargo.lock (expected version = 3 or 4)",
            path.display()
        );
    }
    let mut deps = Vec::new();
    let Some(packages) = document.get("package") else {
        // The supported version header alone describes a valid empty lockfile.
        if document.iter().any(|(key, _)| key != "version") {
            anyhow::bail!("{} has no package array", path.display());
        }
        return Ok(deps);
    };
    let packages = packages
        .as_array_of_tables()
        .with_context(|| format!("{} has an invalid package array", path.display()))?;
    for package in packages {
        let name = package
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .with_context(|| format!("{} contains a package without a name", path.display()))?;
        let version = package
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .with_context(|| format!("{} contains a package without a version", path.display()))?;
        let source =
            match package.get("source") {
                Some(source) => Some(source.as_str().with_context(|| {
                    format!("{} has an invalid package source", path.display())
                })?),
                None => None,
            };
        if source.is_some_and(|s| s.contains("registry")) {
            deps.push(LockedDependency {
                name: name.to_string(),
                version: version.to_string(),
                ecosystem: "crates.io".to_string(),
                declared_by: Vec::new(),
            });
        }
    }

    Ok(deps)
}

// ============================================================================
// mix.lock (Elixir / Hex)
// ============================================================================

/// Parse a mix.lock file into a list of locked Hex dependencies.
///
/// mix.lock uses Elixir term syntax. Each entry looks like:
/// ```text
/// "package": {:hex, :package, "1.2.3", "checksum", ...},
/// ```
/// We parse lines that match this pattern by string scanning (not a full
/// Elixir parser). Git and path dependencies are excluded.
pub fn parse_mix_lock(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let body = content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let body = body
        .trim()
        .strip_prefix("%{")
        .and_then(|s| s.trim_end().strip_suffix('}'))
        .with_context(|| format!("{} is not a supported mix.lock map", path.display()))?;
    let mut deps = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry = line.trim_end_matches(',').trim();
        let (key, value) = entry
            .split_once(':')
            .with_context(|| format!("{} contains an invalid mix.lock entry", path.display()))?;
        let quoted_key = key.trim();
        let value = value.trim();
        if quoted_key.len() < 3
            || !quoted_key.starts_with('"')
            || !quoted_key.ends_with('"')
            || !balanced_mix_tuple(value)
        {
            anyhow::bail!("{} contains an invalid mix.lock entry", path.display());
        }
        if value.starts_with("{:hex,") {
            deps.push(parse_mix_lock_line(entry).with_context(|| {
                format!("{} contains an invalid Hex dependency", path.display())
            })?);
        } else if !value.starts_with("{:git,") && !value.starts_with("{:path,") {
            anyhow::bail!("{} contains an unsupported mix.lock entry", path.display());
        }
    }

    Ok(deps)
}

// Validate nested tuple/list delimiters without evaluating Elixir input.
fn balanced_mix_tuple(value: &str) -> bool {
    if !value.starts_with('{') || !value.ends_with('}') {
        return false;
    }
    let mut stack = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in value.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' if stack.pop() != Some(ch) => return false,
            _ => {}
        }
    }
    !quoted && stack.is_empty()
}

/// Parse a single mix.lock entry line into a LockedDependency.
///
/// Returns None for git/path/non-hex entries.
fn parse_mix_lock_line(line: &str) -> Option<LockedDependency> {
    // Expect:  "name": {:hex, :atom, "version", ...}
    let (key_part, value_part) = line.split_once(':')?;

    // Extract outer name (the map key)
    let name = key_part.trim().trim_matches('"').to_string();
    if name.is_empty() {
        return None;
    }

    // Only process Hex packages — value starts with {:hex,
    let value = value_part.trim();
    if !value.starts_with("{:hex,") {
        return None;
    }

    // Extract version: third comma-separated field inside the tuple, quoted
    // {:hex, :cowboy, "2.10.0", ...}
    let inner = value.trim_start_matches('{').trim_end_matches('}');
    let fields: Vec<&str> = inner.splitn(4, ',').collect();
    if fields.len() < 3 {
        return None;
    }

    let version = fields[2]
        .trim()
        .strip_prefix('"')?
        .strip_suffix('"')?
        .to_string();
    if version.is_empty() || version.starts_with(':') {
        return None;
    }

    Some(LockedDependency {
        name,
        version,
        ecosystem: "Hex".to_string(),
        declared_by: Vec::new(),
    })
}

// ============================================================================
// package-lock.json (npm / Node.js)
// ============================================================================

/// Parse a package-lock.json file (npm lockfile v2/v3) into locked deps.
///
/// npm lockfile v2/v3 uses a flat `packages` map where each key is
/// `node_modules/<name>` and the value has a `version` field. We skip the
/// root entry (empty key) and workspace links. Entries must declare versions.
pub fn parse_package_lock_json(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let root: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "Parsing package-lock.json")?;

    let version = root
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .with_context(|| format!("{} has no lockfileVersion", path.display()))?;
    let mut deps = Vec::new();
    match version {
        2 | 3 => {
            let packages = root
                .get("packages")
                .and_then(|v| v.as_object())
                .with_context(|| format!("{} has no packages object", path.display()))?;
            for (key, pkg) in packages {
                if !pkg.is_object() {
                    anyhow::bail!("Invalid npm package entry: {key}");
                }
                if key.is_empty() {
                    continue;
                }
                // Workspace targets live outside node_modules; links point to them.
                if pkg.get("link").and_then(|v| v.as_bool()) == Some(true) {
                    continue;
                }
                let version = pkg
                    .get("version")
                    .and_then(|v| v.as_str())
                    .filter(|v| !v.is_empty())
                    .with_context(|| format!("npm package {key} has no version"))?;
                if !key.starts_with("node_modules/") {
                    continue;
                }
                let name = key.trim_start_matches("node_modules/");
                if name.is_empty() {
                    anyhow::bail!("Invalid npm package path: {key}");
                }
                deps.push(LockedDependency {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: "npm".to_string(),
                    declared_by: Vec::new(),
                });
            }
        }
        1 => {
            // npm v1 omits `dependencies` when the project has none.
            if let Some(dependencies) = root.get("dependencies") {
                let dependencies = dependencies.as_object().with_context(|| {
                    format!("{} has an invalid dependencies object", path.display())
                })?;
                collect_npm_v1_dependencies(dependencies, &mut deps)?;
            }
        }
        _ => anyhow::bail!("Unsupported npm lockfileVersion: {version}"),
    }

    Ok(deps)
}

fn collect_npm_v1_dependencies(
    packages: &serde_json::Map<String, serde_json::Value>,
    deps: &mut Vec<LockedDependency>,
) -> Result<()> {
    for (name, pkg) in packages {
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
            .with_context(|| format!("npm package {name} has no version"))?;
        if name.is_empty() {
            anyhow::bail!("Empty npm dependency name");
        }
        deps.push(LockedDependency {
            name: name.clone(),
            version: version.to_string(),
            ecosystem: "npm".to_string(),
            declared_by: Vec::new(),
        });
        if let Some(children) = pkg.get("dependencies") {
            let children = children
                .as_object()
                .context("Invalid nested npm dependencies")?;
            collect_npm_v1_dependencies(children, deps)?;
        }
    }
    Ok(())
}

// ============================================================================
// requirements.txt (Python / PyPI)
// ============================================================================

/// Parse a requirements.txt file into locked PyPI dependencies.
///
/// Handles pinned deps (`package==1.2.3`), extras (`pkg[extra]==1.2.3`),
/// and ignores git/URL requirements, comments, and environment markers.
/// Only `==` pins produce reliable version-exact OSV queries; `>=`/`~=`
/// entries are skipped because they represent ranges, not locked versions.
/// Non-empty files with no supported pins return an error rather than claiming
/// the project has no dependencies.
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();
    let mut has_unlocked_entries = false;

    for line in content.lines() {
        // Strip inline comments and whitespace
        let line = line.trim();
        let line = if let Some(idx) = line.find('#') {
            line[..idx].trim()
        } else {
            line
        };

        if line.is_empty() {
            continue;
        }
        if line.starts_with('-') || line.starts_with("git+") {
            has_unlocked_entries = true;
            continue;
        }

        // Only handle exact pins (==) for reliable CVE matching
        if let Some((pkg_part, version)) = line.split_once("==") {
            // Strip extras: requests[security]==2.28.0 → requests
            let name = pkg_part
                .trim()
                .split('[')
                .next()
                .unwrap_or(pkg_part.trim())
                .trim()
                .to_lowercase();

            // Strip environment markers from version: 1.2.3; python_version >= "3.8"
            let version = version
                .split(';')
                .next()
                .unwrap_or(version)
                .trim()
                .to_string();

            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                || version.is_empty()
                || version.contains(['=', '<', '>', '~', '!', ' '])
            {
                anyhow::bail!("{} contains an invalid requirement pin", path.display());
            }
            if version.contains('*') {
                has_unlocked_entries = true;
            } else {
                deps.push(LockedDependency {
                    name,
                    version,
                    ecosystem: "PyPI".to_string(),
                    declared_by: Vec::new(),
                });
            }
        } else {
            has_unlocked_entries = true;
        }
    }
    if deps.is_empty() && has_unlocked_entries {
        anyhow::bail!(
            "{} contains no supported exact requirement pins",
            path.display()
        );
    }

    Ok(deps)
}

// ============================================================================
// Helpers
// ============================================================================

/// Remove surrounding quotes from a TOML value string.
fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

// ============================================================================
// Direct-dependency detection (Cargo.toml)
// ============================================================================

/// Collect the set of crate names declared as **direct** dependencies in the
/// project's `Cargo.toml`. Used to distinguish direct phantoms (genuine
/// "remove the unused dep" candidates) from transitive phantoms (pulled in
/// by an upstream crate — different remediation path).
///
/// Sections inspected (root manifest + each workspace.member manifest):
///
/// - `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`
/// - `[workspace.dependencies]`
/// - `[target.X.dependencies]`, `[target.X.dev-dependencies]`, `[target.X.build-dependencies]`
///
/// Names are normalised to lowercase with `_` → `-` so a CVE feed reporting
/// `serde_json` matches a manifest line `serde-json = ...` and vice versa.
///
/// Best-effort parser: handles plain `crate = "version"` and `crate = { ... }`
/// table forms. Quoted keys (`"crate-name" = ...`) are supported. Lines
/// inside comments (`# ...`) are skipped.
///
/// Returns an empty set on parse failure — callers should treat that as
/// "unknown direct-deps", falling back to the conservative (transitive)
/// classification rather than asserting "direct".
pub fn collect_direct_cargo_dependencies(project_dir: &Path) -> std::collections::HashSet<String> {
    let mut acc = std::collections::HashSet::new();
    collect_from_manifest(&project_dir.join("Cargo.toml"), &mut acc, project_dir);
    acc
}

fn collect_from_manifest(
    manifest: &Path,
    acc: &mut std::collections::HashSet<String>,
    project_dir: &Path,
) {
    let Ok(content) = std::fs::read_to_string(manifest) else {
        return;
    };

    let mut current_section: Option<String> = None;
    let mut workspace_members: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        // Strip inline comments (`key = "val" # note`). Be careful: a `#`
        // inside a quoted string is data, not a comment. Single quotes don't
        // matter in TOML. For our use, the strict version below is enough.
        let line = strip_toml_inline_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Section header?
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_section = Some(name.trim().to_string());
            continue;
        }

        let Some(section) = current_section.as_deref() else {
            continue;
        };

        if is_dependency_section(section) {
            if let Some(crate_name) = extract_dependency_key(trimmed) {
                acc.insert(normalise_crate_name(&crate_name));
            }
        } else if section == "workspace" {
            // members = ["a", "b/c"]
            if let Some(members) = parse_workspace_members(trimmed) {
                workspace_members.extend(members);
            }
        }
    }

    // Recurse into workspace members (one level — we don't support nested
    // workspaces, which are not a real Cargo pattern).
    for member in workspace_members {
        let member_manifest = project_dir.join(&member).join("Cargo.toml");
        if member_manifest.exists() && member_manifest != manifest {
            collect_from_manifest(&member_manifest, acc, project_dir);
        }
    }
}

fn is_dependency_section(section: &str) -> bool {
    // Direct matches
    matches!(
        section,
        "dependencies" | "dev-dependencies" | "build-dependencies" | "workspace.dependencies"
    ) || section.ends_with(".dependencies")
        || section.ends_with(".dev-dependencies")
        || section.ends_with(".build-dependencies")
}

fn extract_dependency_key(line: &str) -> Option<String> {
    // Lines look like one of:
    //   serde = "1.0"
    //   serde = { version = "1.0", features = ["derive"] }
    //   "serde-json" = "1.0"
    // We only care about the LHS of the first `=`.
    let eq = line.find('=')?;
    let lhs = line[..eq].trim();
    let key = lhs.trim_matches('"').trim_matches('\'').trim();
    if key.is_empty() {
        return None;
    }
    // Reject obviously-not-a-crate-name tokens that can appear in nested
    // tables (e.g. `version`, `features`, `default-features`). These would
    // only appear here if a section line is malformed; the section-header
    // check normally keeps us out of nested-table bodies, but a paranoid
    // filter is cheap.
    if key.contains(char::is_whitespace) || key.contains('.') {
        return None;
    }
    Some(key.to_string())
}

fn parse_workspace_members(line: &str) -> Option<Vec<String>> {
    let lhs = line.split('=').next()?.trim();
    if lhs != "members" {
        return None;
    }
    let rhs = line.split_once('=')?.1.trim();
    let inner = rhs
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))?;
    Some(
        inner
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn strip_toml_inline_comment(line: &str) -> &str {
    // Conservative: only strip when the `#` is NOT inside a "..." string.
    let bytes = line.as_bytes();
    let mut in_string = false;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' {
            in_string = !in_string;
        } else if b == b'#' && !in_string {
            return &line[..i];
        }
    }
    line
}

fn normalise_crate_name(s: &str) -> String {
    s.to_ascii_lowercase().replace('_', "-")
}

// ============================================================================
// Parent-dependency identification (Cargo.lock)
// ============================================================================

/// For each transitive crate in `Cargo.lock`, identify the direct dependency
/// (from `direct_deps`) whose closure pulls it in. Best-effort.
///
/// Walks the resolution tree starting from each direct dep, marking every
/// reachable crate with that direct dep as its parent. First match wins
/// (BFS order), so a crate appearing under multiple direct deps gets
/// attributed to whichever one's BFS reaches it first — a heuristic, but
/// fine for "what to bump" recommendations on the common case (~26 of 29
/// Track E issues).
///
/// Returns a map keyed by normalised crate name (lowercase, hyphens) → name
/// of the direct dep (also normalised). Direct deps themselves are NOT
/// included in the map; they're the start of the walk, not transitives.
///
/// If `Cargo.lock` is missing or unparseable, returns an empty map. Callers
/// that need parent info should fall back to the generic "an upstream
/// parent dependency" phrasing in [`crate::bridge::classify`].
pub fn collect_cargo_parents(
    project_dir: &Path,
    direct_deps: &std::collections::HashSet<String>,
) -> std::collections::HashMap<String, String> {
    let lock_path = project_dir.join("Cargo.lock");
    let Ok(content) = std::fs::read_to_string(&lock_path) else {
        return std::collections::HashMap::new();
    };

    // First pass: build child-list per package from `[[package]]` blocks.
    // Each block has `name = "..."` and optionally `dependencies = [ ... ]`.
    // We collect names in their CARGO form (lockfile spelling), then
    // normalise when storing in the map so lookups match the rest of the
    // codebase. Dependency lines inside the array look like:
    //   "serde",
    //   "serde 1.0.200",
    //   "serde 1.0.200 (registry+https://...)",
    let mut children: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    let mut current_name: Option<String> = None;
    let mut in_dep_block = false;
    let mut current_deps: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            // Flush previous package's deps before starting a new one.
            if let Some(name) = current_name.take() {
                children
                    .entry(normalise_crate_name(&name))
                    .or_default()
                    .extend(current_deps.drain(..).map(|d| normalise_crate_name(&d)));
            }
            in_dep_block = false;
            current_deps.clear();
            continue;
        }

        if in_dep_block {
            if trimmed == "]" {
                in_dep_block = false;
                continue;
            }
            // Lines look like `"serde",` or `"serde 1.0.200",` — strip
            // the quote, then take the first whitespace-separated token
            // as the crate name. Version + source suffix are discarded.
            let stripped = trimmed.trim_end_matches(',').trim().trim_matches('"');
            if stripped.is_empty() {
                continue;
            }
            if let Some(name_token) = stripped.split_whitespace().next() {
                current_deps.push(name_token.to_string());
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote(rest));
        } else if trimmed == "dependencies = [" {
            in_dep_block = true;
        }
    }
    // Final package flush.
    if let Some(name) = current_name {
        children
            .entry(normalise_crate_name(&name))
            .or_default()
            .extend(current_deps.into_iter().map(|d| normalise_crate_name(&d)));
    }

    // Second pass: BFS from each direct dep, attributing every reachable
    // transitive crate to that direct dep. First-write-wins keeps the BFS
    // order stable and avoids re-attribution flapping.
    let mut parent: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    for direct in direct_deps {
        let direct_norm = normalise_crate_name(direct);
        let mut queue: std::collections::VecDeque<String> =
            std::collections::VecDeque::from([direct_norm.clone()]);
        // Each direct dep gets its own visited set so two direct deps
        // sharing a transitive both have a chance to attribute it (the
        // first BFS to reach the crate wins, which is what we want).
        while let Some(node) = queue.pop_front() {
            if !visited.insert(node.clone()) {
                continue;
            }
            if let Some(deps) = children.get(&node) {
                for child in deps {
                    // Don't overwrite a direct dep with its own attribution,
                    // and don't claim another direct dep as a transitive.
                    if direct_deps.contains(child) {
                        continue;
                    }
                    parent
                        .entry(child.clone())
                        .or_insert_with(|| direct_norm.clone());
                    queue.push_back(child.clone());
                }
            }
        }
    }

    parent
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_cargo_lock_basic() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "my-project"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "anyhow"
version = "1.0.86"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def456"
"#
        )
        .unwrap();

        let deps = parse_cargo_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, "1.0.200");
        assert_eq!(deps[0].ecosystem, "crates.io");
        assert_eq!(deps[1].name, "anyhow");
    }

    #[test]
    fn test_skips_local_packages() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"version = 4
[[package]]
name = "my-local-dep"
version = "0.1.0"
"#
        )
        .unwrap();

        let deps = parse_cargo_lock(tmp.path()).unwrap();
        assert!(
            deps.is_empty(),
            "Local packages (no source) should be skipped"
        );
    }

    #[test]
    fn test_parse_mix_lock_basic() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        tmp.write_all(
            b"%{\n\"cowboy\": {:hex, :cowboy, \"2.10.0\", \"abc123\", [:rebar3], [{:cowlib, \"~> 2.12.1\", [hex: :cowlib, repo: \"hexpm\"]}], \"hexpm\", \"cowboy\"},\n\"phoenix\": {:hex, :phoenix, \"1.7.10\", \"def456\", [:mix], [], \"hexpm\", \"phoenix\"},\n\"my_app\": {:path, \"apps/my_app\", \"0.1.0\"},\n}\n",
        )
        .unwrap();

        let deps = parse_mix_lock(tmp.path()).unwrap();
        assert_eq!(deps.len(), 2, "Should parse 2 hex deps, skip path dep");
        assert_eq!(deps[0].name, "cowboy");
        assert_eq!(deps[0].version, "2.10.0");
        assert_eq!(deps[0].ecosystem, "Hex");
        assert_eq!(deps[1].name, "phoenix");
        assert_eq!(deps[1].version, "1.7.10");
    }

    #[test]
    fn test_parse_package_lock_json_v2() {
        let json = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "my-app", "version": "1.0.0" },
                "node_modules/express": { "version": "4.18.2" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/@scope/pkg": { "version": "2.0.0" }
            }
        });
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", json).unwrap();

        let deps = parse_package_lock_json(tmp.path()).unwrap();
        assert_eq!(deps.len(), 3);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"@scope/pkg"));
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            r#"# Production dependencies
requests==2.28.0
flask==2.3.0
django>=4.0  # unpinned — should be skipped
git+https://github.com/org/repo  # git dep — skip
sqlalchemy[asyncio]==2.0.0; python_version >= "3.8"
"#
        )
        .unwrap();

        let deps = parse_requirements_txt(tmp.path()).unwrap();
        assert_eq!(deps.len(), 3, "Should parse requests, flask, sqlalchemy");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"sqlalchemy"));
        assert_eq!(
            deps.iter()
                .find(|d| d.name == "sqlalchemy")
                .unwrap()
                .version,
            "2.0.0",
            "Env marker should be stripped"
        );
        assert_eq!(deps[0].ecosystem, "PyPI");
    }

    #[test]
    fn test_discover_and_parse_finds_cargo_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut f = std::fs::File::create(dir.path().join("Cargo.lock")).unwrap();
        write!(
            f,
            "version = 4\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        )
        .unwrap();

        let deps = discover_and_parse(dir.path()).unwrap();
        assert_eq!(deps.lockfiles.len(), 1);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps.dependencies[0].name, "serde");
    }

    #[test]
    fn recursive_discovery_finds_nested_workspace_lockfiles_but_skips_build_trees() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("src/rust");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("Cargo.lock"),
            "version = 4\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        let ignored = dir.path().join("target/generated");
        std::fs::create_dir_all(&ignored).unwrap();
        std::fs::write(ignored.join("Cargo.lock"), "not a lockfile").unwrap();

        let found = discover_and_parse(dir.path()).unwrap();
        assert_eq!(found.lockfiles.len(), 1);
        assert!(found.lockfiles[0].ends_with("src/rust/Cargo.lock"));
        assert_eq!(found.dependencies.len(), 1);
        assert!(!found.dependencies[0].declared_by.is_empty());
    }

    #[test]
    fn empty_valid_lockfile_is_distinct_from_missing_lockfile() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.lock"), "version = 4\n").unwrap();
        let found = discover_and_parse(dir.path()).unwrap();
        assert!(found.has_lockfiles());
        assert!(found.is_empty());
        assert!(found.unreadable.is_empty());

        let no_lock = tempfile::TempDir::new().unwrap();
        let missing = discover_and_parse(no_lock.path()).unwrap();
        assert!(!missing.has_lockfiles());
        assert!(missing.is_empty());
    }

    #[test]
    fn discovery_returns_traversal_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let error = discover_and_parse(&dir.path().join("missing")).unwrap_err();
        assert!(error.to_string().contains("Failed to traverse"));
    }

    #[test]
    fn nested_cargo_context_finds_direct_and_transitive_dependencies() {
        let dir = tempfile::TempDir::new().unwrap();
        let nested = dir.path().join("src/rust");
        std::fs::create_dir_all(&nested).unwrap();
        write_cargo_toml(&nested, "[dependencies]\nparent = \"1\"\n");
        std::fs::write(
            nested.join("Cargo.lock"),
            r#"version = 4
[[package]]
name = "parent"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "child",
]
[[package]]
name = "child"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();
        let discovery = discover_and_parse(dir.path()).unwrap();
        let (direct, parents) = discovery.cargo_context(dir.path());
        let declared = super::super::reachability::check_reachability_with_manifest(
            dir.path(),
            "parent",
            &direct,
            &parents,
        )
        .unwrap();
        assert_eq!(
            declared.status,
            super::super::ReachabilityStatus::PhantomDeclared
        );
        let transitive = super::super::reachability::check_reachability_with_manifest(
            dir.path(),
            "child",
            &direct,
            &parents,
        )
        .unwrap();
        assert_eq!(
            transitive.status,
            super::super::ReachabilityStatus::PhantomTransitive
        );
        assert_eq!(transitive.parent_dep.as_deref(), Some("parent"));

        // Explicit files can live outside project_dir; no recursive discovery
        // should be needed to locate their neighbouring manifests/graphs.
        let other = tempfile::TempDir::new().unwrap();
        let explicit = parse_lockfiles(&[nested.join("Cargo.lock")]).unwrap();
        let (explicit_direct, explicit_parents) = explicit.cargo_context(other.path());
        assert!(explicit.has_lockfiles());
        assert_eq!(explicit_direct, direct);
        assert_eq!(explicit_parents, parents);
    }

    // ------------------------------------------------------------------
    // Direct-dependency parser (regression for #47)
    // ------------------------------------------------------------------

    fn write_cargo_toml(dir: &Path, body: &str) {
        let mut f = std::fs::File::create(dir.join("Cargo.toml")).unwrap();
        write!(f, "{body}").unwrap();
    }

    #[test]
    fn direct_deps_finds_dependencies_section_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[package]
name = "demo"

[dependencies]
serde = "1.0"
anyhow = { version = "1.0" }
"serde-json" = "1.0"
"#,
        );
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.contains("serde"));
        assert!(direct.contains("anyhow"));
        assert!(direct.contains("serde-json"));
    }

    #[test]
    fn direct_deps_skips_transitive_only_crates() {
        // The crate `lru` only appears as a transitive dep through `ratatui`
        // in the real-world repro (#47). Cargo.toml has no `lru =` line, so
        // the parser must NOT consider it direct.
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[package]
name = "demo"

[dependencies]
ratatui = "0.29"
"#,
        );
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.contains("ratatui"));
        assert!(
            !direct.contains("lru"),
            "transitive deps must not be reported as direct"
        );
    }

    #[test]
    fn direct_deps_collects_dev_and_build_sections() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tempfile = "3"

[build-dependencies]
cc = "1"
"#,
        );
        let direct = collect_direct_cargo_dependencies(dir.path());
        for name in ["serde", "tempfile", "cc"] {
            assert!(direct.contains(name), "missing {name}");
        }
    }

    #[test]
    fn direct_deps_handles_target_sections() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[target.'cfg(unix)'.dependencies]
nix = "0.27"

[target.x86_64-pc-windows-msvc.build-dependencies]
winapi = "0.3"
"#,
        );
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.contains("nix"));
        assert!(direct.contains("winapi"));
    }

    #[test]
    fn direct_deps_handles_workspace_members() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[workspace]
members = ["crates/a", "crates/b"]
"#,
        );
        std::fs::create_dir_all(dir.path().join("crates/a")).unwrap();
        std::fs::create_dir_all(dir.path().join("crates/b")).unwrap();
        write_cargo_toml(
            &dir.path().join("crates/a"),
            "[dependencies]\nrand = \"0.8\"\n",
        );
        write_cargo_toml(
            &dir.path().join("crates/b"),
            "[dev-dependencies]\nproptest = \"1\"\n",
        );

        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.contains("rand"));
        assert!(direct.contains("proptest"));
    }

    #[test]
    fn direct_deps_normalises_underscore_to_hyphen() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(dir.path(), "[dependencies]\nserde_json = \"1.0\"\n");
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(
            direct.contains("serde-json"),
            "underscore should normalise to hyphen for CVE feed matching"
        );
        // Either spelling of the same crate must match the same normalised entry.
        for spelling in ["serde_json", "serde-json"] {
            let normalised = normalise_crate_name(spelling);
            assert!(direct.contains(&normalised));
        }
    }

    #[test]
    fn direct_deps_ignores_commented_lines_and_strings_with_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_toml(
            dir.path(),
            r#"
[dependencies]
# commented = "1.0"
serde = "1.0"  # inline comment is fine
"#,
        );
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.contains("serde"));
        assert!(!direct.contains("commented"));
    }

    #[test]
    fn direct_deps_empty_when_no_manifest() {
        let dir = tempfile::TempDir::new().unwrap();
        // No Cargo.toml written
        let direct = collect_direct_cargo_dependencies(dir.path());
        assert!(direct.is_empty());
    }

    // ------------------------------------------------------------------
    // Parent-dependency identification (Track E)
    // ------------------------------------------------------------------

    fn write_cargo_lock(dir: &Path, body: &str) {
        let mut f = std::fs::File::create(dir.join("Cargo.lock")).unwrap();
        write!(f, "{body}").unwrap();
    }

    #[test]
    fn parent_map_identifies_direct_to_transitive_path() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_lock(
            dir.path(),
            r#"version = 4

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "reqwest",
]

[[package]]
name = "reqwest"
version = "0.11.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "rustls",
 "tokio",
]

[[package]]
name = "rustls"
version = "0.21.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "ring",
]

[[package]]
name = "ring"
version = "0.17.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );

        let mut direct = std::collections::HashSet::new();
        direct.insert("reqwest".to_string());

        let parents = collect_cargo_parents(dir.path(), &direct);
        assert_eq!(parents.get("rustls").map(String::as_str), Some("reqwest"));
        assert_eq!(parents.get("ring").map(String::as_str), Some("reqwest"));
        assert_eq!(parents.get("tokio").map(String::as_str), Some("reqwest"));
        // Direct deps themselves must NOT appear in the parent map.
        assert!(!parents.contains_key("reqwest"));
    }

    #[test]
    fn parent_map_returns_empty_when_no_lockfile() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut direct = std::collections::HashSet::new();
        direct.insert("reqwest".to_string());
        let parents = collect_cargo_parents(dir.path(), &direct);
        assert!(parents.is_empty());
    }

    #[test]
    fn parent_map_normalises_underscore_to_hyphen() {
        let dir = tempfile::TempDir::new().unwrap();
        write_cargo_lock(
            dir.path(),
            r#"version = 4

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_derive"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        );

        let mut direct = std::collections::HashSet::new();
        direct.insert("serde".to_string());

        let parents = collect_cargo_parents(dir.path(), &direct);
        // Both spellings must hit the same normalised entry.
        assert_eq!(
            parents.get("serde-derive").map(String::as_str),
            Some("serde")
        );
    }
}
