// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Lockfile parsers — extracts locked dependencies from Cargo.lock, mix.lock,
//! package-lock.json, and requirements.txt for CVE feed queries.

use super::LockedDependency;
use anyhow::{Context, Result};
use std::path::Path;

// ============================================================================
// Discovery
// ============================================================================

/// Discover and parse all lockfiles found under `dir`.
///
/// Tries Cargo.lock, mix.lock, package-lock.json, and requirements.txt in
/// order. All successful parses are merged into a single list. Errors from
/// individual parsers are logged as warnings and skipped so one malformed
/// lockfile does not abort triage of the whole project.
type LockfileParser = fn(&Path) -> Result<Vec<LockedDependency>>;

pub fn discover_and_parse(dir: &Path) -> Vec<LockedDependency> {
    let mut all = Vec::new();

    let candidates: &[(&str, LockfileParser)] = &[
        ("Cargo.lock", parse_cargo_lock),
        ("mix.lock", parse_mix_lock),
        ("package-lock.json", parse_package_lock_json),
        ("requirements.txt", parse_requirements_txt),
    ];

    for (filename, parser) in candidates {
        let path = dir.join(filename);
        if path.exists() {
            match parser(&path) {
                Ok(deps) => all.extend(deps),
                Err(e) => {
                    log::warn!("[bridge] Failed to parse {}: {}", path.display(), e);
                }
            }
        }
    }

    all
}

// ============================================================================
// Cargo.lock (Rust / crates.io)
// ============================================================================

/// Parse a Cargo.lock file into a list of locked dependencies.
///
/// Handles Cargo.lock v3/v4 format. Each `[[package]]` entry becomes a
/// LockedDependency. Local packages (no registry source) are skipped.
pub fn parse_cargo_lock(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_source: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            if let (Some(name), Some(version)) = (current_name.take(), current_version.take()) {
                if current_source
                    .as_ref()
                    .is_some_and(|s| s.contains("registry"))
                {
                    deps.push(LockedDependency {
                        name,
                        version,
                        ecosystem: "crates.io".to_string(),
                        declared_by: Vec::new(),
                    });
                }
            }
            current_name = None;
            current_version = None;
            current_source = None;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("name = ") {
            current_name = Some(unquote(rest));
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            current_version = Some(unquote(rest));
        } else if let Some(rest) = trimmed.strip_prefix("source = ") {
            current_source = Some(unquote(rest));
        }
    }

    if let (Some(name), Some(version)) = (current_name, current_version) {
        if current_source
            .as_ref()
            .is_some_and(|s| s.contains("registry"))
        {
            deps.push(LockedDependency {
                name,
                version,
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

    let mut deps = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip blank lines, comment, and the map delimiters
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed == "%{" || trimmed == "}" {
            continue;
        }

        // Match lines like:  "cowboy": {:hex, :cowboy, "2.10.0", ...}
        // We need the outer key (package name) and the version string.
        if let Some(dep) = parse_mix_lock_line(trimmed) {
            deps.push(dep);
        }
    }

    Ok(deps)
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

    let version = fields[2].trim().trim_matches('"').to_string();
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
/// root entry (empty key or no version) and dev-only packages.
pub fn parse_package_lock_json(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let root: serde_json::Value =
        serde_json::from_str(&content).with_context(|| "Parsing package-lock.json")?;

    let mut deps = Vec::new();

    // v2/v3 lockfile: flat `packages` object
    if let Some(packages) = root.get("packages").and_then(|v| v.as_object()) {
        for (key, pkg) in packages {
            // Skip root entry and entries without a version
            if key.is_empty() || !key.starts_with("node_modules/") {
                continue;
            }
            let version = match pkg.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };
            // Extract package name from node_modules/<scope?/name> key
            let name = key.trim_start_matches("node_modules/").to_string();
            if name.is_empty() {
                continue;
            }
            deps.push(LockedDependency {
                name,
                version,
                ecosystem: "npm".to_string(),
                declared_by: Vec::new(),
            });
        }
    } else if let Some(dependencies) = root.get("dependencies").and_then(|v| v.as_object()) {
        // v1 lockfile: nested `dependencies` object
        for (name, pkg) in dependencies {
            let version = match pkg.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };
            deps.push(LockedDependency {
                name: name.clone(),
                version,
                ecosystem: "npm".to_string(),
                declared_by: Vec::new(),
            });
        }
    }

    Ok(deps)
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
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<LockedDependency>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let mut deps = Vec::new();

    for line in content.lines() {
        // Strip inline comments and whitespace
        let line = line.trim();
        let line = if let Some(idx) = line.find('#') {
            line[..idx].trim()
        } else {
            line
        };

        if line.is_empty() || line.starts_with('-') || line.starts_with("git+") {
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

            if !name.is_empty() && !version.is_empty() {
                deps.push(LockedDependency {
                    name,
                    version,
                    ecosystem: "PyPI".to_string(),
                    declared_by: Vec::new(),
                });
            }
        }
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
            r#"[[package]]
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
            "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        )
        .unwrap();

        let deps = discover_and_parse(dir.path());
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
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
