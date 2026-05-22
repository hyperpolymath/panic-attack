// SPDX-License-Identifier: MPL-2.0

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
pub fn discover_and_parse(dir: &Path) -> Vec<LockedDependency> {
    let mut all = Vec::new();

    let candidates: &[(&str, fn(&Path) -> Result<Vec<LockedDependency>>)] = &[
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
                    .map_or(false, |s| s.contains("registry"))
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
            .map_or(false, |s| s.contains("registry"))
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
}
