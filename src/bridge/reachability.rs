// SPDX-License-Identifier: MPL-2.0

//! Reachability analysis — determines whether a dependency is actually used.
//!
//! Scans Rust source files for import statements (`use <crate>::` or
//! `<crate>::` in code) to detect phantom dependencies: crates declared
//! in Cargo.toml but never imported in any .rs file.
//!
//! For MVP, this is grep-based import detection. Phase 2 will integrate
//! with the kanren taint engine for full source→sink data flow analysis.

use super::{ImportSite, ReachabilityEvidence, ReachabilityStatus};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

/// Upper bound on single-file reads during reachability scans.
/// Rust source files are almost always well under 16 MiB; capping at 64 MiB
/// prevents a pathological or malicious input (e.g. a minified vendor blob
/// masquerading as .rs) from exhausting memory during a mass-panic sweep.
const SOURCE_FILE_READ_LIMIT: u64 = 64 * 1024 * 1024;

/// Check whether a crate is actually imported in the project's Rust source files.
///
/// Convenience wrapper around [`check_reachability_with_manifest`] that does
/// NOT distinguish `PhantomDeclared` from `PhantomTransitive` — kept for the
/// internal test suite. Returns `PhantomTransitive` for the no-`use`-site
/// case as the conservative default (the parent identification will be
/// `None`).
///
/// Production callers should use [`check_reachability_with_manifest`] so
/// the phantom-declared vs phantom-transitive distinction is preserved.
#[cfg(test)]
pub fn check_reachability(project_dir: &Path, crate_name: &str) -> Result<ReachabilityEvidence> {
    check_reachability_with_manifest(project_dir, crate_name, &HashSet::new(), &HashMap::new())
}

/// Check whether a crate is actually imported in the project's Rust source files,
/// distinguishing **declared phantoms** from **transitive phantoms**.
///
/// Scans all .rs files under `project_dir` for patterns that indicate the
/// crate is used:
/// - `use <crate_name>::`  (standard import)
/// - `<crate_name>::`      (fully qualified path in code)
/// - `extern crate <crate_name>`  (legacy import)
///
/// Crate names with hyphens are normalised to underscores for source
/// scanning (Rust convention), and to lowercase-with-hyphens for manifest
/// lookups (Cargo convention).
///
/// When no `use` site is found, classification splits:
///
/// - `declared_deps` contains the crate (lookup against root + workspace
///   Cargo.toml [dependencies] sections) → [`ReachabilityStatus::PhantomDeclared`]
/// - Not in `declared_deps` → [`ReachabilityStatus::PhantomTransitive`] and
///   `parent_dep` is populated from `parent_map` if known.
///
/// `parent_map` maps every transitive crate name to the direct dep whose
/// dependency closure pulls it in (best-effort from Cargo.lock). Names in
/// both maps use the Cargo convention (lowercase, hyphens).
pub fn check_reachability_with_manifest(
    project_dir: &Path,
    crate_name: &str,
    declared_deps: &HashSet<String>,
    parent_map: &HashMap<String, String>,
) -> Result<ReachabilityEvidence> {
    // Rust converts hyphens to underscores in crate names
    let normalised = crate_name.replace('-', "_");

    let patterns = [
        format!("use {}::", normalised),
        format!("use {}", normalised), // bare `use serde;`
        format!("{}::", normalised),   // qualified path
        format!("extern crate {}", normalised),
    ];

    let mut import_sites = Vec::new();

    for entry in WalkDir::new(project_dir)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path()))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }

        // Read file and scan for import patterns. Cap per-file size to
        // avoid an arbitrarily-large file consuming memory; take(N) is
        // an upper bound, not a guarantee the file is <= N bytes — if a
        // file is larger we silently truncate to the first N bytes and
        // scan that prefix (imports live at the top of a Rust file).
        let content = match File::open(path).and_then(|f| {
            let mut buf = String::new();
            f.take(SOURCE_FILE_READ_LIMIT)
                .read_to_string(&mut buf)
                .map(|_| buf)
        }) {
            Ok(c) => c,
            Err(_) => continue, // Skip unreadable files (binary, encoding issues)
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                continue;
            }

            for pattern in &patterns {
                if trimmed.contains(pattern.as_str()) {
                    // Make path relative to project dir for cleaner output
                    let rel_path = path.strip_prefix(project_dir).unwrap_or(path).to_path_buf();

                    import_sites.push(ImportSite {
                        file: rel_path,
                        line: line_num + 1,
                        statement: trimmed.to_string(),
                    });
                    break; // One match per line is sufficient
                }
            }
        }
    }

    let manifest_key = crate_name.to_ascii_lowercase().replace('_', "-");
    let is_imported = !import_sites.is_empty();
    let (status, parent_dep) = if is_imported {
        (ReachabilityStatus::Reachable, None)
    } else if declared_deps.contains(&manifest_key) {
        (ReachabilityStatus::PhantomDeclared, None)
    } else {
        let parent = parent_map.get(&manifest_key).cloned();
        (ReachabilityStatus::PhantomTransitive, parent)
    };

    Ok(ReachabilityEvidence {
        is_imported,
        import_sites,
        status,
        parent_dep,
    })
}

/// Directories to exclude from scanning.
fn is_excluded(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    matches!(
        name,
        "target"
            | ".git"
            | "node_modules"
            | ".lake"
            | "vendor"
            | "_build"
            | "deps"
            | ".elixir_ls"
            | ".machine_readable"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_phantom_dependency() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            "use serde::Serialize;\nfn main() {}\n",
        )
        .unwrap();

        // Check for a crate that is NOT imported. With no declared-set
        // information the conservative default is `PhantomTransitive`.
        let evidence = check_reachability(tmp.path(), "octocrab").unwrap();
        assert!(!evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::PhantomTransitive);
        assert!(evidence.import_sites.is_empty());
        assert!(evidence.parent_dep.is_none());
    }

    #[test]
    fn test_reachable_dependency() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            "use serde::Serialize;\nfn main() {}\n",
        )
        .unwrap();

        let evidence = check_reachability(tmp.path(), "serde").unwrap();
        assert!(evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::Reachable);
        assert_eq!(evidence.import_sites.len(), 1);
        assert_eq!(evidence.import_sites[0].line, 1);
    }

    #[test]
    fn test_hyphenated_crate_name() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("lib.rs"), "use serde_json::Value;\n").unwrap();

        // Query with hyphen — should match underscore form
        let evidence = check_reachability(tmp.path(), "serde-json").unwrap();
        assert!(evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::Reachable);
    }

    #[test]
    fn test_skips_comments() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(
            src_dir.join("main.rs"),
            "// use octocrab::Octocrab;\nfn main() {}\n",
        )
        .unwrap();

        let evidence = check_reachability(tmp.path(), "octocrab").unwrap();
        assert!(!evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::PhantomTransitive);
    }

    // ------------------------------------------------------------------
    // PhantomDeclared vs PhantomTransitive regression tests (Track E)
    // ------------------------------------------------------------------

    #[test]
    fn phantom_declared_when_crate_in_cargo_toml_but_no_use() {
        // file-soup#50 shape: crate listed in [dependencies] but no `use` site.
        // Strip recommendation must be safe.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

        let mut declared = HashSet::new();
        declared.insert("octocrab".to_string());

        let evidence =
            check_reachability_with_manifest(tmp.path(), "octocrab", &declared, &HashMap::new())
                .unwrap();

        assert!(!evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::PhantomDeclared);
        assert!(
            evidence.parent_dep.is_none(),
            "PhantomDeclared has no parent — it IS the direct dep",
        );
    }

    #[test]
    fn phantom_transitive_when_crate_not_in_cargo_toml() {
        // Track E Batch A shape: crate is a transitive pulled in by a parent
        // dep. Local strip is impossible; fix requires bumping the parent.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), "use reqwest::Client;\n").unwrap();

        let mut declared = HashSet::new();
        declared.insert("reqwest".to_string());

        let mut parents = HashMap::new();
        parents.insert("rustls".to_string(), "reqwest".to_string());

        let evidence =
            check_reachability_with_manifest(tmp.path(), "rustls", &declared, &parents).unwrap();

        assert!(!evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::PhantomTransitive);
        assert_eq!(evidence.parent_dep.as_deref(), Some("reqwest"));
    }

    #[test]
    fn reachable_when_declared_and_used() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), "use serde::Serialize;\n").unwrap();

        let mut declared = HashSet::new();
        declared.insert("serde".to_string());

        let evidence =
            check_reachability_with_manifest(tmp.path(), "serde", &declared, &HashMap::new())
                .unwrap();

        assert!(evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::Reachable);
        assert!(evidence.parent_dep.is_none());
    }

    #[test]
    fn phantom_transitive_with_unknown_parent_is_still_classified() {
        // If Cargo.lock could not be parsed (or the parent map is empty),
        // we still emit PhantomTransitive — just with `parent_dep: None`.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

        // Empty declared set: crate is neither imported nor declared.
        let evidence = check_reachability_with_manifest(
            tmp.path(),
            "some-transitive",
            &HashSet::new(),
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(evidence.status, ReachabilityStatus::PhantomTransitive);
        assert!(evidence.parent_dep.is_none());
    }

    #[test]
    fn phantom_declared_resolves_workspace_member_dep() {
        // A crate declared in a workspace MEMBER's Cargo.toml (not the root)
        // should still resolve as PhantomDeclared when not imported. This
        // mirrors the file-soup#50 shape on multi-crate workspaces.
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[workspace]
members = ["crates/member-a"]
"#,
        )
        .unwrap();
        let member_dir = tmp.path().join("crates/member-a");
        std::fs::create_dir_all(member_dir.join("src")).unwrap();
        std::fs::write(
            member_dir.join("Cargo.toml"),
            r#"[package]
name = "member-a"
version = "0.1.0"

[dependencies]
octocrab = "0.32"
"#,
        )
        .unwrap();
        std::fs::write(member_dir.join("src/lib.rs"), "// no use of octocrab\n").unwrap();

        // Simulate triage: collect declared deps the way mod.rs does.
        let declared = crate::bridge::lockfile::collect_direct_cargo_dependencies(tmp.path());
        assert!(
            declared.contains("octocrab"),
            "workspace-member declared dep must be in the direct-deps set"
        );

        let evidence =
            check_reachability_with_manifest(tmp.path(), "octocrab", &declared, &HashMap::new())
                .unwrap();
        assert_eq!(evidence.status, ReachabilityStatus::PhantomDeclared);
    }

    #[test]
    fn phantom_classification_normalises_underscore_to_hyphen() {
        // CVE feed reports `serde_json`; manifest has `serde-json`.
        // Lookup must hit the same bucket either way.
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("main.rs"), "fn main() {}\n").unwrap();

        let mut declared = HashSet::new();
        declared.insert("serde-json".to_string());

        let evidence =
            check_reachability_with_manifest(tmp.path(), "serde_json", &declared, &HashMap::new())
                .unwrap();

        assert_eq!(evidence.status, ReachabilityStatus::PhantomDeclared);
    }
}
