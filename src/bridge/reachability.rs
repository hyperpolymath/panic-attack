// SPDX-License-Identifier: PMPL-1.0-or-later

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
use std::path::Path;
use walkdir::WalkDir;

/// Check whether a crate is actually imported in the project's Rust source files.
///
/// Scans all .rs files under `project_dir` for patterns that indicate the
/// crate is used:
/// - `use <crate_name>::`  (standard import)
/// - `<crate_name>::`      (fully qualified path in code)
/// - `extern crate <crate_name>`  (legacy import)
///
/// Crate names with hyphens are normalised to underscores (Rust convention).
pub fn check_reachability(project_dir: &Path, crate_name: &str) -> Result<ReachabilityEvidence> {
    // Rust converts hyphens to underscores in crate names
    let normalised = crate_name.replace('-', "_");

    let patterns = [
        format!("use {}::", normalised),
        format!("use {}", normalised),     // bare `use serde;`
        format!("{}::", normalised),        // qualified path
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
        if path.extension().map_or(true, |ext| ext != "rs") {
            continue;
        }

        // Read file and scan for import patterns
        let content = match std::fs::read_to_string(path) {
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
                    let rel_path = path
                        .strip_prefix(project_dir)
                        .unwrap_or(path)
                        .to_path_buf();

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

    let is_imported = !import_sites.is_empty();
    let status = if is_imported {
        ReachabilityStatus::Reachable
    } else {
        ReachabilityStatus::Phantom
    };

    Ok(ReachabilityEvidence {
        is_imported,
        import_sites,
        status,
    })
}

/// Directories to exclude from scanning.
fn is_excluded(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    matches!(
        name,
        "target" | ".git" | "node_modules" | ".lake" | "vendor"
            | "_build" | "deps" | ".elixir_ls" | ".machine_readable"
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

        // Check for a crate that is NOT imported
        let evidence = check_reachability(tmp.path(), "octocrab").unwrap();
        assert!(!evidence.is_imported);
        assert_eq!(evidence.status, ReachabilityStatus::Phantom);
        assert!(evidence.import_sites.is_empty());
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
        fs::write(
            src_dir.join("lib.rs"),
            "use serde_json::Value;\n",
        )
        .unwrap();

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
        assert_eq!(evidence.status, ReachabilityStatus::Phantom);
    }
}
