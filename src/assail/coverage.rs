// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Explicit scan inventory. Finding counters are never a coverage denominator.
use crate::types::Language;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    "target",
    "build",
    "node_modules",
    ".git",
    "vendor",
    "_build",
    "_opam",
    ".stack-work",
    "dist-newstyle",
    "deps",
    "_deps",
    "zig-cache",
    ".zig-cache",
    "zig-out",
    ".elixir_ls",
    ".lexical",
    "__pycache__",
    "ebin",
    "_checkouts",
    ".fetch",
    ".hex",
    ".nimble",
    ".dub",
    "obj",
    "runtime",
    ".yarn",
    "idaptik-rescript13-staging",
    "rescript-ecosystem",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputCoverage {
    pub path: PathBuf,
    pub kind: String,
    pub status: String,
    pub language: Language,
    pub analysis: Option<String>,
    pub reason: Option<String>,
    pub content_blake3: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisCoverage {
    pub status: String,
    pub mode: String,
    pub scope: String,
    pub candidate_files: usize,
    pub analyzed_files: usize,
    pub inputs: Vec<InputCoverage>,
    #[serde(skip)]
    index: std::collections::HashMap<PathBuf, usize>,
}

impl Default for AnalysisCoverage {
    /// Represent unrecorded coverage with unknown status and an empty inventory.
    fn default() -> Self {
        Self {
            status: "unknown".into(),
            mode: "not_recorded".into(),
            scope: "legacy report: coverage was not recorded".into(),
            candidate_files: 0,
            analyzed_files: 0,
            inputs: Vec::new(),
            index: Default::default(),
        }
    }
}

impl AnalysisCoverage {
    /// Return whether coverage is anything other than `complete`, including
    /// unknown coverage and scans with no applicable input.
    pub fn incomplete(&self) -> bool {
        self.status != "complete"
    }
    /// Replace an indexed input's status and reason, ignoring unindexed paths.
    /// When supplied, `bytes` replaces its BLAKE3 digest; `None` keeps the old
    /// digest. Counts and overall status are updated only by [`Self::finish`].
    /// After deserialisation, call `finish` first to rebuild the path index.
    pub fn mark(
        &mut self,
        path: &Path,
        status: &str,
        reason: Option<String>,
        bytes: Option<&[u8]>,
    ) {
        if let Some(input) = self
            .index
            .get(path)
            .and_then(|index| self.inputs.get_mut(*index))
        {
            input.status = status.into();
            input.reason = reason;
            if let Some(bytes) = bytes {
                input.content_blake3 = Some(blake3::hash(bytes).to_hex().to_string());
            }
        }
    }
    /// Sort inputs by path, rebuild their index and recompute counts and status.
    /// Non-excluded files are candidates; any input neither analysed nor excluded
    /// is a gap. With analysed inputs, gaps yield `partial`, otherwise `complete`.
    /// Without analysed inputs, gaps yield `failed`, otherwise `no_applicable_input`.
    pub fn finish(&mut self) {
        self.inputs.sort_by(|a, b| a.path.cmp(&b.path));
        self.index = self
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| (input.path.clone(), i))
            .collect();
        self.candidate_files = self
            .inputs
            .iter()
            .filter(|i| i.kind == "file" && i.status != "excluded")
            .count();
        self.analyzed_files = self
            .inputs
            .iter()
            .filter(|i| i.status == "analyzed")
            .count();
        let gaps = self
            .inputs
            .iter()
            .any(|i| i.status != "analyzed" && i.status != "excluded");
        self.status = if self.analyzed_files == 0 {
            if gaps {
                "failed"
            } else {
                "no_applicable_input"
            }
        } else if gaps {
            "partial"
        } else {
            "complete"
        }
        .into();
    }
}

/// Recognise selected source/config extensions case-insensitively and build-file
/// names case-sensitively as candidates even when no language adapter matches.
fn unsupported_candidate(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "php"
            | "phtml"
            | "inc"
            | "kt"
            | "swift"
            | "cs"
            | "fs"
            | "scala"
            | "r"
            | "sql"
            | "yaml"
            | "yml"
            | "toml"
            | "json"
            | "xml"
            | "ps1"
            | "html"
            | "css"
    ) || matches!(
        path.file_name().and_then(|s| s.to_str()),
        Some("Dockerfile" | "Containerfile" | "Makefile" | "Justfile" | "justfile")
    )
}

/// Inventory a file or directory tree and return sorted paths with known languages.
/// Named build/vendor subdirectories are recorded without enumerating their
/// contents; symlinks and other non-regular inputs are excluded. Selected unknown
/// source/config formats are unsupported; other unknown formats are excluded.
/// Returned candidates are still `pending`: use [`AnalysisCoverage::mark`] and
/// [`AnalysisCoverage::finish`] after analysis to update the provisional coverage.
///
/// # Errors
/// Returns root metadata errors and rejects a symlink root. Later traversal
/// errors are recorded as `discovery_error` inputs while discovery continues.
pub fn discover(root: &Path) -> anyhow::Result<(Vec<PathBuf>, AnalysisCoverage)> {
    let meta = std::fs::symlink_metadata(root)?;
    anyhow::ensure!(
        !meta.file_type().is_symlink(),
        "scan root must not be a symlink"
    );
    let mut report = AnalysisCoverage {
        mode: "static_assail".into(),
        scope: "Explicit regular-file inventory; named build/vendor directories and symlinks excluded without following them. Unknown source/config formats are unsupported; other extensions are outside declared scope. Non-PHP adapters are heuristic, not parse or dataflow proofs. No dynamic attacks executed.".into(),
        ..Default::default()
    };
    let mut excluded = Vec::new();
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            let prune = entry.depth() > 0
                && entry.file_type().is_dir()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| SKIP_DIRS.contains(&name));
            if prune {
                excluded.push(InputCoverage {
                    path: entry.path().to_path_buf(),
                    kind: "directory".into(),
                    status: "excluded".into(),
                    language: Language::Unknown,
                    analysis: None,
                    reason: Some("build/vendor directory policy; subtree not enumerated".into()),
                    content_blake3: None,
                });
            }
            !prune
        });
    let mut files = Vec::new();
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                report.inputs.push(InputCoverage {
                    path: e.path().unwrap_or(root).to_path_buf(),
                    kind: "unknown".into(),
                    status: "discovery_error".into(),
                    language: Language::Unknown,
                    analysis: None,
                    reason: Some(e.to_string()),
                    content_blake3: None,
                });
                continue;
            }
        };
        if entry.file_type().is_dir() {
            continue;
        }
        let path = entry.path();
        let language = Language::detect(path.to_str().unwrap_or(""));
        let (status, reason, kind) = if !entry.file_type().is_file() {
            (
                "excluded",
                Some("non-regular input; symlinks are not followed".into()),
                "non_regular",
            )
        } else if language != Language::Unknown {
            files.push(path.to_path_buf());
            ("pending", None, "file")
        } else if unsupported_candidate(path) {
            (
                "unsupported",
                Some(
                    "no source adapter; project manifest checks are not whole-file analysis".into(),
                ),
                "file",
            )
        } else {
            (
                "excluded",
                Some("extension outside declared source/config scope".into()),
                "file",
            )
        };
        report.inputs.push(InputCoverage {
            path: path.to_path_buf(),
            kind: kind.into(),
            status: status.into(),
            language,
            analysis: (language != Language::Unknown).then(|| {
                if language == Language::Php {
                    "tree-sitter-php 0.25.1; local T0 syntax checks; no cross-file taint"
                } else {
                    "language and cross-language heuristics; no parser coverage claim"
                }
                .into()
            }),
            reason,
            content_blake3: None,
        });
    }
    report.inputs.extend(excluded);
    files.sort();
    report.finish();
    Ok((files, report))
}
