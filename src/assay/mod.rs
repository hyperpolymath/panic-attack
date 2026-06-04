// SPDX-License-Identifier: MPL-2.0

//! Assay + Assimilate — proven-library substitution survey and swap-in.
//!
//! `assay` surveys a target tree for code that has a *formally proven*
//! drop-in equivalent in a "proven" library (`hyperpolymath/proven`,
//! `hyperpolymath/proven-servers`, or any local checkout passed with
//! `--proven`), and reports substitution candidates. `assimilate` performs
//! a selected swap: it stages the proven module into the tree, backs up the
//! original, and records provenance (source hash + proof backing) so the
//! substitution is auditable and reversible.
//!
//! This operationalises the **Proven cross-fit** section of
//! `PROOF-PROGRAMME.md`. Rather than hand-maintaining the swap table, the
//! tool discovers candidates mechanically and records the proof artifact
//! that backs each one. The existing `src/safe_path.rs` (a hand port of
//! `proven::SafePath`) is the worked example the built-in catalogue knows
//! about.
//!
//! ## Safety boundary
//!
//! `assimilate` swaps *modules* (whole files) automatically, with a backup
//! and a provenance record. It does **not** silently rewrite call sites —
//! those are reported as `pending_callsite_rewires` for human review,
//! because mechanically editing arbitrary call sites is not a sound,
//! reviewable operation. A swap that only needs call-site rewiring (the
//! proven module is already in-tree) records the rewire list and changes
//! no bytes.

use crate::aggregate::{hash_file, HashRecord};
use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Per-source-file read cap for the survey scan.
const SOURCE_READ_LIMIT: u64 = 2 * 1024 * 1024;

/// Directories never scanned for substitution candidates.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "external_corpora",
    "third_party",
    "corpus",
    "runtime",
    "reports",
    "verisimdb-data",
    "mass-panic-results",
    "generated",
    ".assimilated",
];

fn assay_schema_version() -> String {
    "0.1.0".to_string()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SubstitutionKind {
    /// Replace an unproven local validator with a proven pure-Rust port.
    PortToRust,
    /// Drop in a proven module file wholesale (same module path).
    DropInModule,
    /// Bind to the proven impl over FFI (rare; dylib build cost).
    FfiBind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateStatus {
    /// A swap is available and offered.
    Offered,
    /// The proven module is already in-tree and no unproven call sites
    /// remain — nothing to do.
    AlreadyApplied,
    /// The unproven pattern is present but no proven replacement source was
    /// found (supply `--proven <DIR>` or `--from <FILE>` to assimilate).
    NoReplacementSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetHit {
    pub file: PathBuf,
    pub line: u32,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubstitutionCandidate {
    /// Stable id used by `assimilate --candidate <id>`.
    pub id: String,
    pub proven_name: String,
    /// The proof artifact that backs the proven implementation.
    pub proof_backing: String,
    /// Where the proven module should live in the target tree.
    pub dest_rel: String,
    /// Resolved replacement source (set when a `--proven` checkout supplied
    /// a matching file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replacement_path: Option<PathBuf>,
    /// True when the proven module already lives in the target tree.
    pub port_present: bool,
    pub target_hits: Vec<TargetHit>,
    pub equivalence_basis: String,
    pub perf_note: String,
    pub substitution_kind: SubstitutionKind,
    pub confidence: f64,
    pub status: CandidateStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssayReport {
    #[serde(default = "assay_schema_version")]
    pub schema_version: String,
    pub created_at: String,
    pub target: PathBuf,
    pub proven_sources: Vec<PathBuf>,
    pub catalogue_entries: usize,
    pub candidates: Vec<SubstitutionCandidate>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AssayConfig {
    pub target: PathBuf,
    /// Local checkouts of proven / proven-servers consulted for replacement
    /// sources. May be empty (candidates still reported, sans source).
    pub proven_sources: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Built-in catalogue (PROOF-PROGRAMME "Proven cross-fit")
// ---------------------------------------------------------------------------

struct CatalogueEntry {
    id: &'static str,
    proven_name: &'static str,
    proof_backing: &'static str,
    /// Regex matched per source line.
    detect: &'static str,
    file_exts: &'static [&'static str],
    /// In-tree path that, if present, means the proven module is already
    /// ported (so remaining hits are call sites to rewire, not a missing
    /// module).
    port_marker_path: &'static str,
    dest_rel: &'static str,
    /// Filename stems to look for inside a `--proven` checkout.
    replacement_hints: &'static [&'static str],
    equivalence_basis: &'static str,
    perf_note: &'static str,
    kind: SubstitutionKind,
    confidence: f64,
}

fn catalogue() -> &'static [CatalogueEntry] {
    &[
        CatalogueEntry {
            id: "safe-path",
            proven_name: "SafePath",
            proof_backing: "proven: src/Proven/SafePath/Operations.idr",
            detect: r"canonicalize\s*\([^)]*\)\s*\.\s*unwrap_or_else",
            file_exts: &["rs"],
            port_marker_path: "src/safe_path.rs",
            dest_rel: "src/safe_path.rs",
            replacement_hints: &["safe_path", "SafePath"],
            equivalence_basis: "segment-split traversal predicate; proptest invariants mirror the Idris2 reference lemmas (non-empty, safe-charset, idempotent)",
            perf_note: "pure-Rust port, no dylib; short-circuits before disk I/O",
            kind: SubstitutionKind::PortToRust,
            confidence: 0.9,
        },
        CatalogueEntry {
            id: "safe-url",
            proven_name: "SafeUrl",
            proof_backing: "proven: src/Proven/SafeUrl/Operations.idr",
            detect: r"VERISIMDB_URL",
            file_exts: &["rs"],
            port_marker_path: "src/safe_url.rs",
            dest_rel: "src/safe_url.rs",
            replacement_hints: &["safe_url", "SafeUrl"],
            equivalence_basis: "wraps url::Url with a scheme-required invariant (proptest); rejects schemeless/hostless inputs before HTTP",
            perf_note: "one-time parse at config load; negligible",
            kind: SubstitutionKind::PortToRust,
            confidence: 0.6,
        },
    ]
}

// ---------------------------------------------------------------------------
// Survey
// ---------------------------------------------------------------------------

pub fn run(config: AssayConfig) -> Result<AssayReport> {
    let cat = catalogue();
    let mut notes = Vec::new();

    // Collect (relative-path, content) for every scannable source file once,
    // keyed by extension so each catalogue entry filters cheaply.
    let files = collect_source_files(&config.target)?;

    let mut candidates = Vec::new();
    for entry in cat {
        let re = Regex::new(entry.detect)
            .with_context(|| format!("compiling detector for {}", entry.id))?;
        let mut hits = Vec::new();
        for (rel, content, ext) in &files {
            if !entry.file_exts.contains(&ext.as_str()) {
                continue;
            }
            for (i, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    hits.push(TargetHit {
                        file: rel.clone(),
                        line: (i + 1) as u32,
                        snippet: line.trim().chars().take(160).collect(),
                    });
                }
            }
        }

        let port_present = config.target.join(entry.port_marker_path).is_file();
        let replacement_path = resolve_replacement(&config.proven_sources, entry.replacement_hints);

        // Skip entries that have nothing to say for this target.
        if hits.is_empty() && !port_present {
            continue;
        }

        let status = if hits.is_empty() {
            CandidateStatus::AlreadyApplied
        } else if port_present || replacement_path.is_some() {
            CandidateStatus::Offered
        } else {
            CandidateStatus::NoReplacementSource
        };

        candidates.push(SubstitutionCandidate {
            id: entry.id.to_string(),
            proven_name: entry.proven_name.to_string(),
            proof_backing: entry.proof_backing.to_string(),
            dest_rel: entry.dest_rel.to_string(),
            replacement_path,
            port_present,
            target_hits: hits,
            equivalence_basis: entry.equivalence_basis.to_string(),
            perf_note: entry.perf_note.to_string(),
            substitution_kind: entry.kind,
            confidence: entry.confidence,
            status,
        });
    }

    if candidates.is_empty() {
        notes.push("no substitution candidates found for this target".to_string());
    }
    if config.proven_sources.is_empty() {
        notes.push(
            "no --proven checkout supplied; replacement sources unresolved for not-yet-ported candidates"
                .to_string(),
        );
    }

    Ok(AssayReport {
        schema_version: assay_schema_version(),
        created_at: chrono::Utc::now().to_rfc3339(),
        target: config.target,
        proven_sources: config.proven_sources,
        catalogue_entries: cat.len(),
        candidates,
        notes,
    })
}

pub fn write_report(report: &AssayReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(report).context("serializing assay report")?;
    fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Assimilate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AssimilateAction {
    /// The proven module file was copied into place (original backed up).
    FileSwapped,
    /// The proven module is already in-tree; only call sites need rewiring.
    ModuleAlreadyPresent,
    /// Nothing was written (dry run / preview).
    DryRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssimilationRecord {
    #[serde(default = "assay_schema_version")]
    pub schema_version: String,
    pub created_at: String,
    pub candidate_id: String,
    pub proven_name: String,
    pub proof_backing: String,
    pub action: AssimilateAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_hash: Option<HashRecord>,
    pub destination: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_hash: Option<HashRecord>,
    pub pending_callsite_rewires: Vec<TargetHit>,
    pub trust_basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssimilationOutcome {
    pub schema_version: String,
    pub created_at: String,
    pub target: PathBuf,
    pub applied: Vec<AssimilationRecord>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AssimilateConfig {
    pub target: PathBuf,
    pub proven_sources: Vec<PathBuf>,
    /// Apply just this candidate id; ignored when `apply_all` is set.
    pub candidate_id: Option<String>,
    /// Explicit replacement source, overriding catalogue resolution
    /// (only valid for a single candidate).
    pub from: Option<PathBuf>,
    pub apply_all: bool,
    pub dry_run: bool,
}

pub fn assimilate(config: AssimilateConfig) -> Result<AssimilationOutcome> {
    let assay = run(AssayConfig {
        target: config.target.clone(),
        proven_sources: config.proven_sources.clone(),
    })?;

    // Select candidates to act on.
    let selected: Vec<&SubstitutionCandidate> = if config.apply_all {
        assay
            .candidates
            .iter()
            .filter(|c| c.status == CandidateStatus::Offered)
            .collect()
    } else {
        let id = config.candidate_id.as_deref().ok_or_else(|| {
            anyhow!("specify --candidate <id> (or --all); run `assay` to list ids")
        })?;
        let c = assay
            .candidates
            .iter()
            .find(|c| c.id == id)
            .ok_or_else(|| anyhow!("no assay candidate with id '{}' for this target", id))?;
        vec![c]
    };

    if config.from.is_some() && selected.len() != 1 {
        return Err(anyhow!("--from is only valid with a single --candidate"));
    }

    let mut applied = Vec::new();
    let mut notes = Vec::new();

    for cand in selected {
        if cand.status == CandidateStatus::AlreadyApplied {
            notes.push(format!("{}: already applied; skipping", cand.id));
            continue;
        }

        // Resolve the replacement source.
        let source = config
            .from
            .clone()
            .or_else(|| cand.replacement_path.clone());

        let dest = config.target.join(&cand.dest_rel);

        let trust_basis = format!(
            "Swap of {} backed by {}. Provenance recorded by BLAKE3 hash; a different source file will not reproduce it.",
            cand.proven_name, cand.proof_backing
        );

        // No source and module already in-tree → call-site rewiring only.
        let Some(source) = source else {
            if cand.port_present {
                let record = AssimilationRecord {
                    schema_version: assay_schema_version(),
                    created_at: chrono::Utc::now().to_rfc3339(),
                    candidate_id: cand.id.clone(),
                    proven_name: cand.proven_name.clone(),
                    proof_backing: cand.proof_backing.clone(),
                    action: AssimilateAction::ModuleAlreadyPresent,
                    source: None,
                    source_hash: None,
                    destination: dest.clone(),
                    backup: None,
                    replaced_hash: None,
                    pending_callsite_rewires: cand.target_hits.clone(),
                    trust_basis,
                };
                if !config.dry_run {
                    write_provenance(&config.target, &record)?;
                }
                applied.push(record);
                continue;
            }
            return Err(anyhow!(
                "{}: no replacement source; supply --proven <DIR> or --from <FILE>",
                cand.id
            ));
        };
        if !source.is_file() {
            return Err(anyhow!(
                "{}: replacement source {} is not a file",
                cand.id,
                source.display()
            ));
        }

        let (source_hash, _) = hash_file(&source)?;

        // Back up an existing destination before overwriting.
        let (backup, replaced_hash) = if dest.is_file() {
            let (rh, _) = hash_file(&dest)?;
            let bak = dest.with_extension(format!(
                "{}.orig",
                dest.extension().and_then(|e| e.to_str()).unwrap_or("bak")
            ));
            (Some(bak), Some(rh))
        } else {
            (None, None)
        };

        let record = AssimilationRecord {
            schema_version: assay_schema_version(),
            created_at: chrono::Utc::now().to_rfc3339(),
            candidate_id: cand.id.clone(),
            proven_name: cand.proven_name.clone(),
            proof_backing: cand.proof_backing.clone(),
            action: if config.dry_run {
                AssimilateAction::DryRun
            } else {
                AssimilateAction::FileSwapped
            },
            source: Some(source.clone()),
            source_hash: Some(source_hash),
            destination: dest.clone(),
            backup: backup.clone(),
            replaced_hash,
            pending_callsite_rewires: cand.target_hits.clone(),
            trust_basis,
        };

        if !config.dry_run {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            if let Some(bak) = &backup {
                // Never clobber a pre-existing .orig backup.
                if !bak.exists() {
                    fs::copy(&dest, bak)
                        .with_context(|| format!("backing up {} -> {}", dest.display(), bak.display()))?;
                }
            }
            fs::copy(&source, &dest)
                .with_context(|| format!("copying {} -> {}", source.display(), dest.display()))?;
            write_provenance(&config.target, &record)?;
        }

        applied.push(record);
    }

    Ok(AssimilationOutcome {
        schema_version: assay_schema_version(),
        created_at: chrono::Utc::now().to_rfc3339(),
        target: config.target,
        applied,
        notes,
    })
}

fn write_provenance(target: &Path, record: &AssimilationRecord) -> Result<()> {
    let dir = target.join(".assimilated");
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{}.json", record.candidate_id));
    let json = serde_json::to_string_pretty(record).context("serializing provenance")?;
    fs::write(&path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type SourceFile = (PathBuf, String, String);

fn collect_source_files(root: &Path) -> Result<Vec<SourceFile>> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_skipped_dir(e.path()))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = match path.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_ascii_lowercase(),
            None => continue,
        };
        // Only read text source extensions we have detectors for.
        if !catalogue()
            .iter()
            .any(|c| c.file_exts.contains(&ext.as_str()))
        {
            continue;
        }
        let content = match read_bounded(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let rel = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        out.push((rel, content, ext));
    }
    Ok(out)
}

fn is_skipped_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| SKIP_DIRS.contains(&n))
        .unwrap_or(false)
}

/// Find a replacement source inside any `--proven` checkout by filename stem.
fn resolve_replacement(proven_sources: &[PathBuf], hints: &[&str]) -> Option<PathBuf> {
    for root in proven_sources {
        for entry in WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| !is_skipped_dir(e.path()))
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if hints.iter().any(|h| stem.eq_ignore_ascii_case(h)) {
                    return Some(path.to_path_buf());
                }
            }
        }
    }
    None
}

fn read_bounded(path: &Path) -> Result<String> {
    let mut buf = String::new();
    fs::File::open(path)?
        .take(SOURCE_READ_LIMIT)
        .read_to_string(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn assay_detects_canonicalize_unwrap_pattern() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("foo.rs"),
            "fn d(p: &Path) -> PathBuf {\n    fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())\n}\n",
        )
        .unwrap();

        let report = run(AssayConfig {
            target: dir.path().to_path_buf(),
            proven_sources: Vec::new(),
        })
        .unwrap();

        let safe_path = report
            .candidates
            .iter()
            .find(|c| c.id == "safe-path")
            .expect("safe-path candidate");
        assert_eq!(safe_path.target_hits.len(), 1);
        assert_eq!(safe_path.target_hits[0].line, 2);
        // No proven checkout and no in-tree port → cannot proceed yet.
        assert_eq!(safe_path.status, CandidateStatus::NoReplacementSource);
    }

    #[test]
    fn assay_marks_already_applied_when_port_present_and_no_hits() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        // Port marker present, no offending call sites.
        fs::write(src.join("safe_path.rs"), "// proven port\n").unwrap();
        fs::write(src.join("clean.rs"), "fn ok() {}\n").unwrap();

        let report = run(AssayConfig {
            target: dir.path().to_path_buf(),
            proven_sources: Vec::new(),
        })
        .unwrap();

        let safe_path = report
            .candidates
            .iter()
            .find(|c| c.id == "safe-path")
            .expect("safe-path candidate");
        assert!(safe_path.port_present);
        assert_eq!(safe_path.status, CandidateStatus::AlreadyApplied);
    }

    #[test]
    fn assimilate_swaps_file_with_backup_and_provenance() {
        let target = TempDir::new().unwrap();
        let proven = TempDir::new().unwrap();

        // Target has a VERISIMDB_URL hit (triggers safe-url) and an existing
        // destination file to be replaced.
        let tsrc = target.path().join("src");
        fs::create_dir_all(&tsrc).unwrap();
        fs::write(
            tsrc.join("storage.rs"),
            "let url = std::env::var(\"VERISIMDB_URL\").unwrap();\n",
        )
        .unwrap();
        fs::write(tsrc.join("safe_url.rs"), "// OLD placeholder\n").unwrap();

        // Proven checkout provides the replacement.
        let psrc = proven.path().join("ports");
        fs::create_dir_all(&psrc).unwrap();
        fs::write(psrc.join("safe_url.rs"), "// PROVEN SafeUrl port\n").unwrap();

        let outcome = assimilate(AssimilateConfig {
            target: target.path().to_path_buf(),
            proven_sources: vec![proven.path().to_path_buf()],
            candidate_id: Some("safe-url".to_string()),
            from: None,
            apply_all: false,
            dry_run: false,
        })
        .unwrap();

        assert_eq!(outcome.applied.len(), 1);
        let rec = &outcome.applied[0];
        assert_eq!(rec.action, AssimilateAction::FileSwapped);
        assert!(rec.source_hash.is_some());
        assert!(rec.replaced_hash.is_some(), "old dest should be hashed");
        assert!(rec.backup.is_some(), "backup should be recorded");

        // Destination now holds the proven content.
        let dest = target.path().join("src/safe_url.rs");
        assert!(fs::read_to_string(&dest).unwrap().contains("PROVEN SafeUrl"));
        // Backup holds the old content.
        let bak = rec.backup.as_ref().unwrap();
        assert!(fs::read_to_string(bak).unwrap().contains("OLD placeholder"));
        // Provenance written.
        assert!(target.path().join(".assimilated/safe-url.json").is_file());
    }

    #[test]
    fn assimilate_dry_run_writes_nothing() {
        let target = TempDir::new().unwrap();
        let proven = TempDir::new().unwrap();
        let tsrc = target.path().join("src");
        fs::create_dir_all(&tsrc).unwrap();
        fs::write(
            tsrc.join("storage.rs"),
            "VERISIMDB_URL env access here\n",
        )
        .unwrap();
        let psrc = proven.path().join("ports");
        fs::create_dir_all(&psrc).unwrap();
        fs::write(psrc.join("safe_url.rs"), "// PROVEN\n").unwrap();

        let outcome = assimilate(AssimilateConfig {
            target: target.path().to_path_buf(),
            proven_sources: vec![proven.path().to_path_buf()],
            candidate_id: Some("safe-url".to_string()),
            from: None,
            apply_all: false,
            dry_run: true,
        })
        .unwrap();

        assert_eq!(outcome.applied[0].action, AssimilateAction::DryRun);
        assert!(!target.path().join("src/safe_url.rs").exists());
        assert!(!target.path().join(".assimilated").exists());
    }
}
