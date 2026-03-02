// SPDX-License-Identifier: PMPL-1.0-or-later

//! Assemblyline: batch scanning across multiple git repositories
//!
//! Walks a parent directory, finds subdirectories containing `.git/`,
//! runs `assail::analyze()` on each using rayon for parallel execution,
//! and produces a summary report sorted by weak point count (highest first).
//!
//! Supports BLAKE3 fingerprinting for incremental scanning — on subsequent
//! runs, repos whose source files haven't changed are skipped.

use crate::assail;
use crate::types::AssailReport;
use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration for an assemblyline run.
///
/// Note: `output`, `sarif`, and `cache_file` are read by the CLI caller,
/// not by the assemblyline engine itself (except `cache_file` which is
/// used by `run()` for incremental scanning).
#[allow(dead_code)]
pub struct AssemblylineConfig {
    /// Parent directory to scan for git repos
    pub directory: PathBuf,
    /// Output path for JSON report (handled by caller)
    pub output: Option<PathBuf>,
    /// Only show repos with findings
    pub findings_only: bool,
    /// Minimum number of findings to include
    pub min_findings: usize,
    /// Emit SARIF instead of default JSON (handled by caller)
    pub sarif: bool,
    /// Path to fingerprint cache file for incremental scanning
    pub cache_file: Option<PathBuf>,
}

/// Results from scanning a single repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoResult {
    pub repo_path: PathBuf,
    pub repo_name: String,
    pub weak_point_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub total_files: usize,
    pub total_lines: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// BLAKE3 hash of all source files in this repo (for incremental scanning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip)]
    pub report: Option<AssailReport>,
}

/// Complete assemblyline report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssemblylineReport {
    pub created_at: String,
    pub directory: PathBuf,
    pub repos_scanned: usize,
    pub repos_with_findings: usize,
    pub repos_skipped: usize,
    pub total_weak_points: usize,
    pub total_critical: usize,
    pub results: Vec<RepoResult>,
}

/// Fingerprint cache: maps repo paths to their BLAKE3 hashes from a previous run.
/// Used for incremental scanning — repos with matching fingerprints are skipped.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FingerprintCache {
    pub fingerprints: HashMap<PathBuf, String>,
}

impl FingerprintCache {
    /// Load fingerprint cache from a previous assemblyline report
    pub fn from_report(report: &AssemblylineReport) -> Self {
        let mut fingerprints = HashMap::new();
        for result in &report.results {
            if let Some(fp) = &result.fingerprint {
                fingerprints.insert(result.repo_path.clone(), fp.clone());
            }
        }
        Self { fingerprints }
    }

    /// Load fingerprint cache from a previous assemblyline report JSON file
    pub fn load_from_report_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let report: AssemblylineReport = serde_json::from_str(&content)?;
        Ok(Self::from_report(&report))
    }

    /// Check if a repo's fingerprint matches the cached value
    pub fn is_unchanged(&self, repo_path: &Path, current_fingerprint: &str) -> bool {
        self.fingerprints
            .get(repo_path)
            .map(|cached| cached == current_fingerprint)
            .unwrap_or(false)
    }

    /// Save fingerprint cache extracted from an assemblyline report
    pub fn save_from_report(report: &AssemblylineReport, path: &Path) -> Result<()> {
        let cache = Self::from_report(report);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&cache)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load fingerprint cache from a standalone cache JSON file
    pub fn load_cache_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let cache: Self = serde_json::from_str(&content)?;
        Ok(cache)
    }
}

/// Compute BLAKE3 hash of all source files in a directory.
///
/// Walks the directory recursively, hashing the content of every file
/// with a known source extension. Files are sorted by path for determinism.
/// The final hash is the BLAKE3 digest of all individual file hashes
/// concatenated in sorted order.
pub fn fingerprint_repo(repo_path: &Path) -> Result<String> {
    let mut file_hashes: Vec<(String, blake3::Hash)> = Vec::new();

    collect_source_hashes(repo_path, &mut file_hashes)?;

    // Sort by path for deterministic fingerprint
    file_hashes.sort_by(|a, b| a.0.cmp(&b.0));

    // Combine all file hashes into one repo-level hash
    let mut hasher = blake3::Hasher::new();
    for (path, hash) in &file_hashes {
        hasher.update(path.as_bytes());
        hasher.update(hash.as_bytes());
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Recursively collect BLAKE3 hashes of source files
fn collect_source_hashes(
    dir: &Path,
    hashes: &mut Vec<(String, blake3::Hash)>,
) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Ok(()), // Skip unreadable directories
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip hidden directories (.git, .cache, etc.) and common non-source dirs
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "_build"
                || name == "deps"
                || name == "__pycache__"
                || name == "vendor"
                || name == "build"
            {
                continue;
            }
            collect_source_hashes(&path, hashes)?;
        } else if is_source_file(&path) {
            if let Ok(hash) = hash_file(&path) {
                let rel_path = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                hashes.push((rel_path, hash));
            }
        }
    }

    Ok(())
}

/// Hash a single file with BLAKE3 using memory-mapped I/O for performance
fn hash_file(path: &Path) -> Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_mmap(path)?;
    Ok(hasher.finalize())
}

/// Check if a file has a known source code extension
fn is_source_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    matches!(
        ext,
        "rs" | "c" | "h" | "cpp" | "cc" | "cxx" | "hpp" | "hxx"
            | "go" | "java" | "py" | "pyw"
            | "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx"
            | "rb" | "ex" | "exs" | "erl" | "hrl" | "gleam"
            | "res" | "resi" | "ml" | "mli" | "sml" | "sig"
            | "scm" | "ss" | "sld" | "rkt" | "scrbl"
            | "hs" | "lhs" | "purs"
            | "idr" | "ipkg" | "lean" | "agda" | "lagda"
            | "pl" | "pro" | "lgt" | "logtalk" | "dl"
            | "zig" | "adb" | "ads" | "gpr" | "odin"
            | "nim" | "nims" | "pony" | "d" | "di"
            | "ncl" | "nix" | "sh" | "bash" | "zsh" | "fish"
            | "jl" | "lua" | "luau"
            | "toml" | "yaml" | "yml" | "json"
    )
}

/// Find all git repositories under the given directory
fn discover_repos(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut repos = Vec::new();

    if !directory.is_dir() {
        anyhow::bail!("Not a directory: {}", directory.display());
    }

    let entries = fs::read_dir(directory)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let git_dir = path.join(".git");
            if git_dir.exists() && git_dir.is_dir() {
                repos.push(path);
            }
        }
    }

    repos.sort();
    Ok(repos)
}

/// Scan a single repo, returning its RepoResult.
/// Extracted as a standalone function for parallel execution via rayon.
fn scan_repo(repo_path: &Path) -> RepoResult {
    let repo_name = repo_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| repo_path.display().to_string());

    // Compute BLAKE3 fingerprint (best effort — don't fail the scan if hashing fails)
    let fingerprint = fingerprint_repo(repo_path).ok();

    match assail::analyze(repo_path) {
        Ok(report) => {
            let critical_count = report
                .weak_points
                .iter()
                .filter(|wp| matches!(wp.severity, crate::types::Severity::Critical))
                .count();
            let high_count = report
                .weak_points
                .iter()
                .filter(|wp| matches!(wp.severity, crate::types::Severity::High))
                .count();

            RepoResult {
                repo_path: repo_path.to_path_buf(),
                repo_name,
                weak_point_count: report.weak_points.len(),
                critical_count,
                high_count,
                total_files: report.file_statistics.len(),
                total_lines: report.statistics.total_lines,
                error: None,
                fingerprint,
                report: Some(report),
            }
        }
        Err(e) => RepoResult {
            repo_path: repo_path.to_path_buf(),
            repo_name,
            weak_point_count: 0,
            critical_count: 0,
            high_count: 0,
            total_files: 0,
            total_lines: 0,
            error: Some(e.to_string()),
            fingerprint,
            report: None,
        },
    }
}

/// Run assemblyline across all repos in a directory.
///
/// Uses rayon for parallel scanning across available CPU cores.
/// If a cache file is configured, loads BLAKE3 fingerprints to skip
/// repos whose source files haven't changed (incremental mode).
/// After scanning, saves updated fingerprints back to the cache file.
pub fn run(config: &AssemblylineConfig) -> Result<AssemblylineReport> {
    let cache = match &config.cache_file {
        Some(path) if path.exists() => {
            FingerprintCache::load_cache_file(path)
                .ok() // gracefully degrade if cache is corrupt
        }
        _ => None,
    };

    let report = run_with_cache(config, cache.as_ref())?;

    // Save updated fingerprints for next incremental run
    if let Some(path) = &config.cache_file {
        FingerprintCache::save_from_report(&report, path)?;
    }

    Ok(report)
}

/// Run assemblyline with optional fingerprint cache for incremental scanning.
pub fn run_with_cache(
    config: &AssemblylineConfig,
    cache: Option<&FingerprintCache>,
) -> Result<AssemblylineReport> {
    let repos = discover_repos(&config.directory)?;
    let total_repos = repos.len();

    // Parallel scan using rayon
    let mut results: Vec<RepoResult> = repos
        .par_iter()
        .map(|repo_path| {
            // Check fingerprint cache for incremental scanning
            if let Some(cache) = cache {
                if let Ok(current_fp) = fingerprint_repo(repo_path) {
                    if cache.is_unchanged(repo_path, &current_fp) {
                        let repo_name = repo_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| repo_path.display().to_string());
                        return RepoResult {
                            repo_path: repo_path.clone(),
                            repo_name,
                            weak_point_count: 0,
                            critical_count: 0,
                            high_count: 0,
                            total_files: 0,
                            total_lines: 0,
                            error: Some("skipped (unchanged)".to_string()),
                            fingerprint: Some(current_fp),
                            report: None,
                        };
                    }
                }
            }
            scan_repo(repo_path)
        })
        .collect();

    let repos_skipped = results
        .iter()
        .filter(|r| {
            r.error
                .as_ref()
                .map(|e| e.contains("skipped (unchanged)"))
                .unwrap_or(false)
        })
        .count();

    // Sort by weak point count descending (riskiest repos first)
    results.sort_by(|a, b| b.weak_point_count.cmp(&a.weak_point_count));

    // Apply filters
    if config.findings_only {
        results.retain(|r| r.weak_point_count > 0);
    }
    if config.min_findings > 0 {
        results.retain(|r| r.weak_point_count >= config.min_findings);
    }

    let repos_with_findings = results.iter().filter(|r| r.weak_point_count > 0).count();
    let total_weak_points: usize = results.iter().map(|r| r.weak_point_count).sum();
    let total_critical: usize = results.iter().map(|r| r.critical_count).sum();

    Ok(AssemblylineReport {
        created_at: chrono::Utc::now().to_rfc3339(),
        directory: config.directory.clone(),
        repos_scanned: total_repos,
        repos_with_findings,
        repos_skipped,
        total_weak_points,
        total_critical,
        results,
    })
}

/// Print a summary table to the terminal
pub fn print_summary(report: &AssemblylineReport, quiet: bool) {
    if quiet {
        return;
    }

    println!("\n=== ASSEMBLYLINE SUMMARY ===");
    println!(
        "Directory: {}  |  Repos scanned: {}  |  With findings: {}  |  Skipped: {}",
        report.directory.display(),
        report.repos_scanned,
        report.repos_with_findings,
        report.repos_skipped,
    );
    println!(
        "Total weak points: {}  |  Critical: {}",
        report.total_weak_points, report.total_critical
    );
    println!();

    if report.results.is_empty() {
        println!("  No repositories with findings.");
        return;
    }

    // Header
    println!(
        "  {:<40} {:>6} {:>6} {:>6} {:>8} {:>8}",
        "Repository", "Total", "Crit", "High", "Files", "Lines"
    );
    println!("  {}", "-".repeat(78));

    // Show top 20 repos
    for result in report.results.iter().take(20) {
        if let Some(err) = &result.error {
            println!("  {:<40} ERROR: {}", result.repo_name, err);
        } else {
            println!(
                "  {:<40} {:>6} {:>6} {:>6} {:>8} {:>8}",
                result.repo_name,
                result.weak_point_count,
                result.critical_count,
                result.high_count,
                result.total_files,
                result.total_lines,
            );
        }
    }

    if report.results.len() > 20 {
        println!("  ... and {} more repos", report.results.len() - 20);
    }
    println!();
}

/// Write assemblyline report as JSON
pub fn write_report(report: &AssemblylineReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(report)?;
    fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("main.rs")));
        assert!(is_source_file(Path::new("lib.py")));
        assert!(is_source_file(Path::new("app.js")));
        assert!(is_source_file(Path::new("mod.gleam")));
        assert!(!is_source_file(Path::new("image.png")));
        assert!(!is_source_file(Path::new("binary.exe")));
        assert!(!is_source_file(Path::new("readme.md")));
    }

    #[test]
    fn test_fingerprint_cache_empty() {
        let cache = FingerprintCache::default();
        assert!(!cache.is_unchanged(Path::new("/tmp/repo"), "abc123"));
    }

    #[test]
    fn test_fingerprint_cache_match() {
        let mut cache = FingerprintCache::default();
        cache
            .fingerprints
            .insert(PathBuf::from("/tmp/repo"), "abc123".to_string());
        assert!(cache.is_unchanged(Path::new("/tmp/repo"), "abc123"));
        assert!(!cache.is_unchanged(Path::new("/tmp/repo"), "xyz789"));
    }
}
