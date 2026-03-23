// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core Assail analyzer implementation
//!
//! Language-specific static analysis for 40+ programming languages.
//! Detects weak points, unsafe patterns, and security anti-patterns
//! across BEAM, ML, Lisp, proof assistant, logic programming,
//! systems, functional, config, scripting, and custom DSL families.

use crate::types::*;
use anyhow::Result;
use regex::Regex;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// Thread-local accumulators for migration analysis.
// These collect deprecated/modern API counts across all files during a single
// analyze() run, then get consumed by build_migration_metrics().
thread_local! {
    static MIGRATION_DEPRECATED: RefCell<Vec<DeprecatedPattern>> = RefCell::new(Vec::new());
    static MIGRATION_DEPRECATED_COUNT: RefCell<usize> = const { RefCell::new(0) };
    static MIGRATION_MODERN_COUNT: RefCell<usize> = const { RefCell::new(0) };
    static MIGRATION_FILE_COUNT: RefCell<usize> = const { RefCell::new(0) };
    static MIGRATION_LINE_COUNT: RefCell<usize> = const { RefCell::new(0) };
}

/// Reset migration thread-local accumulators before a new scan
pub fn reset_migration_accumulators() {
    MIGRATION_DEPRECATED.with(|cell| cell.borrow_mut().clear());
    MIGRATION_DEPRECATED_COUNT.with(|cell| *cell.borrow_mut() = 0);
    MIGRATION_MODERN_COUNT.with(|cell| *cell.borrow_mut() = 0);
    MIGRATION_FILE_COUNT.with(|cell| *cell.borrow_mut() = 0);
    MIGRATION_LINE_COUNT.with(|cell| *cell.borrow_mut() = 0);
}

/// Increment migration file/line counters (called per-file during scan)
pub fn record_migration_file(line_count: usize) {
    MIGRATION_FILE_COUNT.with(|cell| *cell.borrow_mut() += 1);
    MIGRATION_LINE_COUNT.with(|cell| *cell.borrow_mut() += line_count);
}

/// Build MigrationMetrics from accumulated thread-local data
pub fn build_migration_metrics(target: &Path) -> MigrationMetrics {
    let deprecated_count = MIGRATION_DEPRECATED_COUNT.with(|cell| *cell.borrow());
    let modern_count = MIGRATION_MODERN_COUNT.with(|cell| *cell.borrow());
    let deprecated_patterns = MIGRATION_DEPRECATED.with(|cell| cell.borrow().clone());
    let file_count = MIGRATION_FILE_COUNT.with(|cell| *cell.borrow());
    let line_count = MIGRATION_LINE_COUNT.with(|cell| *cell.borrow());

    let total = deprecated_count + modern_count;
    let api_migration_ratio = if total > 0 {
        modern_count as f64 / total as f64
    } else {
        1.0 // No API usage detected = fully migrated (or no code)
    };

    let config_format = Analyzer::detect_rescript_config(target);

    // Read config for version detection
    let config_path = if target.is_dir() {
        if target.join("rescript.json").exists() {
            Some(target.join("rescript.json"))
        } else if target.join("bsconfig.json").exists() {
            Some(target.join("bsconfig.json"))
        } else {
            None
        }
    } else {
        let parent = target.parent().unwrap_or(target);
        if parent.join("rescript.json").exists() {
            Some(parent.join("rescript.json"))
        } else if parent.join("bsconfig.json").exists() {
            Some(parent.join("bsconfig.json"))
        } else {
            None
        }
    };
    let config_content = config_path.and_then(|p| fs::read_to_string(p).ok());

    let version_bracket = Analyzer::detect_rescript_version(
        config_format,
        deprecated_count,
        modern_count,
        config_content.as_deref(),
    );

    // Detect JSX version, uncurried mode, module format from config
    let (jsx_version, uncurried, module_format) = if let Some(ref content) = config_content {
        let jsx = if content.contains("\"version\": 4") || content.contains("\"version\":4") {
            Some(4u8)
        } else if content.contains("\"version\": 3") || content.contains("\"version\":3") {
            Some(3u8)
        } else {
            None
        };
        let uncurried = content.contains("\"uncurried\"");
        let module = if content.contains("\"esmodule\"") {
            Some("esmodule".to_string())
        } else if content.contains("\"commonjs\"") {
            Some("commonjs".to_string())
        } else {
            None
        };
        (jsx, uncurried, module)
    } else {
        (None, false, None)
    };

    // Health score: weighted combination of factors
    let config_score = match config_format {
        ReScriptConfigFormat::RescriptJson => 1.0,
        ReScriptConfigFormat::Both => 0.5,
        ReScriptConfigFormat::BsConfig => 0.0,
        ReScriptConfigFormat::None => 0.5,
    };
    let jsx_score = match jsx_version {
        Some(4) => 1.0,
        Some(3) => 0.3,
        _ => 0.5,
    };
    let uncurried_score = if uncurried { 1.0 } else { 0.3 };
    let health_score = (api_migration_ratio * 0.5)
        + (config_score * 0.2)
        + (jsx_score * 0.15)
        + (uncurried_score * 0.15);

    MigrationMetrics {
        deprecated_api_count: deprecated_count,
        modern_api_count: modern_count,
        api_migration_ratio,
        health_score: (health_score * 100.0).round() / 100.0,
        config_format,
        version_bracket,
        build_time_ms: None,
        bundle_size_bytes: None,
        file_count,
        rescript_lines: line_count,
        deprecated_patterns,
        jsx_version,
        uncurried,
        module_format,
    }
}

/// Pre-compiled regexes for hot-path pattern matching.
/// Using OnceLock avoids recompiling on every file analyzed.
static RE_UNCHECKED_MALLOC: OnceLock<Regex> = OnceLock::new();
static RE_ELIXIR_APPLY: OnceLock<Regex> = OnceLock::new();
static RE_PONY_FFI: OnceLock<Regex> = OnceLock::new();
static RE_SHELL_UNQUOTED_VAR: OnceLock<Regex> = OnceLock::new();
static RE_HTTP_URL: OnceLock<Regex> = OnceLock::new();
static RE_HTTP_LOCALHOST: OnceLock<Regex> = OnceLock::new();
static RE_HARDCODED_SECRET: OnceLock<Regex> = OnceLock::new();

pub struct Analyzer {
    target: PathBuf,
    language: Language,
    verbose: bool,
}

impl Analyzer {
    pub fn new(target: &Path) -> Result<Self> {
        Self::build(target, false)
    }

    pub fn new_verbose(target: &Path) -> Result<Self> {
        Self::build(target, true)
    }

    fn build(target: &Path, verbose: bool) -> Result<Self> {
        if !target.exists() {
            anyhow::bail!("Target does not exist: {}", target.display());
        }

        let language = if target.is_file() {
            Language::detect(target.to_str().unwrap_or(""))
        } else {
            Self::detect_directory_language(target)?
        };

        Ok(Self {
            target: target.to_path_buf(),
            language,
            verbose,
        })
    }

    /// Run analysis with an optional evidence accumulator for attestation.
    ///
    /// When `accumulator` is `Some`, each successfully read file and each
    /// traversed directory are recorded into the accumulator for the
    /// attestation chain. When `None`, this behaves identically to
    /// [`analyze()`].
    pub fn analyze_with_accumulator(
        &self,
        accumulator: Option<&mut crate::attestation::EvidenceAccumulator>,
    ) -> Result<AssailReport> {
        self.analyze_inner(accumulator)
    }

    pub fn analyze(&self) -> Result<AssailReport> {
        self.analyze_inner(None)
    }

    fn analyze_inner(
        &self,
        mut accumulator: Option<&mut crate::attestation::EvidenceAccumulator>,
    ) -> Result<AssailReport> {
        // Reset migration accumulators for a clean scan
        reset_migration_accumulators();

        // Global aggregates are intentionally maintained alongside per-file analysis
        // so output can support both campaign-level scoring and local triage.
        let mut global_stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut all_weak_points = Vec::new();
        let mut file_statistics = Vec::new();

        let files = self.collect_source_files()?;

        let base = if self.target.is_dir() {
            self.target.clone()
        } else {
            self.target.parent().unwrap_or(Path::new(".")).to_path_buf()
        };

        // Record traversed directories into the attestation accumulator
        if let Some(ref mut acc) = accumulator {
            let mut seen_dirs: HashSet<String> = HashSet::new();
            for file in &files {
                if let Some(parent) = file.parent() {
                    let dir_str = parent.to_string_lossy().to_string();
                    if seen_dirs.insert(dir_str.clone()) {
                        acc.record_directory(&dir_str);
                    }
                }
            }
        }

        // Each source file is analyzed independently; this keeps weak-point attribution precise.
        for file in &files {
            let raw_bytes = match fs::read(file) {
                Ok(b) => b,
                Err(e) => {
                    if self.verbose {
                        eprintln!("Skipping unreadable file: {} ({})", file.display(), e);
                    }
                    continue;
                }
            };

            // Try UTF-8 first, then Latin-1 fallback.
            // Use str::from_utf8 to borrow rather than cloning raw_bytes.
            let content = match std::str::from_utf8(&raw_bytes) {
                Ok(s) => s.to_owned(),
                Err(_) => {
                    let (cow, _, had_errors) = encoding_rs::WINDOWS_1252.decode(&raw_bytes);
                    if had_errors {
                        if self.verbose {
                            eprintln!(
                                "Skipping non-text file: {} (neither UTF-8 nor Latin-1)",
                                file.display()
                            );
                        }
                        continue;
                    }
                    cow.into_owned()
                }
            };

            let rel_path = file
                .strip_prefix(&base)
                .unwrap_or(file)
                .to_string_lossy()
                .to_string();

            let mut file_stats = ProgramStatistics {
                total_lines: 0,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 0,
                io_operations: 0,
                threading_constructs: 0,
            };

            file_stats.total_lines = content.lines().count();

            let mut file_weak_points = Vec::new();

            // Dispatch to language-specific analyzer
            let file_lang = Language::detect(file.to_str().unwrap_or(""));

            // Record this file into the attestation accumulator (zero-cost when None)
            if let Some(ref mut acc) = accumulator {
                acc.record_file(&rel_path, &raw_bytes, &format!("{:?}", file_lang));
            }

            match file_lang {
                Language::Rust => {
                    self.analyze_rust(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::C | Language::Cpp => {
                    self.analyze_c_cpp(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Go => {
                    self.analyze_go(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Python => {
                    self.analyze_python(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::JavaScript => {
                    self.analyze_javascript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Ruby => {
                    self.analyze_ruby(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // BEAM family
                Language::Elixir => {
                    self.analyze_elixir(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Erlang => {
                    self.analyze_erlang(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Gleam => {
                    self.analyze_gleam(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // ML family
                Language::ReScript => {
                    record_migration_file(file_stats.total_lines);
                    self.analyze_rescript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::OCaml => {
                    self.analyze_ocaml(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::StandardML => {
                    self.analyze_sml(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Lisp family
                Language::Scheme | Language::Racket => {
                    self.analyze_lisp(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Functional
                Language::Haskell => {
                    self.analyze_haskell(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::PureScript => {
                    self.analyze_purescript(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Proof assistants
                Language::Idris => {
                    self.analyze_idris(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Lean => {
                    self.analyze_lean(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Agda => {
                    self.analyze_agda(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Logic programming
                Language::Prolog | Language::Logtalk | Language::Datalog => {
                    self.analyze_logic(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Systems languages
                Language::Zig => {
                    self.analyze_zig(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Ada => {
                    self.analyze_ada(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Odin => {
                    self.analyze_odin(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Nim => {
                    self.analyze_nim(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::Pony => {
                    self.analyze_pony(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                Language::DLang => {
                    self.analyze_dlang(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Config languages
                Language::Nickel | Language::Nix => {
                    self.analyze_config(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                // Scripting
                Language::Shell => {
                    self.analyze_shell(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Julia => {
                    self.analyze_julia(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Lua => {
                    self.analyze_lua(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                // Nextgen DSLs - shared analyzer
                Language::WokeLang
                | Language::Eclexia
                | Language::MyLang
                | Language::JuliaTheViper
                | Language::Oblibeny
                | Language::Anvomidav
                | Language::AffineScript
                | Language::Ephapax
                | Language::BetLang
                | Language::ErrorLang
                | Language::VQL
                | Language::FBQL => {
                    self.analyze_nextgen_dsl(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Java => {
                    self.analyze_java(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
                }
                _ => {
                    self.analyze_generic(&content, &mut file_stats, &rel_path)?;
                }
            }

            // Cross-language security checks (run on all files)
            self.analyze_cross_language(&content, &mut file_weak_points, &rel_path)?;

            // Accumulate global stats
            global_stats.total_lines += file_stats.total_lines;
            global_stats.unsafe_blocks += file_stats.unsafe_blocks;
            global_stats.panic_sites += file_stats.panic_sites;
            global_stats.unwrap_calls += file_stats.unwrap_calls;
            global_stats.allocation_sites += file_stats.allocation_sites;
            global_stats.io_operations += file_stats.io_operations;
            global_stats.threading_constructs += file_stats.threading_constructs;

            all_weak_points.extend(file_weak_points);

            let has_findings = file_stats.unsafe_blocks > 0
                || file_stats.panic_sites > 0
                || file_stats.unwrap_calls > 0
                || file_stats.allocation_sites > 0
                || file_stats.io_operations > 0
                || file_stats.threading_constructs > 0;

            if has_findings {
                file_statistics.push(FileStatistics {
                    file_path: rel_path,
                    lines: file_stats.total_lines,
                    unsafe_blocks: file_stats.unsafe_blocks,
                    panic_sites: file_stats.panic_sites,
                    unwrap_calls: file_stats.unwrap_calls,
                    allocation_sites: file_stats.allocation_sites,
                    io_operations: file_stats.io_operations,
                    threading_constructs: file_stats.threading_constructs,
                });
            }
        }

        // Secondary synthesis stages derive framework hints and relational overlays.
        let frameworks = self.detect_frameworks(&files)?;
        let recommended_attacks = self.generate_recommendations(&all_weak_points, &global_stats);
        let dependency_graph = Self::build_dependency_graph(&file_statistics, &frameworks);
        let taint_matrix = Self::build_taint_matrix(&all_weak_points, &frameworks);

        // Build migration metrics for ReScript projects
        let migration_metrics = if self.language == Language::ReScript {
            Some(build_migration_metrics(&self.target))
        } else {
            None
        };

        Ok(AssailReport {
            program_path: self.target.clone(),
            language: self.language,
            frameworks,
            weak_points: all_weak_points,
            statistics: global_stats,
            file_statistics,
            recommended_attacks,
            dependency_graph,
            taint_matrix,
            migration_metrics,
        })
    }

    fn collect_source_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        if self.target.is_file() {
            files.push(self.target.clone());
        } else {
            // Directory mode performs a conservative recursive walk with language filtering.
            self.walk_directory(&self.target, &mut files)?;
        }

        Ok(files)
    }

    fn walk_directory(&self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Skip build artifacts, hidden dirs, and dependency dirs
                if ![
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
                ]
                .contains(&name)
                {
                    self.walk_directory(&path, files)?;
                }
            } else if path.is_file() {
                let lang = Language::detect(path.to_str().unwrap_or(""));
                if lang != Language::Unknown {
                    files.push(path);
                }
            }
        }

        Ok(())
    }

    fn detect_directory_language(dir: &Path) -> Result<Language> {
        let mut counts = std::collections::HashMap::new();

        // Cap recursion depth for responsiveness on very large trees.
        Self::count_languages_recursive(dir, &mut counts, 0)?;

        counts.remove(&Language::Unknown);

        counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(lang, _)| lang)
            .ok_or_else(|| anyhow::anyhow!("Could not detect language"))
    }

    fn count_languages_recursive(
        dir: &Path,
        counts: &mut std::collections::HashMap<Language, usize>,
        depth: usize,
    ) -> Result<()> {
        if depth > 10 {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_str().unwrap_or("");

            if path.is_dir() {
                if name_str.starts_with('.')
                    || [
                        "target",
                        "node_modules",
                        "vendor",
                        "build",
                        "_build",
                        "_opam",
                        ".stack-work",
                        "dist-newstyle",
                        "deps",
                        "zig-cache",
                        "zig-out",
                        "ebin",
                        "external_corpora",
                        "third_party",
                        "testdata",
                        "test_fixtures",
                        "fixtures",
                        "corpus",
                        "corpora",
                    ]
                    .contains(&name_str)
                {
                    continue;
                }
                Self::count_languages_recursive(&path, counts, depth + 1)?;
            } else if path.is_file() {
                let lang = Language::detect(path.to_str().unwrap_or(""));
                *counts.entry(lang).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    // ============================================================
    // Original language analyzers
    // ============================================================

    fn analyze_rust(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.unsafe_blocks += content.matches("unsafe {").count();
        stats.unsafe_blocks += content.matches("unsafe fn").count();
        stats.panic_sites += content.matches("panic!(").count();
        stats.panic_sites += content.matches("unreachable!(").count();
        stats.unwrap_calls += content.matches(".unwrap()").count();
        stats.unwrap_calls += content.matches(".expect(").count();
        stats.allocation_sites += content.matches("Vec::new()").count();
        stats.allocation_sites += content.matches("Box::new(").count();
        stats.allocation_sites += content.matches("String::new()").count();
        stats.io_operations += content.matches("std::fs::").count();
        stats.io_operations += content.matches("std::io::").count();
        stats.threading_constructs += content.matches("std::thread::").count();
        stats.threading_constructs += content.matches("std::sync::").count();

        if stats.unsafe_blocks > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe blocks in {}", stats.unsafe_blocks, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
            });
        }

        if stats.unwrap_calls > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} unwrap/expect calls in {}",
                    stats.unwrap_calls, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Disk],
            });
        }

        // mem::transmute — type-punning bypasses Rust's type system entirely
        if content.contains("transmute(") || content.contains("transmute::<") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("mem::transmute usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // mem::forget — deliberately leaks resources without running destructors
        if content.contains("mem::forget(") || content.contains("forget(") && content.contains("use std::mem") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("mem::forget usage (resource leak) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Raw pointer casts — escape safe Rust's borrow checker guarantees
        if content.contains("as *const ") || content.contains("as *mut ") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Raw pointer cast in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
            });
        }

        Ok(())
    }

    fn analyze_c_cpp(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("malloc(").count();
        stats.allocation_sites += content.matches("calloc(").count();
        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("fopen(").count();
        stats.io_operations += content.matches("read(").count();
        stats.io_operations += content.matches("write(").count();
        stats.threading_constructs += content.matches("pthread_").count();
        stats.threading_constructs += content.matches("std::thread").count();

        let unchecked_malloc = RE_UNCHECKED_MALLOC.get_or_init(|| Regex::new(r"malloc\([^)]+\)\s*;").unwrap());
        if unchecked_malloc.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedAllocation,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unchecked malloc in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // gets() — no bounds checking, classic buffer overflow vector
        if content.contains("gets(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("gets() usage (unbounded buffer write) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // system() — shell command injection via unvalidated input
        if content.contains("system(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("system() call (command injection risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // sprintf() — no bounds checking, format string overflow
        if content.contains("sprintf(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("sprintf() usage (buffer overflow risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // strcpy/strcat — classic unbounded string operations
        if content.contains("strcpy(") || content.contains("strcat(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unbounded string operation (strcpy/strcat) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_go(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("make(").count();
        stats.threading_constructs += content.matches("go func").count();
        stats.threading_constructs += content.matches("go ").count();

        let go_count = content.matches("go ").count();
        if go_count > 10 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} goroutines spawned in {}", go_count, file_path),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
            });
        }

        // unsafe.Pointer — bypasses Go's type safety and GC guarantees
        if content.contains("unsafe.Pointer") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafe.Pointer usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // exec.Command — shell command execution, injection risk
        if content.contains("exec.Command") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("exec.Command usage (command injection risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    fn analyze_python(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("open(").count();
        stats.threading_constructs += content.matches("threading.").count();

        if content.contains("while True:") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnboundedLoop,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unbounded while True loop in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Time],
            });
        }

        if content.contains("eval(") || content.contains("exec(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Dynamic code execution (eval/exec) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // pickle.load / pickle.loads — arbitrary code execution via deserialization
        if content.contains("pickle.load") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("pickle deserialization (arbitrary code execution) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // os.system / os.popen / subprocess with shell=True — command injection
        if content.contains("os.system(") || content.contains("os.popen(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Shell command execution (os.system/os.popen) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // subprocess with shell=True
        if content.contains("subprocess.call") || content.contains("subprocess.Popen") || content.contains("subprocess.run") {
            if content.contains("shell=True") || content.contains("shell = True") {
                weak_points.push(WeakPoint {
                    category: WeakPointCategory::CommandInjection,
                    location: Some(file_path.to_string()),
                    severity: Severity::High,
                    description: format!("subprocess with shell=True in {}", file_path),
                    recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                });
            }
        }

        Ok(())
    }

    fn analyze_javascript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("fs.read").count();
        stats.io_operations += content.matches("fs.write").count();
        stats.io_operations += content.matches("fetch(").count();
        stats.threading_constructs += content.matches("Worker(").count();
        stats.threading_constructs += content.matches("new Worker").count();

        if content.contains("eval(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval() usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // innerHTML / document.write — DOM-based XSS vectors
        if content.contains("innerHTML") || content.contains("document.write(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("DOM manipulation (innerHTML/document.write) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Network],
            });
        }

        // dangerouslySetInnerHTML — React's explicit escape hatch for raw HTML injection
        if content.contains("dangerouslySetInnerHTML") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("dangerouslySetInnerHTML (XSS risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Network],
            });
        }

        // Deno -A permission check
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
            });
        }

        // JSON.parseExn / JSON.parse without try-catch
        let parse_exn_count = content.matches("JSON.parseExn").count();
        if parse_exn_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} JSON.parseExn calls in {}", parse_exn_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    fn analyze_ruby(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("File.open").count();
        stats.io_operations += content.matches("IO.read").count();
        stats.threading_constructs += content.matches("Thread.new").count();

        if content.contains("eval(") || content.contains("send(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Dynamic code execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_java(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("FileInputStream").count();
        stats.io_operations += content.matches("FileOutputStream").count();
        stats.threading_constructs += content.matches("new Thread").count();
        stats.threading_constructs += content.matches("ExecutorService").count();

        if content.contains("Runtime.getRuntime().exec(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Runtime.exec() in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    // ============================================================
    // BEAM family (Elixir, Erlang, Gleam)
    // ============================================================

    fn analyze_elixir(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Process spawning (concurrency)
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("spawn_link(").count();
        stats.threading_constructs += content.matches("Task.async(").count();
        stats.threading_constructs += content.matches("Task.start(").count();
        stats.threading_constructs += content.matches("GenServer.start").count();

        // I/O operations
        stats.io_operations += content.matches("File.read").count();
        stats.io_operations += content.matches("File.write").count();
        stats.io_operations += content.matches("IO.read").count();
        stats.io_operations += content.matches("HTTPoison").count();
        stats.io_operations += content.matches("Req.").count();

        // Allocations (ETS tables, large data structures)
        stats.allocation_sites += content.matches(":ets.new").count();
        stats.allocation_sites += content.matches("Agent.start").count();

        // Dynamic code execution
        if content.contains("Code.eval_string") || content.contains("Code.eval_quoted") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Code.eval_string/eval_quoted in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // Atom exhaustion
        let atom_count = content.matches("String.to_atom").count();
        if atom_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} String.to_atom calls in {} (use String.to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Port/System.cmd - command injection risk
        if content.contains("Port.open") || content.contains("System.cmd") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("System command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Unsafe apply
        let apply_re = RE_ELIXIR_APPLY.get_or_init(|| Regex::new(r"apply\([^,]+,\s*[^,]+,").unwrap());
        if apply_re.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Dynamic apply/3 in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    fn analyze_erlang(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("spawn_link(").count();
        stats.threading_constructs += content.matches("spawn_monitor(").count();
        stats.io_operations += content.matches("file:read").count();
        stats.io_operations += content.matches("file:write").count();
        stats.io_operations += content.matches("httpc:request").count();
        stats.allocation_sites += content.matches("ets:new").count();

        // Atom exhaustion
        let atom_count =
            content.matches("list_to_atom").count() + content.matches("binary_to_atom").count();
        if atom_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} unchecked atom creation in {} (use list_to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // os:cmd - command injection
        if content.contains("os:cmd") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os:cmd call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        Ok(())
    }

    fn analyze_gleam(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Gleam external functions (FFI boundary)
        let external_count = content.matches("@external(").count();
        stats.unsafe_blocks += external_count;

        stats.io_operations += content.matches("simplifile").count();
        stats.io_operations += content.matches("gleam/http").count();

        if external_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @external FFI calls in {}", external_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    // ============================================================
    // ML family (ReScript, OCaml, Standard ML)
    // ============================================================

    fn analyze_rescript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // External bindings (FFI boundary)
        let external_count = content.matches("@val external").count()
            + content.matches("@module external").count()
            + content.matches("@send external").count()
            + content.matches("@get external").count();
        stats.unsafe_blocks += external_count;

        // Unsafe JSON parsing
        let parse_exn = content.matches("JSON.parseExn").count();
        if parse_exn > 0 {
            stats.panic_sites += parse_exn;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} JSON.parseExn calls in {} (use JSON.parse for safe Result)",
                    parse_exn, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Mutable refs
        stats.allocation_sites += content.matches("ref(").count();

        // Ignored results (potential mutation bug)
        let ignore_count = content.matches("ignore(").count();
        if ignore_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} ignore() calls in {} (may discard important results)",
                    ignore_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // getUnsafe / getExn
        let unsafe_gets = content.matches("getUnsafe").count()
            + content.matches("getExn").count()
            + content.matches("getOrExn").count();
        if unsafe_gets > 0 {
            stats.unwrap_calls += unsafe_gets;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} unsafe get calls in {}", unsafe_gets, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // I/O via Deno/Node APIs
        stats.io_operations += content.matches("Deno.readTextFile").count();
        stats.io_operations += content.matches("Deno.writeTextFile").count();
        stats.io_operations += content.matches("fetch(").count();

        // === Migration analysis: deprecated Js.* APIs ===
        let deprecated_js_apis: &[(&str, &str, DeprecatedCategory)] = &[
            ("Js.Array2", "Array", DeprecatedCategory::JsApi),
            ("Js.Array.", "Array", DeprecatedCategory::JsApi),
            ("Js.String2", "String", DeprecatedCategory::JsApi),
            ("Js.String.", "String", DeprecatedCategory::JsApi),
            ("Js.Dict.", "Dict", DeprecatedCategory::OldDict),
            ("Js.Console.", "Console", DeprecatedCategory::OldConsole),
            ("Js.log", "Console.log", DeprecatedCategory::OldConsole),
            ("Js.log2", "Console.log2", DeprecatedCategory::OldConsole),
            ("Js.Promise.", "Promise", DeprecatedCategory::OldPromise),
            ("Js.Nullable.", "Nullable", DeprecatedCategory::OldNullable),
            ("Js.Float.", "Float", DeprecatedCategory::OldNumeric),
            ("Js.Int.", "Int", DeprecatedCategory::OldNumeric),
            ("Js.Math.", "Math", DeprecatedCategory::OldNumeric),
            ("Js.Json.", "JSON", DeprecatedCategory::OldJson),
            ("Js.Re.", "RegExp", DeprecatedCategory::OldRegExp),
            ("Js.Date.", "Date (no core replacement yet)", DeprecatedCategory::OldDate),
        ];

        let mut deprecated_patterns = Vec::new();
        let mut deprecated_count = 0usize;

        for &(pattern, replacement, category) in deprecated_js_apis {
            let count = content.matches(pattern).count();
            if count > 0 {
                deprecated_count += count;
                deprecated_patterns.push(DeprecatedPattern {
                    pattern: pattern.to_string(),
                    replacement: replacement.to_string(),
                    file_path: file_path.to_string(),
                    line_number: 0,
                    category,
                    count,
                });
            }
        }

        // === Migration analysis: deprecated Belt.* APIs ===
        let deprecated_belt_apis: &[&str] = &[
            "Belt.Array", "Belt.List", "Belt.Map", "Belt.Set",
            "Belt.Option", "Belt.Result", "Belt.Int", "Belt.Float",
            "Belt.SortArray", "Belt.HashMap", "Belt.HashSet",
            "Belt.MutableMap", "Belt.MutableSet", "Belt.MutableQueue",
            "Belt.MutableStack", "Belt.Range",
        ];

        for pattern in deprecated_belt_apis {
            let count = content.matches(pattern).count();
            if count > 0 {
                deprecated_count += count;
                // Belt.X -> X (strip "Belt." prefix)
                let replacement = pattern.strip_prefix("Belt.").unwrap_or(pattern);
                deprecated_patterns.push(DeprecatedPattern {
                    pattern: pattern.to_string(),
                    replacement: replacement.to_string(),
                    file_path: file_path.to_string(),
                    line_number: 0,
                    category: DeprecatedCategory::BeltApi,
                    count,
                });
            }
        }

        // === Migration analysis: modern @rescript/core APIs (positive signals) ===
        let modern_apis: &[&str] = &[
            "Array.", "String.", "Dict.", "Console.", "Promise.",
            "Nullable.", "Float.", "Int.", "Math.", "JSON.",
            "RegExp.", "Map.", "Set.", "Option.", "Result.",
            "Error.", "Iterator.", "AsyncIterator.", "BigInt.",
        ];

        let mut modern_count = 0usize;
        for pattern in modern_apis {
            modern_count += content.matches(pattern).count();
        }
        // Subtract Js.* false positives from modern counts (Js.Array. matched both)
        // Modern APIs are counted independently since they don't have a "Js." prefix.
        // The above count may over-count in files with imports, but it's a useful heuristic.

        // === Migration analysis: old-style patterns ===
        let old_json = content.matches("Js.Json.classify").count();
        if old_json > 0 {
            deprecated_count += old_json;
            deprecated_patterns.push(DeprecatedPattern {
                pattern: "Js.Json.classify".to_string(),
                replacement: "JSON.Classify.classify".to_string(),
                file_path: file_path.to_string(),
                line_number: 0,
                category: DeprecatedCategory::OldJson,
                count: old_json,
            });
        }

        let react_dom_style = content.matches("ReactDOMStyle.make").count()
            + content.matches("ReactDOM.Style.make").count();
        if react_dom_style > 0 {
            deprecated_count += react_dom_style;
            deprecated_patterns.push(DeprecatedPattern {
                pattern: "ReactDOMStyle.make / ReactDOM.Style.make".to_string(),
                replacement: "inline record style={{...}}".to_string(),
                file_path: file_path.to_string(),
                line_number: 0,
                category: DeprecatedCategory::OldReactStyle,
                count: react_dom_style,
            });
        }

        // Store deprecated patterns in a thread-local accumulator
        // (The caller collects them after all files are analyzed)
        MIGRATION_DEPRECATED.with(|cell| {
            cell.borrow_mut().extend(deprecated_patterns);
        });
        MIGRATION_DEPRECATED_COUNT.with(|cell| {
            *cell.borrow_mut() += deprecated_count;
        });
        MIGRATION_MODERN_COUNT.with(|cell| {
            *cell.borrow_mut() += modern_count;
        });

        Ok(())
    }

    /// Detect ReScript config format by checking for bsconfig.json and rescript.json
    fn detect_rescript_config(target: &std::path::Path) -> ReScriptConfigFormat {
        let dir = if target.is_dir() {
            target.to_path_buf()
        } else {
            target.parent().unwrap_or(target).to_path_buf()
        };

        let has_bsconfig = dir.join("bsconfig.json").exists();
        let has_rescript = dir.join("rescript.json").exists();

        match (has_bsconfig, has_rescript) {
            (true, true) => ReScriptConfigFormat::Both,
            (true, false) => ReScriptConfigFormat::BsConfig,
            (false, true) => ReScriptConfigFormat::RescriptJson,
            (false, false) => ReScriptConfigFormat::None,
        }
    }

    /// Detect ReScript version bracket from config + API usage ratios
    fn detect_rescript_version(
        config_format: ReScriptConfigFormat,
        deprecated_count: usize,
        modern_count: usize,
        config_content: Option<&str>,
    ) -> ReScriptVersionBracket {
        // Check config content for version hints
        if let Some(content) = config_content {
            if content.contains("\"uncurried\"") && content.contains("\"v13") {
                return ReScriptVersionBracket::V13PreRelease;
            }
        }

        let total = deprecated_count + modern_count;
        let modern_ratio = if total > 0 {
            modern_count as f64 / total as f64
        } else {
            0.5
        };

        match config_format {
            ReScriptConfigFormat::BsConfig => {
                if modern_ratio < 0.1 {
                    ReScriptVersionBracket::BuckleScript
                } else {
                    ReScriptVersionBracket::V11
                }
            }
            ReScriptConfigFormat::Both => ReScriptVersionBracket::V12Alpha,
            ReScriptConfigFormat::RescriptJson => {
                if modern_ratio > 0.8 {
                    ReScriptVersionBracket::V12Current
                } else {
                    ReScriptVersionBracket::V12Stable
                }
            }
            ReScriptConfigFormat::None => {
                if modern_ratio > 0.5 {
                    ReScriptVersionBracket::V12Current
                } else {
                    ReScriptVersionBracket::V11
                }
            }
        }
    }

    fn analyze_ocaml(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe operations
        if content.contains("Obj.magic") {
            stats.unsafe_blocks += content.matches("Obj.magic").count();
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Obj.magic (unsafe type coercion) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        if content.contains("Obj.repr") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Obj.repr (unsafe representation access) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Unsafe deserialization
        if content.contains("Marshal.from_string") || content.contains("Marshal.from_channel") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unsafe Marshal deserialization in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Command execution
        if content.contains("Unix.system") || content.contains("Unix.execvp") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unix.system/execvp command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        stats.io_operations += content.matches("open_in").count();
        stats.io_operations += content.matches("open_out").count();
        stats.threading_constructs += content.matches("Thread.create").count();
        stats.threading_constructs += content.matches("Mutex.").count();

        Ok(())
    }

    fn analyze_sml(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("TextIO.").count();
        stats.io_operations += content.matches("BinIO.").count();

        // Unsafe operations
        let unsafe_count =
            content.matches("Unsafe.").count() + content.matches("MLton.Pointer").count();
        if unsafe_count > 0 {
            stats.unsafe_blocks += unsafe_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe operations in {}", unsafe_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Exception handling
        let raise_count = content.matches("raise ").count();
        stats.panic_sites += raise_count;

        Ok(())
    }

    // ============================================================
    // Lisp family (Scheme, Racket)
    // ============================================================

    fn analyze_lisp(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic code execution
        if content.contains("(eval ") || content.contains("(eval\n") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // System calls
        if content.contains("(system ") || content.contains("(process ") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("System/process call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // I/O
        stats.io_operations += content.matches("open-input-file").count();
        stats.io_operations += content.matches("open-output-file").count();
        stats.io_operations += content.matches("call-with-input-file").count();
        stats.io_operations += content.matches("call-with-output-file").count();

        // Continuations (can blow the stack)
        let callcc_count = content.matches("call-with-current-continuation").count()
            + content.matches("call/cc").count();
        if callcc_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} call/cc usage in {}", callcc_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    // ============================================================
    // Functional (Haskell, PureScript)
    // ============================================================

    fn analyze_haskell(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe operations
        let unsafe_io = content.matches("unsafePerformIO").count();
        let unsafe_coerce = content.matches("unsafeCoerce").count();
        stats.unsafe_blocks += unsafe_io + unsafe_coerce;

        if unsafe_io > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafePerformIO in {}", unsafe_io, file_path),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
            });
        }

        if unsafe_coerce > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafeCoerce in {}", unsafe_coerce, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Partial functions (crash on empty input)
        let head_count = content.matches(" head ").count() + content.matches("(head ").count();
        let tail_count = content.matches(" tail ").count() + content.matches("(tail ").count();
        let from_just = content.matches("fromJust").count();
        let partials = head_count + tail_count + from_just;
        stats.unwrap_calls += partials;

        if partials > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} partial function calls (head/tail/fromJust) in {}",
                    partials, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // error/undefined
        let error_count = content.matches("error \"").count()
            + content.matches("error \"").count()
            + content.matches("undefined").count();
        stats.panic_sites += error_count;

        if error_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} error/undefined in {}", error_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        stats.io_operations += content.matches("readFile").count();
        stats.io_operations += content.matches("writeFile").count();
        stats.threading_constructs += content.matches("forkIO").count();
        stats.threading_constructs += content.matches("MVar").count();
        stats.threading_constructs += content.matches("STM").count();

        Ok(())
    }

    fn analyze_purescript(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // FFI boundary
        let ffi_count = content.matches("foreign import").count();
        stats.unsafe_blocks += ffi_count;

        if ffi_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} foreign imports in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafeCoerce / unsafePartial
        if content.contains("unsafeCoerce") || content.contains("unsafePartial") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unsafe coercion in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    // ============================================================
    // Proof assistants (Idris, Lean, Agda)
    // ============================================================

    fn analyze_idris(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // believe_me bypasses the type checker
        let believe_count = content.matches("believe_me").count();
        if believe_count > 0 {
            stats.unsafe_blocks += believe_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} believe_me (type checker bypass) in {}",
                    believe_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafePerformIO
        if content.contains("unsafePerformIO") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafePerformIO in {}", file_path),
                recommended_attack: vec![AttackAxis::Concurrency],
            });
        }

        // FFI
        let ffi_count = content.matches("%foreign").count();
        stats.unsafe_blocks += ffi_count;

        Ok(())
    }

    fn analyze_lean(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // sorry - admits unproven propositions
        let sorry_count = content.matches("sorry").count();
        if sorry_count > 0 {
            stats.unsafe_blocks += sorry_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} sorry (unproven proposition) in {}",
                    sorry_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // native_decide - can crash at runtime
        if content.contains("native_decide") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("native_decide in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // unsafe operations
        if content.contains("unsafeCast") || content.contains("implementedBy") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unsafe cast/implementedBy in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        Ok(())
    }

    fn analyze_agda(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // trustMe bypasses proof obligations
        if content.contains("trustMe") || content.contains("primTrustMe") {
            stats.unsafe_blocks += 1;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("trustMe/primTrustMe (proof bypass) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // COMPILED pragma (FFI boundary)
        let compiled_count =
            content.matches("{-# COMPILED").count() + content.matches("{-# FOREIGN").count();
        stats.unsafe_blocks += compiled_count;

        Ok(())
    }

    // ============================================================
    // Logic programming (Prolog, Logtalk, Datalog)
    // ============================================================

    fn analyze_logic(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic predicates (mutable state)
        let assert_count = content.matches("assert(").count()
            + content.matches("assertz(").count()
            + content.matches("asserta(").count();
        let retract_count =
            content.matches("retract(").count() + content.matches("retractall(").count();
        stats.allocation_sites += assert_count + retract_count;

        if assert_count + retract_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::RaceCondition,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} dynamic predicate modifications in {}",
                    assert_count + retract_count,
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Concurrency],
            });
        }

        // System calls
        if content.contains("shell(") || content.contains("process_create(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Shell/process_create in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Meta-interpretation (can be slow)
        if content.contains("call(") {
            stats.allocation_sites += content.matches("call(").count();
        }

        stats.io_operations += content.matches("open(").count();
        stats.io_operations += content.matches("read_term(").count();
        stats.io_operations += content.matches("write_term(").count();

        Ok(())
    }

    // ============================================================
    // Systems languages (Zig, Ada, Odin, Nim, Pony, D)
    // ============================================================

    fn analyze_zig(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe pointer operations
        let ptr_ops = content.matches("@intToPtr").count()
            + content.matches("@ptrToInt").count()
            + content.matches("@ptrCast").count();
        stats.unsafe_blocks += ptr_ops;

        if ptr_ops > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe pointer casts in {}", ptr_ops, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // C interop
        let c_import = content.matches("@cImport").count();
        stats.unsafe_blocks += c_import;

        // unreachable (crash if reached)
        let unreachable_count = content.matches("unreachable").count();
        stats.panic_sites += unreachable_count;

        // Allocator usage
        stats.allocation_sites += content.matches("allocator.alloc").count();
        stats.allocation_sites += content.matches("allocator.create").count();

        stats.io_operations += content.matches("std.fs.").count();
        stats.io_operations += content.matches("std.net.").count();
        stats.threading_constructs += content.matches("std.Thread").count();
        stats.threading_constructs += content.matches("@import(\"std\").Thread").count();

        Ok(())
    }

    fn analyze_ada(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unchecked operations
        let unchecked = content.matches("Unchecked_Conversion").count()
            + content.matches("Unchecked_Deallocation").count()
            + content.matches("Unchecked_Access").count();
        stats.unsafe_blocks += unchecked;

        if unchecked > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} Unchecked_* operations in {}", unchecked, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // pragma Suppress (disables runtime checks)
        if content.contains("pragma Suppress") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("pragma Suppress (runtime checks disabled) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // Tasking (concurrency)
        stats.threading_constructs += content.matches("task type").count();
        stats.threading_constructs += content.matches("task body").count();
        stats.threading_constructs += content.matches("protected type").count();

        stats.io_operations += content.matches("Ada.Text_IO").count();
        stats.io_operations += content.matches("Ada.Streams").count();
        stats.allocation_sites += content.matches("new ").count();

        Ok(())
    }

    fn analyze_odin(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Raw pointers
        let raw_ptr = content.matches("rawptr").count() + content.matches("^").count(); // pointer dereference
        stats.unsafe_blocks += content.matches("rawptr").count();

        if content.contains("#force_inline") || content.contains("#force_no_inline") {
            stats.unsafe_blocks += 1;
        }

        // Foreign imports
        let foreign_count = content.matches("foreign import").count();
        stats.unsafe_blocks += foreign_count;

        stats.allocation_sites += content.matches("make(").count();
        stats.allocation_sites += content.matches("new(").count();
        stats.io_operations += content.matches("os.read").count();
        stats.io_operations += content.matches("os.write").count();
        stats.threading_constructs += content.matches("thread.create").count();

        if raw_ptr > 0 {
            // Only flag if rawptr explicitly used
            let rawptr_count = content.matches("rawptr").count();
            if rawptr_count > 0 {
                weak_points.push(WeakPoint {
                    category: WeakPointCategory::UnsafeCode,
                    location: Some(file_path.to_string()),
                    severity: Severity::Medium,
                    description: format!("{} rawptr usage in {}", rawptr_count, file_path),
                    recommended_attack: vec![AttackAxis::Memory],
                });
            }
        }

        Ok(())
    }

    fn analyze_nim(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Unsafe pragmas
        if content.contains("{.emit:") || content.contains("{.emit.}") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("emit pragma (raw code injection) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
            });
        }

        // cast (unsafe type coercion)
        let cast_count = content.matches("cast[").count();
        if cast_count > 0 {
            stats.unsafe_blocks += cast_count;
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} cast[] (unsafe coercion) in {}", cast_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // unsafeAddr
        if content.contains("unsafeAddr") {
            stats.unsafe_blocks += 1;
        }

        stats.allocation_sites += content.matches("new(").count();
        stats.allocation_sites += content.matches("alloc(").count();
        stats.io_operations += content.matches("readFile(").count();
        stats.io_operations += content.matches("writeFile(").count();
        stats.threading_constructs += content.matches("spawn ").count();
        stats.threading_constructs += content.matches("createThread").count();

        Ok(())
    }

    fn analyze_pony(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // FFI calls (@ prefix)
        let ffi_re = RE_PONY_FFI.get_or_init(|| Regex::new(r"@[a-zA-Z_]\w*\[").unwrap());
        let ffi_count = ffi_re.find_iter(content).count();
        stats.unsafe_blocks += ffi_count;

        if ffi_count > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI calls in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // recover blocks (capability manipulation)
        stats.unsafe_blocks += content.matches("recover").count();
        stats.threading_constructs += content.matches("actor ").count();

        Ok(())
    }

    fn analyze_dlang(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // @system (unsafe by default)
        let system_count = content.matches("@system").count();
        stats.unsafe_blocks += system_count;

        // @trusted (unsafe but marked as "trusted")
        let trusted_count = content.matches("@trusted").count();
        stats.unsafe_blocks += trusted_count;

        if system_count > 5 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @system functions in {}", system_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // __traits (compiler intrinsics)
        stats.unsafe_blocks += content.matches("__traits").count();

        stats.allocation_sites += content.matches("new ").count();
        stats.io_operations += content.matches("std.stdio").count();
        stats.threading_constructs += content.matches("spawn(").count();
        stats.threading_constructs += content.matches("std.concurrency").count();

        Ok(())
    }

    // ============================================================
    // Config languages (Nickel, Nix)
    // ============================================================

    fn analyze_config(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Nix-specific
        if file_path.ends_with(".nix") {
            // builtins.exec (arbitrary command execution)
            if content.contains("builtins.exec") {
                weak_points.push(WeakPoint {
                    category: WeakPointCategory::CommandInjection,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!("builtins.exec (command execution) in {}", file_path),
                    recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                });
            }

            // import from untrusted paths
            let import_count = content.matches("import ").count();
            stats.io_operations += import_count;

            // fetchurl / fetchGit (network)
            stats.io_operations += content.matches("fetchurl").count();
            stats.io_operations += content.matches("fetchGit").count();
            stats.io_operations += content.matches("fetchFromGitHub").count();
        }

        // Nickel-specific
        if file_path.ends_with(".ncl") {
            // import (file reading)
            stats.io_operations += content.matches("import ").count();
        }

        Ok(())
    }

    // ============================================================
    // Shell scripting
    // ============================================================

    fn analyze_shell(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        stats.io_operations += content.matches("cat ").count();
        stats.io_operations += content.matches("curl ").count();
        stats.io_operations += content.matches("wget ").count();

        // Command injection via eval
        if content.contains("eval ") || content.contains("eval\t") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        // Unquoted variable expansion (potential injection)
        let unquoted_var = RE_SHELL_UNQUOTED_VAR.get_or_init(|| Regex::new(r#"\$[A-Za-z_]\w*"#).unwrap());
        let dollar_vars = unquoted_var.find_iter(content).count();
        // Only flag if high number of unquoted vars
        if dollar_vars > 20 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} potentially unquoted variable expansions in {}",
                    dollar_vars, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        // World-writable permissions
        if content.contains("chmod 777") || content.contains("chmod a+w") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("World-writable permissions in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
            });
        }

        // Deno -A in shell scripts
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
            });
        }

        // Unsafe temp files
        if content.contains("/tmp/") && !content.contains("mktemp") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::PathTraversal,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Hardcoded /tmp/ path without mktemp in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
            });
        }

        Ok(())
    }

    // ============================================================
    // Julia
    // ============================================================

    fn analyze_julia(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // eval / Meta.parse (dynamic code execution)
        if content.contains("eval(") || content.contains("Meta.parse(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval/Meta.parse in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // ccall / @ccall (FFI)
        let ccall_count = content.matches("ccall(").count() + content.matches("@ccall").count();
        stats.unsafe_blocks += ccall_count;

        if ccall_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} ccall/FFI calls in {}", ccall_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Unsafe pointer operations
        let ptr_ops = content.matches("pointer_from_objref").count()
            + content.matches("unsafe_load").count()
            + content.matches("unsafe_store!").count();
        stats.unsafe_blocks += ptr_ops;

        stats.io_operations += content.matches("open(").count();
        stats.io_operations += content.matches("read(").count();
        stats.io_operations += content.matches("write(").count();
        stats.io_operations += content.matches("download(").count();
        stats.threading_constructs += content.matches("@spawn").count();
        stats.threading_constructs += content.matches("Threads.@threads").count();
        stats.threading_constructs += content.matches("@distributed").count();
        stats.allocation_sites += content.matches("Array{").count();

        Ok(())
    }

    // ============================================================
    // Lua
    // ============================================================

    fn analyze_lua(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Dynamic code execution
        if content.contains("loadstring(") || content.contains("dofile(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("loadstring/dofile in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
            });
        }

        // os.execute (command injection)
        if content.contains("os.execute(") || content.contains("io.popen(") {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os.execute/io.popen in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
            });
        }

        stats.io_operations += content.matches("io.open(").count();
        stats.io_operations += content.matches("io.read(").count();
        stats.threading_constructs += content.matches("coroutine.").count();

        Ok(())
    }

    // ============================================================
    // Nextgen custom DSLs (shared analyzer)
    // ============================================================

    fn analyze_nextgen_dsl(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Generic pattern detection for custom DSLs
        // These languages are custom and type-safe by design,
        // so we mainly check for FFI boundaries and resource usage

        // FFI / external bindings
        let ffi_patterns = content.matches("foreign").count()
            + content.matches("external").count()
            + content.matches("@ffi").count()
            + content.matches("@native").count();
        stats.unsafe_blocks += ffi_patterns;

        if ffi_patterns > 3 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI/external bindings in {}", ffi_patterns, file_path),
                recommended_attack: vec![AttackAxis::Memory],
            });
        }

        // Resource budgets (Eclexia-specific)
        if file_path.ends_with(".ecl") {
            stats.allocation_sites += content.matches("budget").count();
        }

        // Unsafe/unverified blocks
        let unsafe_count = content.matches("unsafe").count() + content.matches("unchecked").count();
        stats.unsafe_blocks += unsafe_count;

        stats.io_operations += content.matches("read").count().min(10); // cap for generic matches
        stats.io_operations += content.matches("write").count().min(10);

        Ok(())
    }

    // ============================================================
    // Cross-language security checks (run on ALL files)
    // ============================================================

    fn analyze_cross_language(
        &self,
        content: &str,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // HTTP (insecure) URLs - should be HTTPS
        // Count http:// URLs that are NOT localhost/127.0.0.1 (those are fine)
        let http_re = RE_HTTP_URL.get_or_init(|| Regex::new(r#"http://[a-zA-Z0-9]"#).unwrap());
        let http_localhost_re = RE_HTTP_LOCALHOST.get_or_init(||
            Regex::new(r#"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"#).unwrap());
        let http_total = http_re.find_iter(content).count();
        let http_local = http_localhost_re.find_iter(content).count();
        let http_count = http_total.saturating_sub(http_local);
        if http_count > 0 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::InsecureProtocol,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} HTTP (non-HTTPS) URLs in {}", http_count, file_path),
                recommended_attack: vec![AttackAxis::Network],
            });
        }

        // Hardcoded secrets patterns
        let secret_re = RE_HARDCODED_SECRET.get_or_init(|| Regex::new(
            r#"(?i)(api[_-]?key|api[_-]?secret|password|passwd|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*["'][^"']{8,}"#
        ).unwrap());
        if secret_re.is_match(content) {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::HardcodedSecret,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Possible hardcoded secret in {}", file_path),
                recommended_attack: vec![AttackAxis::Network],
            });
        }

        // TODO/FIXME/HACK/XXX markers
        let todo_count = content.matches("TODO").count()
            + content.matches("FIXME").count()
            + content.matches("HACK").count()
            + content.matches("XXX").count();
        if todo_count > 10 {
            weak_points.push(WeakPoint {
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Low,
                description: format!("{} TODO/FIXME/HACK markers in {}", todo_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
            });
        }

        Ok(())
    }

    // ============================================================
    // Generic fallback
    // ============================================================

    fn analyze_generic(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        _file_path: &str,
    ) -> Result<()> {
        stats.allocation_sites += content.matches("alloc").count();
        stats.io_operations += content.matches("open").count();
        stats.threading_constructs += content.matches("thread").count();

        Ok(())
    }

    // ============================================================
    // Framework detection (expanded)
    // ============================================================

    fn detect_frameworks(&self, files: &[PathBuf]) -> Result<Vec<Framework>> {
        let mut frameworks = HashSet::new();

        // Primary signal: dependency manifest files.  These are the most reliable
        // because they declare actual dependencies, not just keyword mentions.
        let target_dir = if self.target.is_dir() {
            &self.target
        } else {
            self.target.parent().unwrap_or(Path::new("."))
        };

        // Cargo.toml (Rust)
        let cargo_toml = target_dir.join("Cargo.toml");
        if let Ok(content) = fs::read_to_string(&cargo_toml) {
            if content.contains("tokio") {
                frameworks.insert(Framework::Networking);
            }
            if content.contains("rayon") || content.contains("crossbeam") {
                frameworks.insert(Framework::Concurrent);
            }
            if content.contains("actix-web") || content.contains("axum")
                || content.contains("warp =") || content.contains("rocket =")
            {
                frameworks.insert(Framework::WebServer);
            }
            if content.contains("diesel") || content.contains("sqlx") {
                frameworks.insert(Framework::Database);
            }
            if content.contains("rdkafka") {
                frameworks.insert(Framework::MessageQueue);
            }
            if content.contains("redis =") || content.contains("[dependencies.redis]") {
                frameworks.insert(Framework::Cache);
            }
            if content.contains("async-std") {
                frameworks.insert(Framework::Networking);
            }
        }

        // mix.exs (Elixir)
        let mix_exs = target_dir.join("mix.exs");
        if let Ok(content) = fs::read_to_string(&mix_exs) {
            if content.contains(":phoenix") {
                frameworks.insert(Framework::Phoenix);
                frameworks.insert(Framework::WebServer);
            }
            if content.contains(":ecto") {
                frameworks.insert(Framework::Ecto);
                frameworks.insert(Framework::Database);
            }
            if content.contains(":cowboy") || content.contains(":bandit") {
                frameworks.insert(Framework::Cowboy);
                frameworks.insert(Framework::WebServer);
            }
            if content.contains(":broadway") || content.contains(":gen_stage") {
                frameworks.insert(Framework::MessageQueue);
            }
            if content.contains(":cachex") || content.contains(":con_cache") {
                frameworks.insert(Framework::Cache);
            }
        }

        // rebar.config (Erlang)
        let rebar_config = target_dir.join("rebar.config");
        if let Ok(content) = fs::read_to_string(&rebar_config) {
            if content.contains("cowboy") {
                frameworks.insert(Framework::Cowboy);
                frameworks.insert(Framework::WebServer);
            }
        }

        // gleam.toml (Gleam)
        let gleam_toml = target_dir.join("gleam.toml");
        if let Ok(content) = fs::read_to_string(&gleam_toml) {
            if content.contains("wisp") || content.contains("mist") {
                frameworks.insert(Framework::WebServer);
            }
        }

        // package.json (JS/TS/ReScript)
        let pkg_json = target_dir.join("package.json");
        if let Ok(content) = fs::read_to_string(&pkg_json) {
            if content.contains("\"express\"") || content.contains("\"fastify\"")
                || content.contains("\"koa\"")
            {
                frameworks.insert(Framework::WebServer);
            }
            if content.contains("\"mongodb\"") || content.contains("\"pg\"")
                || content.contains("\"prisma\"")
            {
                frameworks.insert(Framework::Database);
            }
            if content.contains("\"kafkajs\"") || content.contains("\"amqplib\"") {
                frameworks.insert(Framework::MessageQueue);
            }
            if content.contains("\"ioredis\"") || content.contains("\"redis\"") {
                frameworks.insert(Framework::Cache);
            }
        }

        // requirements.txt / pyproject.toml (Python)
        for manifest in &["requirements.txt", "pyproject.toml", "setup.py"] {
            let path = target_dir.join(manifest);
            if let Ok(content) = fs::read_to_string(&path) {
                if content.contains("flask") || content.contains("django")
                    || content.contains("fastapi")
                {
                    frameworks.insert(Framework::WebServer);
                }
                if content.contains("sqlalchemy") || content.contains("psycopg")
                    || content.contains("pymongo")
                {
                    frameworks.insert(Framework::Database);
                }
                if content.contains("celery") || content.contains("kafka") {
                    frameworks.insert(Framework::MessageQueue);
                }
                if content.contains("redis") {
                    frameworks.insert(Framework::Cache);
                }
            }
        }

        // Secondary signal: import/use statements in source files.
        // Only used for languages whose manifests were not found above.
        // Rust is excluded because Cargo.toml is always present and reliable;
        // scanning .rs files for `use` lines produces false positives from
        // string literals in tests and analyzer patterns.
        for file in files {
            let file_lang = Language::detect(file.to_str().unwrap_or(""));
            let content = match fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };

            match file_lang {
                // Rust: skip — Cargo.toml detection above is sufficient.
                Language::Rust => {}

                Language::Elixir => {
                    // In Elixir, `use GenServer` or `use Supervisor` at line start
                    let has_elixir_use = |module: &str| -> bool {
                        content.lines().any(|line| {
                            let t = line.trim();
                            t.starts_with(&format!("use {}", module))
                                || t.starts_with(&format!("import {}", module))
                                || t.starts_with(&format!("alias {}", module))
                        })
                    };
                    if has_elixir_use("GenServer") || has_elixir_use("Supervisor")
                        || has_elixir_use("Agent")
                    {
                        frameworks.insert(Framework::OTP);
                    }
                    if has_elixir_use("Phoenix") {
                        frameworks.insert(Framework::Phoenix);
                    }
                    if has_elixir_use("Ecto") {
                        frameworks.insert(Framework::Ecto);
                    }
                    if has_elixir_use("Broadway") || has_elixir_use("GenStage") {
                        frameworks.insert(Framework::MessageQueue);
                    }
                    if has_elixir_use("Cachex") || has_elixir_use("ConCache") {
                        frameworks.insert(Framework::Cache);
                    }
                    if has_elixir_use("Plug") || has_elixir_use("Bandit") {
                        frameworks.insert(Framework::WebServer);
                    }
                    if has_elixir_use("Flow") {
                        frameworks.insert(Framework::Concurrent);
                    }
                    if has_elixir_use("Mint") || has_elixir_use("Finch") {
                        frameworks.insert(Framework::Networking);
                    }
                }

                Language::Erlang => {
                    if content.contains("-behaviour(gen_server)")
                        || content.contains("-behaviour(supervisor)")
                    {
                        frameworks.insert(Framework::OTP);
                    }
                }

                Language::Go => {
                    let has_go_import = |pkg: &str| -> bool {
                        content.lines().any(|line| {
                            let t = line.trim();
                            t.contains(&format!("\"{}\"", pkg))
                                || t.contains(&format!("\"{}\"", pkg))
                        })
                    };
                    if has_go_import("net/http") || has_go_import("github.com/gin-gonic") {
                        frameworks.insert(Framework::WebServer);
                    }
                    if has_go_import("database/sql") || has_go_import("github.com/jackc/pgx") {
                        frameworks.insert(Framework::Database);
                    }
                }

                Language::Ruby => {
                    let has_require = |gem: &str| -> bool {
                        content.lines().any(|line| {
                            let t = line.trim();
                            t.starts_with(&format!("require '{}'", gem))
                                || t.starts_with(&format!("require \"{}\"", gem))
                        })
                    };
                    if has_require("rails") || has_require("sinatra") {
                        frameworks.insert(Framework::WebServer);
                    }
                    if has_require("active_record") {
                        frameworks.insert(Framework::Database);
                    }
                }

                Language::Python => {
                    let has_import = |module: &str| -> bool {
                        content.lines().any(|line| {
                            let t = line.trim();
                            t.starts_with(&format!("import {}", module))
                                || t.starts_with(&format!("from {}", module))
                        })
                    };
                    if has_import("flask") || has_import("django") || has_import("fastapi") {
                        frameworks.insert(Framework::WebServer);
                    }
                    if has_import("sqlalchemy") || has_import("psycopg")
                        || has_import("pymongo")
                    {
                        frameworks.insert(Framework::Database);
                    }
                    if has_import("celery") || has_import("kafka") {
                        frameworks.insert(Framework::MessageQueue);
                    }
                    if has_import("redis") {
                        frameworks.insert(Framework::Cache);
                    }
                }

                Language::JavaScript | Language::ReScript => {
                    let has_js_import = |pkg: &str| -> bool {
                        content.lines().any(|line| {
                            let t = line.trim();
                            t.contains(&format!("require('{}')", pkg))
                                || t.contains(&format!("require(\"{}\")", pkg))
                                || t.contains(&format!("from '{}'", pkg))
                                || t.contains(&format!("from \"{}\"", pkg))
                        })
                    };
                    if has_js_import("express") || has_js_import("fastify")
                        || has_js_import("koa")
                    {
                        frameworks.insert(Framework::WebServer);
                    }
                    if has_js_import("mongodb") || has_js_import("pg") {
                        frameworks.insert(Framework::Database);
                    }
                    if has_js_import("kafkajs") || has_js_import("amqplib") {
                        frameworks.insert(Framework::MessageQueue);
                    }
                    if has_js_import("ioredis") || has_js_import("redis") {
                        frameworks.insert(Framework::Cache);
                    }
                }

                // Other languages: rely on manifest detection only.
                _ => {}
            }
        }

        Ok(frameworks.into_iter().collect())
    }

    fn generate_recommendations(
        &self,
        weak_points: &[WeakPoint],
        stats: &ProgramStatistics,
    ) -> Vec<AttackAxis> {
        let mut recommendations = HashSet::new();

        // Base recommendations come from weak-point categories.
        for wp in weak_points {
            recommendations.extend(&wp.recommended_attack);
        }

        // Global heuristics widen coverage when aggregate risk indicators are high.
        if stats.allocation_sites > 10 {
            recommendations.insert(AttackAxis::Memory);
        }

        if stats.io_operations > 5 {
            recommendations.insert(AttackAxis::Disk);
        }

        if stats.threading_constructs > 3 {
            recommendations.insert(AttackAxis::Concurrency);
        }

        recommendations.insert(AttackAxis::Cpu);

        recommendations.into_iter().collect()
    }

    fn build_dependency_graph(
        file_statistics: &[FileStatistics],
        frameworks: &[Framework],
    ) -> DependencyGraph {
        let mut edges = Vec::new();
        let mut dir_groups: HashMap<String, Vec<String>> = HashMap::new();

        // Group by directory first to approximate local import neighborhoods.
        for stat in file_statistics {
            let dir = Path::new(&stat.file_path)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or(".")
                .to_string();
            dir_groups
                .entry(dir)
                .or_default()
                .push(stat.file_path.clone());
        }

        // Sequential edges preserve deterministic output and simple chain traversal.
        for (dir, files) in dir_groups {
            for window in files.windows(2) {
                if let [from, to] = &window {
                    edges.push(DependencyEdge {
                        from: from.clone(),
                        to: to.clone(),
                        relation: format!("shared_dir:{}", dir),
                        weight: 1.0,
                    });
                }
            }
        }

        // Attach framework nodes to each file with risk-weighted edge strength.
        for stat in file_statistics {
            let risk = (stat.unsafe_blocks * 3
                + stat.panic_sites * 2
                + stat.unwrap_calls
                + stat.threading_constructs * 2) as f64;
            for framework in frameworks {
                edges.push(DependencyEdge {
                    from: stat.file_path.clone(),
                    to: format!("{:?}", framework),
                    relation: "framework".to_string(),
                    weight: risk.max(1.0),
                });
            }
        }

        DependencyGraph { edges }
    }

    fn build_taint_matrix(weak_points: &[WeakPoint], frameworks: &[Framework]) -> TaintMatrix {
        let mut matrix: HashMap<(WeakPointCategory, AttackAxis), TaintMatrixRow> = HashMap::new();

        // Rows are keyed by source category x sink axis to enable pivot-friendly reporting.
        for wp in weak_points {
            for axis in &wp.recommended_attack {
                let key = (wp.category, *axis);
                let entry = matrix.entry(key).or_insert_with(|| TaintMatrixRow {
                    source_category: wp.category,
                    sink_axis: *axis,
                    severity_value: Self::severity_value(wp.severity),
                    files: Vec::new(),
                    frameworks: frameworks.to_vec(),
                    relation: format!("{:?}->{:?}", wp.category, axis),
                });
                entry
                    .files
                    .push(wp.location.clone().unwrap_or_else(|| "unknown".to_string()));
                entry.severity_value = entry.severity_value.max(Self::severity_value(wp.severity));
            }
        }

        TaintMatrix {
            rows: matrix.into_values().collect(),
        }
    }

    fn severity_value(severity: Severity) -> f64 {
        match severity {
            Severity::Low => 1.0,
            Severity::Medium => 2.5,
            Severity::High => 3.5,
            Severity::Critical => 5.0,
        }
    }
}
