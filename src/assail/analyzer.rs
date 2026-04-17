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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Upper bound on source-file reads during per-file scanning. Source
/// files are almost always well under 16 MiB; capping at 64 MiB bounds
/// a pathological/malicious input without losing realistic content.
const SOURCE_FILE_READ_LIMIT: u64 = 64 * 1024 * 1024;

/// Upper bound on manifest / config file reads (Cargo.toml, pyproject.toml,
/// flake.nix, deno.json, mix.exs, rebar.config, etc). Manifests are short
/// curated documents; 4 MiB is far beyond realistic sizes.
const MANIFEST_FILE_READ_LIMIT: u64 = 4 * 1024 * 1024;

/// Bounded replacement for `fs::read_to_string(path).ok()` — returns
/// `Some(content)` on success (up to `limit` bytes), `None` on I/O error
/// or if the file is absent. Used by the analyzer to cap every file read
/// against an explicit byte ceiling rather than trusting the filesystem.
fn read_bounded(path: &Path, limit: u64) -> Option<String> {
    let mut buf = String::new();
    fs::File::open(path)
        .ok()?
        .take(limit)
        .read_to_string(&mut buf)
        .ok()?;
    Some(buf)
}

// ═══════════════════════════════════════════════════════════════════════
// UnboundedAllocation detector — word-boundary keyword matchers
// ═══════════════════════════════════════════════════════════════════════
//
// Historical context: the detector originally did substring matches like
// `code_only.contains("unbounded")`. This fires on any identifier
// containing those letters — including the detector's own variable names
// (`has_unbounded_allocations`, `unbounded_vec_patterns`) and normal
// tokio usage (`tokio::sync::mpsc::unbounded_channel`). On a self-scan,
// analyzer.rs was the last residual Critical after the `.take(LIMIT)`
// sweep closed the real unbounded reads.
//
// Fix: word-boundary regex matches. `\bunbounded\b` does NOT match
// `unbounded_channel` or `unbounded_vec_patterns` because `_` is a word
// character in regex, so the trailing `_` blocks the closing boundary.
// It DOES match bare `unbounded` (e.g., `fn unbounded()`, `type T = Unbounded;`),
// which is what we actually want the alarm for.
//
// The regexes are compiled once via OnceLock and reused across every
// file in a scan — per-call overhead is a single pointer read.

/// Match the unbounded-allocation alarm keywords as whole words only.
/// Keywords: unbounded, no_bound, no_limit, boundless, unlimited, unconstrained.
static UNBOUNDED_KEYWORDS_RE: OnceLock<Regex> = OnceLock::new();

/// Match `infinite` as a whole word (not part of `is_infinite`, `infinite_loop_v2`, etc.).
static INFINITE_WORD_RE: OnceLock<Regex> = OnceLock::new();

/// Match `recursion` as a whole word.
static RECURSION_WORD_RE: OnceLock<Regex> = OnceLock::new();

/// Match `limit` as a word prefix, case-insensitively, to disarm
/// read_to_* checks when the file has explicit bounds. Matches `limit`,
/// `Limit`, `LIMIT`, `READ_LIMIT`, `limit_bytes`, `limits`; does NOT match
/// `unlimited` or `sublimit` (those start inside a word).
static LIMIT_WORD_RE: OnceLock<Regex> = OnceLock::new();

fn has_unbounded_keyword(code: &str) -> bool {
    UNBOUNDED_KEYWORDS_RE
        .get_or_init(|| {
            Regex::new(r"\b(unbounded|no_bound|no_limit|boundless|unlimited|unconstrained)\b")
                .expect("static regex is valid")
        })
        .is_match(code)
}

fn has_infinite_word(code: &str) -> bool {
    INFINITE_WORD_RE
        .get_or_init(|| Regex::new(r"\binfinite\b").expect("static regex is valid"))
        .is_match(code)
}

fn has_recursion_word(code: &str) -> bool {
    RECURSION_WORD_RE
        .get_or_init(|| Regex::new(r"\brecursion\b").expect("static regex is valid"))
        .is_match(code)
}

fn has_limit_word(code: &str) -> bool {
    LIMIT_WORD_RE
        .get_or_init(|| Regex::new(r"(?i)\blimit").expect("static regex is valid"))
        .is_match(code)
}

// Thread-local accumulators for migration analysis.
// These collect deprecated/modern API counts across all files during a single
// analyze() run, then get consumed by build_migration_metrics().
thread_local! {
    static MIGRATION_DEPRECATED: RefCell<Vec<DeprecatedPattern>> = const { RefCell::new(Vec::new()) };
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
    let config_content = config_path.and_then(|p| read_bounded(&p, MANIFEST_FILE_READ_LIMIT));

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
/// Match TODO/FIXME/HACK/XXX markers only when preceded by a
/// comment-starter on the same line. Excludes string-literal matches
/// like `.expect("TODO: handle error")` which were previously
/// inflating the UncheckedError count for every `.expect(...)` call
/// that mentioned TODO in its message (observed on 007-lang:
/// parser.rs has 155 `.expect("TODO: ...")` patterns, each of which
/// was being double-counted as both PanicPath (correct) and
/// UncheckedError (FP).
///
/// Comment-starters handled: `//` (Rust/C/JS/...), `/*` (block),
/// `#` (Python/Ruby/Shell/Nix/Elixir-preamble), `--` (Haskell/Ada/
/// SQL/Lua/Idris), `;;` (Lisp/Scheme/Racket), `%%` (Erlang/Matlab).
/// Does not handle OCaml `(* *)` or Forth `\` — edge cases for later.
static RE_TODO_COMMENT: OnceLock<Regex> = OnceLock::new();

pub struct Analyzer {
    target: PathBuf,
    language: Language,
    verbose: bool,
    browser_extension: bool,
}

impl Analyzer {
    pub fn new(target: &Path) -> Result<Self> {
        Self::build(target, false, false)
    }

    pub fn new_verbose(target: &Path) -> Result<Self> {
        Self::build(target, true, false)
    }

    pub fn new_browser_extension(target: &Path) -> Result<Self> {
        Self::build(target, false, true)
    }

    pub fn new_verbose_browser_extension(target: &Path) -> Result<Self> {
        Self::build(target, true, true)
    }

    fn build(target: &Path, verbose: bool, browser_extension: bool) -> Result<Self> {
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
            browser_extension,
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
                        log::debug!("Skipping unreadable file: {} ({})", file.display(), e);
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
                            log::debug!(
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
                Language::Isabelle => {
                    self.analyze_isabelle(
                        &content,
                        &mut file_stats,
                        &mut file_weak_points,
                        &rel_path,
                    )?;
                }
                Language::Coq => {
                    self.analyze_coq(&content, &mut file_stats, &mut file_weak_points, &rel_path)?;
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
                | Language::VCL
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

        // Project-level supply-chain integrity checks (manifest/lockfile checks).
        self.analyze_supply_chain_manifests(&mut all_weak_points)?;

        // Project-level mutation coverage gap checks (tooling presence, not coverage %).
        self.analyze_mutation_gaps(&mut all_weak_points)?;

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

        // Post-process weak points to populate file/line fields from location
        // strings, ensuring GitHub Actions annotations and gitbot-fleet fix scripts
        // can access structured file paths.
        let all_weak_points: Vec<_> = all_weak_points
            .into_iter()
            .map(|wp| wp.with_parsed_location())
            .collect();

        let mut report = AssailReport {
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
            suppressed_count: 0,
        };

        // Apply context-aware FP suppression rules.
        // Marks WeakPoints with suppressed=true where defensive patterns
        // make the finding likely a false positive.
        super::apply_suppression(&mut report);

        Ok(report)
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
                // Skip build artifacts, hidden dirs, dependency dirs, and
                // generated runtime artifacts (e.g. amuck mutation runs).
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
                        ".zig-cache",
                        "zig-out",
                        "ebin",
                        "external_corpora",
                        "third_party",
                        "testdata",
                        "test_fixtures",
                        "fixtures",
                        "corpus",
                        "corpora",
                        "runtime",
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
        // Detect if this is a test file - Expanded patterns
        let is_test_file = file_path.contains("_tests.") 
            || file_path.contains("/tests/") 
            || file_path.ends_with("_test.rs")
            || file_path.starts_with("tests/")
            || file_path.contains("/test_")
            || file_path.contains("_spec.")  // RSpec, Jest patterns
            || file_path.contains("_bench.") // Benchmark files
            || file_path.contains("/benches/") // Rust bench directory
            || file_path.ends_with("_bench.rs")
            || file_path.contains("__tests__/") // JavaScript
            || file_path.contains("/__tests__/")
            || file_path.ends_with(".test.") // Generic test files
            || file_path.ends_with(".spec.")
            || file_path.contains("_integration.") // Integration tests
            || file_path.contains("_e2e.") // End-to-end tests
            || file_path.contains("_unit.") // Unit tests
            || file_path.contains("/examples/") // Example code (often test-like)
            || file_path.contains("/samples/") // Sample code
            || file_path.contains("_mock.") // Mock files
            || file_path.contains("_stub."); // Stub files
        
        // Strip string literal contents AND comments before counting so that
        // detection-tool source files (which embed patterns as string literals)
        // do not trigger their own rules, and so that rule names quoted in
        // `// ...` or `/* ... */` doc comments — meta-tests, audit prose,
        // architectural headers — do not falsely fire.  See
        // `007-lang/audits/audit-ffi-unsafe.md` §3 for the motivating case
        // (a meta-test whose stated purpose is "the absence of `unsafe` in
        // this file IS the assertion" was flagged as containing 1 unsafe
        // block because comments discussed the word "unsafe").
        //
        // Stats that measure code structure rather than dangerous patterns
        // (allocation sites, I/O, threading) still use the raw content
        // because those patterns are safe to count in any context.
        let without_strings = Self::strip_string_literals_rs(content);
        let without_comments =
            strip_proof_comments(&without_strings, "//", Some(("/*", "*/")));
        // Apply inline-test-mod stripping globally so `#[cfg(test)] mod
        // tests { … }` is treated as test context by every substring-based
        // dangerous-pattern check below — the Rust analogue of Zig's
        // `count_unsafe_in_test_blocks`. See
        // `Analyzer::strip_cfg_test_modules_rs` doc-comment for the
        // recognised attribute forms. Previously scoped only to the
        // unbounded-allocation check; widened 2026-04-17 after the same
        // FP class was projected to affect unsafe / panic / unwrap /
        // crypto counts too (a `#[test] fn exercises_unsafe_wrapper()`
        // inside a production file would otherwise count toward that
        // file's unsafe-block total).
        let code_only = Self::strip_cfg_test_modules_rs(&without_comments);

        stats.unsafe_blocks += code_only.matches("unsafe {").count();
        stats.unsafe_blocks += code_only.matches("unsafe fn").count();
        
        // Count panic sites, but suppress them in test files
        let panic_sites = code_only.matches("panic!(").count() + code_only.matches("unreachable!(").count();
        let unwrap_calls = code_only.matches(".unwrap()").count() + code_only.matches(".expect(").count();
        
        // Apply test file suppression. In test files, normal
        // assert-macro use pushes panic/unwrap counts high with no
        // production-code signal, so we suppress the counts unless they
        // exceed a "clearly excessive" threshold — only the delta above
        // the threshold is attributed to the file's statistics.
        //
        // Panic and unwrap thresholds are evaluated independently: a
        // test file with 30 panics + 5 unwraps should report 10 panics
        // (30 − 20) and 0 unwraps, not suppress everything because the
        // unwrap count is normal. The previous version declared both
        // thresholds but only compared panics, silently dropping any
        // excessive unwrap signal.
        let (effective_panic_sites, effective_unwrap_calls) = if is_test_file {
            let panic_threshold = 20;
            let unwrap_threshold = 10;
            let eff_panics = panic_sites.saturating_sub(panic_threshold);
            let eff_unwraps = unwrap_calls.saturating_sub(unwrap_threshold);
            (eff_panics, eff_unwraps)
        } else {
            (panic_sites, unwrap_calls) // Production code: count all
        };
        
        stats.panic_sites += effective_panic_sites;
        stats.unwrap_calls += effective_unwrap_calls;
        
        // Enhanced allocation analysis - detect unbounded allocation patterns
        let vec_new_count = content.matches("Vec::new()").count();
        let box_new_count = content.matches("Box::new(").count();
        let string_new_count = content.matches("String::new()").count();

        // Count allocations; unbounded-pattern *classification* (tiny
        // with_capacity, unlimited-read keywords, etc.) happens in the
        // `has_unbounded_allocations` block below — not as a per-site
        // counter. The previous `unbounded_*_patterns` locals duplicated
        // the count without feeding into any finding and have been
        // removed to clear dead-code warnings.
        stats.allocation_sites += vec_new_count + box_new_count + string_new_count;
        
        // Flag unbounded allocation patterns as high-risk. `code_only`
        // already has string literals, comments, and `#[cfg(test)] mod
        // tests` bodies stripped, so keyword substring checks below do
        // not fire on doc comments, generated source strings, or
        // test-mod identifiers.
        //
        // The earlier version also paired bare `for` / `while let` /
        // `loop` tokens with `push(` or `Vec::new` as standalone
        // heuristics. Those pairs co-occur in essentially every
        // non-trivial Rust file (bounded `for x in collection {
        // v.push(y) }` is normal code), so they generated ~60 critical
        // findings per average repo with no signal. Dropped in favour
        // of the explicit-keyword / tiny-capacity / unlimited-read
        // signals below, which remain specific enough to be useful.
        //
        // `read_to_*` is disarmed by either a `limit`-prefixed word
        // (case-insensitive, e.g. `LIMIT`, `READ_LIMIT`, `limit_bytes`)
        // OR `.take(` in the same file — both are valid bounded-read
        // patterns; `.take(N).read_to_end(&mut buf)` is the canonical
        // idiom. Word-boundary match avoids disarming on `unlimited`.
        let read_is_bounded = has_limit_word(&code_only) || code_only.contains(".take(");
        // Keyword alarms use word-boundary regex so the detector's own
        // variable names (`has_unbounded_allocations`, `unbounded_vec_*`)
        // and legitimate tokio types (`unbounded_channel`) don't trip
        // the substring heuristic. Bare keyword usage as an identifier
        // still fires, which is the intended signal.
        let has_unbounded_allocations = has_unbounded_keyword(&code_only)
            // `infinite` matches Rust std `f64::is_infinite()`, which is
            // benign. Require the word in a non-method-call context.
            || (has_infinite_word(&code_only) && !code_only.contains("is_infinite"))
            // Unterminated recursion lacking any depth guard.
            || (has_recursion_word(&code_only) && !code_only.contains("depth"))
            // Suspiciously small initial capacity for a growing vector.
            || code_only.contains("with_capacity(0)")
            || code_only.contains("with_capacity(1)")
            // Network / I/O primitives that slurp without a cap.
            || (code_only.contains("read_to_end") && !read_is_bounded)
            || (code_only.contains("read_to_string") && !read_is_bounded);
        
        if has_unbounded_allocations && !is_test_file {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnboundedAllocation,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Potential unbounded allocation pattern detected in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
            });
        }
        stats.allocation_sites += content.matches("Vec::new()").count();
        stats.allocation_sites += content.matches("Box::new(").count();
        stats.allocation_sites += content.matches("String::new()").count();
        stats.io_operations += content.matches("std::fs::").count();
        stats.io_operations += content.matches("std::io::").count();
        stats.threading_constructs += content.matches("std::thread::").count();
        stats.threading_constructs += content.matches("std::sync::").count();

        if stats.unsafe_blocks > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe blocks in {}", stats.unsafe_blocks, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                suppressed: false,
            });
        }

        if stats.unwrap_calls > 5 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} unwrap/expect calls in {}",
                    stats.unwrap_calls, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // mem::transmute — type-punning bypasses Rust's type system entirely.
        //
        // JIT-aware classification: when the file is in a Cranelift JIT
        // context AND the transmute targets a function pointer type, this
        // is the canonical pattern for invoking a JIT-emitted function —
        // there is no `unsafe`-free way to call a pointer returned by a
        // code-generation framework. In that context the finding is
        // downgraded from Critical to High and a classification suffix is
        // appended so reviewers know to look at the JIT soundness invariants
        // (signature match, lifetime ownership, thread affinity) rather
        // than treating the transmute as arbitrary type-punning.
        //
        // Both signals are required:
        //   1. JIT context — file imports cranelift_jit / cranelift_module
        //      or constructs a JITModule.
        //   2. Function-pointer target — the transmute target is `fn(...)`,
        //      either via turbofish (`transmute::<_, fn(...) -> R>`) or via
        //      a `let x: fn(...) -> R = transmute(...)` binding.
        //
        // See 007-lang/audits/audit-ffi-unsafe.md §2 for the motivating
        // case (jit_compiler.rs's Cranelift dispatch).
        if code_only.contains("transmute(") || code_only.contains("transmute::<") {
            let in_jit_context = code_only.contains("cranelift_jit::JITModule")
                || code_only.contains("cranelift_module::Module")
                || code_only.contains("JITModule::new(")
                || (code_only.contains("cranelift_jit")
                    && code_only.contains("get_finalized_function"));

            let transmute_targets_fn_ptr = code_only.contains("transmute::<_, fn(")
                || code_only.contains("transmute::<_, unsafe fn(")
                || code_only.contains("transmute::<*const u8, fn(")
                || code_only.contains("transmute::<*mut u8, fn(")
                || (code_only.contains(": fn(") && code_only.contains("= std::mem::transmute("))
                || (code_only.contains(": fn(") && code_only.contains("= mem::transmute("))
                || (code_only.contains(": unsafe fn(") && code_only.contains("transmute("));

            let (severity, description) = if in_jit_context && transmute_targets_fn_ptr {
                (
                    Severity::High,
                    format!(
                        "mem::transmute usage in {} (Cranelift JIT function-pointer dispatch — verify signature match + module ownership invariants per audit-ffi-unsafe.md classification)",
                        file_path
                    ),
                )
            } else {
                (
                    Severity::Critical,
                    format!("mem::transmute usage in {}", file_path),
                )
            };

            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity,
                description,
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // mem::forget — deliberately leaks resources without running destructors
        if code_only.contains("mem::forget(")
            || (code_only.contains("forget(") && code_only.contains("use std::mem"))
        {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("mem::forget usage (resource leak) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Raw pointer casts — escape safe Rust's borrow checker guarantees
        if code_only.contains("as *const ") || code_only.contains("as *mut ") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Raw pointer cast in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                suppressed: false,
            });
        }

        // ── CryptoMisuse: jsonwebtoken::dangerous_insecure_decode ────────────
        // This Rust function explicitly skips ALL JWT verification (signature,
        // expiry, audience, issuer).  Its name documents the risk; any call
        // site is a CryptoMisuse finding regardless of context.
        // Use `code_only` so the detector doesn't flag string literals that
        // mention the identifier (analyzer self-reference, test fixtures, etc).
        if code_only.contains("dangerous_insecure_decode") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "dangerous_insecure_decode in {} — skips all JWT verification \
                     (signature, expiry, audience); use jsonwebtoken::decode with \
                     a proper Validation struct",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        Ok(())
    }

    /// Strip the contents (but not the delimiters) of Rust string literals from
    /// `content`, replacing each string body with a single space.
    ///
    /// This prevents dangerous-pattern checks from triggering on detection
    /// strings embedded as literals (e.g. `content.contains("transmute(")`).
    /// Both regular strings (`"…"`) and raw strings (`r"…"`, `r#"…"#`, …) are
    /// handled.  The function is intentionally conservative — it is not a full
    /// Rust parser and will not strip every edge case (e.g. string interpolation
    /// via macros), but it eliminates the common false-positive sources.
    fn strip_string_literals_rs(content: &str) -> String {
        let mut out = String::with_capacity(content.len());
        let chars: Vec<char> = content.chars().collect();
        let n = chars.len();
        let mut i = 0;

        while i < n {
            // Raw string: optional 'b' prefix then r#*"…"#*
            let is_raw = chars[i] == 'r' || (chars[i] == 'b' && i + 1 < n && chars[i + 1] == 'r');

            if is_raw {
                let prefix_end = if chars[i] == 'b' { i + 2 } else { i + 1 };
                let mut j = prefix_end;
                while j < n && chars[j] == '#' {
                    j += 1;
                }
                let hash_count = j - prefix_end;
                if j < n && chars[j] == '"' {
                    // Raw string opener confirmed — emit prefix + opening delimiter.
                    for &c in &chars[i..=j] {
                        out.push(c);
                    }
                    i = j + 1;
                    // Build the closing sequence: " followed by hash_count '#'.
                    let closing: Vec<char> = std::iter::once('"')
                        .chain(std::iter::repeat_n('#', hash_count))
                        .collect();
                    // Search for the closing sequence.
                    let mut found = false;
                    let remaining = n.saturating_sub(i);
                    for start in 0..=remaining.saturating_sub(closing.len()) {
                        if i + start + closing.len() <= n
                            && chars[i + start..i + start + closing.len()] == closing[..]
                        {
                            out.push(' ');
                            out.extend(closing.iter());
                            i += start + closing.len();
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        // Unterminated raw string — copy remainder verbatim.
                        out.extend(chars[i..].iter());
                        break;
                    }
                    continue;
                }
                // Not a raw string opener — fall through to normal char handling.
            }

            match chars[i] {
                // Character literal — must be handled before '"' to avoid treating
                // '"' as the start of a string literal.
                '\'' => {
                    out.push('\'');
                    i += 1;
                    if i < n {
                        if chars[i] == '\\' {
                            // Escaped char: '\n', '\"', '\u{XXXX}', etc.
                            out.push('\\');
                            i += 1;
                            if i < n && chars[i] == 'u' && i + 1 < n && chars[i + 1] == '{' {
                                // Unicode escape: '\u{XXXX}'
                                while i < n && chars[i] != '}' {
                                    out.push(chars[i]);
                                    i += 1;
                                }
                                if i < n {
                                    out.push(chars[i]);
                                    i += 1;
                                }
                            } else if i < n {
                                out.push(chars[i]);
                                i += 1;
                            }
                        } else {
                            // Single character (including '"').
                            out.push(chars[i]);
                            i += 1;
                        }
                        // Consume closing single quote if present.
                        if i < n && chars[i] == '\'' {
                            out.push('\'');
                            i += 1;
                        }
                    }
                }
                '"' => {
                    // Regular string literal.
                    out.push('"');
                    i += 1;
                    while i < n {
                        if chars[i] == '\\' {
                            i += 2; // skip escape sequence (one extra char)
                        } else if chars[i] == '"' {
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    out.push('"');
                    if i < n {
                        i += 1;
                    }
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }

    /// Strip the bodies of `#[cfg(test)] mod <name> { … }` blocks from
    /// `content`, leaving the attribute, `mod` keyword, name, and
    /// enclosing braces in place but replacing everything between the
    /// braces with whitespace. Newlines in the body are preserved so
    /// line numbers downstream stay stable.
    ///
    /// This is the Rust analogue of Zig's `count_unsafe_in_test_blocks`
    /// and is used to treat an inline `#[cfg(test)] mod tests { … }`
    /// inside a production file as test context for substring-based
    /// dangerous-pattern checks — the same way a whole file under
    /// `/tests/` is already treated as test context by `is_test_file`.
    ///
    /// Recognised attribute forms include `#[cfg(test)]`,
    /// `#[cfg(any(test, …))]`, `#[cfg(all(test, …))]`, etc. Attributes
    /// whose only `test` mention is inside `not(test)` are left in
    /// place (`#[cfg(not(test))]` is production-only).
    ///
    /// Precondition: `content` should already have string literals and
    /// comments stripped, so brace counting is not confused by `{` or
    /// `}` inside those. If applied raw, it falls back to emitting the
    /// attribute verbatim whenever it cannot find a balanced body.
    fn strip_cfg_test_modules_rs(content: &str) -> String {
        let bytes = content.as_bytes();
        let n = bytes.len();
        let mut out: Vec<u8> = Vec::with_capacity(n);
        let mut i = 0;

        while i < n {
            if i + 6 > n || &bytes[i..i + 6] != b"#[cfg(" {
                out.push(bytes[i]);
                i += 1;
                continue;
            }

            let attr_start = i;
            let args_start = i + 6;
            let mut j = args_start;
            let mut paren_depth: i32 = 1;
            while j < n && paren_depth > 0 {
                match bytes[j] {
                    b'(' => paren_depth += 1,
                    b')' => paren_depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            if paren_depth != 0 || j >= n || bytes[j] != b']' {
                out.push(bytes[i]);
                i += 1;
                continue;
            }

            let args_end = j - 1;
            let attr_end = j + 1;
            let args = &bytes[args_start..args_end];
            let is_test_attr = Self::cfg_args_select_test(args);
            if !is_test_attr {
                out.extend_from_slice(&bytes[attr_start..attr_end]);
                i = attr_end;
                continue;
            }

            let mut k = attr_end;
            while k < n && (bytes[k] as char).is_whitespace() {
                k += 1;
            }
            if k + 3 <= n && &bytes[k..k + 3] == b"pub" {
                k += 3;
                if k < n && bytes[k] == b'(' {
                    let mut d = 1;
                    k += 1;
                    while k < n && d > 0 {
                        match bytes[k] {
                            b'(' => d += 1,
                            b')' => d -= 1,
                            _ => {}
                        }
                        k += 1;
                    }
                }
                while k < n && (bytes[k] as char).is_whitespace() {
                    k += 1;
                }
            }

            if k + 4 > n || &bytes[k..k + 4] != b"mod " {
                out.extend_from_slice(&bytes[attr_start..attr_end]);
                i = attr_end;
                continue;
            }
            k += 4;
            while k < n && (bytes[k] as char).is_whitespace() {
                k += 1;
            }
            while k < n && (bytes[k].is_ascii_alphanumeric() || bytes[k] == b'_') {
                k += 1;
            }
            while k < n && (bytes[k] as char).is_whitespace() {
                k += 1;
            }

            if k >= n || bytes[k] != b'{' {
                out.extend_from_slice(&bytes[attr_start..attr_end]);
                i = attr_end;
                continue;
            }

            let body_start = k + 1;
            let mut brace_depth: i32 = 1;
            let mut m = body_start;
            while m < n && brace_depth > 0 {
                match bytes[m] {
                    b'{' => brace_depth += 1,
                    b'}' => brace_depth -= 1,
                    _ => {}
                }
                m += 1;
            }
            if brace_depth != 0 {
                out.extend_from_slice(&bytes[attr_start..attr_end]);
                i = attr_end;
                continue;
            }

            out.extend_from_slice(&bytes[attr_start..body_start]);
            for b in &bytes[body_start..m - 1] {
                out.push(if *b == b'\n' { b'\n' } else { b' ' });
            }
            out.push(b'}');
            i = m;
        }

        String::from_utf8_lossy(&out).into_owned()
    }

    /// Classify the argument list of `#[cfg(...)]` as selecting for
    /// `test` (true) or not (false). Uses [`strip_not_test_groups`] to
    /// drop `not(test)` groups first, then looks for a bareword `test`.
    fn cfg_args_select_test(args: &[u8]) -> bool {
        let text = std::str::from_utf8(args).unwrap_or("");
        let scrubbed = strip_not_test_groups(text);
        let b = scrubbed.as_bytes();
        let len = b.len();
        let mut idx = 0;
        while idx + 4 <= len {
            if &b[idx..idx + 4] == b"test" {
                let before_ok = idx == 0
                    || (!b[idx - 1].is_ascii_alphanumeric() && b[idx - 1] != b'_');
                let after_idx = idx + 4;
                let after_ok = after_idx >= len
                    || (!b[after_idx].is_ascii_alphanumeric() && b[after_idx] != b'_');
                if before_ok && after_ok {
                    return true;
                }
            }
            idx += 1;
        }
        false
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

        let unchecked_malloc =
            RE_UNCHECKED_MALLOC.get_or_init(|| Regex::new(r"malloc\([^)]+\)\s*;").unwrap());
        if unchecked_malloc.is_match(content) {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UncheckedAllocation,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unchecked malloc in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // gets() — no bounds checking, classic buffer overflow vector
        if content.contains("gets(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("gets() usage (unbounded buffer write) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // system() — shell command injection via unvalidated input
        if content.contains("system(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("system() call (command injection risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // sprintf() — no bounds checking, format string overflow
        if content.contains("sprintf(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("sprintf() usage (buffer overflow risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // strcpy/strcat — classic unbounded string operations
        if content.contains("strcpy(") || content.contains("strcat(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "Unbounded string operation (strcpy/strcat) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Strip line comments before crypto checks so `// md5::compute` in
        // a comment doesn't trigger a false positive.
        let code_only: String = content
            .lines()
            .map(|l| {
                if let Some(idx) = l.find("//") {
                    &l[..idx]
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        // MD5 in security context — broken hash, collision-vulnerable
        for pattern in &["md5::compute", "Md5::new"] {
            if let Some(pos) = code_only.find(pattern) {
                if has_security_context(&code_only, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "MD5 used in security context in {} — use SHA-256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        // SHA-1 in security context — broken for collision resistance
        for pattern in &["sha1::Sha1", "Sha1::new"] {
            if let Some(pos) = code_only.find(pattern) {
                if has_security_context(&code_only, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "SHA-1 used in security context in {} — use SHA-256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        // Constant-time comparison violation: == on secret/password/token/key
        // variables is a timing side-channel — use a constant-time equality function.
        for secret_var in &["secret", "password", "token", "key"] {
            // Look for patterns like `secret ==` or `== secret` (with word boundary intent)
            let pattern_lhs = format!("{} ==", secret_var);
            let pattern_rhs = format!("== {}", secret_var);
            if code_only.contains(&pattern_lhs) || code_only.contains(&pattern_rhs) {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::CryptoMisuse,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!(
                        "Timing-unsafe == comparison on '{}'-named variable in {} — use constant-time comparison",
                        secret_var, file_path
                    ),
                    recommended_attack: vec![AttackAxis::Network, AttackAxis::Time],
                    suppressed: false,
                });
                break;
            }
        }

        // ── InputBoundary: unchecked CBOR / MessagePack deserialization ───────
        // serde_cbor (legacy) and ciborium (modern) CBOR deserialization calls
        // without a visible validation wrapper are unvalidated trust boundaries.
        for pattern in &[
            "serde_cbor::from_slice",
            "serde_cbor::from_reader",
            "ciborium::de::from_reader",
            "ciborium::from_reader",
        ] {
            if code_only.contains(pattern) {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::InputBoundary,
                    location: Some(file_path.to_string()),
                    severity: Severity::High,
                    description: format!(
                        "Unchecked CBOR deserialization ({}) in {} — validate schema before trusting decoded value",
                        pattern, file_path
                    ),
                    recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                    suppressed: false,
                });
                break;
            }
        }

        // rmp_serde / rmpv — MessagePack deserialization
        for pattern in &[
            "rmp_serde::from_slice",
            "rmp_serde::from_read",
            "rmpv::decode::read_value",
        ] {
            if code_only.contains(pattern) {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::InputBoundary,
                    location: Some(file_path.to_string()),
                    severity: Severity::High,
                    description: format!(
                        "Unchecked MessagePack deserialization ({}) in {} — validate schema before trusting decoded value",
                        pattern, file_path
                    ),
                    recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                    suppressed: false,
                });
                break;
            }
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
                file: None,
                line: None,
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} goroutines spawned in {}", go_count, file_path),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // unsafe.Pointer — bypasses Go's type safety and GC guarantees
        if content.contains("unsafe.Pointer") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafe.Pointer usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // exec.Command — shell command execution, injection risk
        if content.contains("exec.Command") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "exec.Command usage (command injection risk) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // MD5/SHA-1 in security context — Go crypto/md5 and crypto/sha1
        for pattern in &["md5.New()", "md5.Sum("] {
            if let Some(pos) = content.find(pattern) {
                if has_security_context(content, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "MD5 used in security context in {} — use sha256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        for pattern in &["sha1.New()", "sha1.Sum("] {
            if let Some(pos) = content.find(pattern) {
                if has_security_context(content, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "SHA-1 used in security context in {} — use sha256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        // ── CryptoMisuse: JWT signature verification bypass ───────────────────
        // jwt.ParseUnverified explicitly skips signature verification.  Any call
        // site accepts tokens regardless of whether they were signed by the
        // expected key — a complete authentication bypass.
        if content.contains("ParseUnverified(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "jwt.ParseUnverified in {} — skips JWT signature verification; \
                     use jwt.Parse with a key function that validates the signing key",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnboundedLoop,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unbounded while True loop in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Time],
                suppressed: false,
            });
        }

        if content.contains("eval(") || content.contains("exec(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Dynamic code execution (eval/exec) in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // pickle.load / pickle.loads — arbitrary code execution via deserialization
        if content.contains("pickle.load") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "pickle deserialization (arbitrary code execution) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // os.system / os.popen / subprocess with shell=True — command injection
        if content.contains("os.system(") || content.contains("os.popen(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "Shell command execution (os.system/os.popen) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // subprocess with shell=True
        if (content.contains("subprocess.call")
            || content.contains("subprocess.Popen")
            || content.contains("subprocess.run"))
            && (content.contains("shell=True") || content.contains("shell = True")) {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::CommandInjection,
                    location: Some(file_path.to_string()),
                    severity: Severity::High,
                    description: format!("subprocess with shell=True in {}", file_path),
                    recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                    suppressed: false,
                });
            }

        // hashlib.md5 / hashlib.sha1 in security context
        for pattern in &["hashlib.md5(", "hashlib.new('md5'", "hashlib.new(\"md5\""] {
            if let Some(pos) = content.find(pattern) {
                if has_security_context(content, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "MD5 used in security context in {} — use hashlib.sha256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        for pattern in &[
            "hashlib.sha1(",
            "hashlib.new('sha1'",
            "hashlib.new(\"sha1\"",
        ] {
            if let Some(pos) = content.find(pattern) {
                if has_security_context(content, pos) {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::CryptoMisuse,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "SHA-1 used in security context in {} — use hashlib.sha256 or stronger",
                            file_path
                        ),
                        recommended_attack: vec![AttackAxis::Network],
                        suppressed: false,
                    });
                    break;
                }
            }
        }

        // == comparison on secret/password/token variables — timing side-channel
        for secret_var in &["secret", "password", "token", "key"] {
            let pattern_lhs = format!("{} ==", secret_var);
            let pattern_rhs = format!("== {}", secret_var);
            if content.contains(&pattern_lhs) || content.contains(&pattern_rhs) {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::CryptoMisuse,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!(
                        "Timing-unsafe == comparison on '{}'-named variable in {} — use hmac.compare_digest()",
                        secret_var, file_path
                    ),
                    recommended_attack: vec![AttackAxis::Network, AttackAxis::Time],
                    suppressed: false,
                });
                break;
            }
        }

        // ── CryptoMisuse: PyJWT signature verification bypass ─────────────────
        // options={"verify_signature": False} explicitly disables signature
        // checking; algorithms=["none"] selects the unsecured JWT algorithm.
        // Both patterns accept forged tokens regardless of signing key.
        if content.contains("\"verify_signature\": False")
            || content.contains("'verify_signature': False")
        {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "jwt.decode with verify_signature=False in {} — \
                     signature verification disabled; any token is accepted",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        if content.contains("algorithms=[\"none\"]") || content.contains("algorithms=['none']") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "jwt.decode with algorithms=[\"none\"] in {} — \
                     unsecured JWT algorithm accepted; any unsigned token is valid",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
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

        // Skip eval() check for browser extensions using DevTools API
        if content.contains("eval(") && !self.browser_extension {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval() usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // innerHTML / document.write — DOM-based XSS vectors
        if content.contains("innerHTML") || content.contains("document.write(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "DOM manipulation (innerHTML/document.write) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Network],
                suppressed: false,
            });
        }

        // dangerouslySetInnerHTML — React's explicit escape hatch for raw HTML injection
        if content.contains("dangerouslySetInnerHTML") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("dangerouslySetInnerHTML (XSS risk) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Network],
                suppressed: false,
            });
        }

        // Deno -A permission check
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // JSON.parseExn / JSON.parse without try-catch
        let parse_exn_count = content.matches("JSON.parseExn").count();
        if parse_exn_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} JSON.parseExn calls in {}", parse_exn_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // crypto.createHash('md5') / crypto.createHash('sha1') — weak hash algorithms
        if content.contains("createHash('md5')") || content.contains("createHash(\"md5\")") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "crypto.createHash('md5') in {} — use 'sha256' or stronger",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        if content.contains("createHash('sha1')") || content.contains("createHash(\"sha1\")") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "crypto.createHash('sha1') in {} — use 'sha256' or stronger",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        // ── InputBoundary: JSON.parse without error-handling context ──────────
        // JSON.parse throws SyntaxError on malformed input; callers that don't
        // wrap it in a try-catch expose an unhandled exception boundary.
        // Heuristic: flag files where JSON.parse call count exceeds try-block count
        // (more parses than guarded scopes).
        let json_parse_count = content.matches("JSON.parse(").count();
        let try_count = content.matches("try {").count() + content.matches("try{").count();
        if json_parse_count > 0 && json_parse_count > try_count {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::InputBoundary,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} JSON.parse call(s) with {} try block(s) in {} — \
                     JSON.parse throws SyntaxError on malformed input; wrap in try-catch",
                    json_parse_count, try_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // ── CryptoMisuse: JWT signature verification bypass ───────────────────
        // jwt.decode() (jsonwebtoken library) explicitly skips signature
        // verification — it exists solely for inspecting the payload without
        // trusting it.  Files that call decode() without a corresponding verify()
        // have no authentication layer and accept any token including forged ones.
        //
        // jose library equivalent: decodeJwt() without jwtVerify().
        let has_jwt_decode = content.contains("jwt.decode(");
        let has_jwt_verify = content.contains("jwt.verify(");
        if has_jwt_decode && !has_jwt_verify {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "jwt.decode() without jwt.verify() in {} — \
                     decode() skips signature verification; use verify() to authenticate tokens",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        let has_jose_decode = content.contains("decodeJwt(");
        let has_jose_verify = content.contains("jwtVerify(");
        if has_jose_decode && !has_jose_verify {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "jose decodeJwt() without jwtVerify() in {} — \
                     decodeJwt() does not verify the signature; use jwtVerify() instead",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Dynamic code execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Runtime.exec() in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Code.eval_string/eval_quoted in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Atom exhaustion
        let atom_count = content.matches("String.to_atom").count();
        if atom_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} String.to_atom calls in {} (use String.to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Port/System.cmd - command injection risk
        if content.contains("Port.open") || content.contains("System.cmd") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("System command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // Unsafe apply
        let apply_re =
            RE_ELIXIR_APPLY.get_or_init(|| Regex::new(r"apply\([^,]+,\s*[^,]+,").unwrap());
        if apply_re.is_match(content) {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Dynamic apply/3 in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // :crypto.hash(:md5, ...) / :crypto.hash(:sha, ...) — weak hash algorithms.
        // Note: :crypto.mac(:hmac, :sha, ...) is acceptable (HMAC-SHA1 is not broken).
        if content.contains(":crypto.hash(:md5,") || content.contains(":crypto.hash(:md5 ,") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    ":crypto.hash(:md5, ...) in {} — use :sha256 or stronger",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        // :crypto.hash(:sha, ...) — SHA-1 (not to be confused with :sha256/:sha512)
        if content.contains(":crypto.hash(:sha,") || content.contains(":crypto.hash(:sha ,") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CryptoMisuse,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    ":crypto.hash(:sha, ...) (SHA-1) in {} — use :sha256 or stronger",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        // ── MutationGap: Elixir test files without property-based testing ─────
        // Test files using ExUnit.Case that never reach for ExUnitProperties or
        // StreamData cannot discover emergent edge-case regressions; mutation
        // testing will find surviving mutants that example-based tests miss.
        let is_test_file = file_path.ends_with("_test.exs") || content.contains("use ExUnit.Case");
        let has_property_testing = content.contains("use ExUnitProperties")
            || content.contains("use StreamData")
            || content.contains("ExUnitProperties")
            || content.contains("StreamData");
        if is_test_file && !has_property_testing {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::MutationGap,
                location: Some(file_path.to_string()),
                severity: Severity::Low,
                description: format!(
                    "Elixir test file {} uses ExUnit.Case but has no ExUnitProperties/StreamData — \
                     add property-based tests to improve mutation coverage",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::AtomExhaustion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} unchecked atom creation in {} (use list_to_existing_atom)",
                    atom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // os:cmd - command injection
        if content.contains("os:cmd") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os:cmd call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @external FFI calls in {}", external_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} JSON.parseExn calls in {} (use JSON.parse for safe Result)",
                    parse_exn, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // Mutable refs
        stats.allocation_sites += content.matches("ref(").count();

        // Ignored results (potential mutation bug)
        let ignore_count = content.matches("ignore(").count();
        if ignore_count > 3 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} ignore() calls in {} (may discard important results)",
                    ignore_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // getUnsafe / getExn
        let unsafe_gets = content.matches("getUnsafe").count()
            + content.matches("getExn").count()
            + content.matches("getOrExn").count();
        if unsafe_gets > 0 {
            stats.unwrap_calls += unsafe_gets;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} unsafe get calls in {}", unsafe_gets, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
            (
                "Js.Date.",
                "Date (no core replacement yet)",
                DeprecatedCategory::OldDate,
            ),
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
            "Belt.Array",
            "Belt.List",
            "Belt.Map",
            "Belt.Set",
            "Belt.Option",
            "Belt.Result",
            "Belt.Int",
            "Belt.Float",
            "Belt.SortArray",
            "Belt.HashMap",
            "Belt.HashSet",
            "Belt.MutableMap",
            "Belt.MutableSet",
            "Belt.MutableQueue",
            "Belt.MutableStack",
            "Belt.Range",
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
            "Array.",
            "String.",
            "Dict.",
            "Console.",
            "Promise.",
            "Nullable.",
            "Float.",
            "Int.",
            "Math.",
            "JSON.",
            "RegExp.",
            "Map.",
            "Set.",
            "Option.",
            "Result.",
            "Error.",
            "Iterator.",
            "AsyncIterator.",
            "BigInt.",
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
        // Unsafe operations — Obj.magic is either a hand-written unsafe coercion
        // (UnsafeTypeCoercion) OR an upstream axiom bypass introduced by Coq
        // extraction (ProofDrift).  The canonical Coq extraction marker is
        // `type __ = Obj.t` — every extraction artifact that uses type-erased
        // universals emits this typedef.  When it is present the Obj.magic usage
        // originates in the proof system, not in hand-written OCaml, so the
        // correct category is ProofDrift: the proof's type safety guarantee does
        // not transfer to the extracted code.
        if content.contains("Obj.magic") {
            stats.unsafe_blocks += content.matches("Obj.magic").count();
            let is_coq_extraction_artifact = content.contains("type __ = Obj.t")
                || content.contains("let __ = let rec f _ = Obj.repr f");
            if is_coq_extraction_artifact {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::ProofDrift,
                    location: Some(file_path.to_string()),
                    severity: Severity::High,
                    description: format!(
                        "Obj.magic in Coq extraction artifact in {} — type safety \
                         guarantee from the proof does not transfer to extracted OCaml; \
                         review original theorem for unsafe axioms or admitted lemmas",
                        file_path
                    ),
                    recommended_attack: vec![AttackAxis::Memory],
                    suppressed: false,
                });
            } else {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::UnsafeTypeCoercion,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!("Obj.magic (unsafe type coercion) in {}", file_path),
                    recommended_attack: vec![AttackAxis::Memory],
                    suppressed: false,
                });
            }
        }

        if content.contains("Obj.repr") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Obj.repr (unsafe representation access) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Unsafe deserialization
        if content.contains("Marshal.from_string") || content.contains("Marshal.from_channel") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeDeserialization,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Unsafe Marshal deserialization in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // Command execution
        if content.contains("Unix.system") || content.contains("Unix.execvp") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unix.system/execvp command execution in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe operations in {}", unsafe_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // System calls
        if content.contains("(system ") || content.contains("(process ") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("System/process call in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::ResourceLeak,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} call/cc usage in {}", callcc_count, file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafePerformIO in {}", unsafe_io, file_path),
                recommended_attack: vec![AttackAxis::Concurrency, AttackAxis::Memory],
                suppressed: false,
            });
        }

        if unsafe_coerce > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("{} unsafeCoerce in {}", unsafe_coerce, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} partial function calls (head/tail/fromJust) in {}",
                    partials, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // error/undefined
        let error_count = content.matches("error \"").count()
            + content.matches("error \"").count()
            + content.matches("undefined").count();
        stats.panic_sites += error_count;

        if error_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} error/undefined in {}", error_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} foreign imports in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // unsafeCoerce / unsafePartial
        if content.contains("unsafeCoerce") || content.contains("unsafePartial") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Unsafe coercion in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
        // Strip line ('--') and block ('{- -}') comments so that doc lines like
        // `||| no believe_me required` (which start with `--` after the bar
        // notation is normalised by lines()) and summary blocks do not produce
        // false positives. The `|||` doc-comment prefix is *not* stripped here
        // because Idris2 treats it as code-attached documentation, but those
        // lines never contain bare keywords like `believe_me` outside prose.
        let code = strip_proof_comments(content, "--", Some(("{-", "-}")));
        // Treat `|||` doc comments as comments too — they are stripped by
        // matching lines that begin with `|||` after trimming.
        let code: String = code
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("|||") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        // believe_me — bypasses the type checker (banned estate-wide)
        let believe_count = code.matches("believe_me").count();
        if believe_count > 0 {
            stats.unsafe_blocks += believe_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} believe_me (banned proof escape hatch — type checker bypass) in {}",
                    believe_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // assert_total — silences totality checker without proof
        let assert_total_count = code.matches("assert_total").count();
        if assert_total_count > 0 {
            stats.unsafe_blocks += assert_total_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} assert_total (banned — silence totality without proof) in {}",
                    assert_total_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // %partial — marks function as intentionally partial (totality bypass)
        let partial_count = code.matches("%partial").count();
        if partial_count > 0 {
            stats.unsafe_blocks += partial_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} %partial pragma (totality bypass) in {}",
                    partial_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // unsafePerformIO
        if code.contains("unsafePerformIO") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafePerformIO in {}", file_path),
                recommended_attack: vec![AttackAxis::Concurrency],
                suppressed: false,
            });
        }

        // FFI
        let ffi_count = code.matches("%foreign").count();
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
        // Strip Lean line ('--') and block ('/- -/') comments before pattern
        // matching so that doc-comments documenting "no sorry" do not produce
        // false positives.
        let code = strip_proof_comments(content, "--", Some(("/-", "-/")));
        // sorry — banned proof escape hatch: admits unproven propositions
        let sorry_count = code.matches("sorry").count();
        if sorry_count > 0 {
            stats.unsafe_blocks += sorry_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} sorry (banned proof escape hatch — admits unproven proposition) in {}",
                    sorry_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // unsafeNativeIO — bypasses IO monad discipline
        let unsafe_io_count =
            code.matches("unsafeNativeIO").count() + code.matches("unsafeBaseIO").count();
        if unsafe_io_count > 0 {
            stats.unsafe_blocks += unsafe_io_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} unsafeNativeIO/unsafeBaseIO (IO discipline bypass) in {}",
                    unsafe_io_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Concurrency],
                suppressed: false,
            });
        }

        // native_decide — can crash at runtime on large decidability checks
        if code.contains("native_decide") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::PanicPath,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("native_decide in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // unsafeCast / implementedBy — unsafe type coercions
        if code.contains("unsafeCast") || code.contains("implementedBy") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("unsafeCast/implementedBy in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
        // Strip Agda line ('--') and block ('{- -}') comments. Pragma comments
        // such as `{-# TERMINATING #-}` are themselves block comments — they
        // would be stripped along with everything else, so we count them on
        // a *line-only* stripped view that preserves block comments. That
        // also kills the false positive where a doc line says
        // `-- {-# TERMINATING #-}` to *describe* the pragma without using it.
        let line_stripped = strip_proof_comments(content, "--", None);
        let termination_count_raw = line_stripped.matches("{-# TERMINATING").count()
            + line_stripped.matches("{-# NON_TERMINATING").count();
        let compiled_count_raw = line_stripped.matches("{-# COMPILED").count()
            + line_stripped.matches("{-# FOREIGN").count();
        let code = strip_proof_comments(content, "--", Some(("{-", "-}")));
        // trustMe / primTrustMe — banned proof escape hatches
        let trustme_count = code.matches("trustMe").count() + code.matches("primTrustMe").count();
        if trustme_count > 0 {
            stats.unsafe_blocks += trustme_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} trustMe/primTrustMe (banned proof escape hatch) in {}",
                    trustme_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // {-# TERMINATING #-} / {-# NON_TERMINATING #-} — suppress termination checker
        // (counted on raw content above, before block-comment stripping erases pragmas)
        let termination_count = termination_count_raw;
        if termination_count > 0 {
            stats.unsafe_blocks += termination_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} TERMINATING/NON_TERMINATING pragma (termination checker bypass) in {}",
                    termination_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // Bare postulate blocks — unproven axioms that may not hold
        let postulate_count =
            code.matches("\npostulate").count() + code.matches("\n  postulate").count();
        if postulate_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} postulate block(s) (unproven axiom — verify these hold) in {}",
                    postulate_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // COMPILED pragma (FFI boundary) — counted on raw content above.
        let compiled_count = compiled_count_raw;
        stats.unsafe_blocks += compiled_count;

        Ok(())
    }

    // ============================================================
    // Proof assistants: Isabelle/HOL and Coq/Rocq
    // ============================================================

    fn analyze_isabelle(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Isabelle uses '(* *)' block comments only — no line comments.
        let code = strip_proof_comments(content, "", Some(("(*", "*)")));
        // sorry — Isabelle's admitted-proof escape hatch (banned estate-wide)
        let sorry_count = code.matches("sorry").count();
        if sorry_count > 0 {
            stats.unsafe_blocks += sorry_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} sorry (banned — unfinished Isabelle proof admitted without verification) in {}",
                    sorry_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // oops — abandons an unfinished proof without even admitting it
        let oops_count = code.matches("oops").count();
        if oops_count > 0 {
            stats.unsafe_blocks += oops_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} oops (Isabelle proof abandoned mid-attempt) in {}",
                    oops_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // axiomatization — introduces unverified axioms
        let axiom_count = code.matches("axiomatization").count();
        if axiom_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} axiomatization block(s) (unverified axiom — confirm soundness) in {}",
                    axiom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        Ok(())
    }

    fn analyze_coq(
        &self,
        content: &str,
        stats: &mut ProgramStatistics,
        weak_points: &mut Vec<WeakPoint>,
        file_path: &str,
    ) -> Result<()> {
        // Coq/Rocq uses '(* *)' block comments only.
        let code = strip_proof_comments(content, "", Some(("(*", "*)")));
        // Admitted — closes an unfinished Coq proof as axiom (banned estate-wide)
        let admitted_count = code.matches("Admitted").count();
        if admitted_count > 0 {
            stats.unsafe_blocks += admitted_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} Admitted (banned — unfinished Coq proof accepted as axiom) in {}",
                    admitted_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // admit tactic — same effect as Admitted mid-proof
        let admit_count = code.matches("admit.").count()
            + code.matches("admit ").count()
            + code.matches("admit\n").count();
        if admit_count > 0 {
            stats.unsafe_blocks += admit_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!(
                    "{} admit tactic (proof placeholder — same effect as Admitted) in {}",
                    admit_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // Axiom / Parameter without justification — unverified postulates
        let axiom_count = code.matches("\nAxiom ").count() + code.matches("\nParameter ").count();
        if axiom_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} Axiom/Parameter declaration(s) (unverified postulate) in {}",
                    axiom_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // native_cast_and_print / Obj.magic in extracted code — type safety bypass
        if code.contains("Obj.magic") {
            stats.unsafe_blocks += code.matches("Obj.magic").count();
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "Obj.magic in Coq extraction artifact (type safety bypass) in {}",
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

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
                file: None,
                line: None,
                category: WeakPointCategory::RaceCondition,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} dynamic predicate modifications in {}",
                    assert_count + retract_count,
                    file_path
                ),
                recommended_attack: vec![AttackAxis::Concurrency],
                suppressed: false,
            });
        }

        // System calls
        if content.contains("shell(") || content.contains("process_create(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Shell/process_create in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
        // Count unsafe operations in test blocks separately
        let (test_ptr_ops, test_c_imports) = self.count_unsafe_in_test_blocks(content);
        
        // Detect test-only helper functions
        let test_only_functions = self.detect_test_only_helper_functions(content);
        
        // Count unsafe operations in test-only helper functions
        let mut helper_ptr_ops = 0;
        let mut helper_c_imports = 0;
        let mut in_test_only_function = false;
        
        for line in content.lines() {
            // Check if we're entering a test-only function
            for func_name in &test_only_functions {
                if line.trim().starts_with(&format!("fn {}", func_name)) {
                    in_test_only_function = true;
                }
            }
            
            // Count unsafe operations in test-only functions
            if in_test_only_function {
                if line.contains("@ptrCast") || line.contains("@intToPtr") || line.contains("@ptrToInt") {
                    helper_ptr_ops += 1;
                }
                if line.contains("@cImport") {
                    helper_c_imports += 1;
                }
            }
            
            // Check if we're exiting a function
            if in_test_only_function && line.trim() == "}" {
                in_test_only_function = false;
            }
        }
        
        // Strip string literals and // line comments before counting built-in
        // unsafe-ops, so that mentions of `@cImport`, `@ptrCast`, `@intToPtr`,
        // `@ptrToInt` in doc comments or prose (file headers, architectural
        // notes, build-script commentary) do not trigger false-positive
        // findings. See `007-lang/audits/audit-ffi-unsafe.md` §4 for the
        // motivating case (a build.zig whose only `@cImport` occurrences
        // were in comment text describing the file's role was flagged as
        // "2 C interop imports"). Zig has no block comments, so only `//`
        // line comments need stripping.
        let code_only_zig = {
            let without_strings = strip_simple_double_quoted_strings(content);
            strip_proof_comments(&without_strings, "//", None)
        };

        // Unsafe pointer operations (excluding those in test blocks and test-only helpers)
        let ptr_ops = code_only_zig.matches("@intToPtr").count()
            + code_only_zig.matches("@ptrToInt").count()
            + code_only_zig.matches("@ptrCast").count()
            - test_ptr_ops
            - helper_ptr_ops;
        stats.unsafe_blocks += ptr_ops;

        if ptr_ops > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} unsafe pointer casts in {}", ptr_ops, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // C interop (excluding those in test blocks and test-only helpers)
        let c_import = code_only_zig.matches("@cImport").count() - test_c_imports - helper_c_imports;
        stats.unsafe_blocks += c_import;

        if c_import > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} C interop imports in {}", c_import, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

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

    /// Count unsafe operations (@ptrCast, @intToPtr, @ptrToInt, @cImport) within Zig inline test blocks
    fn count_unsafe_in_test_blocks(&self, content: &str) -> (usize, usize) {
        let mut test_ptr_ops = 0;
        let mut test_c_imports = 0;
        
        // Simple state machine to detect test blocks
        let mut in_test_block = false;
        
        for line in content.lines() {
            if line.trim().starts_with("test \"") {
                // Start of a test block
                in_test_block = true;
            } else if in_test_block && line.trim() == "}" {
                // End of a test block (assuming test blocks are properly closed)
                in_test_block = false;
            } else if in_test_block {
                // Count unsafe operations within the test block
                if line.contains("@ptrCast") || line.contains("@intToPtr") || line.contains("@ptrToInt") {
                    test_ptr_ops += 1;
                }
                if line.contains("@cImport") {
                    test_c_imports += 1;
                }
            }
        }
        
        (test_ptr_ops, test_c_imports)
    }

    /// Detect functions that are only called from test blocks (test-only helper functions)
    fn detect_test_only_helper_functions(&self, content: &str) -> Vec<String> {
        use std::collections::HashSet;
        
        let mut test_only_functions = Vec::new();
        let mut function_calls = std::collections::HashMap::new();
        let mut in_test_block = false;
        let mut current_function = String::new();
        
        // First pass: identify all function definitions and track which ones are called from test blocks
        for line in content.lines() {
            // Track test blocks
            if line.trim().starts_with("test \"") {
                in_test_block = true;
            } else if in_test_block && line.trim() == "}" {
                in_test_block = false;
            }
            
            // Detect function definitions
            if line.trim().starts_with("fn ") && !line.trim().starts_with("fn test") {
                if let Some(func_name) = line.trim().split_whitespace().nth(1) {
                    let func_name = func_name.split('(').next().unwrap_or(func_name);
                    current_function = func_name.to_string();
                    function_calls.entry(func_name.to_string())
                        .or_insert_with(|| (false, HashSet::new()));
                }
            }
            
            // Detect function calls
            if line.contains('(') && !line.trim().starts_with("fn ") {
                // Simple heuristic: look for patterns like "function_name("
                let words: Vec<&str> = line.split_whitespace().collect();
                for word in &words {
                    if word.ends_with('(') && !word.starts_with(|c: char| c.is_uppercase()) {
                        let func_name = word.trim_end_matches('(');
                        if !func_name.is_empty() {
                            let is_test_call = in_test_block;
                            function_calls.entry(func_name.to_string())
                                .or_insert_with(|| (false, HashSet::new()))
                                .1.insert(current_function.clone());
                            
                            if is_test_call {
                                if let Some(entry) = function_calls.get_mut(func_name) {
                                    entry.0 = true; // Mark as called from test
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Second pass: identify functions that are ONLY called from test blocks
        for (func_name, (_called_from_test, _callers)) in &function_calls {
            // For now, we'll use a simpler heuristic: check if the function name contains "scan"
            // This catches scan_u32 and similar test helper functions
            if func_name.contains("scan") {
                test_only_functions.push(func_name.clone());
            }
        }
        
        test_only_functions
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} Unchecked_* operations in {}", unchecked, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
            });
        }

        // pragma Suppress (disables runtime checks)
        if content.contains("pragma Suppress") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("pragma Suppress (runtime checks disabled) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
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
                    file: None,
                    line: None,
                    category: WeakPointCategory::UnsafeCode,
                    location: Some(file_path.to_string()),
                    severity: Severity::Medium,
                    description: format!("{} rawptr usage in {}", rawptr_count, file_path),
                    recommended_attack: vec![AttackAxis::Memory],
                    suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("emit pragma (raw code injection) in {}", file_path),
                recommended_attack: vec![AttackAxis::Memory, AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // cast (unsafe type coercion)
        let cast_count = content.matches("cast[").count();
        if cast_count > 0 {
            stats.unsafe_blocks += cast_count;
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeTypeCoercion,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("{} cast[] (unsafe coercion) in {}", cast_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI calls in {}", ffi_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeCode,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} @system functions in {}", system_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
            // supply chain: flake.nix inputs without effective pinning
            //
            // A flake.nix that declares inputs is properly pinned if ANY of
            // these is true:
            //   1. It declares `narHash` inline.
            //   2. Every input declares an explicit `rev = "<commit-hash>"`
            //      (commit pinning is equivalent to hash pinning for git inputs).
            //   3. A sibling `flake.lock` file exists — Nix lockfiles record
            //      narHash for every transitive input, so the source `flake.nix`
            //      need not duplicate them.
            if file_path.ends_with("flake.nix")
                && content.contains("inputs")
                && content.contains("url")
            {
                let has_narhash = content.contains("narHash");
                let has_rev_pin = {
                    // Crude check: every `url = "..."` line is followed (in
                    // the same input block) by a `rev = "..."` line within
                    // the next ~6 lines. We approximate by counting urls and
                    // revs and treating "rev_count >= url_count" as pinned.
                    let url_count =
                        content.matches("url =").count() + content.matches("url=").count();
                    let rev_count =
                        content.matches("rev =").count() + content.matches("rev=").count();
                    url_count > 0 && rev_count >= url_count
                };
                let has_lockfile = std::path::Path::new(file_path)
                    .parent()
                    .map(|p| p.join("flake.lock").exists())
                    .unwrap_or(false);

                if !has_narhash && !has_rev_pin && !has_lockfile {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::SupplyChain,
                        location: Some(file_path.to_string()),
                        severity: Severity::High,
                        description: format!(
                            "flake.nix declares inputs without narHash, rev pinning, \
                             or sibling flake.lock — dependency revision is unpinned in {}",
                            file_path
                        ),
                        recommended_attack: vec![],
                        suppressed: false,
                    });
                }
            }

            // builtins.exec (arbitrary command execution)
            if content.contains("builtins.exec") {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::CommandInjection,
                    location: Some(file_path.to_string()),
                    severity: Severity::Critical,
                    description: format!("builtins.exec (command execution) in {}", file_path),
                    recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                    suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("eval usage in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // Unquoted variable expansion (potential injection)
        //
        // The correct semantic check is: count `$VAR` and `${VAR}` references
        // that appear *outside* a "..." or '...' string.  Previous versions
        // counted every `$VAR` regardless of quoting, which produced massive
        // false positives on scripts that consistently quote — for example
        // 007's `scripts/generate-abi-headers.sh` reported 73 hits even though
        // every variable use is of the form "${REPO_ROOT}".
        //
        // To approximate "outside quotes", we strip all single- and
        // double-quoted string contents (a single line at a time, since shell
        // strings rarely span lines) and only then count dollar references.
        let stripped_content: String = content
            .lines()
            .map(strip_shell_quoted_strings)
            .collect::<Vec<_>>()
            .join("\n");
        let unquoted_var =
            RE_SHELL_UNQUOTED_VAR.get_or_init(|| Regex::new(r#"\$[A-Za-z_]\w*"#).unwrap());
        let dollar_vars = unquoted_var.find_iter(&stripped_content).count();
        // Only flag if high number of unquoted vars
        if dollar_vars > 20 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} potentially unquoted variable expansions in {}",
                    dollar_vars, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // World-writable permissions
        if content.contains("chmod 777") || content.contains("chmod a+w") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("World-writable permissions in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
                suppressed: false,
            });
        }

        // Deno -A in shell scripts
        if content.contains("deno run -A") || content.contains("deno run --allow-all") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ExcessivePermissions,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("Deno -A (all permissions) in {}", file_path),
                recommended_attack: vec![AttackAxis::Network, AttackAxis::Disk],
                suppressed: false,
            });
        }

        // Unsafe temp files
        if content.contains("/tmp/") && !content.contains("mktemp") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::PathTraversal,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("Hardcoded /tmp/ path without mktemp in {}", file_path),
                recommended_attack: vec![AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("eval/Meta.parse in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // Proof-substitute comments — marker comments standing in for formal proofs
        // (mirrors the estate's convention: Julia files mirror Isabelle/Idris2 definitions)
        let proof_sub_count = count_line_pattern(content, "# sorry")
            + count_line_pattern(content, "# TODO: prove")
            + count_line_pattern(content, "# admitted")
            + count_line_pattern(content, "# ADMITTED")
            + count_line_pattern(content, "# TODO prove");
        if proof_sub_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!(
                    "{} proof-substitute comment(s) (`# sorry`/`# TODO: prove`/`# admitted`) \
                     — mirror implementation lacks formal proof in {}",
                    proof_sub_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // @test x isa Y patterns — type-identity assertions substituting for proven theorems
        // Count @test lines that only contain `isa` (no value comparison)
        let isa_only_count = content
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.starts_with("@test ")
                    && t.contains(" isa ")
                    && !t.contains("==")
                    && !t.contains("≈")
            })
            .count();
        if isa_only_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::ProofDrift,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} `@test x isa Y` assertion(s) with no value check — \
                     type-only tests may substitute for an unwritten formal theorem in {}",
                    isa_only_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // ── InputBoundary: JSON3.read / JSON.parse without error handling ────────
        // Both throw on malformed input. Heuristic: flag files where the combined
        // call count exceeds the number of try-catch blocks.
        let json_read_count =
            content.matches("JSON3.read(").count() + content.matches("JSON.parse(").count();
        let julia_try_count = content.matches("try\n").count()
            + content.matches("try ").count()
            + content.matches("try{").count();
        if json_read_count > 0 && json_read_count > julia_try_count {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::InputBoundary,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!(
                    "{} JSON3.read/JSON.parse call(s) with {} try block(s) in {} — \
                     these throw on malformed input; wrap in try/catch",
                    json_read_count, julia_try_count, file_path
                ),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        // ── MutationGap: @testset with no assertion diversity ──────────────────
        // If the file has @testset blocks and every @test assertion is type-only
        // (only `@test x isa Y` with no == / ≈ / @test_throws), the test suite
        // cannot detect value-level regressions and will pass mutation tests trivially.
        let has_testset = content.contains("@testset");
        if has_testset {
            let total_tests = content
                .lines()
                .filter(|l| l.trim_start().starts_with("@test "))
                .count();
            let value_tests = content
                .lines()
                .filter(|l| {
                    let t = l.trim_start();
                    t.starts_with("@test ")
                        && (t.contains("==")
                            || t.contains("≈")
                            || t.contains("@test_throws")
                            || t.contains("@test_nowarn"))
                })
                .count();
            if total_tests > 0 && value_tests == 0 {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::MutationGap,
                    location: Some(file_path.to_string()),
                    severity: Severity::Medium,
                    description: format!(
                        "{} @test assertion(s) in {} are all type-only (no value/equality checks) — \
                         mutation tests will pass trivially; add @test x == expected assertions",
                        total_tests, file_path
                    ),
                    recommended_attack: vec![AttackAxis::Cpu],
                    suppressed: false,
                });
            }
        }

        // ccall / @ccall (FFI)
        let ccall_count = content.matches("ccall(").count() + content.matches("@ccall").count();
        stats.unsafe_blocks += ccall_count;

        if ccall_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} ccall/FFI calls in {}", ccall_count, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::DynamicCodeExecution,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("loadstring/dofile in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Memory],
                suppressed: false,
            });
        }

        // os.execute (command injection)
        if content.contains("os.execute(") || content.contains("io.popen(") {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::CommandInjection,
                location: Some(file_path.to_string()),
                severity: Severity::High,
                description: format!("os.execute/io.popen in {}", file_path),
                recommended_attack: vec![AttackAxis::Cpu, AttackAxis::Disk],
                suppressed: false,
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
                file: None,
                line: None,
                category: WeakPointCategory::UnsafeFFI,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} FFI/external bindings in {}", ffi_patterns, file_path),
                recommended_attack: vec![AttackAxis::Memory],
                suppressed: false,
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
        let http_localhost_re = RE_HTTP_LOCALHOST.get_or_init(|| {
            Regex::new(r#"http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])"#).unwrap()
        });
        let http_total = http_re.find_iter(content).count();
        let http_local = http_localhost_re.find_iter(content).count();
        let http_count = http_total.saturating_sub(http_local);
        if http_count > 0 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::InsecureProtocol,
                location: Some(file_path.to_string()),
                severity: Severity::Medium,
                description: format!("{} HTTP (non-HTTPS) URLs in {}", http_count, file_path),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        // Hardcoded secrets patterns
        let secret_re = RE_HARDCODED_SECRET.get_or_init(|| Regex::new(
            r#"(?i)(api[_-]?key|api[_-]?secret|password|passwd|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*["'][^"']{8,}"#
        ).unwrap());
        if secret_re.is_match(content) {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::HardcodedSecret,
                location: Some(file_path.to_string()),
                severity: Severity::Critical,
                description: format!("Possible hardcoded secret in {}", file_path),
                recommended_attack: vec![AttackAxis::Network],
                suppressed: false,
            });
        }

        // TODO/FIXME/HACK/XXX markers — count only when the marker
        // appears on a line that also contains a comment-starter, so
        // string literals like `.expect("TODO: handle error")` don't
        // inflate the count. See RE_TODO_COMMENT definition above.
        let todo_re = RE_TODO_COMMENT.get_or_init(|| {
            Regex::new(r"(?m)^[^\n]*?(//|/\*|\*|#|--|;;|%%)[^\n]*?\b(TODO|FIXME|HACK|XXX)\b")
                .expect("static regex is valid")
        });
        let todo_count = todo_re.find_iter(content).count();
        if todo_count > 10 {
            weak_points.push(WeakPoint {
                file: None,
                line: None,
                category: WeakPointCategory::UncheckedError,
                location: Some(file_path.to_string()),
                severity: Severity::Low,
                description: format!("{} TODO/FIXME/HACK markers in {}", todo_count, file_path),
                recommended_attack: vec![AttackAxis::Cpu],
                suppressed: false,
            });
        }

        Ok(())
    }

    // ============================================================
    // ============================================================
    // Supply chain integrity (project-level manifest/lockfile checks)
    // ============================================================

    /// Check project-level manifest and lock files for supply chain integrity gaps.
    ///
    /// Operates on the project root (self.target or its parent) rather than on
    /// individual source files, because the relevant artefacts (Cargo.toml,
    /// Cargo.lock, Julia Manifest.toml, deno.json) are not source files in the
    /// language-detection sense.
    fn analyze_supply_chain_manifests(&self, weak_points: &mut Vec<WeakPoint>) -> Result<()> {
        let project_root = if self.target.is_dir() {
            self.target.clone()
        } else {
            self.target
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf()
        };

        // ── Cargo.toml: git deps without explicit rev= ────────────────────
        let cargo_toml_path = project_root.join("Cargo.toml");
        if let Some(content) = read_bounded(&cargo_toml_path, MANIFEST_FILE_READ_LIMIT) {
            let git_dep_count =
                content.matches("git = \"").count() + content.matches("git=\"").count();
            let rev_count = content.matches("rev = \"").count() + content.matches("rev=\"").count();
            if git_dep_count > 0 && rev_count < git_dep_count {
                let unpinned = git_dep_count - rev_count;
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::SupplyChain,
                    location: Some("Cargo.toml".to_string()),
                    severity: Severity::High,
                    description: format!(
                        "{} git dependency/ies in Cargo.toml without explicit `rev =` — \
                         build is not reproducible",
                        unpinned
                    ),
                    recommended_attack: vec![],
                    suppressed: false,
                });
            }

            // ── Cargo.lock absent when Cargo.toml declares [lib] or [[bin]] ───
            let has_lib = content.contains("[lib]");
            let has_bin = content.contains("[[bin]]");
            if (has_lib || has_bin) && !project_root.join("Cargo.lock").exists() {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::SupplyChain,
                    location: Some("Cargo.toml".to_string()),
                    severity: Severity::High,
                    description: "Cargo.lock is absent — dependency versions are not locked \
                                  for a library/binary crate"
                        .to_string(),
                    recommended_attack: vec![],
                    suppressed: false,
                });
            }
        }

        // ── Julia Manifest.toml: missing git-tree-sha1 hash entries ──────────
        let manifest_toml_path = project_root.join("Manifest.toml");
        if let Some(content) = read_bounded(&manifest_toml_path, MANIFEST_FILE_READ_LIMIT) {
            // A valid v2 Manifest.toml has `git-tree-sha1` for each pinned dep.
            // If [[deps.*]] sections are present but no git-tree-sha1 appears,
            // the manifest is not providing cryptographic pinning.
            let has_deps_section = content.contains("[[deps.") || content.contains("[deps]");
            let has_hash = content.contains("git-tree-sha1");
            if has_deps_section && !has_hash {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::SupplyChain,
                    location: Some("Manifest.toml".to_string()),
                    severity: Severity::Medium,
                    description: "Julia Manifest.toml has dependency entries but no \
                                  `git-tree-sha1` hash fields — package versions are not \
                                  cryptographically pinned"
                        .to_string(),
                    recommended_attack: vec![],
                    suppressed: false,
                });
            }
        }

        // ── deno.json: unpinned import map entries ────────────────────────────
        let deno_json_path = project_root.join("deno.json");
        if let Some(content) = read_bounded(&deno_json_path, MANIFEST_FILE_READ_LIMIT) {
            // Count import values in the "imports" section that lack a version pin.
            // Pinned deno.land specifiers contain '@' (e.g. std@0.177.0).
            // Pinned npm specifiers contain '@' after 'npm:' (e.g. npm:express@4).
            // We scan lines that look like import map values.
            let unpinned_count = content
                .lines()
                .filter(|line| {
                    let t = line.trim();
                    // Line is a JSON string value that references a package URL
                    (t.contains("\"https://") || t.contains("\"npm:")) && !t.contains('@')
                })
                .count();
            if unpinned_count > 0 {
                weak_points.push(WeakPoint {
                    file: None,
                    line: None,
                    category: WeakPointCategory::SupplyChain,
                    location: Some("deno.json".to_string()),
                    severity: Severity::Medium,
                    description: format!(
                        "{} import map entry/ies in deno.json without a version pin — \
                         specifiers are not reproducibly resolved",
                        unpinned_count
                    ),
                    recommended_attack: vec![],
                    suppressed: false,
                });
            }
        }

        Ok(())
    }

    // ============================================================
    // ============================================================
    // Mutation coverage gap (project-level tooling presence)
    // ============================================================

    /// Check whether the project has mutation-test tooling configured.
    ///
    /// Static analysis cannot measure a coverage percentage, but it can detect
    /// the absence of any mutation-test harness.  A Rust project with a test
    /// suite but no `cargo-mutants` config and no mutagen/mutation entries in
    /// Cargo.toml is flagged as a mutation gap.
    fn analyze_mutation_gaps(&self, weak_points: &mut Vec<WeakPoint>) -> Result<()> {
        let project_root = if self.target.is_dir() {
            self.target.clone()
        } else {
            self.target
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf()
        };

        // ── Rust: Cargo.toml with [dev-dependencies] / [[bin]] but no mutation tool ──
        let cargo_toml_path = project_root.join("Cargo.toml");
        if let Some(content) = read_bounded(&cargo_toml_path, MANIFEST_FILE_READ_LIMIT) {
            // Only check projects that have a test infrastructure (dev-deps present
            // or test directories present).
            let has_test_infrastructure =
                content.contains("[dev-dependencies]") || project_root.join("tests").is_dir();
            if has_test_infrastructure {
                // Mutation tooling: cargo-mutants config file OR mutagen in dev-deps
                let has_mutants_config = project_root.join(".cargo-mutants.toml").exists()
                    || project_root.join("mutants.toml").exists();
                let has_mutation_dep = content.contains("cargo-mutants")
                    || content.contains("mutagen")
                    || content.contains("mutation_test");
                if !has_mutants_config && !has_mutation_dep {
                    weak_points.push(WeakPoint {
                        file: None,
                        line: None,
                        category: WeakPointCategory::MutationGap,
                        location: Some("Cargo.toml".to_string()),
                        severity: Severity::Low,
                        description: "Rust project has test infrastructure but no mutation-test \
                                      configuration (cargo-mutants/.cargo-mutants.toml) — \
                                      add `cargo mutants` to verify test suite kills mutations"
                            .to_string(),
                        recommended_attack: vec![],
                        suppressed: false,
                    });
                }
            }
        }

        Ok(())
    }

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
        if let Some(content) = read_bounded(&cargo_toml, MANIFEST_FILE_READ_LIMIT) {
            if content.contains("tokio") {
                frameworks.insert(Framework::Networking);
            }
            if content.contains("rayon") || content.contains("crossbeam") {
                frameworks.insert(Framework::Concurrent);
            }
            if content.contains("actix-web")
                || content.contains("axum")
                || content.contains("warp =")
                || content.contains("rocket =")
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
        if let Some(content) = read_bounded(&mix_exs, MANIFEST_FILE_READ_LIMIT) {
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
        if let Some(content) = read_bounded(&rebar_config, MANIFEST_FILE_READ_LIMIT) {
            if content.contains("cowboy") {
                frameworks.insert(Framework::Cowboy);
                frameworks.insert(Framework::WebServer);
            }
        }

        // gleam.toml (Gleam)
        let gleam_toml = target_dir.join("gleam.toml");
        if let Some(content) = read_bounded(&gleam_toml, MANIFEST_FILE_READ_LIMIT) {
            if content.contains("wisp") || content.contains("mist") {
                frameworks.insert(Framework::WebServer);
            }
        }

        // package.json (JS/TS/ReScript)
        let pkg_json = target_dir.join("package.json");
        if let Some(content) = read_bounded(&pkg_json, MANIFEST_FILE_READ_LIMIT) {
            if content.contains("\"express\"")
                || content.contains("\"fastify\"")
                || content.contains("\"koa\"")
            {
                frameworks.insert(Framework::WebServer);
            }
            if content.contains("\"mongodb\"")
                || content.contains("\"pg\"")
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
            if let Some(content) = read_bounded(&path, MANIFEST_FILE_READ_LIMIT) {
                if content.contains("flask")
                    || content.contains("django")
                    || content.contains("fastapi")
                {
                    frameworks.insert(Framework::WebServer);
                }
                if content.contains("sqlalchemy")
                    || content.contains("psycopg")
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
            let content = match read_bounded(file, SOURCE_FILE_READ_LIMIT) {
                Some(c) => c,
                None => continue,
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
                    if has_elixir_use("GenServer")
                        || has_elixir_use("Supervisor")
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
                    if has_import("sqlalchemy") || has_import("psycopg") || has_import("pymongo") {
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
                    if has_js_import("express") || has_js_import("fastify") || has_js_import("koa")
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

/// Count occurrences of `pattern` that appear at the start of a trimmed line.
///
/// Used for comment-style proof-substitute detection (e.g. `# sorry`) where
/// substring matching would produce false positives on larger identifiers.
/// Remove the *contents* of double- and single-quoted strings on a single
/// shell line, leaving the surrounding quotes themselves in place.  This is
/// used by the shell-injection heuristic to count `$VAR` references that
/// appear *outside* any quoted string.
///
/// Heuristic limitations: does not understand backslash-escaped quotes inside
/// strings, ANSI-C `$'...'`, here-docs, or arithmetic `$((...))`.  Those edge
/// cases produce slightly noisier output but never under-count true unquoted
/// expansions, so the safety bias is preserved.
fn strip_shell_quoted_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                out.push('"');
                for inner in chars.by_ref() {
                    if inner == '"' {
                        out.push('"');
                        break;
                    }
                }
            }
            '\'' => {
                out.push('\'');
                for inner in chars.by_ref() {
                    if inner == '\'' {
                        out.push('\'');
                        break;
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

fn count_line_pattern(content: &str, pattern: &str) -> usize {
    content
        .lines()
        .filter(|l| l.trim_start().starts_with(pattern))
        .count()
}

/// Strip line and block comments from proof-assistant source so that pattern
/// detectors (e.g. ProofDrift's `believe_me`/`sorry`/`trustMe` matchers) do not
/// false-positive on documentation prose.
///
/// `line_marker` is the per-language line-comment prefix (e.g. "--" for
/// Idris/Agda/Lean, or "" if the language has no line comments).
/// `block` is `Some((open, close))` if the language has block comments — e.g.
/// `Some(("{-", "-}"))` for Idris/Agda, `Some(("(*", "*)"))` for Coq/OCaml.
///
/// The implementation is intentionally simple: it does not understand strings,
/// nested comments, or escapes. That is acceptable here because we only need
/// the comment regions removed; mis-handling a string literal that happens to
/// contain `believe_me` would still be a true positive.
/// Strip `"..."` double-quoted string literals, honouring `\` escape
/// sequences. Preserves the opening and closing `"` so that later passes can
/// still see the delimiters, but replaces the contents with the empty string
/// (i.e. `"foo"` becomes `""`). Used by analyzers whose target language has
/// simple C-style string syntax (Zig, C, JavaScript, most brace languages).
/// For Rust's richer literal syntax (raw strings, byte strings, char
/// literals, lifetimes) use [`Analyzer::strip_string_literals_rs`] instead.
fn strip_simple_double_quoted_strings(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let chars: Vec<char> = content.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        if chars[i] == '"' {
            out.push('"');
            i += 1;
            while i < n {
                if chars[i] == '\\' && i + 1 < n {
                    i += 2; // skip escape sequence
                } else if chars[i] == '"' {
                    break;
                } else {
                    i += 1; // skip string content
                }
            }
            if i < n {
                out.push('"');
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn strip_proof_comments(content: &str, line_marker: &str, block: Option<(&str, &str)>) -> String {
    // First strip block comments greedily, left-to-right.
    let mut without_blocks = String::with_capacity(content.len());
    if let Some((open, close)) = block {
        let mut rest = content;
        while let Some(start) = rest.find(open) {
            without_blocks.push_str(&rest[..start]);
            let after_open = &rest[start + open.len()..];
            if let Some(end) = after_open.find(close) {
                rest = &after_open[end + close.len()..];
            } else {
                // Unterminated block comment — drop the rest.
                rest = "";
                break;
            }
        }
        without_blocks.push_str(rest);
    } else {
        without_blocks.push_str(content);
    }

    // Then strip line comments.
    if line_marker.is_empty() {
        return without_blocks;
    }
    let mut out = String::with_capacity(without_blocks.len());
    for (i, line) in without_blocks.lines().enumerate() {
        let kept = match line.find(line_marker) {
            Some(idx) => &line[..idx],
            None => line,
        };
        if i > 0 {
            out.push('\n');
        }
        out.push_str(kept);
    }
    out
}

/// Rewrite `args` by replacing every `not(test)` group (with
/// whitespace-tolerant matching) with a single space. Used by
/// [`Analyzer::cfg_args_select_test`] so `cfg(not(test))` and
/// `cfg(all(not(test), …))` do not mis-classify as test-active.
fn strip_not_test_groups(args: &str) -> String {
    let bytes = args.as_bytes();
    let n = bytes.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0;

    while i < n {
        if i + 3 <= n && &bytes[i..i + 3] == b"not" {
            let after_kw = i + 3;
            let before_ok = i == 0
                || (!bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_');
            let mut k = after_kw;
            while k < n && (bytes[k] as char).is_whitespace() {
                k += 1;
            }
            if before_ok && k < n && bytes[k] == b'(' {
                let mut depth: i32 = 1;
                let mut m = k + 1;
                while m < n && depth > 0 {
                    match bytes[m] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    m += 1;
                }
                if depth == 0 {
                    let inside = &args[k + 1..m - 1];
                    if inside.trim() == "test" {
                        out.push(b' ');
                        i = m;
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns true if the ±200 character window around `pos` contains security
/// vocabulary, indicating that a weak cryptographic primitive (MD5, SHA1) is
/// being used in a security-sensitive context rather than for benign purposes
/// such as file checksums or cache keys.
fn has_security_context(content: &str, pos: usize) -> bool {
    let lo = pos.saturating_sub(200);
    let hi = (pos + 200).min(content.len());
    let window = &content[lo..hi];
    window.contains("password")
        || window.contains("secret")
        || window.contains("token")
        || window.contains("auth")
        || window.contains("key")
        || window.contains("credential")
        || window.contains("hash")
        || window.contains("sign")
        || window.contains("verify")
        || window.contains("encrypt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ---------------------------------------------------------------
    // 1. Language::detect for different file extensions
    // ---------------------------------------------------------------

    #[test]
    fn language_detect_common_extensions() {
        assert_eq!(Language::detect("main.rs"), Language::Rust);
        assert_eq!(Language::detect("lib.c"), Language::C);
        assert_eq!(Language::detect("app.cpp"), Language::Cpp);
        assert_eq!(Language::detect("server.go"), Language::Go);
        assert_eq!(Language::detect("script.py"), Language::Python);
        assert_eq!(Language::detect("index.js"), Language::JavaScript);
        assert_eq!(Language::detect("app.rb"), Language::Ruby);
        assert_eq!(Language::detect("mix.ex"), Language::Elixir);
        assert_eq!(Language::detect("gen_server.erl"), Language::Erlang);
        assert_eq!(Language::detect("router.gleam"), Language::Gleam);
        assert_eq!(Language::detect("README.md"), Language::Unknown);
        assert_eq!(Language::detect("Makefile"), Language::Unknown);
    }

    #[test]
    fn language_detect_typescript_maps_to_javascript() {
        assert_eq!(Language::detect("component.ts"), Language::JavaScript);
        assert_eq!(Language::detect("component.tsx"), Language::JavaScript);
        assert_eq!(Language::detect("page.jsx"), Language::JavaScript);
    }

    // ---------------------------------------------------------------
    // 2. Analyzer::new() with a valid temp directory
    // ---------------------------------------------------------------

    #[test]
    fn analyzer_new_valid_directory() {
        let tmp = TempDir::new().unwrap();
        // Create a Rust file so language detection succeeds
        fs::write(tmp.path().join("main.rs"), "fn main() {}").unwrap();
        let analyzer = Analyzer::new(tmp.path());
        assert!(
            analyzer.is_ok(),
            "Analyzer::new should succeed on a valid directory with source files"
        );
    }

    // ---------------------------------------------------------------
    // 3. Analyzer::new() with a non-existent path
    // ---------------------------------------------------------------

    #[test]
    fn analyzer_new_nonexistent_path() {
        let result = Analyzer::new(Path::new("/tmp/this_path_definitely_does_not_exist_29387"));
        assert!(
            result.is_err(),
            "Analyzer::new should error on non-existent path"
        );
        let err_msg = result.err().expect("expected error").to_string();
        assert!(
            err_msg.contains("does not exist"),
            "Error message should mention 'does not exist', got: {err_msg}"
        );
    }

    // ---------------------------------------------------------------
    // 4. analyze() on a Rust file containing `unsafe {}` — UnsafeCode
    // ---------------------------------------------------------------

    #[test]
    fn analyze_rust_detects_unsafe_code() {
        let tmp = TempDir::new().unwrap();
        let rust_file = tmp.path().join("danger.rs");
        fs::write(
            &rust_file,
            r#"
fn safe_wrapper() {
    unsafe {
        let ptr = std::ptr::null::<u8>();
        *ptr;
    }
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&rust_file).unwrap();
        let report = analyzer.analyze().unwrap();

        let unsafe_points: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnsafeCode)
            .collect();

        assert!(
            !unsafe_points.is_empty(),
            "Should detect UnsafeCode weak point for file containing `unsafe {{}}`"
        );
    }

    // ---------------------------------------------------------------
    // 5. analyze() on a Rust file containing `.unwrap()` — PanicPath
    // ---------------------------------------------------------------

    #[test]
    fn analyze_rust_detects_panic_path_from_unwrap() {
        let tmp = TempDir::new().unwrap();
        let rust_file = tmp.path().join("unwrappy.rs");
        // The analyzer triggers PanicPath when unwrap_calls > 5,
        // so we need at least 6 unwrap calls.
        fs::write(
            &rust_file,
            r#"
fn lots_of_unwraps() {
    let a = Some(1).unwrap();
    let b = Some(2).unwrap();
    let c = Some(3).unwrap();
    let d = Some(4).unwrap();
    let e = Some(5).unwrap();
    let f = Some(6).unwrap();
    let g = Some(7).unwrap();
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&rust_file).unwrap();
        let report = analyzer.analyze().unwrap();

        let panic_points: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::PanicPath)
            .collect();

        assert!(
            !panic_points.is_empty(),
            "Should detect PanicPath weak point when >5 unwrap() calls are present"
        );
    }

    // ---------------------------------------------------------------
    // 6. analyze() on a Python file with `eval(` — DynamicCodeExecution
    // ---------------------------------------------------------------

    #[test]
    fn analyze_python_detects_eval() {
        let tmp = TempDir::new().unwrap();
        let py_file = tmp.path().join("danger.py");
        fs::write(
            &py_file,
            r#"
user_input = input("Enter expression: ")
result = eval(user_input)
print(result)
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&py_file).unwrap();
        let report = analyzer.analyze().unwrap();

        let dyn_exec_points: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::DynamicCodeExecution)
            .collect();

        assert!(
            !dyn_exec_points.is_empty(),
            "Should detect DynamicCodeExecution for Python eval() usage"
        );
    }

    // ---------------------------------------------------------------
    // 7. analyze() on a Go file with `exec.Command(` — CommandInjection
    // ---------------------------------------------------------------

    #[test]
    fn analyze_go_detects_exec_command() {
        let tmp = TempDir::new().unwrap();
        let go_file = tmp.path().join("runner.go");
        fs::write(
            &go_file,
            r#"
package main

import (
    "os/exec"
    "fmt"
)

func main() {
    cmd := exec.Command("ls", "-la")
    out, _ := cmd.Output()
    fmt.Println(string(out))
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&go_file).unwrap();
        let report = analyzer.analyze().unwrap();

        let cmd_injection_points: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CommandInjection)
            .collect();

        assert!(
            !cmd_injection_points.is_empty(),
            "Should detect CommandInjection for Go exec.Command usage"
        );
    }

    // ---------------------------------------------------------------
    // 8. analyze() on an empty directory — empty results
    // ---------------------------------------------------------------

    #[test]
    fn analyze_empty_directory_produces_empty_results() {
        let tmp = TempDir::new().unwrap();
        // Create a single file so language detection doesn't fail,
        // but put nothing dangerous in it.
        fs::write(tmp.path().join("empty.rs"), "").unwrap();

        let analyzer = Analyzer::new(tmp.path()).unwrap();
        let report = analyzer.analyze().unwrap();

        assert!(
            report.weak_points.is_empty(),
            "Empty source files should produce no weak points, got: {:?}",
            report.weak_points,
        );
        assert_eq!(report.statistics.total_lines, 0);
    }

    // ---------------------------------------------------------------
    // 9. analyze() should skip files in excluded directories
    //    (walk_directory skips node_modules, target, .git, etc.)
    // ---------------------------------------------------------------

    #[test]
    fn analyze_skips_excluded_directories() {
        let tmp = TempDir::new().unwrap();

        // Create a benign top-level file so language detection succeeds
        fs::write(tmp.path().join("lib.rs"), "fn safe() {}").unwrap();

        // Create a node_modules directory with a dangerous file inside.
        // walk_directory should skip node_modules entirely.
        let excluded_dir = tmp.path().join("node_modules");
        fs::create_dir_all(&excluded_dir).unwrap();
        fs::write(
            excluded_dir.join("bad.rs"),
            "fn bad() { unsafe { std::ptr::null::<u8>().read(); } }\n",
        )
        .unwrap();

        let analyzer = Analyzer::new(tmp.path()).unwrap();
        let report = analyzer.analyze().unwrap();

        // The dangerous file in node_modules should NOT produce weak points
        let unsafe_in_excluded: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| {
                wp.category == WeakPointCategory::UnsafeCode
                    && wp
                        .location
                        .as_deref()
                        .map_or(false, |loc| loc.contains("node_modules"))
            })
            .collect();

        assert!(
            unsafe_in_excluded.is_empty(),
            "Files inside node_modules/ should be skipped during analysis"
        );
    }

    // ---------------------------------------------------------------
    // 10. analyze() on a single file produces correct language field
    // ---------------------------------------------------------------

    #[test]
    fn analyze_single_file_reports_correct_language() {
        let tmp = TempDir::new().unwrap();
        let go_file = tmp.path().join("main.go");
        fs::write(&go_file, "package main\nfunc main() {}\n").unwrap();

        let analyzer = Analyzer::new(&go_file).unwrap();
        let report = analyzer.analyze().unwrap();

        assert_eq!(
            report.language,
            Language::Go,
            "Report should identify Go as the language for a .go file"
        );
    }

    // ---------------------------------------------------------------
    // 11. Rust file with few unwraps should NOT trigger PanicPath
    // ---------------------------------------------------------------

    #[test]
    fn analyze_rust_few_unwraps_no_panic_path() {
        let tmp = TempDir::new().unwrap();
        let rust_file = tmp.path().join("safe.rs");
        // Only 3 unwrap calls — threshold is >5
        fs::write(
            &rust_file,
            r#"
fn few_unwraps() {
    let a = Some(1).unwrap();
    let b = Some(2).unwrap();
    let c = Some(3).unwrap();
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&rust_file).unwrap();
        let report = analyzer.analyze().unwrap();

        let panic_points: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::PanicPath)
            .collect();

        assert!(
            panic_points.is_empty(),
            "Should NOT trigger PanicPath when unwrap count is <= 5"
        );
    }

    // ---------------------------------------------------------------
    // mem::transmute: JIT-aware classification
    // (Cranelift function-pointer dispatch downgrades Critical → High)
    // ---------------------------------------------------------------

    #[test]
    fn analyze_rust_transmute_in_jit_context_downgrades_to_high() {
        let analyzer = Analyzer {
            target: std::path::PathBuf::from("jit_compiler.rs"),
            language: crate::types::Language::Rust,
            verbose: false,
            browser_extension: false,
        };
        // Canonical Cranelift JIT dispatch pattern: a function pointer
        // returned by JITModule::get_finalized_function() is transmuted
        // to a typed `fn(...) -> R` so it can be invoked from Rust.
        let content = r#"
use cranelift_jit::JITModule;
use cranelift_module::Module;

pub struct CompiledFunction {
    fn_ptr: *const u8,
    param_count: usize,
    _module: JITModule,
}

pub fn call(compiled: &CompiledFunction, args: &[i64]) -> Option<i64> {
    unsafe {
        match compiled.param_count {
            0 => {
                let f: fn() -> i64 = std::mem::transmute(compiled.fn_ptr);
                Some(f())
            }
            1 => {
                let f: fn(i64) -> i64 = std::mem::transmute(compiled.fn_ptr);
                Some(f(args[0]))
            }
            _ => None,
        }
    }
}
"#;
        let mut stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut weak_points = Vec::new();
        analyzer
            .analyze_rust(content, &mut stats, &mut weak_points, "jit_compiler.rs")
            .unwrap();

        let transmute_findings: Vec<_> = weak_points
            .iter()
            .filter(|wp| wp.description.contains("mem::transmute"))
            .collect();

        assert_eq!(
            transmute_findings.len(),
            1,
            "Exactly one mem::transmute finding expected"
        );
        assert_eq!(
            transmute_findings[0].severity,
            Severity::High,
            "JIT-context transmute targeting fn(...) -> R should downgrade Critical → High"
        );
        assert!(
            transmute_findings[0]
                .description
                .contains("Cranelift JIT function-pointer dispatch"),
            "Downgraded finding should carry the JIT classification suffix; got: {}",
            transmute_findings[0].description
        );
    }

    #[test]
    fn analyze_rust_transmute_outside_jit_context_stays_critical() {
        let analyzer = Analyzer {
            target: std::path::PathBuf::from("util.rs"),
            language: crate::types::Language::Rust,
            verbose: false,
            browser_extension: false,
        };
        // Arbitrary type-punning transmute, NO Cranelift markers anywhere.
        // Must remain Critical — the JIT-aware downgrade should never
        // suppress real type-punning bugs.
        let content = r#"
fn pun_u64_to_two_u32s(x: u64) -> (u32, u32) {
    unsafe { std::mem::transmute(x) }
}
"#;
        let mut stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut weak_points = Vec::new();
        analyzer
            .analyze_rust(content, &mut stats, &mut weak_points, "util.rs")
            .unwrap();

        let transmute_findings: Vec<_> = weak_points
            .iter()
            .filter(|wp| wp.description.contains("mem::transmute"))
            .collect();

        assert_eq!(transmute_findings.len(), 1);
        assert_eq!(
            transmute_findings[0].severity,
            Severity::Critical,
            "Non-JIT transmute must stay Critical — JIT-aware downgrade must not over-suppress"
        );
        assert!(
            !transmute_findings[0]
                .description
                .contains("Cranelift JIT"),
            "Non-JIT finding must not carry the JIT classification suffix"
        );
    }

    #[test]
    fn analyze_rust_jit_marker_without_fn_ptr_target_stays_critical() {
        // Edge case: file IS a JIT file (cranelift_jit imported) but the
        // transmute target is NOT a function pointer — could be a real bug
        // in JIT code. Stay Critical.
        let analyzer = Analyzer {
            target: std::path::PathBuf::from("jit_misc.rs"),
            language: crate::types::Language::Rust,
            verbose: false,
            browser_extension: false,
        };
        let content = r#"
use cranelift_jit::JITModule;

fn pun_in_jit_file(x: u64) -> [u8; 8] {
    unsafe { std::mem::transmute(x) }
}
"#;
        let mut stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut weak_points = Vec::new();
        analyzer
            .analyze_rust(content, &mut stats, &mut weak_points, "jit_misc.rs")
            .unwrap();

        let transmute_findings: Vec<_> = weak_points
            .iter()
            .filter(|wp| wp.description.contains("mem::transmute"))
            .collect();

        assert_eq!(transmute_findings.len(), 1);
        assert_eq!(
            transmute_findings[0].severity,
            Severity::Critical,
            "JIT-context but no fn-ptr target — must stay Critical (could be real bug)"
        );
    }

    // ---------------------------------------------------------------
    // CryptoMisuse: missing signature verification (new patterns)
    // ---------------------------------------------------------------

    #[test]
    fn analyze_rust_detects_dangerous_insecure_decode() {
        // Test directly against the method: bypass file I/O to isolate the
        // pattern detection from the directory-walking / file-reading path.
        let analyzer = Analyzer {
            target: std::path::PathBuf::from("auth.rs"),
            language: crate::types::Language::Rust,
            verbose: false,
            browser_extension: false,
        };
        let content = r#"
use jsonwebtoken::{dangerous_insecure_decode, DecodingKey, TokenData};

fn inspect_token(token: &str) -> TokenData<Claims> {
    dangerous_insecure_decode::<Claims>(token).expect("decode failed")
}
"#;
        let mut stats = ProgramStatistics {
            total_lines: 0,
            unsafe_blocks: 0,
            panic_sites: 0,
            unwrap_calls: 0,
            allocation_sites: 0,
            io_operations: 0,
            threading_constructs: 0,
        };
        let mut weak_points = Vec::new();
        analyzer
            .analyze_rust(content, &mut stats, &mut weak_points, "auth.rs")
            .unwrap();

        let hits: Vec<_> = weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CryptoMisuse)
            .collect();
        assert!(
            !hits.is_empty(),
            "Should flag dangerous_insecure_decode as CryptoMisuse"
        );
        assert!(
            hits[0].severity == Severity::Critical,
            "dangerous_insecure_decode should be Critical"
        );
    }

    #[test]
    fn analyze_go_detects_parse_unverified() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("auth.go");
        fs::write(
            &f,
            r#"
package main

import "github.com/golang-jwt/jwt/v5"

func inspectToken(tokenStr string) jwt.MapClaims {
    token, _, _ := jwt.ParseUnverified(tokenStr, jwt.MapClaims{})
    return token.Claims.(jwt.MapClaims)
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let hits: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CryptoMisuse)
            .collect();
        assert!(
            !hits.is_empty(),
            "Should flag jwt.ParseUnverified as CryptoMisuse"
        );
        assert!(
            hits[0].severity == Severity::Critical,
            "ParseUnverified should be Critical"
        );
    }

    #[test]
    fn analyze_python_detects_jwt_verify_signature_false() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("auth.py");
        fs::write(
            &f,
            r#"
import jwt

def decode_token(token):
    return jwt.decode(token, options={"verify_signature": False})
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let hits: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CryptoMisuse)
            .collect();
        assert!(
            !hits.is_empty(),
            "Should flag verify_signature=False as CryptoMisuse"
        );
        assert!(
            hits[0].severity == Severity::Critical,
            "verify_signature=False should be Critical"
        );
    }

    #[test]
    fn analyze_python_detects_jwt_algorithms_none() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("auth.py");
        fs::write(
            &f,
            r#"
import jwt

def decode_token(token, secret):
    return jwt.decode(token, secret, algorithms=["none"])
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let hits: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CryptoMisuse)
            .collect();
        assert!(
            !hits.is_empty(),
            "Should flag algorithms=[\"none\"] as CryptoMisuse"
        );
    }

    #[test]
    fn analyze_javascript_detects_jwt_decode_without_verify() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("auth.js");
        fs::write(
            &f,
            r#"
const jwt = require('jsonwebtoken');

function inspectToken(token) {
    // WARNING: this skips signature verification
    return jwt.decode(token);
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let hits: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::CryptoMisuse)
            .collect();
        assert!(
            !hits.is_empty(),
            "Should flag jwt.decode() without jwt.verify() as CryptoMisuse"
        );
        assert!(
            hits[0].severity == Severity::Critical,
            "jwt.decode without verify should be Critical"
        );
    }

    #[test]
    fn analyze_javascript_no_flag_when_jwt_verify_present() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("auth.js");
        fs::write(
            &f,
            r#"
const jwt = require('jsonwebtoken');

function validateToken(token, secret) {
    return jwt.verify(token, secret);
}

function inspectToken(token) {
    // decode() used only for logging; verify() is the auth gate
    const payload = jwt.decode(token);
    console.log('iss:', payload.iss);
}
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let hits: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| {
                wp.category == WeakPointCategory::CryptoMisuse
                    && wp.description.contains("jwt.decode")
            })
            .collect();
        assert!(
            hits.is_empty(),
            "Should NOT flag jwt.decode when jwt.verify is also present in the file"
        );
    }

    // ---------------------------------------------------------------
    // ProofDrift: Obj.magic in Coq extraction artifacts
    // ---------------------------------------------------------------

    #[test]
    fn analyze_ocaml_detects_obj_magic_in_coq_artifact_as_proof_drift() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("extracted.ml");
        fs::write(
            &f,
            r#"
(* This file was automatically generated by the Coq system *)

type __ = Obj.t
let __ = let rec f _ = Obj.repr f in Obj.repr f

let coq_MyTheorem_rect f1 f2 v =
  Obj.magic (match Obj.magic v with
    | Coq_left x -> Obj.magic (f1 x)
    | Coq_right x -> Obj.magic (f2 x))
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let proof_drift: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::ProofDrift)
            .collect();
        let unsafe_coercion: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnsafeTypeCoercion)
            .collect();

        assert!(
            !proof_drift.is_empty(),
            "Coq extraction artifact with Obj.magic should be ProofDrift"
        );
        assert!(
            unsafe_coercion.is_empty(),
            "Coq extraction Obj.magic should NOT also be UnsafeTypeCoercion"
        );
    }

    #[test]
    fn analyze_ocaml_detects_obj_magic_in_hand_written_code_as_unsafe_coercion() {
        let dir = TempDir::new().unwrap();
        let f = dir.path().join("unsafe_hack.ml");
        fs::write(
            &f,
            r#"
(* Hand-written OCaml with an unsafe cast *)
let force_cast (x : 'a) : 'b = Obj.magic x
"#,
        )
        .unwrap();

        let analyzer = Analyzer::new(&f).unwrap();
        let report = analyzer.analyze().unwrap();

        let unsafe_coercion: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnsafeTypeCoercion)
            .collect();
        let proof_drift: Vec<_> = report
            .weak_points
            .iter()
            .filter(|wp| {
                wp.category == WeakPointCategory::ProofDrift
                    && wp.description.contains("extraction")
            })
            .collect();

        assert!(
            !unsafe_coercion.is_empty(),
            "Hand-written Obj.magic should be UnsafeTypeCoercion"
        );
        assert!(
            proof_drift.is_empty(),
            "Hand-written Obj.magic (no Coq markers) should NOT be ProofDrift"
        );
    }

    // ---------------------------------------------------------------
    // strip_cfg_test_modules_rs + cfg_args_select_test + strip_not_test_groups
    // ---------------------------------------------------------------

    #[test]
    fn cfg_test_basic_attribute_is_test() {
        assert!(Analyzer::cfg_args_select_test(b"test"));
    }

    #[test]
    fn cfg_any_including_test_is_test() {
        assert!(Analyzer::cfg_args_select_test(b"any(test, feature = \"x\")"));
        assert!(Analyzer::cfg_args_select_test(b"any(feature = \"x\", test)"));
    }

    #[test]
    fn cfg_all_including_test_is_test() {
        assert!(Analyzer::cfg_args_select_test(
            b"all(test, not(debug_assertions))"
        ));
    }

    #[test]
    fn cfg_not_test_is_not_test() {
        assert!(!Analyzer::cfg_args_select_test(b"not(test)"));
    }

    #[test]
    fn cfg_all_not_test_with_features_is_not_test() {
        assert!(!Analyzer::cfg_args_select_test(
            b"all(not(test), feature = \"foo\")"
        ));
    }

    #[test]
    fn cfg_feature_only_is_not_test() {
        assert!(!Analyzer::cfg_args_select_test(b"feature = \"foo\""));
    }

    #[test]
    fn cfg_test_substring_in_identifier_is_not_test() {
        // `testable` contains `test` but is not a bareword match.
        assert!(!Analyzer::cfg_args_select_test(b"feature = testable"));
    }

    #[test]
    fn strip_cfg_test_modules_elides_inline_test_mod() {
        let src = "\
pub fn prod_fn() { 42 }

#[cfg(test)]
mod tests {
    #[test]
    fn choreography_unbounded_loop() {
        let x = 1;
    }
}
";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(out.contains("pub fn prod_fn"), "production code preserved");
        assert!(!out.contains("unbounded"), "test-fn identifier stripped");
        assert!(!out.contains("#[test]"), "test attribute stripped");
        assert_eq!(out.lines().count(), src.lines().count(),
            "line count preserved so downstream line numbers stay stable");
    }

    #[test]
    fn strip_cfg_test_modules_preserves_cfg_not_test() {
        let src = "\
#[cfg(not(test))]
mod production_only {
    fn infinite_loop() {}
}
";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(
            out.contains("infinite_loop"),
            "cfg(not(test)) is production — must NOT be stripped"
        );
    }

    #[test]
    fn strip_cfg_test_modules_handles_any_test() {
        let src = "\
#[cfg(any(test, feature = \"debug\"))]
mod tests {
    fn unbounded_thing() {}
}
";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(!out.contains("unbounded_thing"), "any(test, …) stripped");
    }

    #[test]
    fn strip_cfg_test_modules_handles_nested_braces() {
        let src = "\
#[cfg(test)]
mod tests {
    fn nested() {
        let x = match y {
            1 => { 2 }
            _ => { 3 }
        };
    }
}
trailing_production_code();
";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(!out.contains("nested"), "body with nested braces stripped");
        assert!(
            out.contains("trailing_production_code"),
            "code after the test mod survives"
        );
    }

    #[test]
    fn strip_cfg_test_modules_ignores_mod_decl_without_body() {
        let src = "#[cfg(test)]\nmod tests;\nfn prod() {}";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(out.contains("mod tests;"));
        assert!(out.contains("fn prod"));
    }

    #[test]
    fn strip_cfg_test_modules_handles_pub_mod() {
        let src = "\
#[cfg(test)]
pub mod tests {
    fn unbounded_thing() {}
}
";
        let out = Analyzer::strip_cfg_test_modules_rs(src);
        assert!(!out.contains("unbounded_thing"), "pub mod body stripped");
    }

    #[test]
    fn strip_not_test_groups_removes_not_test() {
        assert_eq!(strip_not_test_groups("not(test)").trim(), "");
        assert_eq!(
            strip_not_test_groups("all(not(test), feature = \"x\")"),
            "all( , feature = \"x\")"
        );
    }

    #[test]
    fn strip_not_test_groups_preserves_other_not() {
        let out = strip_not_test_groups("all(test, not(debug_assertions))");
        assert!(out.contains("not(debug_assertions)"));
        assert!(out.contains("test"));
    }

    // ---------------------------------------------------------------
    // End-to-end: inline #[cfg(test)] mod is test context for *every*
    // substring-based check in analyze_rust, not just unbounded-alloc.
    // ---------------------------------------------------------------

    fn analyze_rust_file(path: &str, content: &str) -> Vec<WeakPoint> {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join(path);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&file_path, content).unwrap();
        let analyzer = Analyzer::new(tmp.path()).unwrap();
        let report = analyzer.analyze().unwrap();
        report.weak_points
    }

    #[test]
    fn analyze_rust_ignores_unsafe_inside_cfg_test_mod() {
        // Production code: zero unsafe blocks. Test code: one unsafe
        // block. The file as a whole should NOT be flagged for
        // UnsafeCode because the unsafe block is test-context.
        let src = "\
pub fn safe_prod() -> i64 { 1 + 2 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exercises_raw_pointer() {
        let x: u64 = 42;
        let ptr = &x as *const u64;
        unsafe {
            assert_eq!(*ptr, 42);
        }
    }
}
";
        let findings = analyze_rust_file("src/lib.rs", src);
        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnsafeCode)
            .collect();
        assert!(
            unsafe_findings.is_empty(),
            "unsafe inside #[cfg(test)] mod must not count: {:?}",
            unsafe_findings
        );
    }

    #[test]
    fn analyze_rust_ignores_unbounded_keyword_in_cfg_test_mod() {
        let src = "\
pub fn prod() -> i64 { 42 }

#[cfg(test)]
mod tests {
    #[test]
    fn choreography_unbounded_loop() {
        assert_eq!(1, 1);
    }
}
";
        let findings = analyze_rust_file("src/lib.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            ub_findings.is_empty(),
            "`unbounded` in test-fn identifier must not count: {:?}",
            ub_findings
        );
    }

    #[test]
    fn analyze_rust_take_disarms_read_to_string() {
        // `.take(N).read_to_string(...)` is a bounded read — must not
        // trigger UnboundedAllocation even without the word `limit`.
        let src = "\
use std::io::Read;

const CAP: u64 = 64 * 1024 * 1024;

pub fn load(path: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::fs::File::open(path)?.take(CAP).read_to_string(&mut buf)?;
    Ok(buf)
}
";
        let findings = analyze_rust_file("src/read.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            ub_findings.is_empty(),
            "`.take(N).read_to_string(...)` is bounded and must not fire: {:?}",
            ub_findings
        );
    }

    #[test]
    fn analyze_rust_read_to_string_without_bound_still_fires() {
        // Sanity: the rule still catches the genuine pattern.
        let src = "\
pub fn load(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}
";
        let findings = analyze_rust_file("src/read.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            !ub_findings.is_empty(),
            "unbounded read_to_string in production must still fire"
        );
    }

    // ────────────────────────────────────────────────────────────────
    // Word-boundary detector regression tests (Task #25 — zero-FN gate)
    //
    // Lock in that the substring -> word-boundary refactor does not
    // reintroduce self-reference FPs or drop real signal.
    // ────────────────────────────────────────────────────────────────

    #[test]
    fn analyze_rust_unbounded_as_identifier_substring_does_not_fire() {
        // Self-reference FP regression: the detector's own variable
        // names (and tokio's `unbounded_channel`) previously tripped
        // the substring check. Word-boundary regex must not match
        // these because the trailing `_` is a word char.
        let src = "\
use tokio::sync::mpsc;

pub fn make_channel() -> (mpsc::UnboundedSender<u8>, mpsc::UnboundedReceiver<u8>) {
    mpsc::unbounded_channel()
}

pub fn analyze(body: &str) -> bool {
    let has_unbounded_allocations = body.contains(\"x\");
    let unbounded_vec_patterns = body.len();
    let unbounded_string_patterns = unbounded_vec_patterns * 2;
    has_unbounded_allocations || unbounded_string_patterns > 0
}
";
        let findings = analyze_rust_file("src/lib.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            ub_findings.is_empty(),
            "identifiers containing `unbounded` as substring must not fire: {:?}",
            ub_findings
        );
    }

    #[test]
    fn analyze_rust_unbounded_as_bare_identifier_still_fires() {
        // Sanity: when `unbounded` is actually a bare word/identifier
        // (not inside a longer name), we still flag it.
        let src = "\
pub fn unbounded() -> Vec<u8> {
    Vec::new()
}
";
        let findings = analyze_rust_file("src/lib.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            !ub_findings.is_empty(),
            "bare `unbounded` identifier should still fire the alarm"
        );
    }

    #[test]
    fn analyze_rust_unlimited_does_not_disarm_limit_check() {
        // `unlimited` must NOT disarm read_to_string bound check — the
        // word-prefix regex for `limit` should only match at word
        // boundaries. Previously the substring `.contains("limit")`
        // disarmed via the tail of `unlimited`.
        let src = "\
pub fn slurp_unlimited(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}
";
        let findings = analyze_rust_file("src/read.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            !ub_findings.is_empty(),
            "`unlimited` in an identifier must not disarm the read check — \
             unbounded read_to_string is still unbounded: {:?}",
            ub_findings
        );
    }

    #[test]
    fn analyze_rust_uppercase_limit_const_disarms_read_check() {
        // A `const READ_LIMIT: u64` should disarm the read_to_string
        // check via the case-insensitive \blimit regex.
        let src = "\
use std::io::Read;

const READ_LIMIT: u64 = 64 * 1024;

pub fn load(path: &str) -> std::io::Result<String> {
    let mut buf = String::new();
    std::fs::File::open(path)?.take(READ_LIMIT).read_to_string(&mut buf)?;
    Ok(buf)
}
";
        let findings = analyze_rust_file("src/read.rs", src);
        let ub_findings: Vec<_> = findings
            .iter()
            .filter(|wp| wp.category == WeakPointCategory::UnboundedAllocation)
            .collect();
        assert!(
            ub_findings.is_empty(),
            "`.take(READ_LIMIT)` plus `READ_LIMIT` constant must disarm: {:?}",
            ub_findings
        );
    }
}
