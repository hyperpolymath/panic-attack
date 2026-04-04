// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core type definitions for panic-attack
//!
//! Supports 40+ programming languages across systems, functional,
//! BEAM, ML, proof assistants, logic programming, config, scripting,
//! and custom DSL families.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::path::PathBuf;
use std::time::Duration;

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    // === Original languages ===
    Rust,
    C,
    Cpp,
    Go,
    Java,
    Python,
    JavaScript,
    Ruby,

    // === BEAM family ===
    Elixir,
    Erlang,
    Gleam,

    // === ML family ===
    ReScript,
    OCaml,
    StandardML,

    // === Lisp family ===
    Scheme,
    Racket,

    // === Functional ===
    Haskell,
    PureScript,

    // === Proof assistants ===
    Idris,
    Lean,
    Agda,

    // === Logic programming ===
    Prolog,
    Logtalk,
    Datalog,

    // === Systems languages ===
    Zig,
    Ada,
    Odin,
    Nim,
    Pony,
    DLang,

    // === Config languages ===
    Nickel,
    Nix,

    // === Scripting / data ===
    Shell,
    Julia,
    Lua,

    // === Nextgen custom DSLs ===
    WokeLang,
    Eclexia,
    MyLang,
    JuliaTheViper,
    Oblibeny,
    Anvomidav,
    AffineScript,
    Ephapax,
    BetLang,
    ErrorLang,
    VQL,
    FBQL,

    Unknown,
}

impl Language {
    pub fn detect(path: &str) -> Self {
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        match ext {
            // Original languages
            "rs" => Language::Rust,
            "c" | "h" => Language::C,
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Language::Cpp,
            "go" => Language::Go,
            "java" => Language::Java,
            "py" | "pyw" => Language::Python,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" | "jsx" => Language::JavaScript,
            "rb" => Language::Ruby,

            // BEAM family
            "ex" | "exs" => Language::Elixir,
            "erl" | "hrl" => Language::Erlang,
            "gleam" => Language::Gleam,

            // ML family
            "res" | "resi" => Language::ReScript,
            "ml" | "mli" => Language::OCaml,
            "sml" | "sig" | "fun" => Language::StandardML,

            // Lisp family
            "scm" | "ss" | "sld" => Language::Scheme,
            "rkt" | "scrbl" => Language::Racket,

            // Functional
            "hs" | "lhs" => Language::Haskell,
            "purs" => Language::PureScript,

            // Proof assistants
            "idr" | "ipkg" => Language::Idris,
            "lean" => Language::Lean,
            "agda" | "lagda" => Language::Agda,

            // Logic programming
            "pl" | "pro" | "P" => Language::Prolog,
            "lgt" | "logtalk" => Language::Logtalk,
            "dl" => Language::Datalog,

            // Systems languages
            "zig" => Language::Zig,
            "adb" | "ads" | "gpr" => Language::Ada,
            "odin" => Language::Odin,
            "nim" | "nims" | "nimble" => Language::Nim,
            "pony" => Language::Pony,
            "d" | "di" => Language::DLang,

            // Config languages
            "ncl" => Language::Nickel,
            "nix" => Language::Nix,

            // Scripting / data
            "sh" | "bash" | "zsh" | "fish" => Language::Shell,
            "jl" => Language::Julia,
            "lua" | "luau" => Language::Lua,

            // Nextgen custom DSLs
            "woke" => Language::WokeLang,
            "ecl" => Language::Eclexia,
            "my" | "solo" | "duet" | "ensemble" => Language::MyLang,
            "jtv" => Language::JuliaTheViper,
            "obli" => Language::Oblibeny,
            "anvom" => Language::Anvomidav,
            "aff" => Language::AffineScript,
            "ephapax" | "eph" => Language::Ephapax,
            "bet" => Language::BetLang,
            "err" => Language::ErrorLang,
            "vql" => Language::VQL,
            "fbql" => Language::FBQL,

            _ => Language::Unknown,
        }
    }

    /// Language family for grouping related languages in analysis
    pub fn family(&self) -> &'static str {
        match self {
            Language::Elixir | Language::Erlang | Language::Gleam => "beam",
            Language::ReScript | Language::OCaml | Language::StandardML => "ml",
            Language::Scheme | Language::Racket => "lisp",
            Language::Haskell | Language::PureScript => "functional",
            Language::Idris | Language::Lean | Language::Agda => "proof",
            Language::Prolog | Language::Logtalk | Language::Datalog => "logic",
            Language::Zig
            | Language::Ada
            | Language::Odin
            | Language::Nim
            | Language::Pony
            | Language::DLang => "systems",
            Language::Nickel | Language::Nix => "config",
            Language::Shell => "shell",
            Language::Julia => "julia",
            Language::Lua => "lua",
            Language::Rust => "rust",
            Language::C | Language::Cpp => "c-family",
            Language::Go => "go",
            Language::Java => "java",
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::Ruby => "ruby",
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
            | Language::FBQL => "nextgen-dsl",
            Language::Unknown => "unknown",
        }
    }
}

/// Application frameworks detected in the codebase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Framework {
    WebServer,
    Database,
    MessageQueue,
    Cache,
    FileSystem,
    Networking,
    Concurrent,
    // New frameworks for expanded language support
    Phoenix,
    Ecto,
    OTP,
    Cowboy,
    Unknown,
}

/// Dependency edge between two files/components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub relation: String,
    pub weight: f64,
}

/// Graph describing upstream/downstream relationships
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DependencyGraph {
    pub edges: Vec<DependencyEdge>,
}

/// Attack axes for stress testing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackAxis {
    Cpu,
    Memory,
    Disk,
    Network,
    Concurrency,
    Time,
}

impl AttackAxis {
    pub fn all() -> Vec<Self> {
        vec![
            AttackAxis::Cpu,
            AttackAxis::Memory,
            AttackAxis::Disk,
            AttackAxis::Network,
            AttackAxis::Concurrency,
            AttackAxis::Time,
        ]
    }
}

/// Known weak points in program behavior
///
/// The `file` and `line` fields are derived from `location` for compatibility
/// with GitHub Actions annotation format and gitbot-fleet fix scripts.
/// Consumers should prefer `file`/`line` over parsing `location` directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeakPoint {
    pub category: WeakPointCategory,
    pub location: Option<String>,
    /// Structured file path extracted from location (e.g. "src/main.rs")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Line number extracted from location
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub severity: Severity,
    pub description: String,
    pub recommended_attack: Vec<AttackAxis>,
}

impl WeakPoint {
    /// Parse file and line from a "path:line" location string
    pub fn with_parsed_location(mut self) -> Self {
        if let Some(ref loc) = self.location {
            if let Some((path, line_str)) = loc.rsplit_once(':') {
                if let Ok(line_num) = line_str.parse::<u32>() {
                    self.file = Some(path.to_string());
                    self.line = Some(line_num);
                } else {
                    self.file = Some(loc.clone());
                }
            } else {
                self.file = Some(loc.clone());
            }
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WeakPointCategory {
    // Original categories
    UncheckedAllocation,
    UnboundedLoop,
    BlockingIO,
    UnsafeCode,
    PanicPath,
    RaceCondition,
    DeadlockPotential,
    ResourceLeak,
    // New categories from expanded analysis
    CommandInjection,
    UnsafeDeserialization,
    DynamicCodeExecution,
    UnsafeFFI,
    AtomExhaustion,
    InsecureProtocol,
    ExcessivePermissions,
    PathTraversal,
    HardcodedSecret,
    UncheckedError,
    InfiniteRecursion,
    UnsafeTypeCoercion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Bug signatures detected via logic programming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugSignature {
    pub signature_type: SignatureType,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    UseAfterFree,
    DoubleFree,
    MemoryLeak,
    Deadlock,
    DataRace,
    BufferOverflow,
    IntegerOverflow,
    NullPointerDeref,
    UnhandledError,
}

/// Per-file statistics from Assail analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStatistics {
    pub file_path: String,
    pub lines: usize,
    pub unsafe_blocks: usize,
    pub panic_sites: usize,
    pub unwrap_calls: usize,
    pub allocation_sites: usize,
    pub io_operations: usize,
    pub threading_constructs: usize,
}

/// Assail analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssailReport {
    pub program_path: PathBuf,
    pub language: Language,
    pub frameworks: Vec<Framework>,
    pub weak_points: Vec<WeakPoint>,
    pub statistics: ProgramStatistics,
    pub file_statistics: Vec<FileStatistics>,
    pub recommended_attacks: Vec<AttackAxis>,
    #[serde(default)]
    pub dependency_graph: DependencyGraph,
    #[serde(default)]
    pub taint_matrix: TaintMatrix,
    /// Migration-specific metrics (populated when target is ReScript)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration_metrics: Option<MigrationMetrics>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProgramStatistics {
    pub total_lines: usize,
    pub unsafe_blocks: usize,
    pub panic_sites: usize,
    pub unwrap_calls: usize,
    pub allocation_sites: usize,
    pub io_operations: usize,
    pub threading_constructs: usize,
}

/// Attack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub axes: Vec<AttackAxis>,
    pub duration: Duration,
    pub intensity: IntensityLevel,
    pub target_programs: Vec<PathBuf>,
    pub data_corpus: Option<PathBuf>,
    pub parallel_attacks: bool,
    #[serde(default)]
    pub common_args: Vec<String>,
    #[serde(default)]
    pub axis_args: HashMap<AttackAxis, Vec<String>>,
    #[serde(default)]
    pub probe_mode: ProbeMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntensityLevel {
    Light,
    Medium,
    Heavy,
    Extreme,
}

impl IntensityLevel {
    pub fn multiplier(&self) -> f64 {
        match self {
            IntensityLevel::Light => 1.0,
            IntensityLevel::Medium => 5.0,
            IntensityLevel::Heavy => 10.0,
            IntensityLevel::Extreme => 50.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    Auto,
    Always,
    Never,
}

impl Default for ProbeMode {
    fn default() -> Self {
        ProbeMode::Auto
    }
}

/// Attack execution results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackResult {
    pub program: PathBuf,
    pub axis: AttackAxis,
    pub success: bool,
    #[serde(default)]
    pub skipped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    pub exit_code: Option<i32>,
    pub duration: Duration,
    pub peak_memory: u64,
    pub crashes: Vec<CrashReport>,
    pub signatures_detected: Vec<BugSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub timestamp: String,
    pub signal: Option<String>,
    pub backtrace: Option<String>,
    pub stderr: String,
    pub stdout: String,
}

/// Complete assault report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssaultReport {
    pub assail_report: AssailReport,
    pub attack_results: Vec<AttackResult>,
    pub total_crashes: usize,
    pub total_signatures: usize,
    pub overall_assessment: OverallAssessment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeline: Option<TimelineReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallAssessment {
    pub robustness_score: f64,
    pub critical_issues: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Timeline metadata for ambush runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineReport {
    pub duration: Duration,
    pub events: Vec<TimelineEventReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEventReport {
    pub id: String,
    pub axis: AttackAxis,
    pub start_offset: Duration,
    pub duration: Duration,
    pub intensity: IntensityLevel,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_memory: Option<u64>,
    #[serde(default)]
    pub ran: bool,
}

/// Matrix rows representing taint source/sink interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintMatrix {
    pub rows: Vec<TaintMatrixRow>,
}

impl Default for TaintMatrix {
    fn default() -> Self {
        Self { rows: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintMatrixRow {
    pub source_category: WeakPointCategory,
    pub sink_axis: AttackAxis,
    pub severity_value: f64,
    pub files: Vec<String>,
    pub frameworks: Vec<Framework>,
    pub relation: String,
}

/// Pattern library entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub name: String,
    pub description: String,
    pub applicable_axes: Vec<AttackAxis>,
    pub applicable_languages: Vec<Language>,
    pub applicable_frameworks: Vec<Framework>,
    pub command_template: String,
}

// ============================================================
// ReScript Migration Analysis types
// ============================================================

/// ReScript version bracket determined by heuristic analysis of config
/// format, API usage patterns, and dependency versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReScriptVersionBracket {
    /// Pre-v11 BuckleScript era (bsconfig.json, bs-dependencies, Js.* APIs)
    BuckleScript,
    /// v11.x (bsconfig.json, early uncurried support)
    V11,
    /// v12.0-alpha / v12.0-beta (rescript.json transition)
    V12Alpha,
    /// v12.0.x - v12.1.x (stable rescript.json, mixed API usage)
    V12Stable,
    /// v12.2.0+ (rescript.json, @rescript/core primary)
    V12Current,
    /// v13.x pre-release (v13 features detected)
    V13PreRelease,
}

impl std::fmt::Display for ReScriptVersionBracket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReScriptVersionBracket::BuckleScript => write!(f, "BuckleScript (pre-v11)"),
            ReScriptVersionBracket::V11 => write!(f, "v11.x"),
            ReScriptVersionBracket::V12Alpha => write!(f, "v12.0-alpha"),
            ReScriptVersionBracket::V12Stable => write!(f, "v12.0.x-v12.1.x"),
            ReScriptVersionBracket::V12Current => write!(f, "v12.2.0+"),
            ReScriptVersionBracket::V13PreRelease => write!(f, "v13.x (pre-release)"),
        }
    }
}

/// ReScript project configuration format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReScriptConfigFormat {
    /// Legacy bsconfig.json only
    BsConfig,
    /// Modern rescript.json only
    RescriptJson,
    /// Both files present (transitional state)
    Both,
    /// No config found (library or incomplete project)
    None,
}

/// Category of deprecated ReScript API usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeprecatedCategory {
    /// Js.Array2, Js.String2, Js.Dict, etc.
    JsApi,
    /// Belt.Array, Belt.List, Belt.Map, etc.
    BeltApi,
    /// bsconfig.json fields (bs-dependencies, etc.)
    BsConfig,
    /// Curried-by-default function signatures
    CurriedDefault,
    /// JSX v3 or earlier syntax
    OldJsx,
    /// Js.Json.classify instead of JSON.Classify.classify
    OldJson,
    /// Js.Dict instead of Dict module
    OldDict,
    /// Js.Nullable instead of Nullable module
    OldNullable,
    /// Js.Console instead of Console module
    OldConsole,
    /// Js.Promise instead of Promise module
    OldPromise,
    /// Js.Float/Js.Int/Js.Math instead of Float/Int/Math
    OldNumeric,
    /// Js.Re instead of RegExp module
    OldRegExp,
    /// Js.Date (no modern replacement yet)
    OldDate,
    /// ReactDOMStyle.make or ReactDOM.Style.make (use inline records)
    OldReactStyle,
}

/// A single deprecated pattern occurrence with location info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedPattern {
    /// The deprecated API pattern string (e.g. "Js.Array2")
    pub pattern: String,
    /// The modern replacement (e.g. "Array")
    pub replacement: String,
    /// File where the pattern was found
    pub file_path: String,
    /// Line number (0 if not available)
    pub line_number: usize,
    /// Category for grouping
    pub category: DeprecatedCategory,
    /// Number of occurrences in this file
    pub count: usize,
}

/// Migration-specific metrics for a ReScript project
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationMetrics {
    /// Count of deprecated Js.* and Belt.* API calls
    pub deprecated_api_count: usize,
    /// Count of modern @rescript/core API calls
    pub modern_api_count: usize,
    /// Ratio of modern to total API calls (0.0 = all deprecated, 1.0 = all modern)
    pub api_migration_ratio: f64,
    /// Overall migration health score (0.0 = unmigrated, 1.0 = fully migrated)
    pub health_score: f64,
    /// Detected configuration format
    pub config_format: ReScriptConfigFormat,
    /// Detected version bracket
    pub version_bracket: ReScriptVersionBracket,
    /// Build time in milliseconds (if measured)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time_ms: Option<u64>,
    /// Bundle size in bytes (if measured)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_size_bytes: Option<u64>,
    /// Number of .res/.resi files
    pub file_count: usize,
    /// Total lines of ReScript code
    pub rescript_lines: usize,
    /// Individual deprecated patterns found
    pub deprecated_patterns: Vec<DeprecatedPattern>,
    /// JSX version detected (3 or 4, None if not detected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsx_version: Option<u8>,
    /// Whether uncurried mode is enabled
    pub uncurried: bool,
    /// Module format (esmodule, commonjs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_format: Option<String>,
}

/// Snapshot of migration state at a point in time (for before/after comparison)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSnapshot {
    /// Label for this snapshot (e.g. "before", "after", "v12-trial")
    pub label: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Target path that was scanned
    pub target_path: String,
    /// The assail report from the scan
    pub assail_report: AssailReport,
    /// Migration-specific metrics
    pub migration_metrics: MigrationMetrics,
}

/// Diff between two migration snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationDiff {
    /// Before snapshot label
    pub before_label: String,
    /// After snapshot label
    pub after_label: String,
    /// Health score change (positive = improvement)
    pub health_delta: f64,
    /// Deprecated API count change (negative = improvement)
    pub deprecated_delta: i64,
    /// Modern API count change (positive = improvement)
    pub modern_delta: i64,
    /// Build time change in ms (negative = improvement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time_delta_ms: Option<i64>,
    /// Bundle size change in bytes (negative = improvement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_size_delta_bytes: Option<i64>,
    /// Deprecated patterns that were removed
    pub patterns_removed: Vec<DeprecatedPattern>,
    /// Deprecated patterns that were added (regressions)
    pub patterns_added: Vec<DeprecatedPattern>,
    /// Version bracket change
    pub version_before: ReScriptVersionBracket,
    pub version_after: ReScriptVersionBracket,
    /// Config format change
    pub config_before: ReScriptConfigFormat,
    pub config_after: ReScriptConfigFormat,
}

/// Datalog fact for signature detection.
///
/// All variants are part of the fact vocabulary even if not yet generated
/// by the current set of analyzers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum Fact {
    Alloc {
        var: String,
        location: usize,
    },
    Free {
        var: String,
        location: usize,
    },
    Use {
        var: String,
        location: usize,
    },
    Lock {
        mutex: String,
        location: usize,
    },
    Unlock {
        mutex: String,
        location: usize,
    },
    ThreadSpawn {
        id: String,
        location: usize,
    },
    ThreadJoin {
        id: String,
        location: usize,
    },
    Write {
        var: String,
        location: usize,
    },
    Read {
        var: String,
        location: usize,
    },
    Ordering {
        before: usize,
        after: usize,
    },
}

/// Datalog rule for pattern detection.
///
/// `head` is the consequent of the rule — used by the forward-chaining
/// engine even though the signature matcher currently accesses rules
/// only through `body`.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Rule {
    pub name: String,
    pub head: Predicate,
    pub body: Vec<Predicate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    UseAfterFree {
        var: String,
        use_loc: usize,
        free_loc: usize,
    },
    DoubleFree {
        var: String,
        loc1: usize,
        loc2: usize,
    },
    Deadlock {
        m1: String,
        m2: String,
    },
    DataRace {
        var: String,
        loc1: usize,
        loc2: usize,
    },
    Fact(Fact),
}
