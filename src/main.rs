// SPDX-License-Identifier: MPL-2.0

//! panic-attack: Universal stress testing and logic-based bug signature detection
//!
//! A tool for stress testing programs across multiple attack axes (CPU, memory, disk, network,
//! concurrency) and detecting bug signatures using logic programming techniques inspired by
//! Mozart/Oz and Datalog.

mod a2ml;
mod abduct;
mod adjudicate;
mod aggregate;
mod ambush;
mod amuck;
mod assail;
mod assay;
mod assemblyline;
mod attack;
mod attestation;
mod axial;
#[cfg(feature = "http")]
mod bridge;
mod campaign;
mod comment_marker;
mod diagnostics;
mod ffi_kind;
mod groove;
mod i18n;
mod jit_context;
mod kanren;
mod kin;
mod mass_panic;
mod notify;
mod panll;
mod query;
mod report;
mod signatures;
mod storage;
mod sweep_tracker;
mod test_context;
mod types;

extern crate walkdir;

use crate::a2ml::{Manifest, ReportBundleKind};
use crate::abduct::{
    AbductConfig, DependencyScope, ExecutionCommand as AbductExecutionCommand, TimeMode,
};
use crate::adjudicate::AdjudicateConfig;
use crate::aggregate::{AggregateConfig, ProofInput};
use crate::amuck::{AmuckConfig, AmuckPreset, ExecutionCommand as AmuckExecutionCommand};
use crate::assay::{AssayConfig, AssimilateConfig};
use crate::attack::AttackProfile;
use crate::axial::{AxialConfig, ExecutionCommand as AxialExecutionCommand};
use crate::i18n::Lang;
use crate::report::{format_diff, load_report, ReportOutputFormat, ReportTui, ReportView};
use crate::storage::{latest_reports, persist_report};
use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use clap_complete_nushell::Nushell;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Upper bound on report JSON reads in the CLI. Reports are aggregated
/// scan outputs; 64 MiB is two orders of magnitude beyond any realistic
/// size and bounds tampered or malformed input before parsing.
const REPORT_FILE_READ_LIMIT: u64 = 64 * 1024 * 1024;

/// Read a file into a String, capped at `limit` bytes. Silent-truncates
/// if the file is larger; returns I/O errors as-is via `?`.
fn read_report_bounded(path: &Path) -> Result<String> {
    let mut buf = String::new();
    File::open(path)
        .with_context(|| format!("opening {}", path.display()))?
        .take(REPORT_FILE_READ_LIMIT)
        .read_to_string(&mut buf)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(buf)
}
use types::*;

macro_rules! qprintln {
    ($quiet:expr, $($arg:tt)+) => {
        if !$quiet {
            println!($($arg)+);
        }
    };
}

#[derive(Parser)]
#[command(name = "panic-attack")]
#[command(version)]
#[command(about = "Universal stress testing and logic-based bug signature detection")]
#[command(long_about = None)]
#[command(disable_help_subcommand = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, value_enum, default_value_t = ReportView::Accordion, global = true)]
    report_view: ReportView,

    #[arg(long, default_value_t = false, global = true)]
    expand_sections: bool,

    #[arg(long, value_enum, default_value_t = ReportOutputFormat::Json, global = true)]
    output_format: ReportOutputFormat,

    #[arg(long, default_value_t = false, global = true)]
    pivot: bool,

    #[arg(long, value_name = "DIR", global = true)]
    store: Option<PathBuf>,

    #[arg(long, default_value_t = false, global = true)]
    quiet: bool,

    #[arg(long, default_value_t = false, global = true)]
    parallel: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run assail static analysis on a target program
    Assail {
        /// Target program or directory to analyze
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Enable attestation chain (writes .attestation.json sidecar)
        #[arg(long, default_value_t = false)]
        attest: bool,

        /// Path to Ed25519 private key (32-byte seed) for signing the attestation.
        /// Requires the `signing` feature.
        #[arg(long, value_name = "PATH")]
        signing_key: Option<PathBuf>,

        /// Browser extension mode: ignore DevTools API eval() usage
        #[arg(long, default_value_t = false)]
        browser_extension: bool,

        /// Headless mode: emit JSON to stdout, suppress interactive prompts (CI-safe)
        #[arg(long, default_value_t = false)]
        headless: bool,
    },

    /// Execute a single attack on a target program
    Attack {
        /// Target program to attack
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,

        /// Attack profile file (json/yaml)
        #[arg(long, value_name = "PROFILE")]
        profile: Option<PathBuf>,

        /// Extra argument(s) passed to the target program
        #[arg(long = "arg", value_name = "ARG", action = clap::ArgAction::Append)]
        args: Vec<String>,

        /// Axis-specific argument, format: AXIS=ARG
        #[arg(long = "axis-arg", value_name = "AXIS=ARG", action = clap::ArgAction::Append)]
        axis_args: Vec<String>,

        /// Probe mode for detecting unsupported flags
        #[arg(long, value_enum)]
        probe: Option<ProbeModeArg>,

        /// Attack axis to use
        #[arg(short, long, value_enum)]
        axis: AttackAxisArg,

        /// Attack intensity
        #[arg(short, long, default_value = "medium")]
        intensity: IntensityArg,

        /// Attack duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },

    /// Full assault: combines static analysis (`assail`) with multi-axis dynamic attacks (`attack`).
    Assault {
        /// Target program to assault
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,

        /// Source directory or file for assail analysis (defaults to PROGRAM)
        #[arg(long, value_name = "PATH")]
        source: Option<PathBuf>,

        /// Attack profile file (json/yaml)
        #[arg(long, value_name = "PROFILE")]
        profile: Option<PathBuf>,

        /// Extra argument(s) passed to the target program
        #[arg(long = "arg", value_name = "ARG", action = clap::ArgAction::Append)]
        args: Vec<String>,

        /// Axis-specific argument, format: AXIS=ARG
        #[arg(long = "axis-arg", value_name = "AXIS=ARG", action = clap::ArgAction::Append)]
        axis_args: Vec<String>,

        /// Probe mode for detecting unsupported flags
        #[arg(long, value_enum)]
        probe: Option<ProbeModeArg>,

        /// Attack axes (default: all)
        #[arg(short, long, value_delimiter = ',')]
        axes: Option<Vec<AttackAxisArg>>,

        /// Attack intensity
        #[arg(short, long, default_value = "medium")]
        intensity: IntensityArg,

        /// Attack duration per axis in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Ambush: run a target program while applying ambient stressors
    Ambush {
        /// Target program to ambush
        #[arg(value_name = "PROGRAM")]
        program: PathBuf,

        /// Source directory or file for assail analysis (defaults to PROGRAM)
        #[arg(long, value_name = "PATH")]
        source: Option<PathBuf>,

        /// Timeline file (JSON/YAML) for DAW-style scheduling
        #[arg(long, value_name = "TIMELINE")]
        timeline: Option<PathBuf>,

        /// Attack profile file (json/yaml) for target args
        #[arg(long, value_name = "PROFILE")]
        profile: Option<PathBuf>,

        /// Extra argument(s) passed to the target program
        #[arg(long = "arg", value_name = "ARG", action = clap::ArgAction::Append)]
        args: Vec<String>,

        /// Axis-specific argument, format: AXIS=ARG
        #[arg(long = "axis-arg", value_name = "AXIS=ARG", action = clap::ArgAction::Append)]
        axis_args: Vec<String>,

        /// Stress axes to apply (default: all)
        #[arg(short, long, value_delimiter = ',')]
        axes: Option<Vec<AttackAxisArg>>,

        /// Stress intensity
        #[arg(short, long, default_value = "medium")]
        intensity: IntensityArg,

        /// Ambush duration per axis in seconds
        #[arg(short, long, default_value = "30")]
        duration: u64,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Amuck: mutate a file with dangerous/user-defined combinations and optionally execute checks
    Amuck {
        /// Target file to mutate (never modified in place)
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Mutation preset when no --spec is provided
        #[arg(long, value_enum, default_value = "dangerous")]
        preset: AmuckPresetArg,

        /// Custom mutation combinations file (json/yaml)
        #[arg(long, value_name = "SPEC")]
        spec: Option<PathBuf>,

        /// Maximum combinations to execute
        #[arg(long, default_value_t = 16)]
        max_combinations: usize,

        /// Directory where mutated variants are written
        #[arg(long, value_name = "DIR", default_value = "runtime/amuck")]
        output_dir: PathBuf,

        /// Optional executable run per mutated file
        #[arg(long, value_name = "PROGRAM")]
        exec_program: Option<String>,

        /// Arguments for --exec-program; use {file} for the mutated file path
        #[arg(long = "exec-arg", value_name = "ARG", action = clap::ArgAction::Append)]
        exec_args: Vec<String>,

        /// Optional report output path (JSON)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Abduct: isolate, lock, and time-skew a target file (optionally with dependencies)
    Abduct {
        /// Target file to abduct into an isolated workspace
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Optional source root used to resolve dependency graph paths
        #[arg(long, value_name = "PATH")]
        source_root: Option<PathBuf>,

        /// Dependency scope for selecting related files
        #[arg(long, value_enum, default_value = "direct")]
        scope: AbductScopeArg,

        /// Workspace root where abduct runs are created
        #[arg(long, value_name = "DIR", default_value = "runtime/abduct")]
        output_dir: PathBuf,

        /// Disable readonly lock-down of copied files
        #[arg(long, default_value_t = false)]
        no_lock: bool,

        /// Shift copied file mtimes by this many days (negative or positive)
        #[arg(long, default_value_t = 0)]
        mtime_offset_days: i64,

        /// Time mode metadata exported to executed process
        #[arg(long, value_enum, default_value = "normal")]
        time_mode: AbductTimeModeArg,

        /// Virtual time scale factor when --time-mode slow
        #[arg(long, default_value_t = 0.1)]
        time_scale: f64,

        /// Optional virtual timestamp (RFC3339) exported as ABDUCT_VIRTUAL_NOW
        #[arg(long, value_name = "TIMESTAMP")]
        virtual_now: Option<String>,

        /// Optional executable to run after lock/time setup
        #[arg(long, value_name = "PROGRAM")]
        exec_program: Option<String>,

        /// Arguments for --exec-program; placeholders: {file}, {workspace}
        #[arg(long = "exec-arg", value_name = "ARG", action = clap::ArgAction::Append)]
        exec_args: Vec<String>,

        /// Timeout (seconds) for the optional execution command
        #[arg(long, default_value_t = 120)]
        exec_timeout: u64,

        /// Optional report output path (JSON)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Adjudicate: aggregate reports into a campaign-wide expert-system verdict
    Adjudicate {
        /// Input report files (assault/amuck/abduct JSON, assault YAML)
        #[arg(value_name = "REPORTS", required = true)]
        reports: Vec<PathBuf>,

        /// Optional report output path (JSON)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Axial: observe target reactions across attack axes from tool outputs and report artifacts
    Axial {
        /// Target file/program under observation
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Optional executable to run for reaction observation
        #[arg(long, value_name = "PROGRAM")]
        exec_program: Option<String>,

        /// Arguments for --exec-program; placeholder: {target}
        #[arg(long = "exec-arg", value_name = "ARG", action = clap::ArgAction::Append)]
        exec_args: Vec<String>,

        /// Number of repeated observation runs for --exec-program
        #[arg(long, default_value_t = 1)]
        repeat: usize,

        /// Timeout (seconds) per observation run
        #[arg(long, default_value_t = 60)]
        timeout: u64,

        /// Existing reports to observe (can be provided multiple times)
        #[arg(long = "report", value_name = "PATH", action = clap::ArgAction::Append)]
        reports: Vec<PathBuf>,

        /// Include the first N lines from observed output/content
        #[arg(long, default_value_t = 20)]
        head: usize,

        /// Include the last N lines from observed output/content
        #[arg(long, default_value_t = 20)]
        tail: usize,

        /// Exact pattern search (repeatable)
        #[arg(long = "grep", value_name = "PATTERN", action = clap::ArgAction::Append)]
        grep: Vec<String>,

        /// Approximate/fuzzy pattern search (repeatable)
        #[arg(long = "agrep", value_name = "PATTERN", action = clap::ArgAction::Append)]
        agrep: Vec<String>,

        /// Maximum edit distance for --agrep matches
        #[arg(long, default_value_t = 2)]
        agrep_distance: usize,

        /// Output language (ISO 639-1 code: en, es, fr, de, ja)
        #[arg(long, value_enum, default_value = "en")]
        lang: LangArg,

        /// Enable aspell checks on observed text
        #[arg(long, default_value_t = false)]
        aspell: bool,

        /// Aspell dictionary language (default derived from --lang)
        #[arg(long, value_name = "CODE")]
        aspell_lang: Option<String>,

        /// Optional markdown output path
        #[arg(long, value_name = "OUT")]
        markdown_output: Option<PathBuf>,

        /// Optional pandoc target format (e.g. html, docx, gfm, latex)
        #[arg(long, value_name = "FMT")]
        pandoc_to: Option<String>,

        /// Optional pandoc output path (required for custom destination)
        #[arg(long, value_name = "OUT")]
        pandoc_output: Option<PathBuf>,

        /// Optional report output path (JSON)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Assay: survey a target for proven-library substitution candidates.
    ///
    /// Scans the target for code that has a formally proven drop-in
    /// equivalent in a `proven` / `proven-servers` library and reports each
    /// swap candidate with the proof artifact that backs it. Operationalises
    /// the "Proven cross-fit" section of PROOF-PROGRAMME.md.
    Assay {
        /// Target directory to survey (default: current directory)
        #[arg(value_name = "TARGET", default_value = ".")]
        target: PathBuf,

        /// Local checkout of a proven / proven-servers library to resolve
        /// replacement sources from (repeatable)
        #[arg(long = "proven", value_name = "DIR", action = clap::ArgAction::Append)]
        proven: Vec<PathBuf>,

        /// Output report to file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Assimilate: apply a proven-library substitution found by `assay`.
    ///
    /// Stages the proven module into the tree (backing up the original) and
    /// records provenance — source BLAKE3 hash + proof backing — under
    /// `.assimilated/`. Call sites that still need manual rewiring are
    /// reported, never auto-edited.
    Assimilate {
        /// Target directory (default: current directory)
        #[arg(value_name = "TARGET", default_value = ".")]
        target: PathBuf,

        /// Local proven / proven-servers checkout(s) for replacement sources
        #[arg(long = "proven", value_name = "DIR", action = clap::ArgAction::Append)]
        proven: Vec<PathBuf>,

        /// Candidate id to apply (run `assay` to list ids); omit with --all
        #[arg(long, value_name = "ID")]
        candidate: Option<String>,

        /// Apply every offered candidate
        #[arg(long, default_value_t = false)]
        all: bool,

        /// Explicit replacement source file (overrides catalogue resolution;
        /// only valid with a single --candidate)
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,

        /// Preview only: compute the swap but write nothing
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Output outcome to file (JSON)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Aggregate: fold external prover output into a report (hashed, trust-tagged).
    ///
    /// Hashes each prover artifact (BLAKE3) for non-repudiation, classifies
    /// its verdict (closed / holes / refuted), and reconciles it against an
    /// existing report's findings (backed / corroborated / contradicted).
    /// Verdicts are explicitly conditioned on the named checker's trust.
    Aggregate {
        /// External prover output file(s) to fold in (repeatable)
        #[arg(long = "proof", value_name = "PATH", action = clap::ArgAction::Append, required = true)]
        proofs: Vec<PathBuf>,

        /// Friendly-name override(s): PATH=NAME (repeatable)
        #[arg(long = "label", value_name = "PATH=NAME", action = clap::ArgAction::Append)]
        labels: Vec<String>,

        /// Coverage override(s): PATH=[claim:]kind:value (repeatable)
        #[arg(long = "covers", value_name = "PATH=SPEC", action = clap::ArgAction::Append)]
        covers: Vec<String>,

        /// Base assail/assault report to reconcile against (optional)
        #[arg(long = "report", value_name = "PATH")]
        report: Option<PathBuf>,

        /// Output report to file (JSON; default: reports/aggregate-<ts>.json)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Analyze crash reports for bug signatures
    Analyze {
        /// Crash report file (JSON)
        #[arg(value_name = "REPORT")]
        report: PathBuf,
    },

    /// Render a saved assault report with view controls
    Report {
        /// JSON assault report path
        #[arg(value_name = "REPORT")]
        report: PathBuf,
    },

    /// Interactive review of a saved report
    Tui {
        /// Assault report JSON file
        #[arg(value_name = "REPORT")]
        report: PathBuf,

        /// Headless mode: print sections as plain text without requiring a TTY (CI-safe)
        #[arg(long, default_value_t = false)]
        headless: bool,
    },

    /// GUI review of a saved report.
    ///
    /// `--headless` always works (text panel summaries to stdout). The
    /// windowed renderer requires `--features gui` at build time because
    /// eframe/egui raise MSRV above 1.85.0.
    Gui {
        /// Assault report JSON file
        #[arg(value_name = "REPORT")]
        report: PathBuf,

        /// Headless mode: print panel summaries without requiring a display server (CI-safe)
        #[arg(long, default_value_t = false)]
        headless: bool,
    },

    /// Compare two assault reports (defaults to latest VerisimDB runs)
    Diff {
        /// Base report path
        #[arg(value_name = "BASE")]
        base: Option<PathBuf>,

        /// Compare report path
        #[arg(value_name = "COMPARE")]
        compare: Option<PathBuf>,

        /// VerisimDB directory to scan for latest reports
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data/verisimdb")]
        verisimdb_dir: PathBuf,
    },

    /// Export the AI manifest as Nickel
    Manifest {
        /// Alternate AI manifest file
        #[arg(short, long, value_name = "PATH")]
        path: Option<PathBuf>,

        /// Save Nickel output to file
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Export a report file into the A2ML report-bundle document type
    A2mlExport {
        /// Report kind to encode in the bundle
        #[arg(long, value_enum)]
        kind: A2mlReportKindArg,

        /// Source report file (json/yaml depending on kind)
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Destination A2ML file
        #[arg(short, long, value_name = "OUT")]
        output: PathBuf,
    },

    /// Import an A2ML report-bundle file back into JSON
    A2mlImport {
        /// Source A2ML bundle file
        #[arg(value_name = "INPUT")]
        input: PathBuf,

        /// Destination JSON file
        #[arg(short, long, value_name = "OUT")]
        output: PathBuf,

        /// Optional expected kind check
        #[arg(long, value_enum)]
        kind: Option<A2mlReportKindArg>,
    },

    /// Export an assault report as a PanLL event-chain model
    Panll {
        /// Assault report JSON/YAML file
        #[arg(value_name = "REPORT")]
        report: PathBuf,

        /// Output file for PanLL export (JSON)
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,
    },

    /// Print detailed help text (man-style)
    Help {
        /// Optional subcommand name to display help for
        #[arg(value_name = "COMMAND")]
        command: Option<String>,
    },

    /// Assemblyline: batch-scan a directory of repos (assail each, aggregate results)
    Assemblyline {
        /// Parent directory containing repos to scan
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,

        /// Output report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Only show repos with findings
        #[arg(long)]
        findings_only: bool,

        /// Minimum number of findings to include a repo
        #[arg(long, default_value = "0")]
        min_findings: usize,

        /// Enable incremental scanning (skip repos unchanged since last run)
        #[arg(long)]
        incremental: bool,

        /// Path to fingerprint cache file (default: .panic-attack-cache.json in DIRECTORY)
        #[arg(long, value_name = "FILE")]
        cache: Option<PathBuf>,
    },

    /// Run panic-attack self-diagnostics for Hypatia/gitbot-fleet visibility
    Diagnostics {
        /// Alternate AI manifest file (default: AI.a2ml)
        #[arg(long, value_name = "PATH")]
        manifest: Option<PathBuf>,
    },

    /// Take a ReScript migration snapshot (assail + migration metrics)
    MigrationSnapshot {
        /// Target ReScript project directory
        #[arg(value_name = "TARGET")]
        target: PathBuf,

        /// Label for this snapshot (e.g. "before", "after", "v12-trial")
        #[arg(long, value_name = "LABEL")]
        label: String,

        /// Measure build time (runs `rescript build`)
        #[arg(long, default_value_t = false)]
        build_time: bool,

        /// Measure bundle size (scans output directory)
        #[arg(long, default_value_t = false)]
        bundle_size: bool,

        /// Store snapshot as VeriSimDB hexad
        #[arg(long = "store-hexad", default_value_t = false)]
        store_hexad: bool,

        /// Output snapshot to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Compare two migration snapshots and produce a diff report
    MigrationDiff {
        /// Before snapshot JSON file
        #[arg(value_name = "BEFORE")]
        before: PathBuf,

        /// After snapshot JSON file
        #[arg(value_name = "AFTER")]
        after: PathBuf,

        /// Output diff report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format (markdown or json)
        #[arg(long, default_value = "markdown")]
        format: MigrationDiffFormatArg,
    },

    /// Notify: generate annotated findings summary from an assemblyline report
    Notify {
        /// Assemblyline JSON report file
        #[arg(value_name = "REPORT")]
        report: PathBuf,

        /// Output markdown file
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,

        /// Only include repos with critical findings
        #[arg(long)]
        critical_only: bool,

        /// Minimum findings to include a repo
        #[arg(long, default_value = "1")]
        min_findings: usize,

        /// Create GitHub issues for repos with critical findings (requires gh CLI)
        #[arg(long)]
        create_issues: bool,

        /// GitHub owner for issue creation
        #[arg(long, default_value = "hyperpolymath")]
        github_owner: String,
    },

    /// Image: generate a system health image from an assemblyline scan (fNIRS-style)
    Image {
        /// Parent directory containing repos to scan (runs assemblyline internally)
        #[arg(value_name = "DIRECTORY")]
        directory: PathBuf,

        /// Output file for the system image JSON
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,

        /// Enable incremental scanning
        #[arg(long)]
        incremental: bool,

        /// Fingerprint cache file
        #[arg(long, value_name = "FILE")]
        cache: Option<PathBuf>,

        /// Take a temporal snapshot (writes to VeriSimDB)
        #[arg(long)]
        snapshot: bool,

        /// Label for the temporal snapshot
        #[arg(long, value_name = "LABEL", default_value = "")]
        label: String,

        /// VeriSimDB directory for snapshots
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,

        /// Export PanLL-format system image alongside raw output
        #[arg(long)]
        panll: bool,
    },

    /// Temporal: navigate system health through time (diff, list, replay)
    Temporal {
        #[command(subcommand)]
        action: TemporalAction,
    },

    /// Patch Bridge: CVE triage with reachability analysis
    #[cfg(feature = "http")]
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },

    /// Generate shell completions for the specified shell
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: ShellArg,
    },

    /// Start the groove discovery server for service mesh integration.
    ///
    /// Runs a lightweight HTTP server exposing panic-attacker's static-analysis
    /// capabilities via the Gossamer groove protocol. Other groove-aware systems
    /// (PanLL, Gossamer, Hypatia, etc.) can discover panic-attacker by probing
    /// GET /.well-known/groove on the configured port.
    Groove {
        /// Port to bind the groove server to
        #[arg(short, long, default_value = "7600")]
        port: u16,
    },

    /// Compute the BLAKE3 fingerprint of a directory (for incremental scanning)
    Fingerprint {
        /// Directory to fingerprint (hashes all source files recursively)
        #[arg(value_name = "DIR")]
        dir: PathBuf,
    },

    /// Attestation utilities (verify chain integrity, check signatures)
    Attest {
        #[command(subcommand)]
        action: AttestAction,
    },

    /// Campaign: lifecycle tracking for findings (register-pr, dismiss, status).
    ///
    /// Operates on the per-finding hexad store written by `assemblyline` when
    /// `PANIC_ATTACK_STORE_FINDING_HEXADS=1` is set with verisimdb storage.
    Campaign {
        #[command(subcommand)]
        action: CampaignAction,
    },

    /// Sweep-tracker: render an issue-#32-style estate-sweep Markdown report.
    ///
    /// Joins per-finding hexads (issue #33 S1) with campaign-state hexads
    /// (issue #33 S2) and groups them by repo and/or category. Distinct
    /// from `campaign status`: that is a flat per-finding table; this is
    /// a hierarchical sweep checklist.
    SweepTracker {
        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,

        /// Write the Markdown to a file instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Emit only the "By repo" section.
        #[arg(long, group = "sweep_shape", default_value_t = false)]
        by_repo: bool,

        /// Emit only the "By category" section.
        #[arg(long, group = "sweep_shape", default_value_t = false)]
        by_category: bool,
    },

    /// Query persisted findings + campaign state with a small S-expression
    /// language (issue #33 S3). See `panic-attack query --help` for syntax.
    Query {
        /// Query expression, e.g. `(and (category UnsafeCode) (pr-state nil))`.
        #[arg(value_name = "EXPR")]
        expr: String,

        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = QueryFormatArg::Table)]
        format: QueryFormatArg,
    },

    /// Emit a machine-readable description of the panic-attack CLI contract
    /// (accepted flags per subcommand, report `schema_version`, CLI version)
    /// for external orchestrators.
    ///
    /// This is a generic capability — useful to Chapel mass-panic, Nextflow,
    /// Airflow, Slurm, or any shell script that needs to discover the
    /// panic-attack interface at runtime without coupling to its source.
    /// The output schema is stable across patch releases.
    DescribeContract,

    /// Push a single hexad JSON file (written by the Chapel metalayer
    /// `takeSnapshot` or any other producer) to a running `verisim-panic-api`
    /// instance via HTTP `POST /octads`.
    ///
    /// Reads the JSON hexad from `<HEXAD>`, deserialises it as a
    /// `PanicAttackHexad`, and pushes it. Uses `$VERISIMDB_URL` if set,
    /// otherwise defaults to `http://localhost:8080`.
    ///
    /// On HTTP failure, the file is left in place — re-running the command
    /// retries. With `--fallback-dir`, also writes a filesystem copy under
    /// `<fallback-dir>/hexads/` so an offline orchestrator can replay later.
    ///
    /// Requires the `http` Cargo feature to be enabled at build time.
    /// Closes the v3.0.0 ROADMAP item "VeriSimDB HTTP push from Chapel
    /// metalayer (currently file-only)".
    #[cfg(feature = "http")]
    VerisimPush {
        /// Path to the JSON hexad file produced by the Chapel metalayer
        /// (or any other producer that emits the canonical hexad schema).
        #[arg(value_name = "HEXAD")]
        hexad: PathBuf,

        /// VeriSimDB gateway URL. Defaults to `$VERISIMDB_URL` if set,
        /// otherwise `http://localhost:8080`.
        #[arg(long, value_name = "URL")]
        url: Option<String>,

        /// Filesystem fallback directory. If specified, a copy of the
        /// hexad is also written under `<dir>/hexads/<id>.json` so the
        /// push survives an offline gateway. The local-only run on the
        /// Chapel side already wrote to `verisimdb-data/hexads/`, so this
        /// is typically left unset when the push is invoked from Chapel.
        #[arg(long, value_name = "DIR")]
        fallback_dir: Option<PathBuf>,

        /// Retry on transient HTTP failures (network errors, 5xx). The
        /// underlying `push_hexad_http_with_retry` exponential-backs off
        /// up to three attempts.
        #[arg(long, default_value_t = false)]
        retry: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum QueryFormatArg {
    Table,
    Json,
}

#[derive(Subcommand)]
enum AttestAction {
    /// Verify an attestation sidecar file (.attestation.json)
    Verify {
        /// Path to the .attestation.json file
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

/// Campaign subcommands for finding-lifecycle tracking (issue #33 S2).
#[derive(Subcommand)]
enum CampaignAction {
    /// Register an open PR against a known finding-id.
    RegisterPr {
        /// Finding id (e.g. `finding:demo:src/a.rs:1:UnsafeCode`).
        #[arg(value_name = "FINDING_ID")]
        finding_id: String,
        /// PR URL (e.g. `https://github.com/org/repo/pull/123`).
        #[arg(value_name = "PR_URL")]
        pr_url: String,
        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,
    },

    /// Mark a finding as dismissed (parked, known-good, out-of-scope).
    Dismiss {
        /// Finding id.
        #[arg(value_name = "FINDING_ID")]
        finding_id: String,
        /// Short human-readable reason.
        #[arg(value_name = "REASON")]
        reason: String,
        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,
    },

    /// Render a Markdown tracker of the current campaign state.
    Status {
        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,
        /// Write the Markdown to a file instead of stdout.
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },

    /// Poll GitHub for PR-state transitions on every `pr-filed` finding
    /// and write new campaign hexads when state changes (issue #33 S2b).
    ///
    /// Requires the `http` feature. Reads auth token from `GH_TOKEN` or
    /// `GITHUB_TOKEN` (falls back to unauthenticated, 60 req/hr).
    #[cfg(feature = "http")]
    Poll {
        /// VeriSimDB data directory (default: `verisimdb-data`).
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,
    },
}

/// Patch Bridge subcommands for CVE lifecycle management.
#[cfg(feature = "http")]
#[derive(Subcommand)]
enum BridgeAction {
    /// Run full CVE triage: discover, assess reachability, classify
    Triage {
        /// Project directory to assess (default: current directory)
        #[arg(value_name = "DIR", default_value = ".")]
        dir: PathBuf,

        /// Output report to file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Skip network API calls (offline mode)
        #[arg(long, default_value_t = false)]
        offline: bool,

        /// Update the mitigation registry with new findings
        #[arg(long, default_value_t = false)]
        register: bool,
    },

    /// Show active mitigation registry status
    Status {
        /// Project directory (default: current directory)
        #[arg(value_name = "DIR", default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum TemporalAction {
    /// List all temporal snapshots
    List {
        /// VeriSimDB directory
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,
    },

    /// Diff two temporal snapshots
    Diff {
        /// Sequence number of the older snapshot
        #[arg(value_name = "FROM")]
        from_seq: usize,

        /// Sequence number of the newer snapshot
        #[arg(value_name = "TO")]
        to_seq: usize,

        /// VeriSimDB directory
        #[arg(long, value_name = "DIR", default_value = "verisimdb-data")]
        verisimdb_dir: PathBuf,

        /// Output diff report to file
        #[arg(short, long, value_name = "OUT")]
        output: Option<PathBuf>,

        /// Export PanLL-format temporal diff alongside raw output
        #[arg(long)]
        panll: bool,
    },
}

// CLI argument types
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AttackAxisArg {
    Cpu,
    Memory,
    Disk,
    Network,
    Concurrency,
    Time,
}

impl From<AttackAxisArg> for AttackAxis {
    fn from(arg: AttackAxisArg) -> Self {
        match arg {
            AttackAxisArg::Cpu => AttackAxis::Cpu,
            AttackAxisArg::Memory => AttackAxis::Memory,
            AttackAxisArg::Disk => AttackAxis::Disk,
            AttackAxisArg::Network => AttackAxis::Network,
            AttackAxisArg::Concurrency => AttackAxis::Concurrency,
            AttackAxisArg::Time => AttackAxis::Time,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum IntensityArg {
    Light,
    Medium,
    Heavy,
    Extreme,
}

impl From<IntensityArg> for IntensityLevel {
    fn from(arg: IntensityArg) -> Self {
        match arg {
            IntensityArg::Light => IntensityLevel::Light,
            IntensityArg::Medium => IntensityLevel::Medium,
            IntensityArg::Heavy => IntensityLevel::Heavy,
            IntensityArg::Extreme => IntensityLevel::Extreme,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ProbeModeArg {
    Auto,
    Always,
    Never,
}

impl From<ProbeModeArg> for ProbeMode {
    fn from(arg: ProbeModeArg) -> Self {
        match arg {
            ProbeModeArg::Auto => ProbeMode::Auto,
            ProbeModeArg::Always => ProbeMode::Always,
            ProbeModeArg::Never => ProbeMode::Never,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AmuckPresetArg {
    Light,
    Dangerous,
}

impl From<AmuckPresetArg> for AmuckPreset {
    fn from(arg: AmuckPresetArg) -> Self {
        match arg {
            AmuckPresetArg::Light => AmuckPreset::Light,
            AmuckPresetArg::Dangerous => AmuckPreset::Dangerous,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AbductScopeArg {
    None,
    Direct,
    TwoHops,
    Directory,
}

impl From<AbductScopeArg> for DependencyScope {
    fn from(arg: AbductScopeArg) -> Self {
        match arg {
            AbductScopeArg::None => DependencyScope::None,
            AbductScopeArg::Direct => DependencyScope::Direct,
            AbductScopeArg::TwoHops => DependencyScope::TwoHops,
            AbductScopeArg::Directory => DependencyScope::Directory,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AbductTimeModeArg {
    Normal,
    Frozen,
    Slow,
}

impl From<AbductTimeModeArg> for TimeMode {
    fn from(arg: AbductTimeModeArg) -> Self {
        match arg {
            AbductTimeModeArg::Normal => TimeMode::Normal,
            AbductTimeModeArg::Frozen => TimeMode::Frozen,
            AbductTimeModeArg::Slow => TimeMode::Slow,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LangArg {
    En,
    Es,
    Fr,
    De,
    Ja,
}

impl From<LangArg> for Lang {
    fn from(arg: LangArg) -> Self {
        match arg {
            LangArg::En => Lang::En,
            LangArg::Es => Lang::Es,
            LangArg::Fr => Lang::Fr,
            LangArg::De => Lang::De,
            LangArg::Ja => Lang::Ja,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum A2mlReportKindArg {
    Assail,
    Attack,
    Assault,
    Ambush,
    Amuck,
    Abduct,
    Adjudicate,
    Axial,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum MigrationDiffFormatArg {
    Markdown,
    Json,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ShellArg {
    Bash,
    Zsh,
    Fish,
    Nushell,
    Powershell,
}

impl From<A2mlReportKindArg> for ReportBundleKind {
    fn from(arg: A2mlReportKindArg) -> Self {
        match arg {
            A2mlReportKindArg::Assail => ReportBundleKind::Assail,
            A2mlReportKindArg::Attack => ReportBundleKind::Attack,
            A2mlReportKindArg::Assault => ReportBundleKind::Assault,
            A2mlReportKindArg::Ambush => ReportBundleKind::Ambush,
            A2mlReportKindArg::Amuck => ReportBundleKind::Amuck,
            A2mlReportKindArg::Abduct => ReportBundleKind::Abduct,
            A2mlReportKindArg::Adjudicate => ReportBundleKind::Adjudicate,
            A2mlReportKindArg::Axial => ReportBundleKind::Axial,
        }
    }
}

type AttackOverrides = (Vec<String>, HashMap<AttackAxis, Vec<String>>, ProbeMode);

fn build_attack_overrides(
    profile_path: Option<PathBuf>,
    args: Vec<String>,
    axis_args: Vec<String>,
    probe: Option<ProbeModeArg>,
) -> Result<AttackOverrides> {
    let profile = if let Some(path) = profile_path {
        Some(AttackProfile::load(&path)?)
    } else {
        None
    };

    let mut common_args = profile
        .as_ref()
        .map(|p| p.common_args.clone())
        .unwrap_or_default();
    common_args.extend(args);

    let mut merged_axis_args = profile.as_ref().map(|p| p.axes.clone()).unwrap_or_default();
    for spec in axis_args {
        let (axis, arg) = parse_axis_arg(&spec)?;
        merged_axis_args.entry(axis).or_default().push(arg);
    }

    let probe_mode = probe
        .map(ProbeMode::from)
        .or_else(|| profile.and_then(|p| p.probe_mode))
        .unwrap_or_default();

    Ok((common_args, merged_axis_args, probe_mode))
}

fn parse_axis_arg(spec: &str) -> Result<(AttackAxis, String)> {
    let (axis_raw, arg) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("axis arg must be in the form AXIS=ARG"))?;
    let axis =
        parse_axis(axis_raw).ok_or_else(|| anyhow!("unknown axis '{}' in axis arg", axis_raw))?;
    Ok((axis, arg.to_string()))
}

fn parse_axis(value: &str) -> Option<AttackAxis> {
    match value.trim().to_ascii_lowercase().as_str() {
        "cpu" => Some(AttackAxis::Cpu),
        "memory" => Some(AttackAxis::Memory),
        "disk" => Some(AttackAxis::Disk),
        "network" => Some(AttackAxis::Network),
        "concurrency" => Some(AttackAxis::Concurrency),
        "time" => Some(AttackAxis::Time),
        _ => None,
    }
}

fn default_amuck_report_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/amuck-{}.json", ts))
}

fn default_abduct_report_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/abduct-{}.json", ts))
}

fn default_adjudicate_report_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/adjudicate-{}.json", ts))
}

fn default_axial_report_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/axial-{}.json", ts))
}

fn default_axial_markdown_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/axial-{}.md", ts))
}

fn default_aggregate_report_path() -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    PathBuf::from(format!("reports/aggregate-{}.json", ts))
}

/// Parse a `KEY=VALUE` CLI spec, splitting on the first `=`.
fn parse_kv(spec: &str) -> Result<(String, String)> {
    spec.split_once('=')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .ok_or_else(|| anyhow!("expected KEY=VALUE, got '{}'", spec))
}

fn main() -> Result<()> {
    // Write startup heartbeat for kin coordination
    let _ = kin::write_startup_heartbeat();

    let result = run_main();

    // Write final heartbeat based on outcome
    match &result {
        Ok(()) => {
            let _ = kin::write_heartbeat(
                kin::RunMetrics {
                    command: std::env::args().collect::<Vec<_>>().join(" "),
                    repos_scanned: None,
                    findings: None,
                    duration_secs: None,
                    exit_success: true,
                },
                vec![],
            );
        }
        Err(e) => {
            let _ = kin::write_error_heartbeat(format!("{}", e));
        }
    }

    result
}

fn run_main() -> Result<()> {
    let cli = Cli::parse();
    let manifest = match Manifest::load_default() {
        Ok(manifest) => manifest,
        Err(err) => {
            eprintln!("warning: failed to read AI manifest: {}", err);
            Manifest::default()
        }
    };
    let storage_modes = manifest.storage_modes();
    let manifest_formats = manifest.report_formats();

    match cli.command {
        Commands::Assail {
            target,
            output,
            verbose,
            attest,
            signing_key,
            browser_extension,
            headless,
        } => {
            qprintln!(
                cli.quiet,
                "Running assail analysis on: {}",
                target.display()
            );

            // Build CLI args for attestation recording
            let cli_args: Vec<String> = std::env::args().collect();

            // Optionally start attestation chain before scanning
            let mut chain_builder = if attest {
                qprintln!(cli.quiet, "Attestation enabled");
                Some(attestation::AttestationChainBuilder::begin(
                    &target, &cli_args,
                )?)
            } else {
                None
            };

            let report = if let Some(ref mut builder) = chain_builder {
                // Attested mode: use the analyzer with an evidence accumulator
                let analyzer = if verbose {
                    if browser_extension {
                        assail::analyzer::Analyzer::new_verbose_browser_extension(&target)?
                    } else {
                        assail::analyzer::Analyzer::new_verbose(&target)?
                    }
                } else {
                    if browser_extension {
                        assail::analyzer::Analyzer::new_browser_extension(&target)?
                    } else {
                        assail::analyzer::Analyzer::new(&target)?
                    }
                };
                analyzer.analyze_with_accumulator(Some(builder.accumulator()))?
            } else if verbose {
                if browser_extension {
                    assail::analyze_verbose_browser_extension(&target)?
                } else {
                    assail::analyze_verbose(&target)?
                }
            } else {
                if browser_extension {
                    assail::analyze_browser_extension(&target)?
                } else {
                    assail::analyze(&target)?
                }
            };

            let report_json = serde_json::to_string_pretty(&report)?;

            if let Some(output_path) = &output {
                fs::write(output_path, &report_json)?;
                qprintln!(cli.quiet, "Report saved to: {}", output_path.display());
            } else if cli.quiet || headless {
                // Machine-readable mode: emit JSON to stdout for pipeline consumers.
                // `--headless` makes this explicit for CI callers that cannot pass --quiet.
                println!("{report_json}");
            } else {
                println!("\nAssail Summary:");
                println!("  Language: {:?}", report.language);
                println!("  Weak points: {}", report.weak_points.len());
                println!("  Recommended attacks: {:?}", report.recommended_attacks);
            }

            // Seal and write attestation sidecar
            if let Some(builder) = chain_builder {
                let envelope = builder.seal(report_json.as_bytes(), signing_key.as_deref())?;
                let attestation_json = serde_json::to_string_pretty(&envelope)?;

                let sidecar_path = if let Some(out) = &output {
                    let stem = out.file_stem().unwrap_or_default().to_string_lossy();
                    let parent = out.parent().unwrap_or(Path::new("."));
                    parent.join(format!("{}.attestation.json", stem))
                } else {
                    PathBuf::from("assail-report.attestation.json")
                };

                fs::write(&sidecar_path, attestation_json)?;
                qprintln!(
                    cli.quiet,
                    "Attestation written to: {}",
                    sidecar_path.display()
                );
            }
        }

        Commands::Attack {
            program,
            profile,
            args,
            axis_args,
            probe,
            axis,
            intensity,
            duration,
        } => {
            qprintln!(
                cli.quiet,
                "Attacking {} with {:?} (intensity: {:?}, duration: {}s)",
                program.display(),
                axis,
                intensity,
                duration
            );

            let (common_args, axis_args, probe_mode) =
                build_attack_overrides(profile, args, axis_args, probe)?;

            let config = AttackConfig {
                axes: vec![axis.into()],
                duration: Duration::from_secs(duration),
                intensity: intensity.into(),
                target_programs: vec![program],
                data_corpus: None,
                parallel_attacks: cli.parallel,
                common_args,
                axis_args,
                probe_mode,
            };

            let results = attack::execute_attack(config)?;

            for result in &results {
                qprintln!(cli.quiet, "\nResult:");
                let status = if result.skipped {
                    "skipped"
                } else if result.success {
                    "passed"
                } else {
                    "failed"
                };
                qprintln!(cli.quiet, "  Status: {}", status);
                if result.skipped {
                    if let Some(reason) = &result.skip_reason {
                        qprintln!(cli.quiet, "  Skip reason: {}", reason);
                    }
                }
                qprintln!(cli.quiet, "  Exit code: {:?}", result.exit_code);
                qprintln!(
                    cli.quiet,
                    "  Duration: {:.2}s",
                    result.duration.as_secs_f64()
                );
                qprintln!(cli.quiet, "  Crashes: {}", result.crashes.len());
                if !result.crashes.is_empty() {
                    for (i, crash) in result.crashes.iter().enumerate() {
                        qprintln!(cli.quiet, "    {}. Signal: {:?}", i + 1, crash.signal);
                    }
                }
            }
        }

        Commands::Assault {
            program,
            source,
            profile,
            args,
            axis_args,
            probe,
            axes,
            intensity,
            duration,
            output,
        } => {
            qprintln!(
                cli.quiet,
                "Launching full assault on: {}",
                program.display()
            );

            qprintln!(cli.quiet, "\nPhase 1: Assail Analysis");
            let assail_target = source.as_ref().unwrap_or(&program);
            let assail_report = assail::analyze_verbose(assail_target)?;

            qprintln!(cli.quiet, "\nPhase 2: Attack Execution");
            let attack_axes = if let Some(axes_arg) = axes {
                axes_arg.into_iter().map(|a| a.into()).collect()
            } else {
                AttackAxis::all()
            };

            let (common_args, axis_args, probe_mode) =
                build_attack_overrides(profile, args, axis_args, probe)?;

            let config = AttackConfig {
                axes: attack_axes,
                duration: Duration::from_secs(duration),
                intensity: intensity.into(),
                target_programs: vec![program],
                data_corpus: None,
                parallel_attacks: cli.parallel,
                common_args,
                axis_args,
                probe_mode,
            };

            let attack_results = attack::execute_attack_with_patterns(
                config,
                assail_report.language,
                &assail_report.frameworks,
            )?;

            qprintln!(cli.quiet, "\nPhase 3: Report Generation");
            let assault_report = report::generate_assault_report(assail_report, attack_results)?;

            if !cli.quiet {
                report::print_report(
                    &assault_report,
                    cli.report_view,
                    cli.expand_sections,
                    cli.pivot,
                );
            }

            if let Some(output_path) = output {
                report::save_report(&assault_report, &output_path, cli.output_format)?;
                qprintln!(cli.quiet, "Report saved to: {}", output_path.display());
            }

            if !storage_modes.is_empty() {
                let stored = persist_report(
                    &assault_report,
                    cli.store.as_deref(),
                    &manifest_formats,
                    &storage_modes,
                )?;
                for path in stored {
                    qprintln!(cli.quiet, "Stored report: {}", path.display());
                }
            }
        }

        Commands::Ambush {
            program,
            source,
            timeline,
            profile,
            args,
            axis_args,
            axes,
            intensity,
            duration,
            output,
        } => {
            qprintln!(cli.quiet, "Launching ambush on: {}", program.display());

            qprintln!(cli.quiet, "\nPhase 1: Assail Analysis");
            let assail_target = source.as_ref().unwrap_or(&program);
            let assail_report = assail::analyze_verbose(assail_target)?;

            qprintln!(cli.quiet, "\nPhase 2: Ambush Execution");
            let mut timeline_report = None;
            let attack_results = if let Some(timeline_path) = timeline {
                let timeline_plan =
                    ambush::load_timeline_with_default(&timeline_path, Some(intensity.into()))?;
                if let Some(timeline_program) = &timeline_plan.program {
                    if timeline_program != &program {
                        eprintln!(
                            "warning: timeline program {} overrides CLI program {}",
                            timeline_program.display(),
                            program.display()
                        );
                    }
                }

                let (common_args, _axis_args, _probe_mode) =
                    build_attack_overrides(profile, args, Vec::new(), None)?;

                let config = AttackConfig {
                    axes: AttackAxis::all(),
                    duration: timeline_plan.duration,
                    intensity: intensity.into(),
                    target_programs: vec![program.clone()],
                    data_corpus: None,
                    parallel_attacks: cli.parallel,
                    common_args,
                    axis_args: HashMap::new(),
                    probe_mode: ProbeMode::Never,
                };

                let (results, timeline) = ambush::execute_timeline(config, &timeline_plan)?;
                timeline_report = Some(timeline);
                results
            } else {
                let ambush_axes = if let Some(axes_arg) = axes {
                    axes_arg.into_iter().map(|a| a.into()).collect()
                } else {
                    AttackAxis::all()
                };

                let (common_args, axis_args, _probe_mode) =
                    build_attack_overrides(profile, args, axis_args, None)?;

                let config = AttackConfig {
                    axes: ambush_axes,
                    duration: Duration::from_secs(duration),
                    intensity: intensity.into(),
                    target_programs: vec![program],
                    data_corpus: None,
                    parallel_attacks: cli.parallel,
                    common_args,
                    axis_args,
                    probe_mode: ProbeMode::Never,
                };

                ambush::execute(config)?
            };

            qprintln!(cli.quiet, "\nPhase 3: Report Generation");
            let mut assault_report =
                report::generate_assault_report(assail_report, attack_results)?;
            if let Some(timeline) = timeline_report {
                assault_report.timeline = Some(timeline);
            }

            if !cli.quiet {
                report::print_report(
                    &assault_report,
                    cli.report_view,
                    cli.expand_sections,
                    cli.pivot,
                );
            }

            if let Some(output_path) = output {
                report::save_report(&assault_report, &output_path, cli.output_format)?;
                qprintln!(cli.quiet, "Report saved to: {}", output_path.display());
            }

            if !storage_modes.is_empty() {
                let stored = persist_report(
                    &assault_report,
                    cli.store.as_deref(),
                    &manifest_formats,
                    &storage_modes,
                )?;
                for path in stored {
                    qprintln!(cli.quiet, "Stored report: {}", path.display());
                }
            }
        }

        Commands::Amuck {
            target,
            preset,
            spec,
            max_combinations,
            output_dir,
            exec_program,
            exec_args,
            output,
        } => {
            let execute = exec_program.map(|program| AmuckExecutionCommand {
                program,
                args: exec_args,
            });
            let report = amuck::run(AmuckConfig {
                target,
                spec_path: spec,
                preset: preset.into(),
                max_combinations,
                output_dir,
                execute,
            })?;
            let report_path = output.unwrap_or_else(default_amuck_report_path);
            amuck::write_report(&report, &report_path)?;
            qprintln!(
                cli.quiet,
                "amuck complete: {}/{} combinations wrote mutated files",
                report.combinations_run,
                report.combinations_planned
            );
            qprintln!(
                cli.quiet,
                "amuck report saved to: {}",
                report_path.display()
            );
        }

        Commands::Abduct {
            target,
            source_root,
            scope,
            output_dir,
            no_lock,
            mtime_offset_days,
            time_mode,
            time_scale,
            virtual_now,
            exec_program,
            exec_args,
            exec_timeout,
            output,
        } => {
            let execute = exec_program.map(|program| AbductExecutionCommand {
                program,
                args: exec_args,
            });
            let report = abduct::run(AbductConfig {
                target,
                source_root,
                output_root: output_dir,
                dependency_scope: scope.into(),
                lock_files: !no_lock,
                mtime_offset_days,
                time_mode: time_mode.into(),
                time_scale,
                virtual_now,
                execute,
                exec_timeout_secs: exec_timeout,
            })?;
            let report_path = output.unwrap_or_else(default_abduct_report_path);
            abduct::write_report(&report, &report_path)?;
            qprintln!(
                cli.quiet,
                "abduct complete: {} files copied ({} locked, {} mtime-shifted)",
                report.selected_files,
                report.locked_files,
                report.mtime_shifted_files
            );
            qprintln!(
                cli.quiet,
                "abduct workspace: {}",
                report.workspace_dir.display()
            );
            qprintln!(
                cli.quiet,
                "abduct report saved to: {}",
                report_path.display()
            );
        }

        Commands::Adjudicate { reports, output } => {
            let report = adjudicate::run(AdjudicateConfig { reports })?;
            let report_path = output.unwrap_or_else(default_adjudicate_report_path);
            adjudicate::write_report(&report, &report_path)?;
            qprintln!(
                cli.quiet,
                "adjudicate verdict: {} (processed {}, failed {})",
                report.verdict,
                report.processed_reports,
                report.failed_reports
            );
            qprintln!(
                cli.quiet,
                "adjudicate report saved to: {}",
                report_path.display()
            );
        }

        Commands::Axial {
            target,
            exec_program,
            exec_args,
            repeat,
            timeout,
            reports,
            head,
            tail,
            grep,
            agrep,
            agrep_distance,
            lang,
            aspell,
            aspell_lang,
            markdown_output,
            pandoc_to,
            pandoc_output,
            output,
        } => {
            let execute = exec_program.map(|program| AxialExecutionCommand {
                program,
                args: exec_args,
            });
            let report = axial::run(AxialConfig {
                target,
                execute,
                repeat,
                timeout_secs: timeout,
                reports,
                head_lines: head,
                tail_lines: tail,
                grep_patterns: grep,
                agrep_patterns: agrep,
                agrep_distance,
                lang: lang.into(),
                aspell,
                aspell_lang,
            })?;
            let report_path = output.unwrap_or_else(default_axial_report_path);
            axial::write_report(&report, &report_path)?;
            let markdown_path = markdown_output.unwrap_or_else(default_axial_markdown_path);
            axial::write_markdown(&report, &markdown_path)?;
            if let Some(target_format) = pandoc_to {
                let pandoc_path = pandoc_output.unwrap_or_else(|| {
                    let mut p = markdown_path.clone();
                    p.set_extension(target_format.as_str());
                    p
                });
                axial::convert_markdown_with_pandoc(&markdown_path, &target_format, &pandoc_path)?;
                qprintln!(
                    cli.quiet,
                    "axial pandoc export ({}) saved to: {}",
                    target_format,
                    pandoc_path.display()
                );
            }
            qprintln!(
                cli.quiet,
                "axial observed {} runs and {} report artifacts",
                report.observed_runs,
                report.observed_reports
            );
            qprintln!(
                cli.quiet,
                "axial report saved to: {}",
                report_path.display()
            );
            qprintln!(
                cli.quiet,
                "axial markdown saved to: {}",
                markdown_path.display()
            );
        }

        Commands::Analyze {
            report: report_path,
        } => {
            qprintln!(
                cli.quiet,
                "Analyzing crash report: {}",
                report_path.display()
            );

            let content = read_report_bounded(&report_path)?;
            let crash: CrashReport = serde_json::from_str(&content)?;

            let signatures = signatures::detect_signatures(&crash);

            if !cli.quiet {
                println!("\nSignatures Detected: {}", signatures.len());
                for sig in &signatures {
                    println!(
                        "\n  {:?} (confidence: {:.2})",
                        sig.signature_type, sig.confidence
                    );
                    println!("  Evidence:");
                    for evidence in &sig.evidence {
                        println!("    - {}", evidence);
                    }
                    if let Some(loc) = &sig.location {
                        println!("  Location: {}", loc);
                    }
                }
            }
        }

        Commands::Report { report } => {
            let content = read_report_bounded(&report)?;
            let assault_report: AssaultReport = serde_json::from_str(&content)?;
            if !cli.quiet {
                report::print_report(
                    &assault_report,
                    cli.report_view,
                    cli.expand_sections,
                    cli.pivot,
                );
            }
        }

        Commands::Tui { report, headless } => {
            let content = read_report_bounded(&report)?;
            let assault_report: AssaultReport = serde_json::from_str(&content)?;
            if headless {
                ReportTui::run_headless(&assault_report)?;
            } else {
                ReportTui::run(&assault_report)?;
            }
        }

        Commands::Gui { report, headless } => {
            let content = read_report_bounded(&report)?;
            let assault_report: AssaultReport = serde_json::from_str(&content)?;
            if headless {
                report::gui_text::run_headless(assault_report)?;
            } else {
                #[cfg(feature = "gui")]
                {
                    report::ReportGui::run(assault_report)?;
                }
                #[cfg(not(feature = "gui"))]
                {
                    anyhow::bail!(
                        "windowed GUI requires the `gui` feature; rebuild with `cargo build --features gui`, or pass --headless"
                    );
                }
            }
        }

        Commands::Diff {
            base,
            compare,
            verisimdb_dir,
        } => {
            let (base_path, compare_path) = match (base, compare) {
                (Some(base_path), Some(compare_path)) => (base_path, compare_path),
                (None, None) => {
                    let latest = latest_reports(&verisimdb_dir, 2)?;
                    (latest[0].clone(), latest[1].clone())
                }
                _ => {
                    return Err(anyhow!(
                        "provide both BASE and COMPARE paths, or neither to use latest reports"
                    ))
                }
            };

            let base_report = load_report(&base_path)?;
            let compare_report = load_report(&compare_path)?;
            let diff = format_diff(
                &base_report,
                &compare_report,
                &base_path.display().to_string(),
                &compare_path.display().to_string(),
            );
            println!("{}", diff);
        }

        Commands::Manifest { path, output } => {
            let target = path.unwrap_or_else(|| {
                if PathBuf::from("0-AI-MANIFEST.a2ml").exists() {
                    PathBuf::from("0-AI-MANIFEST.a2ml")
                } else {
                    PathBuf::from("AI.a2ml")
                }
            });
            let manifest = Manifest::load(&target).unwrap_or_default();
            let nickel = manifest.to_nickel();
            if let Some(output_path) = output {
                fs::write(&output_path, nickel)?;
                qprintln!(cli.quiet, "Manifest exported to {}", output_path.display());
            } else {
                println!("{}", nickel);
            }
        }

        Commands::A2mlExport {
            kind,
            input,
            output,
        } => {
            let report_kind: ReportBundleKind = kind.into();
            a2ml::export_report_file(report_kind, &input, &output)?;
            qprintln!(
                cli.quiet,
                "A2ML export [{}] written to {}",
                report_kind.as_str(),
                output.display()
            );
        }

        Commands::A2mlImport {
            input,
            output,
            kind,
        } => {
            let imported_kind = a2ml::import_report_file(&input, &output)?;
            if let Some(expected_kind) = kind {
                let expected: ReportBundleKind = expected_kind.into();
                if imported_kind != expected {
                    return Err(anyhow!(
                        "A2ML bundle kind mismatch: expected {}, got {}",
                        expected.as_str(),
                        imported_kind.as_str()
                    ));
                }
            }
            qprintln!(
                cli.quiet,
                "A2ML import [{}] written to {}",
                imported_kind.as_str(),
                output.display()
            );
        }

        Commands::Panll { report, output } => {
            let assault_report = load_report(&report)?;
            let output_path = output.unwrap_or_else(|| PathBuf::from("panll-event-chain.json"));
            panll::write_export(&assault_report, Some(&report), &output_path)?;
            qprintln!(
                cli.quiet,
                "PanLL export written to {}",
                output_path.display()
            );
        }

        Commands::Help { command } => {
            let mut app = Cli::command();
            match command {
                Some(cmd_name) => {
                    let mut stdout = io::stdout();
                    if let Some(subcmd) = app.find_subcommand_mut(&cmd_name) {
                        subcmd.write_long_help(&mut stdout)?;
                        stdout.write_all(b"\n")?;
                        stdout.flush()?;
                    } else {
                        eprintln!("Unknown command '{}'", cmd_name);
                        app.print_long_help()?;
                    }
                }
                None => {
                    app.print_long_help()?;
                }
            }
            println!();
            return Ok(());
        }

        Commands::Assemblyline {
            directory,
            output,
            findings_only,
            min_findings,
            incremental,
            cache,
        } => {
            let cache_file = if incremental {
                Some(cache.unwrap_or_else(|| directory.join(".panic-attack-cache.json")))
            } else {
                cache // explicit --cache implies incremental
            };

            let config = assemblyline::AssemblylineConfig {
                directory: directory.clone(),
                output: output.clone(),
                findings_only,
                min_findings,
                sarif: cli.output_format == report::output::ReportOutputFormat::Sarif,
                cache_file: cache_file.clone(),
            };

            if let Some(cf) = &cache_file {
                if !cli.quiet {
                    if cf.exists() {
                        println!("Incremental mode: loading cache from {}", cf.display());
                    } else {
                        println!(
                            "Incremental mode: first run (cache will be saved to {})",
                            cf.display()
                        );
                    }
                }
            }

            let report = assemblyline::run(&config)?;
            assemblyline::print_summary(&report, cli.quiet);

            if report.repos_skipped > 0 && !cli.quiet {
                println!(
                    "  {} repos skipped (unchanged since last scan)",
                    report.repos_skipped
                );
            }

            if let Some(out_path) = output {
                assemblyline::write_report(&report, &out_path)?;
                if !cli.quiet {
                    println!("Report written to {}", out_path.display());
                }
            }

            // Persist to verisimdb/filesystem if storage modes are configured
            if !storage_modes.is_empty() {
                let stored = storage::persist_assemblyline_report(
                    &report,
                    cli.store.as_deref(),
                    &storage_modes,
                )?;
                for path in stored {
                    qprintln!(cli.quiet, "Stored report: {}", path.display());
                }
            }

            return Ok(());
        }

        Commands::Diagnostics {
            manifest: manifest_path,
        } => {
            let diag_manifest = if let Some(path) = manifest_path {
                Manifest::load(&path)
                    .with_context(|| format!("reading manifest {}", path.display()))?
            } else {
                manifest.clone()
            };
            diagnostics::run_self_diagnostics(&diag_manifest)?;
            return Ok(());
        }

        Commands::Notify {
            report: report_path,
            output,
            critical_only,
            min_findings,
            create_issues,
            github_owner,
        } => {
            let content = read_report_bounded(&report_path)?;
            let asmline_report: assemblyline::AssemblylineReport =
                serde_json::from_str(&content)
                    .with_context(|| "parsing assemblyline report JSON")?;

            let config = notify::NotifyConfig {
                create_issues,
                min_findings,
                critical_only,
                github_owner: Some(github_owner),
            };

            let output_path = output.unwrap_or_else(|| PathBuf::from("reports/notification.md"));
            notify::write_notification(&asmline_report, &config, &output_path)?;
            qprintln!(
                cli.quiet,
                "Notification written to: {}",
                output_path.display()
            );

            if create_issues {
                let created = notify::create_github_issues(&asmline_report, &config)?;
                qprintln!(cli.quiet, "Created {} GitHub issues", created.len());
                for url in &created {
                    qprintln!(cli.quiet, "  {}", url);
                }
            }

            return Ok(());
        }

        Commands::MigrationSnapshot {
            target,
            label,
            build_time,
            bundle_size,
            store_hexad,
            output,
        } => {
            qprintln!(
                cli.quiet,
                "Taking migration snapshot '{}' of: {}",
                label,
                target.display()
            );

            // Run assail analysis
            let assail_report = if cli.quiet {
                assail::analyze(&target)?
            } else {
                assail::analyze_verbose(&target)?
            };

            // Check that migration_metrics were populated
            let mut metrics = assail_report.migration_metrics.clone().unwrap_or_else(|| {
                eprintln!("warning: target does not appear to be a ReScript project");
                // Return empty metrics as fallback
                types::MigrationMetrics {
                    deprecated_api_count: 0,
                    modern_api_count: 0,
                    api_migration_ratio: 1.0,
                    health_score: 1.0,
                    config_format: types::ReScriptConfigFormat::None,
                    version_bracket: types::ReScriptVersionBracket::V12Current,
                    build_time_ms: None,
                    bundle_size_bytes: None,
                    file_count: 0,
                    rescript_lines: 0,
                    deprecated_patterns: Vec::new(),
                    jsx_version: None,
                    uncurried: false,
                    module_format: None,
                }
            });

            // Optionally measure build time
            if build_time {
                qprintln!(cli.quiet, "Measuring build time...");
                let start = std::time::Instant::now();
                let build_result = std::process::Command::new("npx")
                    .args(["rescript", "build"])
                    .current_dir(&target)
                    .output();
                let elapsed = start.elapsed();
                match build_result {
                    Ok(out) if out.status.success() => {
                        metrics.build_time_ms = Some(elapsed.as_millis() as u64);
                        qprintln!(cli.quiet, "Build time: {}ms", elapsed.as_millis());
                    }
                    Ok(out) => {
                        eprintln!(
                            "warning: rescript build failed (exit {})",
                            out.status.code().unwrap_or(-1)
                        );
                    }
                    Err(e) => {
                        eprintln!("warning: could not run rescript build: {}", e);
                    }
                }
            }

            // Optionally measure bundle size
            if bundle_size {
                qprintln!(cli.quiet, "Measuring bundle size...");
                let lib_dir = target.join("lib");
                if lib_dir.exists() {
                    let mut total: u64 = 0;
                    for entry in walkdir::WalkDir::new(&lib_dir)
                        .into_iter()
                        .filter_map(|e| e.ok())
                    {
                        if entry.file_type().is_file() {
                            if let Ok(meta) = entry.metadata() {
                                total += meta.len();
                            }
                        }
                    }
                    metrics.bundle_size_bytes = Some(total);
                    qprintln!(cli.quiet, "Bundle size: {} bytes", total);
                } else {
                    eprintln!("warning: lib/ directory not found (run build first?)");
                }
            }

            let snapshot = types::MigrationSnapshot {
                label: label.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                target_path: target.display().to_string(),
                assail_report,
                migration_metrics: metrics,
            };

            let json = serde_json::to_string_pretty(&snapshot)?;

            if let Some(out_path) = output {
                fs::write(&out_path, &json)?;
                qprintln!(cli.quiet, "Snapshot written to: {}", out_path.display());
            } else {
                println!("{}", json);
            }

            if store_hexad {
                qprintln!(cli.quiet, "VeriSimDB storage for snapshots: planned");
            }

            return Ok(());
        }

        Commands::MigrationDiff {
            before,
            after,
            output,
            format,
        } => {
            let before_snapshot = report::migration::load_snapshot(&before)?;
            let after_snapshot = report::migration::load_snapshot(&after)?;
            let diff = report::migration::compute_diff(&before_snapshot, &after_snapshot);

            let content = match format {
                MigrationDiffFormatArg::Markdown => report::migration::format_diff_markdown(&diff),
                MigrationDiffFormatArg::Json => serde_json::to_string_pretty(&diff)?,
            };

            if let Some(out_path) = output {
                fs::write(&out_path, &content)?;
                qprintln!(
                    cli.quiet,
                    "Migration diff written to: {}",
                    out_path.display()
                );
            } else {
                println!("{}", content);
            }

            return Ok(());
        }

        Commands::Image {
            directory,
            output,
            incremental,
            cache,
            snapshot,
            label,
            verisimdb_dir,
            panll,
        } => {
            // Run assemblyline scan on the directory
            let cache_file = if incremental {
                Some(cache.unwrap_or_else(|| directory.join(".panic-attack-cache.json")))
            } else {
                cache
            };

            let config = assemblyline::AssemblylineConfig {
                directory: directory.clone(),
                output: None,
                findings_only: false,
                min_findings: 0,
                sarif: false,
                cache_file: cache_file.clone(),
            };

            qprintln!(cli.quiet, "Running assemblyline scan for imaging...");
            let report = assemblyline::run(&config)?;
            qprintln!(cli.quiet, "Scan complete. Building system image...");

            // Build the fNIRS-style system image
            let image = mass_panic::imaging::build_image(&report);

            qprintln!(
                cli.quiet,
                "System image: {} nodes, {} edges, global health {:.1}%, global risk {:.1}%",
                image.node_count,
                image.edge_count,
                image.global_health * 100.0,
                image.global_risk * 100.0
            );

            // Write image to output file
            let out_path = output.unwrap_or_else(|| directory.join("system-image.json"));
            mass_panic::imaging::write_image(&image, &out_path)?;
            qprintln!(cli.quiet, "System image written to: {}", out_path.display());

            // Export PanLL-format system image
            if panll {
                let panll_path = out_path.with_extension("panll.json");
                panll::write_image_export(&image, &panll_path)?;
                qprintln!(cli.quiet, "PanLL image export: {}", panll_path.display());
            }

            // Optionally take a temporal snapshot
            if snapshot {
                let snap_label = if label.is_empty() {
                    String::new()
                } else {
                    label.clone()
                };
                let entry =
                    mass_panic::temporal::take_snapshot(&image, &verisimdb_dir, &snap_label)?;
                qprintln!(
                    cli.quiet,
                    "Temporal snapshot #{} saved ({})",
                    entry.sequence,
                    entry.timestamp
                );
            }

            return Ok(());
        }

        #[cfg(feature = "http")]
        Commands::Bridge { action } => {
            match action {
                BridgeAction::Triage {
                    dir,
                    output,
                    offline,
                    register,
                } => {
                    // Reject path traversal sequences BEFORE any disk I/O.
                    // The prior `canonicalize().unwrap_or_else(|_| dir.clone())`
                    // pattern silently fell back to the un-canonicalized path
                    // on failure, which let `../`-laden inputs slip past.
                    // safe_path::has_traversal is a pure-Rust port of
                    // proven::SafePath::containsTraversal (issue #115).
                    if let Some(dir_str) = dir.to_str() {
                        if panic_attack::safe_path::has_traversal(dir_str) {
                            anyhow::bail!(
                                "rejected: directory contains '..' traversal sequence: {}",
                                dir.display()
                            );
                        }
                    }
                    let project_dir = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());

                    qprintln!(cli.quiet, "Patch Bridge triage: {}", project_dir.display());

                    let report = bridge::triage(&project_dir, offline)?;

                    qprintln!(
                        cli.quiet,
                        "Dependencies: {}  CVEs: {}  Mitigable: {}  Unmitigable: {}  Informational: {}",
                        report.total_dependencies,
                        report.cves.len(),
                        report.mitigated,
                        report.unmitigable,
                        report.informational
                    );

                    // Print details for non-informational CVEs
                    for cve in &report.cves {
                        if cve.classification != bridge::Classification::Informational
                            || cli.expand_sections
                        {
                            let icon = match cve.classification {
                                bridge::Classification::Mitigable => "MITIGABLE",
                                bridge::Classification::Unmitigable => "UNMITIGABLE",
                                bridge::Classification::Informational => "INFO",
                            };
                            qprintln!(cli.quiet, "");
                            qprintln!(
                                cli.quiet,
                                "  [{}] {} {} ({})",
                                icon,
                                cve.vulnerability.package,
                                cve.vulnerability.version,
                                cve.vulnerability.id
                            );
                            qprintln!(cli.quiet, "    {}", cve.rationale);
                            qprintln!(cli.quiet, "    Action: {}", cve.action);
                        }
                    }

                    // Register mitigations if requested
                    if register {
                        let mut registry =
                            bridge::registry::MitigationRegistry::load(&project_dir)?;
                        let added = registry.register_from_triage(&report.cves);
                        if added > 0 {
                            registry.save(&project_dir)?;
                            qprintln!(cli.quiet, "\nRegistered {} new mitigation entries.", added);
                        }
                    }

                    // Output JSON
                    let json = serde_json::to_string_pretty(&report)?;
                    if let Some(out_path) = output {
                        std::fs::write(&out_path, &json)?;
                        qprintln!(cli.quiet, "\nReport written to: {}", out_path.display());
                    } else if cli.quiet {
                        // In quiet mode with no output file, print JSON to stdout
                        println!("{}", json);
                    }
                }

                BridgeAction::Status { dir } => {
                    // Same safe_path::has_traversal guard as the triage arm.
                    if let Some(dir_str) = dir.to_str() {
                        if panic_attack::safe_path::has_traversal(dir_str) {
                            anyhow::bail!(
                                "rejected: directory contains '..' traversal sequence: {}",
                                dir.display()
                            );
                        }
                    }
                    let project_dir = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());

                    let registry = bridge::registry::MitigationRegistry::load(&project_dir)?;

                    if registry.entries.is_empty() {
                        println!("No mitigation entries registered.");
                        println!("Run `panic-attack bridge triage --register` to populate.");
                    } else {
                        println!(
                            "{:<12} {:<20} {:<15} {:<15} ACTION",
                            "ID", "ADVISORY", "PACKAGE", "STATUS"
                        );
                        println!("{}", "-".repeat(80));
                        for entry in &registry.entries {
                            let status_str = match entry.status {
                                bridge::registry::MitigationStatus::Pending => "pending",
                                bridge::registry::MitigationStatus::Active => "active",
                                bridge::registry::MitigationStatus::Retiring => "retiring",
                                bridge::registry::MitigationStatus::Retired => "retired",
                                bridge::registry::MitigationStatus::AcceptedRisk => "accepted",
                            };
                            println!(
                                "{:<12} {:<20} {:<15} {:<15} {}",
                                entry.id,
                                entry.advisory_id,
                                entry.package,
                                status_str,
                                entry.action
                            );
                        }
                        println!(
                            "\n{} entries ({} pending, {} accepted risk).",
                            registry.entries.len(),
                            registry.count_by_status(bridge::registry::MitigationStatus::Pending),
                            registry
                                .count_by_status(bridge::registry::MitigationStatus::AcceptedRisk),
                        );
                    }
                }
            }
            return Ok(());
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = "panic-attack".to_string();
            match shell {
                ShellArg::Bash => generate(Shell::Bash, &mut cmd, &bin_name, &mut io::stdout()),
                ShellArg::Zsh => generate(Shell::Zsh, &mut cmd, &bin_name, &mut io::stdout()),
                ShellArg::Fish => generate(Shell::Fish, &mut cmd, &bin_name, &mut io::stdout()),
                ShellArg::Nushell => generate(Nushell, &mut cmd, &bin_name, &mut io::stdout()),
                ShellArg::Powershell => {
                    generate(Shell::PowerShell, &mut cmd, &bin_name, &mut io::stdout())
                }
            }
            return Ok(());
        }

        Commands::Groove { port } => {
            groove::run(port)?;
            return Ok(());
        }

        Commands::Fingerprint { dir } => {
            let fp = assemblyline::fingerprint_repo(&dir)?;
            println!("{fp}");
            return Ok(());
        }

        Commands::Attest { action } => match action {
            AttestAction::Verify { file } => {
                match attestation::verify_attestation_file(&file)? {
                    attestation::VerifyResult::Ok {
                        issuer,
                        issued_at,
                        chain_hash,
                        signature_verified,
                    } => {
                        println!("  [OK] Attestation verified");
                        println!("       Issuer:    {}", issuer);
                        println!("       Issued at: {}", issued_at);
                        println!("       Chain:     {}", chain_hash);
                        if signature_verified {
                            println!("       Signature: verified (Ed25519)");
                        } else {
                            println!("       Signature: not present");
                        }
                    }
                    attestation::VerifyResult::Failed(reasons) => {
                        eprintln!("  [FAIL] Attestation verification failed:");
                        for reason in &reasons {
                            eprintln!("         - {}", reason);
                        }
                        return Err(anyhow::anyhow!("attestation verification failed"));
                    }
                }
                return Ok(());
            }
        },

        Commands::Query {
            expr,
            verisimdb_dir,
            format,
        } => {
            let q = query::parse(&expr)?;
            let hits = query::run(&q, &verisimdb_dir)?;
            match format {
                QueryFormatArg::Table => {
                    print!("{}", query::render_table(&hits));
                }
                QueryFormatArg::Json => {
                    println!("{}", serde_json::to_string_pretty(&hits)?);
                }
            }
            return Ok(());
        }

        Commands::DescribeContract => {
            let cmd = Cli::command();
            let mut modes = serde_json::Map::new();
            for sub in cmd.get_subcommands() {
                let name = sub.get_name().to_string();
                let mut flags: Vec<String> = sub
                    .get_arguments()
                    .filter(|a| !a.is_positional())
                    .map(|a| a.get_id().to_string())
                    .collect();
                flags.sort();
                let mut positional: Vec<String> = sub
                    .get_arguments()
                    .filter(|a| a.is_positional())
                    .map(|a| {
                        a.get_value_names()
                            .and_then(|v| v.first().map(|s| s.to_string()))
                            .unwrap_or_else(|| a.get_id().to_string())
                    })
                    .collect();
                positional.sort();
                let description = sub.get_about().map(|s| s.to_string()).unwrap_or_default();
                modes.insert(
                    name,
                    serde_json::json!({
                        "description": description,
                        "positional": positional,
                        "flags": flags,
                    }),
                );
            }
            let mut global_flags: Vec<String> = cmd
                .get_arguments()
                .filter(|a| a.is_global_set())
                .map(|a| a.get_id().to_string())
                .collect();
            global_flags.sort();
            // Report-schema version mirrors types.rs::assail_schema_version
            // and types.rs::assault_schema_version (both "2.5" in v2.5.0).
            // The chapel-cli-contract CI gate catches drift between this
            // string and the serialiser defaults.
            let contract = serde_json::json!({
                "schema_version": "1",
                "tool": "panic-attack",
                "cli_version": env!("CARGO_PKG_VERSION"),
                "report_schema_version": "2.5",
                "detachability": {
                    "standalone": true,
                    "orchestrator_agnostic": true,
                    "chapel_optional": true,
                },
                "global_flags": global_flags,
                "modes": modes,
            });
            println!("{}", serde_json::to_string_pretty(&contract)?);
            return Ok(());
        }

        #[cfg(feature = "http")]
        Commands::VerisimPush {
            hexad,
            url,
            fallback_dir,
            retry,
        } => {
            use panic_attack::storage::{
                push_hexad_http, push_hexad_http_with_retry, push_hexad_with_fallback,
                PanicAttackHexad,
            };

            let json = std::fs::read_to_string(&hexad).with_context(|| {
                format!("reading hexad file {}", hexad.display())
            })?;
            let hexad_value: PanicAttackHexad = serde_json::from_str(&json)
                .with_context(|| format!("parsing hexad JSON at {}", hexad.display()))?;

            let gateway_url = url
                .or_else(|| std::env::var("VERISIMDB_URL").ok())
                .unwrap_or_else(|| "http://localhost:8080".to_string());

            qprintln!(
                cli.quiet,
                "verisim-push: POST {} ({})",
                gateway_url,
                hexad.display()
            );

            let push_result = if retry {
                push_hexad_http_with_retry(&hexad_value, &gateway_url)
            } else {
                push_hexad_http(&hexad_value, &gateway_url)
            };

            match push_result {
                Ok(pushed_id) => {
                    qprintln!(cli.quiet, "verisim-push: pushed hexad id={}", pushed_id);
                }
                Err(http_err) => {
                    // HTTP failed — if a fallback dir is set, write the
                    // hexad there so an offline orchestrator can replay
                    // later. push_hexad_with_fallback respects VERISIMDB_URL
                    // env too, but we've already established HTTP isn't
                    // reachable, so the fallback-to-disk is the value here.
                    if let Some(dir) = fallback_dir.as_ref() {
                        let written = push_hexad_with_fallback(&hexad_value, dir)?;
                        qprintln!(
                            cli.quiet,
                            "verisim-push: HTTP failed ({}); fell back to {} path(s) under {}",
                            http_err,
                            written.len(),
                            dir.display()
                        );
                    } else {
                        return Err(http_err);
                    }
                }
            }
            return Ok(());
        }

        Commands::Campaign { action } => {
            match action {
                CampaignAction::RegisterPr {
                    finding_id,
                    pr_url,
                    verisimdb_dir,
                } => {
                    let path = campaign::register_pr(&finding_id, &pr_url, &verisimdb_dir)?;
                    qprintln!(
                        cli.quiet,
                        "Registered PR {} for {} ({})",
                        pr_url,
                        finding_id,
                        path.display()
                    );
                }
                CampaignAction::Dismiss {
                    finding_id,
                    reason,
                    verisimdb_dir,
                } => {
                    let path = campaign::dismiss(&finding_id, &reason, &verisimdb_dir)?;
                    qprintln!(
                        cli.quiet,
                        "Dismissed {} ({}): {}",
                        finding_id,
                        reason,
                        path.display()
                    );
                }
                CampaignAction::Status {
                    verisimdb_dir,
                    output,
                } => {
                    let md = campaign::status_markdown(&verisimdb_dir)?;
                    match output {
                        Some(path) => {
                            std::fs::write(&path, &md)?;
                            qprintln!(cli.quiet, "Status written to {}", path.display());
                        }
                        None => print!("{}", md),
                    }
                }
                #[cfg(feature = "http")]
                CampaignAction::Poll { verisimdb_dir } => {
                    let outcomes = campaign::poll(&verisimdb_dir)?;
                    let transitioned = outcomes.iter().filter(|o| o.transitioned).count();
                    qprintln!(
                        cli.quiet,
                        "Polled {} open findings, {} state transitions",
                        outcomes.len(),
                        transitioned
                    );
                    for o in &outcomes {
                        if o.transitioned {
                            qprintln!(
                                cli.quiet,
                                "  {} : {} -> {}",
                                o.finding_id,
                                o.old_state,
                                o.new_state
                            );
                        }
                    }
                }
            }
            return Ok(());
        }

        Commands::SweepTracker {
            verisimdb_dir,
            output,
            by_repo,
            by_category,
        } => {
            let shape = match (by_repo, by_category) {
                (true, false) => sweep_tracker::ReportShape::ByRepo,
                (false, true) => sweep_tracker::ReportShape::ByCategory,
                _ => sweep_tracker::ReportShape::Both,
            };
            let md = sweep_tracker::render_report(&verisimdb_dir, shape)?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &md)?;
                    qprintln!(cli.quiet, "Sweep tracker written to {}", path.display());
                }
                None => print!("{}", md),
            }
            return Ok(());
        }

        Commands::Temporal { action } => {
            match action {
                TemporalAction::List { verisimdb_dir } => {
                    let snapshots = mass_panic::temporal::list_snapshots(&verisimdb_dir)?;
                    if snapshots.is_empty() {
                        println!("No temporal snapshots found.");
                    } else {
                        println!(
                            "{:<6} {:<28} {:<8} {:<10} LABEL",
                            "SEQ", "TIMESTAMP", "NODES", "HEALTH"
                        );
                        println!("{}", "-".repeat(60));
                        for snap in &snapshots {
                            println!(
                                "{:<6} {:<28} {:<8} {:<10.1}% {}",
                                snap.sequence,
                                snap.timestamp,
                                snap.node_count,
                                snap.global_health * 100.0,
                                snap.label
                            );
                        }
                        println!("\n{} snapshots total.", snapshots.len());
                    }
                }
                TemporalAction::Diff {
                    from_seq,
                    to_seq,
                    verisimdb_dir,
                    output,
                    panll,
                } => {
                    let (older_entry, newer_entry) =
                        mass_panic::temporal::get_snapshot_pair(&verisimdb_dir, from_seq, to_seq)?;
                    let older_image = mass_panic::temporal::load_snapshot_image(&older_entry)?;
                    let newer_image = mass_panic::temporal::load_snapshot_image(&newer_entry)?;

                    let older_label = format!("#{}", from_seq);
                    let newer_label = format!("#{}", to_seq);
                    let diff = mass_panic::temporal::diff_images(
                        &older_image,
                        &newer_image,
                        &older_label,
                        &newer_label,
                    );

                    println!(
                        "Temporal diff: {} → {} | Δhealth {}{:.1}%, Δrisk {}{:.1}%",
                        older_label,
                        newer_label,
                        if diff.health_delta >= 0.0 { "+" } else { "" },
                        diff.health_delta * 100.0,
                        if diff.risk_delta >= 0.0 { "+" } else { "" },
                        diff.risk_delta * 100.0,
                    );
                    println!(
                        "  New: {} | Removed: {} | Improved: {} | Degraded: {} | Unchanged: {}",
                        diff.new_nodes.len(),
                        diff.removed_nodes.len(),
                        diff.improved_nodes.len(),
                        diff.degraded_nodes.len(),
                        diff.unchanged_count,
                    );

                    if let Some(ref out_path) = output {
                        mass_panic::temporal::write_diff(&diff, out_path)?;
                        println!("Diff report written to: {}", out_path.display());
                    }

                    if panll {
                        let panll_path = output
                            .as_ref()
                            .map(|p| p.with_extension("panll.json"))
                            .unwrap_or_else(|| {
                                verisimdb_dir
                                    .join(format!("diff-{}-{}.panll.json", from_seq, to_seq))
                            });
                        panll::write_temporal_export(&diff, &panll_path)?;
                        println!("PanLL temporal export: {}", panll_path.display());
                    }
                }
            }

            return Ok(());
        }

        Commands::Assay {
            target,
            proven,
            output,
        } => {
            qprintln!(
                cli.quiet,
                "Assaying {} for proven-library substitutions",
                target.display()
            );
            let report = assay::run(AssayConfig {
                target,
                proven_sources: proven,
            })?;
            if let Some(path) = &output {
                assay::write_report(&report, path)?;
                qprintln!(cli.quiet, "Assay report saved to: {}", path.display());
            } else if cli.quiet {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "\nAssay: {} candidate(s) across {} catalogue entries",
                    report.candidates.len(),
                    report.catalogue_entries
                );
                for c in &report.candidates {
                    println!(
                        "  [{}] {} — {:?} ({} hit(s), confidence {:.2})",
                        c.id,
                        c.proven_name,
                        c.status,
                        c.target_hits.len(),
                        c.confidence
                    );
                    println!("        backing: {}", c.proof_backing);
                }
                for n in &report.notes {
                    println!("  note: {}", n);
                }
            }
        }

        Commands::Assimilate {
            target,
            proven,
            candidate,
            all,
            from,
            dry_run,
            output,
        } => {
            qprintln!(
                cli.quiet,
                "Assimilating proven substitution(s) into {}",
                target.display()
            );
            let outcome = assay::assimilate(AssimilateConfig {
                target,
                proven_sources: proven,
                candidate_id: candidate,
                from,
                apply_all: all,
                dry_run,
            })?;
            if let Some(path) = &output {
                let json = serde_json::to_string_pretty(&outcome)?;
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                fs::write(path, json)?;
                qprintln!(
                    cli.quiet,
                    "Assimilation outcome saved to: {}",
                    path.display()
                );
            } else if cli.quiet {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                println!("\nAssimilate: {} action(s)", outcome.applied.len());
                for r in &outcome.applied {
                    println!(
                        "  [{}] {:?} -> {}",
                        r.candidate_id,
                        r.action,
                        r.destination.display()
                    );
                    if !r.pending_callsite_rewires.is_empty() {
                        println!(
                            "      {} call site(s) still need manual rewiring:",
                            r.pending_callsite_rewires.len()
                        );
                        for h in &r.pending_callsite_rewires {
                            println!("        {}:{}", h.file.display(), h.line);
                        }
                    }
                }
                for n in &outcome.notes {
                    println!("  note: {}", n);
                }
            }
        }

        Commands::Aggregate {
            proofs,
            labels,
            covers,
            report,
            output,
        } => {
            let mut label_map: HashMap<String, String> = HashMap::new();
            for kv in &labels {
                let (p, name) = parse_kv(kv)?;
                label_map.insert(p, name);
            }
            let mut covers_map: HashMap<String, Vec<aggregate::Coverage>> = HashMap::new();
            for kv in &covers {
                let (p, spec) = parse_kv(kv)?;
                let cov = aggregate::parse_coverage_spec(&spec)
                    .ok_or_else(|| anyhow!("invalid --covers spec '{}'", spec))?;
                covers_map.entry(p).or_default().push(cov);
            }
            let proof_inputs: Vec<ProofInput> = proofs
                .into_iter()
                .map(|path| {
                    let key = path.to_string_lossy().to_string();
                    ProofInput {
                        label: label_map.get(&key).cloned(),
                        covers: covers_map.get(&key).cloned().unwrap_or_default(),
                        path,
                    }
                })
                .collect();
            let agg = aggregate::run(AggregateConfig {
                proofs: proof_inputs,
                base_report: report,
            })?;
            let path = output.unwrap_or_else(default_aggregate_report_path);
            aggregate::write_report(&agg, &path)?;
            if !cli.quiet {
                println!(
                    "\nAggregate: {} proof artifact(s) folded in",
                    agg.aggregated_proofs.len()
                );
                for p in &agg.aggregated_proofs {
                    let short = &p.hash.hex[..p.hash.hex.len().min(16)];
                    println!(
                        "  {} [{:?}] {:?}  {}:{}…",
                        p.friendly_name, p.prover, p.verdict, p.hash.algorithm, short
                    );
                }
                if !agg.reconciliations.is_empty() {
                    println!("  reconciliations:");
                    for r in &agg.reconciliations {
                        println!(
                            "    {:?}: {} ({} finding(s)) — {}",
                            r.effect, r.subject, r.affected_findings, r.detail
                        );
                    }
                }
                println!("  TRUST: {}", agg.trust_disclaimer);
            }
            qprintln!(cli.quiet, "Aggregate report saved to: {}", path.display());
        }
    }

    Ok(())
}
