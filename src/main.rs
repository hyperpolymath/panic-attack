// SPDX-License-Identifier: PMPL-1.0-or-later

//! panic-attack: Universal stress testing and logic-based bug signature detection
//!
//! A tool for stress testing programs across multiple attack axes (CPU, memory, disk, network,
//! concurrency) and detecting bug signatures using logic programming techniques inspired by
//! Mozart/Oz and Datalog.

mod a2ml;
mod abduct;
mod adjudicate;
mod ambush;
mod amuck;
mod assail;
mod attestation;
mod attack;
mod axial;
mod diagnostics;
mod i18n;
mod kanren;
mod kin;
mod panll;
mod report;
mod signatures;
mod storage;
mod assemblyline;
mod mass_panic;
mod notify;
mod types;

extern crate walkdir;

use crate::a2ml::{Manifest, ReportBundleKind};
use crate::abduct::{
    AbductConfig, DependencyScope, ExecutionCommand as AbductExecutionCommand, TimeMode,
};
use crate::adjudicate::AdjudicateConfig;
use crate::amuck::{AmuckConfig, AmuckPreset, ExecutionCommand as AmuckExecutionCommand};
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
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
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
#[command(version = "2.0.0")]
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

        /// Export kanren logic facts as Logtalk predicates for hypatia integration
        #[arg(long, value_name = "PATH")]
        logtalk: Option<PathBuf>,
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
    },

    /// GUI review of a saved report
    Gui {
        /// Assault report JSON file
        #[arg(value_name = "REPORT")]
        report: PathBuf,
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

    /// Generate shell completions for the specified shell
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: ShellArg,
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

fn build_attack_overrides(
    profile_path: Option<PathBuf>,
    args: Vec<String>,
    axis_args: Vec<String>,
    probe: Option<ProbeModeArg>,
) -> Result<(Vec<String>, HashMap<AttackAxis, Vec<String>>, ProbeMode)> {
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
            eprintln!("warning: failed to read AI.a2ml: {}", err);
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
            logtalk,
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
                Some(attestation::AttestationChainBuilder::begin(&target, &cli_args)?)
            } else {
                None
            };

            let report = if let Some(ref mut builder) = chain_builder {
                // Attested mode: use the analyzer with an evidence accumulator
                let analyzer = if verbose {
                    assail::analyzer::Analyzer::new_verbose(&target)?
                } else {
                    assail::analyzer::Analyzer::new(&target)?
                };
                analyzer.analyze_with_accumulator(Some(builder.accumulator()))?
            } else if verbose {
                assail::analyze_verbose(&target)?
            } else {
                assail::analyze(&target)?
            };

            let report_json = serde_json::to_string_pretty(&report)?;

            if let Some(output_path) = &output {
                fs::write(output_path, &report_json)?;
                qprintln!(cli.quiet, "Report saved to: {}", output_path.display());
            } else if !cli.quiet {
                println!("\nAssail Summary:");
                println!("  Language: {:?}", report.language);
                println!("  Weak points: {}", report.weak_points.len());
                println!("  Recommended attacks: {:?}", report.recommended_attacks);
            }

            // Seal and write attestation sidecar
            if let Some(builder) = chain_builder {
                let envelope = builder.seal(
                    report_json.as_bytes(),
                    signing_key.as_deref(),
                )?;
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

            // Export kanren facts as Logtalk predicates for hypatia
            if let Some(logtalk_path) = &logtalk {
                let db = assail::build_logic_db(&report);
                kanren::write_logtalk_export(&db, logtalk_path)?;
                qprintln!(
                    cli.quiet,
                    "Logtalk export written to: {}",
                    logtalk_path.display()
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
                axial::convert_markdown_with_pandoc(
                    &markdown_path,
                    &target_format,
                    &pandoc_path,
                )?;
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

            let content = fs::read_to_string(&report_path)?;
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
            let content = fs::read_to_string(&report)?;
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

        Commands::Tui { report } => {
            let content = fs::read_to_string(&report)?;
            let assault_report: AssaultReport = serde_json::from_str(&content)?;
            ReportTui::run(&assault_report)?;
        }

        Commands::Gui { report } => {
            let content = fs::read_to_string(&report)?;
            let assault_report: AssaultReport = serde_json::from_str(&content)?;
            report::ReportGui::run(assault_report)?;
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
            let target = path.unwrap_or_else(|| PathBuf::from("AI.a2ml"));
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
                        println!("Incremental mode: first run (cache will be saved to {})", cf.display());
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
            let content = fs::read_to_string(&report_path)
                .with_context(|| format!("reading assemblyline report {}", report_path.display()))?;
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
            qprintln!(cli.quiet, "Notification written to: {}", output_path.display());

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
            let mut metrics = assail_report
                .migration_metrics
                .clone()
                .unwrap_or_else(|| {
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
                MigrationDiffFormatArg::Markdown => {
                    report::migration::format_diff_markdown(&diff)
                }
                MigrationDiffFormatArg::Json => {
                    serde_json::to_string_pretty(&diff)?
                }
            };

            if let Some(out_path) = output {
                fs::write(&out_path, &content)?;
                qprintln!(cli.quiet, "Migration diff written to: {}", out_path.display());
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

        Commands::Temporal { action } => {
            match action {
                TemporalAction::List { verisimdb_dir } => {
                    let snapshots = mass_panic::temporal::list_snapshots(&verisimdb_dir)?;
                    if snapshots.is_empty() {
                        println!("No temporal snapshots found.");
                    } else {
                        println!(
                            "{:<6} {:<28} {:<8} {:<10} {}",
                            "SEQ", "TIMESTAMP", "NODES", "HEALTH", "LABEL"
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
                    let older_image =
                        mass_panic::temporal::load_snapshot_image(&older_entry)?;
                    let newer_image =
                        mass_panic::temporal::load_snapshot_image(&newer_entry)?;

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
                                verisimdb_dir.join(format!(
                                    "diff-{}-{}.panll.json",
                                    from_seq, to_seq
                                ))
                            });
                        panll::write_temporal_export(&diff, &panll_path)?;
                        println!("PanLL temporal export: {}", panll_path.display());
                    }
                }
            }

            return Ok(());
        }
    }

    Ok(())
}
