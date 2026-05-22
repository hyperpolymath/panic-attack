// SPDX-License-Identifier: MPL-2.0

//! panic-attack: Universal stress testing and logic-based bug signature detection
//!
//! A tool for stress testing programs across multiple attack axes (CPU, memory, disk, network,
//! concurrency) and detecting bug signatures using logic programming techniques inspired by
//! Mozart/Oz and Datalog.

mod a2ml;
mod abduct;
mod ambush;
mod amuck;
mod assail;
mod attack;
mod diagnostics;
mod kanren;
mod panll;
mod report;
mod signatures;
mod storage;
mod types;

use crate::a2ml::Manifest;
use crate::abduct::{
    AbductConfig, DependencyScope, ExecutionCommand as AbductExecutionCommand, TimeMode,
};
use crate::amuck::{AmuckConfig, AmuckPreset, ExecutionCommand as AmuckExecutionCommand};
use crate::attack::AttackProfile;
use crate::report::{format_diff, load_report, ReportOutputFormat, ReportTui, ReportView};
use crate::storage::{latest_reports, persist_report};
use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
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

    /// Run panic-attack self-diagnostics for Hypatia/gitbot-fleet visibility
    Diagnostics {
        /// Alternate AI manifest file (default: AI.a2ml)
        #[arg(long, value_name = "PATH")]
        manifest: Option<PathBuf>,
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

fn main() -> Result<()> {
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
        } => {
            qprintln!(
                cli.quiet,
                "Running assail analysis on: {}",
                target.display()
            );

            let report = if verbose {
                assail::analyze_verbose(&target)?
            } else {
                assail::analyze(&target)?
            };

            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&report)?;
                fs::write(&output_path, json)?;
                qprintln!(cli.quiet, "Report saved to: {}", output_path.display());
            } else if !cli.quiet {
                println!("\nAssail Summary:");
                println!("  Language: {:?}", report.language);
                println!("  Weak points: {}", report.weak_points.len());
                println!("  Recommended attacks: {:?}", report.recommended_attacks);
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
    }

    Ok(())
}
