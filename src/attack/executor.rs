// SPDX-License-Identifier: PMPL-1.0-or-later

//! Attack execution engine

use crate::assail::patterns::PatternDetector;
use crate::attack::strategies::*;
use crate::signatures::SignatureEngine;
use crate::types::*;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct AttackRun {
    output: Output,
    peak_memory: u64,
}

pub struct AttackExecutor {
    config: AttackConfig,
    patterns: Vec<AttackPattern>,
}

impl AttackExecutor {
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config,
            patterns: Vec::new(),
        }
    }

    pub fn with_patterns(
        config: AttackConfig,
        language: Language,
        frameworks: &[Framework],
    ) -> Self {
        let patterns = PatternDetector::patterns_for(language, frameworks);
        Self { config, patterns }
    }

    pub fn execute(&self) -> Result<Vec<AttackResult>> {
        let mut results = Vec::new();
        // Probe cache avoids re-running `--help` for every axis when probing is enabled.
        let mut probe_cache: HashMap<std::path::PathBuf, Option<String>> = HashMap::new();

        for program in &self.config.target_programs {
            let probe_text = if self.config.probe_mode == ProbeMode::Always {
                probe_cache
                    .entry(program.clone())
                    .or_insert_with(|| Self::probe_help(program))
                    .clone()
            } else {
                None
            };

            for axis in &self.config.axes {
                println!("Attacking {:?} on axis {:?}...", program, axis);

                if let Some(help_text) = &probe_text {
                    // In probe mode, skip axes whose required flags are clearly unsupported.
                    let required_flags = self.required_flags_for_axis(*axis);
                    if !required_flags.is_empty()
                        && !required_flags.iter().all(|flag| help_text.contains(flag))
                    {
                        results.push(AttackResult {
                            program: program.clone(),
                            axis: *axis,
                            success: false,
                            skipped: true,
                            skip_reason: Some(format!(
                                "probe: missing flags [{}]",
                                required_flags.join(", ")
                            )),
                            exit_code: None,
                            duration: std::time::Duration::from_secs(0),
                            peak_memory: 0,
                            crashes: Vec::new(),
                            signatures_detected: Vec::new(),
                        });
                        continue;
                    }
                }

                let result = self.execute_single_attack(program, *axis)?;
                results.push(result);
            }
        }

        Ok(results)
    }

    fn execute_single_attack(
        &self,
        program: &std::path::PathBuf,
        axis: AttackAxis,
    ) -> Result<AttackResult> {
        let strategy = self.select_strategy(axis);
        println!("  Strategy: {}", strategy.description());

        // Log applicable patterns for this axis
        let applicable: Vec<_> = self
            .patterns
            .iter()
            .filter(|p| p.applicable_axes.contains(&axis))
            .collect();
        if !applicable.is_empty() {
            println!("  Applicable patterns:");
            for pat in &applicable {
                println!("    - {}: {}", pat.name, pat.description);
            }
        }

        let start = Instant::now();

        // Execute attack based on strategy
        let run = if let Some(custom_args) = self.config.axis_args.get(&axis) {
            self.attack_custom(program, axis, custom_args)?
        } else {
            match strategy {
                AttackStrategy::CpuStress => self.attack_cpu(program)?,
                AttackStrategy::MemoryExhaustion => self.attack_memory(program)?,
                AttackStrategy::DiskThrashing => self.attack_disk(program)?,
                AttackStrategy::NetworkFlood => self.attack_network(program)?,
                AttackStrategy::ConcurrencyStorm => self.attack_concurrency(program)?,
                AttackStrategy::TimeBomb => self.attack_time(program)?,
            }
        };

        let duration = start.elapsed();
        let exit_code = run.output.status.code();

        // Auto-probe fallback: convert obvious flag incompatibility into a skip with context.
        if self.config.probe_mode != ProbeMode::Never && Self::is_unsupported_flags(&run.output) {
            let fallback = Self::fallback_run(program);
            let reason = Self::unsupported_reason(&run.output, fallback.as_ref());
            return Ok(AttackResult {
                program: program.clone(),
                axis,
                success: false,
                skipped: true,
                skip_reason: Some(reason),
                exit_code,
                duration,
                peak_memory: run.peak_memory,
                crashes: Vec::new(),
                signatures_detected: Vec::new(),
            });
        }

        let success = run.output.status.success();
        let mut crashes = Vec::new();
        if !success {
            crashes.push(Self::crash_from_output(&run.output));
        }

        // Run signature detection on any crashes
        let signatures_detected = if !crashes.is_empty() {
            let engine = SignatureEngine::new();
            crashes
                .iter()
                .flat_map(|crash| engine.detect_from_crash(crash))
                .collect()
        } else {
            Vec::new()
        };

        Ok(AttackResult {
            program: program.clone(),
            axis,
            success,
            skipped: false,
            skip_reason: None,
            exit_code,
            duration,
            peak_memory: run.peak_memory,
            crashes,
            signatures_detected,
        })
    }

    fn select_strategy(&self, axis: AttackAxis) -> AttackStrategy {
        match axis {
            AttackAxis::Cpu => AttackStrategy::CpuStress,
            AttackAxis::Memory => AttackStrategy::MemoryExhaustion,
            AttackAxis::Disk => AttackStrategy::DiskThrashing,
            AttackAxis::Network => AttackStrategy::NetworkFlood,
            AttackAxis::Concurrency => AttackStrategy::ConcurrencyStorm,
            AttackAxis::Time => AttackStrategy::TimeBomb,
        }
    }

    fn attack_cpu(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // CPU stress: run program with high computational load
        let iterations = (1000.0 * self.config.intensity.multiplier()) as u64;

        let args = self.args_with_common(vec!["--iterations".to_string(), iterations.to_string()]);
        let output = Self::run_program(program, &args)?;
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn attack_memory(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // Memory exhaustion: allocate large amounts of memory
        let memory_mb = (1024.0 * self.config.intensity.multiplier()) as u64;

        let args = self.args_with_common(vec!["--allocate-mb".to_string(), memory_mb.to_string()]);
        let output = Self::run_program(program, &args)?;
        Ok(AttackRun {
            output,
            peak_memory: memory_mb * 1024 * 1024,
        })
    }

    fn attack_disk(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // Disk I/O stress
        let file_count = (100.0 * self.config.intensity.multiplier()) as u64;

        let args = self.args_with_common(vec!["--write-files".to_string(), file_count.to_string()]);
        let output = Self::run_program(program, &args)?;
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn attack_network(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // Network flood
        let connections = (100.0 * self.config.intensity.multiplier()) as u64;

        let args =
            self.args_with_common(vec!["--connections".to_string(), connections.to_string()]);
        let output = Self::run_program(program, &args)?;
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn attack_concurrency(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // Concurrency storm: spawn many threads/tasks
        let threads = (50.0 * self.config.intensity.multiplier()) as u64;

        let args = self.args_with_common(vec!["--threads".to_string(), threads.to_string()]);
        let output = Self::run_program(program, &args)?;
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn attack_time(&self, program: &std::path::PathBuf) -> Result<AttackRun> {
        // Time-based attacks: run for extended duration
        let duration_secs = if self.config.duration.as_secs() > 0 {
            self.config.duration.as_secs()
        } else {
            (60.0 * self.config.intensity.multiplier()) as u64
        };
        let args = self.args_with_common(Vec::new());
        let output = Self::run_program_with_timeout(program, &args, duration_secs)?;
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn attack_custom(
        &self,
        program: &std::path::PathBuf,
        axis: AttackAxis,
        custom_args: &[String],
    ) -> Result<AttackRun> {
        let args = self.args_with_common(custom_args.to_vec());
        let output = if axis == AttackAxis::Time {
            let duration_secs = if self.config.duration.as_secs() > 0 {
                self.config.duration.as_secs()
            } else {
                (60.0 * self.config.intensity.multiplier()) as u64
            };
            Self::run_program_with_timeout(program, &args, duration_secs)?
        } else {
            Self::run_program(program, &args)?
        };
        Ok(AttackRun {
            output,
            peak_memory: 0,
        })
    }

    fn crash_from_output(output: &Output) -> CrashReport {
        CrashReport {
            schema_version: "2.5".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            signal: Self::extract_signal(&output.stderr),
            backtrace: Self::extract_backtrace(&output.stderr),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        }
    }

    fn args_with_common(&self, mut args: Vec<String>) -> Vec<String> {
        if self.config.common_args.is_empty() {
            return args;
        }
        // Common args always prefix axis args so profile defaults remain stable.
        let mut combined = self.config.common_args.clone();
        combined.append(&mut args);
        combined
    }

    fn run_program(program: &std::path::PathBuf, args: &[String]) -> Result<Output> {
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("Failed to execute program")
    }

    fn run_program_with_timeout(
        program: &std::path::PathBuf,
        args: &[String],
        duration_secs: u64,
    ) -> Result<Output> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to execute program")?;

        let start = Instant::now();
        let limit = Duration::from_secs(duration_secs);
        loop {
            if let Some(_status) = child.try_wait()? {
                break;
            }
            if start.elapsed() >= limit {
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        Ok(child.wait_with_output()?)
    }

    fn probe_help(program: &std::path::PathBuf) -> Option<String> {
        let output = Command::new(program).arg("--help").output().ok()?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Some(combined.to_lowercase())
    }

    fn required_flags_for_axis(&self, axis: AttackAxis) -> Vec<String> {
        let mut required = Self::flag_tokens_from_args(&self.config.common_args);
        if let Some(custom) = self.config.axis_args.get(&axis) {
            required.extend(Self::flag_tokens_from_args(custom));
        } else {
            // Built-in strategy flags are used only when no axis override is provided.
            let built_in = match axis {
                AttackAxis::Cpu => vec!["--iterations"],
                AttackAxis::Memory => vec!["--allocate-mb"],
                AttackAxis::Disk => vec!["--write-files"],
                AttackAxis::Network => vec!["--connections"],
                AttackAxis::Concurrency => vec!["--threads"],
                AttackAxis::Time => Vec::new(),
            };
            required.extend(built_in.into_iter().map(|s| s.to_string()));
        }
        required.sort();
        required.dedup();
        required
    }

    fn flag_tokens_from_args(args: &[String]) -> Vec<String> {
        args.iter()
            .filter_map(|arg| {
                if arg.starts_with('-') {
                    Some(arg.split('=').next().unwrap_or(arg.as_str()).to_lowercase())
                } else {
                    None
                }
            })
            .collect()
    }

    fn is_unsupported_flags(output: &Output) -> bool {
        if output.status.success() {
            return false;
        }
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        let combined = combined.to_lowercase();
        let patterns = [
            "unexpected argument",
            "unknown argument",
            "unknown option",
            "unrecognized option",
            "usage:",
        ];
        patterns.iter().any(|pat| combined.contains(pat))
    }

    fn fallback_run(program: &std::path::PathBuf) -> Option<Output> {
        Command::new(program)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .ok()
    }

    fn unsupported_reason(output: &Output, fallback: Option<&Output>) -> String {
        let mut reason = "target does not accept attack flags".to_string();
        if let Some(code) = output.status.code() {
            reason.push_str(&format!(" (exit code {})", code));
        }
        // Baseline output gives operators a quick signal about target health without attack flags.
        if let Some(fallback_output) = fallback {
            let fallback_code = fallback_output.status.code();
            let fallback_note = match fallback_code {
                Some(code) => format!("baseline run exit code {}", code),
                None => "baseline run terminated by signal".to_string(),
            };
            reason.push_str(&format!("; {}", fallback_note));
        }
        reason
    }

    fn extract_signal(stderr: &[u8]) -> Option<String> {
        let stderr_str = String::from_utf8_lossy(stderr);
        if stderr_str.contains("SIGSEGV") {
            Some("SIGSEGV".to_string())
        } else if stderr_str.contains("SIGABRT") {
            Some("SIGABRT".to_string())
        } else if stderr_str.contains("SIGILL") {
            Some("SIGILL".to_string())
        } else {
            None
        }
    }

    fn extract_backtrace(stderr: &[u8]) -> Option<String> {
        let stderr_str = String::from_utf8_lossy(stderr);
        if stderr_str.contains("backtrace") || stderr_str.contains("stack backtrace") {
            Some(stderr_str.to_string())
        } else {
            None
        }
    }
}
