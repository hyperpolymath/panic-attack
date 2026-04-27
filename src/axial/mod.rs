// SPDX-License-Identifier: PMPL-1.0-or-later

//! Axial observer: observe target reactions across attack axes from tool
//! executions and report artifacts.

use crate::abduct::AbductReport;
use crate::amuck::AmuckReport;
use crate::i18n::{t, Lang};
use crate::report;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ExecutionCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AxialConfig {
    pub target: PathBuf,
    pub execute: Option<ExecutionCommand>,
    pub repeat: usize,
    pub timeout_secs: u64,
    pub reports: Vec<PathBuf>,
    pub head_lines: usize,
    pub tail_lines: usize,
    pub grep_patterns: Vec<String>,
    pub agrep_patterns: Vec<String>,
    pub agrep_distance: usize,
    pub lang: Lang,
    pub aspell: bool,
    pub aspell_lang: Option<String>,
}

#[derive(Debug, Clone)]
struct RunOnceConfig<'a> {
    command: &'a ExecutionCommand,
    run_index: usize,
    target: &'a Path,
    timeout_secs: u64,
    head_lines: usize,
    tail_lines: usize,
    matcher: &'a PatternMatcher,
    use_aspell: bool,
    aspell_lang: &'a str,
}

fn axial_schema_version() -> String {
    "2.5".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxialReport {
    #[serde(default = "axial_schema_version")]
    pub schema_version: String,
    pub created_at: String,
    pub target: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_program: Option<String>,
    pub repeat: usize,
    pub observed_runs: usize,
    pub observed_reports: usize,
    pub language: String,
    #[serde(default)]
    pub run_observations: Vec<RunObservation>,
    #[serde(default)]
    pub report_observations: Vec<ReportObservation>,
    #[serde(default)]
    pub signal_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aspell: Option<SpellcheckSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunObservation {
    pub run_index: usize,
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub stdout_head: Vec<String>,
    #[serde(default)]
    pub stdout_tail: Vec<String>,
    #[serde(default)]
    pub stderr_head: Vec<String>,
    #[serde(default)]
    pub stderr_tail: Vec<String>,
    #[serde(default)]
    pub matches: Vec<PatternMatch>,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spellcheck: Option<SpellcheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportObservation {
    pub path: PathBuf,
    pub kind: String,
    #[serde(default)]
    pub excerpt_head: Vec<String>,
    #[serde(default)]
    pub excerpt_tail: Vec<String>,
    #[serde(default)]
    pub matches: Vec<PatternMatch>,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spellcheck: Option<SpellcheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub mode: String,
    pub pattern: String,
    pub line_no: usize,
    pub line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distance: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub severity: String,
    pub name: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellcheckResult {
    pub enabled: bool,
    pub lang: String,
    #[serde(default)]
    pub misspellings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellcheckSummary {
    pub lang: String,
    pub total_misspellings: usize,
    pub run_observations_with_misspellings: usize,
    pub report_observations_with_misspellings: usize,
}

pub fn run(config: AxialConfig) -> Result<AxialReport> {
    if !config.target.exists() {
        return Err(anyhow!("target {} does not exist", config.target.display()));
    }
    if config.repeat == 0 {
        return Err(anyhow!("--repeat must be at least 1"));
    }
    if config.timeout_secs == 0 {
        return Err(anyhow!("--timeout must be at least 1 second"));
    }
    if config.head_lines > 2000 || config.tail_lines > 2000 {
        return Err(anyhow!("--head/--tail values above 2000 are not allowed"));
    }
    if config.agrep_distance > 12 {
        return Err(anyhow!("--agrep-distance above 12 is not allowed"));
    }
    if config.execute.is_none() && config.reports.is_empty() {
        return Err(anyhow!(
            "axial needs --exec-program or at least one --report"
        ));
    }

    let aspell_lang = config
        .aspell_lang
        .clone()
        .unwrap_or_else(|| config.lang.aspell_code().to_string());

    // Compile search strategy once so run and report observations stay consistent.
    let matcher = PatternMatcher {
        grep_patterns: config.grep_patterns.clone(),
        agrep_patterns: config.agrep_patterns.clone(),
        agrep_distance: config.agrep_distance,
    };

    let mut run_observations = Vec::new();
    if let Some(exec) = &config.execute {
        // Repeated observations help surface flaky, timing-dependent reactions.
        for run_idx in 0..config.repeat {
            let run_config = RunOnceConfig {
                command: exec,
                run_index: run_idx + 1,
                target: &config.target,
                timeout_secs: config.timeout_secs,
                head_lines: config.head_lines,
                tail_lines: config.tail_lines,
                matcher: &matcher,
                use_aspell: config.aspell,
                aspell_lang: &aspell_lang,
            };
            run_observations.push(run_once(run_config)?);
        }
    }

    let mut report_observations = Vec::new();
    for path in &config.reports {
        // Report observation reuses the same matcher to align artifact and runtime signals.
        report_observations.push(observe_report(
            path,
            config.head_lines,
            config.tail_lines,
            &matcher,
            config.aspell,
            &aspell_lang,
        )?);
    }

    // Aggregate cross-source signals into a compact map for triage and recommendations.
    let mut signal_counts = BTreeMap::<String, usize>::new();
    for run in &run_observations {
        for signal in &run.signals {
            *signal_counts.entry(signal.name.clone()).or_insert(0) += 1;
        }
    }
    for report_obs in &report_observations {
        for signal in &report_obs.signals {
            *signal_counts.entry(signal.name.clone()).or_insert(0) += 1;
        }
    }

    let recommendations = build_recommendations(&signal_counts, config.lang);
    let aspell_summary = if config.aspell {
        // Spellcheck metrics are useful when scanning social/UX payloads for suspicious wording drift.
        let (total_misspellings, runs_with, reports_with) =
            summarize_spellcheck(&run_observations, &report_observations);
        if total_misspellings > 0 {
            *signal_counts
                .entry("spelling_signal".to_string())
                .or_insert(0) += total_misspellings;
        }
        Some(SpellcheckSummary {
            lang: aspell_lang.clone(),
            total_misspellings,
            run_observations_with_misspellings: runs_with,
            report_observations_with_misspellings: reports_with,
        })
    } else {
        None
    };

    Ok(AxialReport {
        schema_version: "2.5".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        target: config.target,
        executed_program: config.execute.as_ref().map(|e| e.program.clone()),
        repeat: config.repeat,
        observed_runs: run_observations.len(),
        observed_reports: report_observations.len(),
        language: config.lang.code().to_string(),
        run_observations,
        report_observations,
        signal_counts,
        recommendations,
        aspell: aspell_summary,
    })
}

pub fn write_report(report: &AxialReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report parent directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing axial report")?;
    fs::write(path, json).with_context(|| format!("writing report {}", path.display()))?;
    Ok(())
}

pub fn write_markdown(report: &AxialReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating markdown parent {}", parent.display()))?;
    }
    let lang = Lang::from_code(&report.language).unwrap_or_default();
    // Keep markdown export stable and machine-diff-friendly for CI artifact review.
    let mut lines = Vec::new();
    lines.push(format!("# {}", t(lang, "axial.title")));
    lines.push(String::new());
    lines.push(format!(
        "{}: `{}`",
        t(lang, "axial.target"),
        report.target.display()
    ));
    lines.push(format!(
        "{}: `{}`",
        t(lang, "axial.created_at"),
        report.created_at
    ));
    lines.push(format!(
        "{}: `{}`",
        t(lang, "axial.language"),
        report.language
    ));
    lines.push(format!(
        "{}: {}",
        t(lang, "axial.observed_runs"),
        report.observed_runs
    ));
    lines.push(format!(
        "{}: {}",
        t(lang, "axial.observed_reports"),
        report.observed_reports
    ));
    lines.push(String::new());
    lines.push(format!("## {}", t(lang, "axial.signals")));
    if report.signal_counts.is_empty() {
        lines.push(format!("- {}", t(lang, "axial.none")));
    } else {
        for (name, count) in &report.signal_counts {
            lines.push(format!("- `{}`: {}", name, count));
        }
    }
    lines.push(String::new());
    lines.push(format!("## {}", t(lang, "axial.recommendations")));
    for rec in &report.recommendations {
        lines.push(format!("- {}", rec));
    }
    if let Some(spell) = &report.aspell {
        lines.push(String::new());
        lines.push(format!("## {}", t(lang, "axial.spelling")));
        lines.push(format!("- lang: `{}`", spell.lang));
        lines.push(format!(
            "- total misspellings: {}",
            spell.total_misspellings
        ));
        lines.push(format!(
            "- runs with misspellings: {}",
            spell.run_observations_with_misspellings
        ));
        lines.push(format!(
            "- reports with misspellings: {}",
            spell.report_observations_with_misspellings
        ));
    }

    fs::write(path, lines.join("\n"))
        .with_context(|| format!("writing markdown report {}", path.display()))?;
    Ok(())
}

pub fn convert_markdown_with_pandoc(markdown: &Path, to: &str, output: &Path) -> Result<()> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating pandoc parent {}", parent.display()))?;
    }
    // Use pandoc as an optional post-processing step; core axial output remains JSON/Markdown.
    let out = Command::new("pandoc")
        .arg(markdown)
        .arg("-f")
        .arg("markdown")
        .arg("-t")
        .arg(to)
        .arg("-o")
        .arg(output)
        .output()
        .context("running pandoc")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        return Err(anyhow!("pandoc failed: {}", stderr.trim()));
    }
    Ok(())
}

fn run_once(config: RunOnceConfig) -> Result<RunObservation> {
    let target_token = config.target.to_string_lossy().to_string();
    let mut args = config
        .command
        .args
        .iter()
        .map(|arg| arg.replace("{target}", &target_token))
        .collect::<Vec<_>>();
    if args.is_empty() || !args.iter().any(|arg| arg == &target_token) {
        args.push(target_token.clone());
    }

    let started = Instant::now();
    let mut child = Command::new(&config.command.program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("executing {}", config.command.program))?;

    // Hard timeout prevents long-running probes from stalling full campaigns.
    let limit = Duration::from_secs(config.timeout_secs);
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= limit {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let output = child.wait_with_output()?;
    let stdout = clamp_output(String::from_utf8_lossy(&output.stdout).to_string());
    let stderr = clamp_output(String::from_utf8_lossy(&output.stderr).to_string());
    let stdout_head = head_lines_of(&stdout, config.head_lines);
    let stdout_tail = tail_lines_of(&stdout, config.tail_lines);
    let stderr_head = head_lines_of(&stderr, config.head_lines);
    let stderr_tail = tail_lines_of(&stderr, config.tail_lines);

    let combined = format!("{}\n{}", stdout, stderr);
    let matches = config.matcher.scan(&combined);
    let spellcheck = if config.use_aspell {
        Some(spellcheck_text(&combined, config.aspell_lang))
    } else {
        None
    };
    // Signal extraction remains heuristic-by-design: fast triage first, deep investigation later.
    let signals = detect_signals(
        &stdout,
        &stderr,
        output.status.code(),
        timed_out,
        "run-output",
    );

    Ok(RunObservation {
        run_index: config.run_index,
        success: output.status.success() && !timed_out,
        exit_code: output.status.code(),
        duration_ms: started.elapsed().as_millis(),
        timed_out,
        stdout,
        stderr,
        stdout_head,
        stdout_tail,
        stderr_head,
        stderr_tail,
        matches,
        signals,
        spellcheck,
    })
}

fn observe_report(
    path: &Path,
    head_lines: usize,
    tail_lines: usize,
    matcher: &PatternMatcher,
    use_aspell: bool,
    aspell_lang: &str,
) -> Result<ReportObservation> {
    let content =
        fs::read_to_string(path).with_context(|| format!("reading report {}", path.display()))?;
    let excerpt_head = head_lines_of(&content, head_lines);
    let excerpt_tail = tail_lines_of(&content, tail_lines);
    let matches = matcher.scan(&content);
    let spellcheck = if use_aspell {
        Some(spellcheck_text(&content, aspell_lang))
    } else {
        None
    };

    // Parse order prefers assault first because its schema overlaps less with custom report types.
    if let Ok(assault) = report::load_report(path) {
        let mut signals = Vec::new();
        if assault.total_crashes > 0 {
            signals.push(Signal {
                severity: "high".to_string(),
                name: "crash_signal".to_string(),
                evidence: format!("{} crashes in {}", assault.total_crashes, path.display()),
            });
        }
        if assault
            .attack_results
            .iter()
            .any(|r| !r.skipped && !r.success)
        {
            signals.push(Signal {
                severity: "medium".to_string(),
                name: "attack_failure_signal".to_string(),
                evidence: "failed attack results in assault report".to_string(),
            });
        }
        return Ok(ReportObservation {
            path: path.to_path_buf(),
            kind: "assault".to_string(),
            excerpt_head,
            excerpt_tail,
            matches,
            signals,
            spellcheck,
        });
    }

    if let Ok(amuck) = serde_json::from_str::<AmuckReport>(&content) {
        let mut signals = Vec::new();
        let apply_errors = amuck
            .outcomes
            .iter()
            .filter(|o| o.apply_error.is_some())
            .count();
        if apply_errors > 0 {
            signals.push(Signal {
                severity: "medium".to_string(),
                name: "mutation_apply_error_signal".to_string(),
                evidence: format!("{} amuck mutation apply errors", apply_errors),
            });
        }
        let exec_failures = amuck
            .outcomes
            .iter()
            .filter(|o| o.execution.as_ref().is_some_and(|e| !e.success))
            .count();
        if exec_failures > 0 {
            signals.push(Signal {
                severity: "medium".to_string(),
                name: "mutation_exec_failure_signal".to_string(),
                evidence: format!("{} amuck execution failures", exec_failures),
            });
        }
        return Ok(ReportObservation {
            path: path.to_path_buf(),
            kind: "amuck".to_string(),
            excerpt_head,
            excerpt_tail,
            matches,
            signals,
            spellcheck,
        });
    }

    if let Ok(abduct) = serde_json::from_str::<AbductReport>(&content) {
        let mut signals = Vec::new();
        if let Some(exe) = &abduct.execution {
            if exe.timed_out {
                signals.push(Signal {
                    severity: "high".to_string(),
                    name: "abduct_timeout_signal".to_string(),
                    evidence: "abduct execution timed out".to_string(),
                });
            } else if !exe.success {
                signals.push(Signal {
                    severity: "medium".to_string(),
                    name: "abduct_exec_failure_signal".to_string(),
                    evidence: "abduct execution failed".to_string(),
                });
            }
        }
        return Ok(ReportObservation {
            path: path.to_path_buf(),
            kind: "abduct".to_string(),
            excerpt_head,
            excerpt_tail,
            matches,
            signals,
            spellcheck,
        });
    }

    Err(anyhow!("unsupported report format: {}", path.display()))
}

fn detect_signals(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
    timed_out: bool,
    evidence_prefix: &str,
) -> Vec<Signal> {
    let mut signals = Vec::new();
    let combined = format!("{}\n{}", stdout, stderr).to_ascii_lowercase();

    if timed_out {
        signals.push(Signal {
            severity: "high".to_string(),
            name: "timeout_signal".to_string(),
            evidence: format!("{}: process timed out", evidence_prefix),
        });
    }

    if combined.contains("sigsegv")
        || combined.contains("segmentation fault")
        || combined.contains("access violation")
    {
        signals.push(Signal {
            severity: "high".to_string(),
            name: "crash_signal".to_string(),
            evidence: format!("{}: segmentation/crash marker", evidence_prefix),
        });
    }

    if combined.contains("panic")
        || combined.contains("fatal")
        || combined.contains("sigabrt")
        || combined.contains("assertion failed")
    {
        signals.push(Signal {
            severity: "high".to_string(),
            name: "panic_signal".to_string(),
            evidence: format!("{}: panic/fatal marker", evidence_prefix),
        });
    }

    if combined.contains("permission denied")
        || combined.contains("read-only file system")
        || combined.contains("operation not permitted")
    {
        signals.push(Signal {
            severity: "info".to_string(),
            name: "lock_reaction_signal".to_string(),
            evidence: format!("{}: lock/permission reaction", evidence_prefix),
        });
    }

    if combined.contains("unknown option")
        || combined.contains("unknown argument")
        || combined.contains("unexpected argument")
    {
        signals.push(Signal {
            severity: "low".to_string(),
            name: "interface_mismatch_signal".to_string(),
            evidence: format!("{}: interface mismatch marker", evidence_prefix),
        });
    }

    if exit_code.is_some_and(|code| code != 0) && signals.is_empty() {
        signals.push(Signal {
            severity: "low".to_string(),
            name: "nonzero_exit_signal".to_string(),
            evidence: format!("{}: non-zero exit code {:?}", evidence_prefix, exit_code),
        });
    }

    signals
}

fn clamp_output(mut value: String) -> String {
    const MAX_LEN: usize = 8192;
    if value.len() > MAX_LEN {
        value.truncate(MAX_LEN);
        value.push_str("\n...<truncated>");
    }
    value
}

fn build_recommendations(signal_counts: &BTreeMap<String, usize>, lang: Lang) -> Vec<String> {
    let mut recommendations = Vec::new();
    if signal_counts.get("crash_signal").copied().unwrap_or(0) > 0 {
        recommendations.push(t(lang, "rec.crash").to_string());
    }
    if signal_counts.get("panic_signal").copied().unwrap_or(0) > 0 {
        recommendations.push(t(lang, "rec.panic").to_string());
    }
    if signal_counts.get("timeout_signal").copied().unwrap_or(0) > 0 {
        recommendations.push(t(lang, "rec.timeout").to_string());
    }
    if recommendations.is_empty() {
        recommendations.push(t(lang, "rec.none").to_string());
    }
    recommendations
}

fn summarize_spellcheck(
    runs: &[RunObservation],
    reports: &[ReportObservation],
) -> (usize, usize, usize) {
    let mut total = 0usize;
    let mut runs_with = 0usize;
    let mut reports_with = 0usize;
    for run in runs {
        if let Some(spell) = &run.spellcheck {
            total += spell.misspellings.len();
            if !spell.misspellings.is_empty() {
                runs_with += 1;
            }
        }
    }
    for report in reports {
        if let Some(spell) = &report.spellcheck {
            total += spell.misspellings.len();
            if !spell.misspellings.is_empty() {
                reports_with += 1;
            }
        }
    }
    (total, runs_with, reports_with)
}

fn spellcheck_text(text: &str, lang: &str) -> SpellcheckResult {
    let output = Command::new("aspell")
        .arg("list")
        .arg("--lang")
        .arg(lang)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(text.as_bytes());
            }
            child.wait_with_output()
        });

    match output {
        Ok(out) if out.status.success() => {
            let mut uniq = BTreeSet::new();
            for word in String::from_utf8_lossy(&out.stdout).lines() {
                let w = word.trim();
                if !w.is_empty() {
                    uniq.insert(w.to_string());
                }
            }
            SpellcheckResult {
                enabled: true,
                lang: lang.to_string(),
                misspellings: uniq.into_iter().collect(),
                error: None,
            }
        }
        Ok(out) => SpellcheckResult {
            enabled: false,
            lang: lang.to_string(),
            misspellings: Vec::new(),
            error: Some(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        },
        Err(err) => SpellcheckResult {
            enabled: false,
            lang: lang.to_string(),
            misspellings: Vec::new(),
            error: Some(err.to_string()),
        },
    }
}

#[derive(Debug, Clone)]
struct PatternMatcher {
    grep_patterns: Vec<String>,
    agrep_patterns: Vec<String>,
    agrep_distance: usize,
}

impl PatternMatcher {
    fn scan(&self, text: &str) -> Vec<PatternMatch> {
        let mut hits = Vec::new();
        for (idx, line) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line_lower = line.to_ascii_lowercase();
            for pattern in &self.grep_patterns {
                if pattern.is_empty() {
                    continue;
                }
                if line_lower.contains(&pattern.to_ascii_lowercase()) {
                    hits.push(PatternMatch {
                        mode: "grep".to_string(),
                        pattern: pattern.clone(),
                        line_no,
                        line: line.to_string(),
                        distance: None,
                    });
                }
            }
            for pattern in &self.agrep_patterns {
                if pattern.is_empty() {
                    continue;
                }
                if let Some(distance) = fuzzy_line_distance(
                    &line_lower,
                    &pattern.to_ascii_lowercase(),
                    self.agrep_distance,
                ) {
                    hits.push(PatternMatch {
                        mode: "agrep".to_string(),
                        pattern: pattern.clone(),
                        line_no,
                        line: line.to_string(),
                        distance: Some(distance),
                    });
                }
            }
        }
        hits
    }
}

fn head_lines_of(text: &str, n: usize) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }
    text.lines().take(n).map(|line| line.to_string()).collect()
}

fn tail_lines_of(text: &str, n: usize) -> Vec<String> {
    if n == 0 {
        return Vec::new();
    }
    let lines = text.lines().collect::<Vec<_>>();
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|line| (*line).to_string())
        .collect()
}

fn fuzzy_line_distance(line: &str, pattern: &str, max_dist: usize) -> Option<usize> {
    if pattern.is_empty() {
        return None;
    }
    if line.contains(pattern) {
        return Some(0);
    }

    let mut best = usize::MAX;
    for token in line.split_whitespace() {
        let d = levenshtein(token, pattern);
        if d < best {
            best = d;
        }
    }
    if best <= max_dist {
        return Some(best);
    }

    let plen = pattern.chars().count();
    let min_len = plen.saturating_sub(max_dist).max(1);
    let max_len = plen + max_dist;
    let chars = line.chars().collect::<Vec<_>>();
    for start in 0..chars.len() {
        for len in min_len..=max_len {
            if start + len > chars.len() {
                continue;
            }
            let candidate = chars[start..start + len].iter().collect::<String>();
            let d = levenshtein(&candidate, pattern);
            if d < best {
                best = d;
            }
        }
    }
    if best <= max_dist {
        Some(best)
    } else {
        None
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars = a.chars().collect::<Vec<_>>();
    let b_chars = b.chars().collect::<Vec<_>>();
    if a_chars.is_empty() {
        return b_chars.len();
    }
    if b_chars.is_empty() {
        return a_chars.len();
    }
    let mut prev = (0..=b_chars.len()).collect::<Vec<_>>();
    let mut curr = vec![0usize; b_chars.len() + 1];
    for (i, ac) in a_chars.iter().enumerate() {
        curr[0] = i + 1;
        for (j, bc) in b_chars.iter().enumerate() {
            let cost = if ac == bc { 0 } else { 1 };
            let deletion = prev[j + 1] + 1;
            let insertion = curr[j] + 1;
            let substitution = prev[j] + cost;
            curr[j + 1] = deletion.min(insertion).min(substitution);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b_chars.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amuck::{AmuckOutcome, AmuckReport};
    use tempfile::TempDir;

    #[test]
    fn axial_reads_amuck_report_signals() {
        let dir = TempDir::new().expect("tempdir should create");
        let target = dir.path().join("target.rs");
        fs::write(&target, "fn main() {}\n").expect("target should write");

        let path = dir.path().join("amuck.json");
        let report = AmuckReport {
            created_at: chrono::Utc::now().to_rfc3339(),
            target: target.clone(),
            source_spec: None,
            preset: "dangerous".to_string(),
            max_combinations: 1,
            output_dir: PathBuf::from("runtime/amuck"),
            combinations_planned: 1,
            combinations_run: 0,
            outcomes: vec![AmuckOutcome {
                id: 1,
                name: "bad".to_string(),
                operations: vec!["x".to_string()],
                applied_changes: 0,
                mutated_file: None,
                apply_error: Some("combination produced no change".to_string()),
                execution: None,
            }],
        };
        fs::write(
            &path,
            serde_json::to_string_pretty(&report).expect("serialize should succeed"),
        )
        .expect("report should write");

        let out = run(AxialConfig {
            target,
            execute: None,
            repeat: 1,
            timeout_secs: 30,
            reports: vec![path],
            head_lines: 3,
            tail_lines: 3,
            grep_patterns: vec!["combination".to_string()],
            agrep_patterns: vec!["combinatoin".to_string()],
            agrep_distance: 2,
            lang: Lang::En,
            aspell: false,
            aspell_lang: None,
        })
        .expect("axial should run");

        assert_eq!(out.observed_reports, 1);
        assert!(!out.signal_counts.is_empty());
        assert!(
            !out.report_observations[0].matches.is_empty(),
            "grep/agrep matches expected"
        );
    }

    #[test]
    fn markdown_writer_outputs_report() {
        let dir = TempDir::new().expect("tempdir should create");
        let report = AxialReport {
            schema_version: "2.5".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            target: PathBuf::from("src/main.rs"),
            executed_program: None,
            repeat: 1,
            observed_runs: 0,
            observed_reports: 0,
            language: "en".to_string(),
            run_observations: Vec::new(),
            report_observations: Vec::new(),
            signal_counts: BTreeMap::new(),
            recommendations: vec!["no critical reaction signals observed".to_string()],
            aspell: None,
        };
        let path = dir.path().join("audience.md");
        write_markdown(&report, &path).expect("markdown should write");
        let body = fs::read_to_string(path).expect("markdown should read");
        assert!(body.contains("Axial Report"));
    }
}
