// SPDX-License-Identifier: PMPL-1.0-or-later

//! Amuck mutation runner for stress-testing source files with combination attacks.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// Upper bound on mutation-target source file reads. Amuck operates on a
/// single source file at a time; 64 MiB is well beyond any realistic
/// target and prevents a hostile or runaway input from exhausting memory.
const TARGET_SOURCE_READ_LIMIT: u64 = 64 * 1024 * 1024;

/// Upper bound on mutation spec JSON/YAML reads. Specs are curated,
/// short documents — 4 MiB is two orders of magnitude beyond realistic
/// spec size and still catches a malformed or hostile config.
const SPEC_FILE_READ_LIMIT: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmuckPreset {
    Light,
    Dangerous,
}

#[derive(Debug, Clone)]
pub struct AmuckConfig {
    pub target: PathBuf,
    pub spec_path: Option<PathBuf>,
    pub preset: AmuckPreset,
    pub max_combinations: usize,
    pub output_dir: PathBuf,
    pub execute: Option<ExecutionCommand>,
}

#[derive(Debug, Clone)]
pub struct ExecutionCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MutationOperation {
    ReplaceFirst { from: String, to: String },
    ReplaceAll { from: String, to: String },
    InsertBefore { needle: String, text: String },
    InsertAfter { needle: String, text: String },
    DeleteLinesContaining { needle: String },
    DuplicateLinesContaining { needle: String, times: usize },
    SwapTokens { left: String, right: String },
    AppendText { text: String },
    PrependText { text: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationComboSpec {
    #[serde(default)]
    pub name: Option<String>,
    pub operations: Vec<MutationOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationSpecFile {
    pub combos: Vec<MutationComboSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmuckReport {
    pub created_at: String,
    pub target: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_spec: Option<PathBuf>,
    pub preset: String,
    pub max_combinations: usize,
    pub output_dir: PathBuf,
    pub combinations_planned: usize,
    pub combinations_run: usize,
    pub outcomes: Vec<AmuckOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmuckOutcome {
    pub id: usize,
    pub name: String,
    pub operations: Vec<String>,
    pub applied_changes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutated_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub duration_ms: u128,
    pub stdout: String,
    pub stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spawn_error: Option<String>,
}

pub fn run(config: AmuckConfig) -> Result<AmuckReport> {
    if config.max_combinations == 0 {
        return Err(anyhow!("--max-combinations must be at least 1"));
    }

    if !config.target.exists() {
        return Err(anyhow!(
            "target file {} does not exist",
            config.target.display()
        ));
    }
    if !config.target.is_file() {
        return Err(anyhow!(
            "target path {} is not a file",
            config.target.display()
        ));
    }

    // Source text is loaded once and each combo is applied from the pristine
    // baseline. Cap to TARGET_SOURCE_READ_LIMIT — a larger file is truncated
    // rather than swallowed whole, and mutations apply to that prefix only.
    let source = {
        let mut buf = String::new();
        File::open(&config.target)
            .with_context(|| format!("opening target file {}", config.target.display()))?
            .take(TARGET_SOURCE_READ_LIMIT)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading target file {}", config.target.display()))?;
        buf
    };

    let mut combos = if let Some(spec_path) = &config.spec_path {
        let spec = load_spec(spec_path)?;
        spec.combos
    } else {
        built_in_combinations(config.preset, &source)
    };

    if combos.is_empty() {
        return Err(anyhow!("no mutation combinations available"));
    }

    combos.truncate(config.max_combinations);
    fs::create_dir_all(&config.output_dir)
        .with_context(|| format!("creating output directory {}", config.output_dir.display()))?;

    // Each combination yields an independent artifact to preserve reproducibility and diffability.
    let mut outcomes = Vec::with_capacity(combos.len());
    for (idx, combo) in combos.iter().enumerate() {
        let id = idx + 1;
        let name = combo
            .name
            .clone()
            .unwrap_or_else(|| format!("combo-{:03}", id));
        let operation_labels = combo.operations.iter().map(describe_operation).collect();

        match apply_operations(&source, &combo.operations) {
            Ok((mutated, applied_changes)) => {
                let mutated_file = mutation_path(&config.target, &config.output_dir, id);
                match fs::write(&mutated_file, mutated.as_bytes()) {
                    Ok(()) => {
                        let execution = config.execute.as_ref().map(|exec| {
                            run_execution(exec, &mutated_file).unwrap_or_else(|err| {
                                ExecutionOutcome {
                                    success: false,
                                    exit_code: None,
                                    duration_ms: 0,
                                    stdout: String::new(),
                                    stderr: String::new(),
                                    spawn_error: Some(err.to_string()),
                                }
                            })
                        });
                        outcomes.push(AmuckOutcome {
                            id,
                            name,
                            operations: operation_labels,
                            applied_changes,
                            mutated_file: Some(mutated_file),
                            apply_error: None,
                            execution,
                        });
                    }
                    Err(err) => {
                        outcomes.push(AmuckOutcome {
                            id,
                            name,
                            operations: operation_labels,
                            applied_changes,
                            mutated_file: None,
                            apply_error: Some(format!("write error: {}", err)),
                            execution: None,
                        });
                    }
                }
            }
            Err(err) => {
                outcomes.push(AmuckOutcome {
                    id,
                    name,
                    operations: operation_labels,
                    applied_changes: 0,
                    mutated_file: None,
                    apply_error: Some(err.to_string()),
                    execution: None,
                });
            }
        }
    }

    let combinations_run = outcomes.iter().filter(|o| o.mutated_file.is_some()).count();
    let report = AmuckReport {
        created_at: chrono::Utc::now().to_rfc3339(),
        target: config.target,
        source_spec: config.spec_path,
        preset: match config.preset {
            AmuckPreset::Light => "light".to_string(),
            AmuckPreset::Dangerous => "dangerous".to_string(),
        },
        max_combinations: config.max_combinations,
        output_dir: config.output_dir,
        combinations_planned: outcomes.len(),
        combinations_run,
        outcomes,
    };
    Ok(report)
}

pub fn write_report(report: &AmuckReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating report parent directory {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(report).context("serializing amuck report")?;
    fs::write(path, json).with_context(|| format!("writing report {}", path.display()))?;
    Ok(())
}

fn run_execution(command: &ExecutionCommand, mutated_file: &Path) -> Result<ExecutionOutcome> {
    let mut args = command.args.clone();
    if args.is_empty() || !args.iter().any(|arg| arg.contains("{file}")) {
        args.push("{file}".to_string());
    }

    let file_token = mutated_file.to_string_lossy().to_string();
    let resolved_args = args
        .into_iter()
        .map(|arg| arg.replace("{file}", &file_token))
        .collect::<Vec<_>>();

    let started = Instant::now();
    let output = Command::new(&command.program)
        .args(&resolved_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("executing {}", command.program))?;

    let duration_ms = started.elapsed().as_millis();
    Ok(ExecutionOutcome {
        success: output.status.success(),
        exit_code: output.status.code(),
        duration_ms,
        stdout: clamp_output(String::from_utf8_lossy(&output.stdout).to_string()),
        stderr: clamp_output(String::from_utf8_lossy(&output.stderr).to_string()),
        spawn_error: None,
    })
}

fn clamp_output(mut value: String) -> String {
    const MAX_LEN: usize = 8192;
    if value.len() > MAX_LEN {
        value.truncate(MAX_LEN);
        value.push_str("\n...<truncated>");
    }
    value
}

fn mutation_path(target: &Path, output_dir: &Path, id: usize) -> PathBuf {
    let stem = target
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    let ext = target
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s))
        .unwrap_or_default();
    let filename = format!("{}.amuck.{:03}{}", stem, id, ext);
    output_dir.join(filename)
}

fn load_spec(path: &Path) -> Result<MutationSpecFile> {
    // Cap spec reads at SPEC_FILE_READ_LIMIT — specs are short curated docs.
    let content = {
        let mut buf = String::new();
        File::open(path)
            .with_context(|| format!("opening spec {}", path.display()))?
            .take(SPEC_FILE_READ_LIMIT)
            .read_to_string(&mut buf)
            .with_context(|| format!("reading spec {}", path.display()))?;
        buf
    };
    let spec =
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => serde_json::from_str(&content)
                .with_context(|| format!("parsing {}", path.display()))?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
                .with_context(|| format!("parsing {}", path.display()))?,
            _ => {
                return Err(anyhow!(
                    "spec {} must be json/yaml/yml",
                    path.to_string_lossy()
                ));
            }
        };
    Ok(spec)
}

fn built_in_combinations(preset: AmuckPreset, source: &str) -> Vec<MutationComboSpec> {
    let mut combos = vec![
        MutationComboSpec {
            name: Some("boolean-flip".to_string()),
            operations: vec![
                MutationOperation::ReplaceFirst {
                    from: "true".to_string(),
                    to: "false".to_string(),
                },
                MutationOperation::ReplaceFirst {
                    from: "false".to_string(),
                    to: "true".to_string(),
                },
            ],
        },
        MutationComboSpec {
            name: Some("comparison-flip".to_string()),
            operations: vec![
                MutationOperation::ReplaceFirst {
                    from: "==".to_string(),
                    to: "!=".to_string(),
                },
                MutationOperation::ReplaceFirst {
                    from: ">=".to_string(),
                    to: "<=".to_string(),
                },
            ],
        },
        MutationComboSpec {
            name: Some("mutation-marker".to_string()),
            operations: vec![
                MutationOperation::PrependText {
                    text: "/* amuck: mutated file */\n".to_string(),
                },
                MutationOperation::AppendText {
                    text: "\n/* amuck: end marker */\n".to_string(),
                },
            ],
        },
    ];

    if preset == AmuckPreset::Dangerous {
        combos.extend([
            MutationComboSpec {
                name: Some("guard-removal".to_string()),
                operations: vec![
                    MutationOperation::DeleteLinesContaining {
                        needle: "if ".to_string(),
                    },
                    MutationOperation::DeleteLinesContaining {
                        needle: "guard".to_string(),
                    },
                ],
            },
            MutationComboSpec {
                name: Some("auth-bypass-token-swap".to_string()),
                operations: vec![
                    MutationOperation::SwapTokens {
                        left: "allow".to_string(),
                        right: "deny".to_string(),
                    },
                    MutationOperation::SwapTokens {
                        left: "permit".to_string(),
                        right: "reject".to_string(),
                    },
                ],
            },
            MutationComboSpec {
                name: Some("dup-dangerous-calls".to_string()),
                operations: vec![
                    MutationOperation::DuplicateLinesContaining {
                        needle: "exec".to_string(),
                        times: 1,
                    },
                    MutationOperation::DuplicateLinesContaining {
                        needle: "eval".to_string(),
                        times: 1,
                    },
                ],
            },
        ]);
    }

    combos
        .into_iter()
        .filter(|combo| operation_list_has_any_effect(source, &combo.operations))
        .collect()
}

fn operation_list_has_any_effect(source: &str, operations: &[MutationOperation]) -> bool {
    operations
        .iter()
        .any(|operation| operation_can_change_source(source, operation))
}

fn operation_can_change_source(source: &str, operation: &MutationOperation) -> bool {
    match operation {
        MutationOperation::ReplaceFirst { from, .. }
        | MutationOperation::ReplaceAll { from, .. } => !from.is_empty() && source.contains(from),
        MutationOperation::InsertBefore { needle, .. }
        | MutationOperation::InsertAfter { needle, .. }
        | MutationOperation::DeleteLinesContaining { needle }
        | MutationOperation::DuplicateLinesContaining { needle, .. } => {
            !needle.is_empty() && source.contains(needle)
        }
        MutationOperation::SwapTokens { left, right } => {
            !left.is_empty()
                && !right.is_empty()
                && (source.contains(left) || source.contains(right))
        }
        MutationOperation::AppendText { text } | MutationOperation::PrependText { text } => {
            !text.is_empty()
        }
    }
}

fn apply_operations(source: &str, operations: &[MutationOperation]) -> Result<(String, usize)> {
    let mut content = source.to_string();
    let mut changes = 0usize;
    for operation in operations {
        changes += apply_operation(&mut content, operation)?;
    }
    if changes == 0 {
        return Err(anyhow!("combination produced no change"));
    }
    Ok((content, changes))
}

fn apply_operation(content: &mut String, operation: &MutationOperation) -> Result<usize> {
    match operation {
        MutationOperation::ReplaceFirst { from, to } => {
            if from.is_empty() {
                return Err(anyhow!("replace_first cannot use empty 'from' token"));
            }
            if let Some(idx) = content.find(from) {
                content.replace_range(idx..idx + from.len(), to);
                Ok(1)
            } else {
                Ok(0)
            }
        }
        MutationOperation::ReplaceAll { from, to } => {
            if from.is_empty() {
                return Err(anyhow!("replace_all cannot use empty 'from' token"));
            }
            let count = content.matches(from).count();
            if count > 0 {
                *content = content.replace(from, to);
            }
            Ok(count)
        }
        MutationOperation::InsertBefore { needle, text } => {
            if needle.is_empty() {
                return Err(anyhow!("insert_before cannot use empty 'needle' token"));
            }
            if let Some(idx) = content.find(needle) {
                content.insert_str(idx, text);
                Ok(1)
            } else {
                Ok(0)
            }
        }
        MutationOperation::InsertAfter { needle, text } => {
            if needle.is_empty() {
                return Err(anyhow!("insert_after cannot use empty 'needle' token"));
            }
            if let Some(idx) = content.find(needle) {
                let insertion_at = idx + needle.len();
                content.insert_str(insertion_at, text);
                Ok(1)
            } else {
                Ok(0)
            }
        }
        MutationOperation::DeleteLinesContaining { needle } => {
            if needle.is_empty() {
                return Err(anyhow!(
                    "delete_lines_containing cannot use empty 'needle' token"
                ));
            }
            let mut removed = 0usize;
            let mut output = Vec::new();
            for line in content.lines() {
                if line.contains(needle) {
                    removed += 1;
                } else {
                    output.push(line);
                }
            }
            if removed > 0 {
                *content = output.join("\n");
                if content.as_bytes().last() != Some(&b'\n') {
                    content.push('\n');
                }
            }
            Ok(removed)
        }
        MutationOperation::DuplicateLinesContaining { needle, times } => {
            if needle.is_empty() {
                return Err(anyhow!(
                    "duplicate_lines_containing cannot use empty 'needle' token"
                ));
            }
            if *times == 0 {
                return Ok(0);
            }
            let mut duplicated = 0usize;
            let mut output = Vec::new();
            for line in content.lines() {
                output.push(line.to_string());
                if line.contains(needle) {
                    for _ in 0..*times {
                        output.push(line.to_string());
                        duplicated += 1;
                    }
                }
            }
            if duplicated > 0 {
                *content = output.join("\n");
                if content.as_bytes().last() != Some(&b'\n') {
                    content.push('\n');
                }
            }
            Ok(duplicated)
        }
        MutationOperation::SwapTokens { left, right } => {
            if left.is_empty() || right.is_empty() {
                return Err(anyhow!("swap_tokens requires non-empty tokens"));
            }
            let left_count = content.matches(left).count();
            let right_count = content.matches(right).count();
            let touched = left_count + right_count;
            if touched == 0 {
                return Ok(0);
            }
            let placeholder = "__AMUCK_SWAP__";
            let step_one = content.replace(left, placeholder);
            let step_two = step_one.replace(right, left);
            *content = step_two.replace(placeholder, right);
            Ok(touched)
        }
        MutationOperation::AppendText { text } => {
            if text.is_empty() {
                return Ok(0);
            }
            content.push_str(text);
            Ok(1)
        }
        MutationOperation::PrependText { text } => {
            if text.is_empty() {
                return Ok(0);
            }
            content.insert_str(0, text);
            Ok(1)
        }
    }
}

fn describe_operation(operation: &MutationOperation) -> String {
    match operation {
        MutationOperation::ReplaceFirst { from, to } => {
            format!("replace_first('{}' -> '{}')", from, to)
        }
        MutationOperation::ReplaceAll { from, to } => {
            format!("replace_all('{}' -> '{}')", from, to)
        }
        MutationOperation::InsertBefore { needle, .. } => {
            format!("insert_before('{}', ...)", needle)
        }
        MutationOperation::InsertAfter { needle, .. } => format!("insert_after('{}', ...)", needle),
        MutationOperation::DeleteLinesContaining { needle } => {
            format!("delete_lines_containing('{}')", needle)
        }
        MutationOperation::DuplicateLinesContaining { needle, times } => {
            format!("duplicate_lines_containing('{}', {})", needle, times)
        }
        MutationOperation::SwapTokens { left, right } => {
            format!("swap_tokens('{}', '{}')", left, right)
        }
        MutationOperation::AppendText { .. } => "append_text(...)".to_string(),
        MutationOperation::PrependText { .. } => "prepend_text(...)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn replace_first_changes_only_one_match() {
        let mut content = "true true true\n".to_string();
        let count = apply_operation(
            &mut content,
            &MutationOperation::ReplaceFirst {
                from: "true".to_string(),
                to: "false".to_string(),
            },
        )
        .expect("replace_first should succeed");
        assert_eq!(count, 1);
        assert_eq!(content, "false true true\n");
    }

    #[test]
    fn delete_lines_containing_removes_matching_lines() {
        let mut content = "keep\nremove-this\nkeep-too\n".to_string();
        let count = apply_operation(
            &mut content,
            &MutationOperation::DeleteLinesContaining {
                needle: "remove".to_string(),
            },
        )
        .expect("delete_lines_containing should succeed");
        assert_eq!(count, 1);
        assert_eq!(content, "keep\nkeep-too\n");
    }

    #[test]
    fn run_with_spec_writes_mutated_file() {
        let dir = TempDir::new().expect("tempdir should create");
        let target = dir.path().join("sample.rs");
        fs::write(&target, "fn main() { if true { println!(\"ok\"); } }\n")
            .expect("target should write");

        let spec_path = dir.path().join("spec.json");
        let spec = MutationSpecFile {
            combos: vec![MutationComboSpec {
                name: Some("flip".to_string()),
                operations: vec![MutationOperation::ReplaceFirst {
                    from: "true".to_string(),
                    to: "false".to_string(),
                }],
            }],
        };
        fs::write(
            &spec_path,
            serde_json::to_string_pretty(&spec).expect("spec should serialize"),
        )
        .expect("spec should write");

        let output_dir = dir.path().join("out");
        let report = run(AmuckConfig {
            target: target.clone(),
            spec_path: Some(spec_path),
            preset: AmuckPreset::Light,
            max_combinations: 8,
            output_dir: output_dir.clone(),
            execute: None,
        })
        .expect("amuck should run");

        assert_eq!(report.combinations_planned, 1);
        assert_eq!(report.combinations_run, 1);
        let first = &report.outcomes[0];
        assert!(first.mutated_file.is_some());
        assert!(first.apply_error.is_none());
        let mutated = first.mutated_file.as_ref().expect("mutated file expected");
        assert!(mutated.exists());
        let mutated_body = fs::read_to_string(mutated).expect("mutated file should read");
        assert!(mutated_body.contains("false"));
    }
}
