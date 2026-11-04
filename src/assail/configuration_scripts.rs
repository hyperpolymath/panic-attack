// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Bounded extraction of executable configuration fields. This does not expand
//! Actions expressions, load referenced actions, resolve npm's runtime shell or
//! execute anything. Unrecognised Actions interpreters remain coverage gaps.

use super::configuration::Format;
use super::input_adapters::{EmbeddedScript, UnsupportedInput};
use crate::types::Language;
use anyhow::{anyhow, ensure, Result};
use serde_json::Value;
use std::path::Path;

fn unsupported(reason: &str) -> anyhow::Error {
    UnsupportedInput(reason.into()).into()
}

fn explicit_shell(value: &Value) -> Result<Language> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("Actions shell is not a string"))?;
    let executable = text
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("Actions shell is empty"))?;
    match executable.rsplit('/').next().unwrap_or(executable) {
        "bash" | "sh" | "zsh" | "dash" => Ok(Language::Shell),
        "python" | "python3" => Ok(Language::Python),
        "node" | "nodejs" => Ok(Language::JavaScript),
        _ => Err(unsupported(
            "Actions run-step interpreter has no selected adapter",
        )),
    }
}

fn default_shell(document: &Value) -> Option<&Value> {
    document.get("defaults")?.get("run")?.get("shell")
}

fn inferred_shell(job: &Value) -> Result<Language> {
    // Actions' unspecified Linux/macOS runner shell is sh/bash; a container
    // job defaults to sh. Dynamic, Windows and unqualified self-hosted runner
    // declarations cannot be assigned this interpreter without evidence.
    if job.get("container").is_some() {
        return Ok(Language::Shell);
    }
    let Some(runner) = job.get("runs-on") else {
        return Err(unsupported(
            "Actions run step has no resolvable default interpreter",
        ));
    };
    let posix = |label: &str| {
        label.starts_with("ubuntu-")
            || label.starts_with("macos-")
            || label == "linux"
            || label == "macOS"
    };
    let known = runner.as_str().is_some_and(posix)
        || runner.as_array().is_some_and(|labels| {
            labels.iter().any(|label| label.as_str().is_some_and(posix))
                && labels.iter().all(|label| {
                    label.as_str().is_some_and(|s| {
                        !s.contains("${{") && !s.to_ascii_lowercase().contains("windows")
                    })
                })
        });
    if known {
        Ok(Language::Shell)
    } else {
        Err(unsupported(
            "Actions runner does not establish a supported default shell",
        ))
    }
}

fn steps(
    values: &Value,
    job: Option<&Value>,
    workflow: &Value,
    field: &str,
    scripts: &mut Vec<EmbeddedScript>,
) -> Result<()> {
    let values = values
        .as_array()
        .ok_or_else(|| anyhow!("Actions steps is not an array"))?;
    for (index, step) in values.iter().enumerate() {
        let map = step
            .as_object()
            .ok_or_else(|| anyhow!("Actions step is not a mapping"))?;
        let Some(run) = map.get("run") else { continue };
        let source = run
            .as_str()
            .ok_or_else(|| anyhow!("Actions run field is not a string"))?;
        ensure!(
            !map.contains_key("uses"),
            "Actions step has both run and uses"
        );
        let shell = map
            .get("shell")
            .or_else(|| job.and_then(default_shell))
            .or_else(|| job.and_then(|_| default_shell(workflow)));
        let language = match shell {
            Some(value) => explicit_shell(value)?,
            None => match job {
                Some(job) => inferred_shell(job)?,
                None => {
                    return Err(unsupported(
                        "composite action run step lacks its required shell",
                    ))
                }
            },
        };
        scripts.push(EmbeddedScript {
            content: source.into(),
            language,
            origin: format!("configuration field {field}/{index}/run"),
        });
    }
    Ok(())
}

/// Append recognised Actions run steps or package.json scripts for later checks.
/// `field` identifies the document within the input; npm scripts use POSIX-style
/// heuristics without resolving the runtime shell. Actions shell selection uses
/// step, job and workflow defaults before considering the runner.
///
/// # Errors
/// Returns errors for malformed recognised structures and unsupported or
/// unresolved interpreters. Scripts already appended are retained on error.
pub(super) fn extract(
    format: Format,
    document: &Value,
    field: &str,
    file: &str,
    scripts: &mut Vec<EmbeddedScript>,
) -> Result<()> {
    if format == Format::Yaml {
        // Recognise the workflow structure, not arbitrary keys named `run`.
        // This also works when a single workflow is scanned as the root file.
        if document.get("on").is_some() && document.get("jobs").is_some() {
            let jobs = document["jobs"]
                .as_object()
                .ok_or_else(|| anyhow!("Actions jobs is not a mapping"))?;
            for (name, job) in jobs {
                if let Some(values) = job.get("steps") {
                    steps(
                        values,
                        Some(job),
                        document,
                        &format!("{field}/jobs/{name}/steps"),
                        scripts,
                    )?;
                }
            }
        }
        if document.pointer("/runs/using").and_then(Value::as_str) == Some("composite") {
            let values = document
                .pointer("/runs/steps")
                .ok_or_else(|| anyhow!("composite action has no steps"))?;
            steps(
                values,
                None,
                document,
                &format!("{field}/runs/steps"),
                scripts,
            )?;
        }
    }
    if format == Format::Json
        && Path::new(file).file_name().and_then(std::ffi::OsStr::to_str) == Some("package.json")
    {
        if let Some(values) = document.get("scripts") {
            let values = values
                .as_object()
                .ok_or_else(|| anyhow!("package.json scripts is not a mapping"))?;
            for (name, value) in values {
                let source = value
                    .as_str()
                    .ok_or_else(|| anyhow!("package.json script is not a string"))?;
                // This is intentionally POSIX-style lexical checking. npm can
                // select cmd.exe or an externally configured script-shell; the
                // coverage description expressly does not claim to resolve it.
                scripts.push(EmbeddedScript {
                    content: source.into(),
                    language: Language::Shell,
                    origin: format!("package.json script {field}/scripts/{name} (POSIX-style heuristics; runtime shell unresolved)"),
                });
            }
        }
    }
    Ok(())
}
