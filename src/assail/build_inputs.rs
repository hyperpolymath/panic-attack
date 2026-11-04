// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Build-input checks and extraction. No recipe, import, build, interpolation or
//! command is executed. Unhandled dialects remain explicit coverage gaps.

use super::input_adapters::{Analysis, EmbeddedScript, UnsupportedInput};
use crate::types::{Language, Severity, WeakPoint, WeakPointCategory};
use anyhow::{anyhow, ensure, Result};
use std::collections::BTreeSet;

fn unsupported(message: &str) -> anyhow::Error {
    UnsupportedInput(message.into()).into()
}

fn finding(file: &str, line: usize, category: WeakPointCategory, reason: &str) -> WeakPoint {
    WeakPoint {
        file: Some(file.into()),
        line: Some(line as u32),
        category,
        location: Some(format!("{file}:{line}")),
        severity: Severity::High,
        description: reason.into(),
        recommended_attack: Vec::new(),
        suppressed: false,
        test_context: None,
    }
}

fn interpreter(command: &str) -> Result<Language> {
    let name = command.rsplit('/').next().unwrap_or(command);
    match name {
        "sh" | "bash" | "zsh" | "fish" | "dash" => Ok(Language::Shell),
        "python" | "python3" => Ok(Language::Python),
        "node" | "nodejs" => Ok(Language::JavaScript),
        _ => Err(unsupported(&format!(
            "embedded interpreter {name:?} has no selected adapter"
        ))),
    }
}

fn command_input(text: &str, line: usize, shell: Language, result: &mut Analysis) -> Result<()> {
    if text.starts_with('[') {
        let argv: Vec<String> = serde_json::from_str(text)?;
        ensure!(!argv.is_empty(), "empty build command vector");
        let name = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
        // A JSON exec vector is not a shell string. Only an explicit inline
        // interpreter invocation supplies executable source for these checks.
        if matches!(
            name,
            "sh" | "bash" | "zsh" | "fish" | "dash" | "python" | "python3" | "node" | "nodejs"
        ) {
            if let Some(index) = argv.iter().position(|arg| arg == "-c" || arg == "-e") {
                let source = argv
                    .get(index + 1)
                    .ok_or_else(|| anyhow!("inline interpreter option has no source"))?;
                result.scripts.push(EmbeddedScript {
                    content: source.clone(),
                    language: interpreter(name)?,
                    origin: format!("source block beginning at line {line}"),
                });
            }
        }
    } else {
        result.scripts.push(EmbeddedScript {
            content: text.into(),
            language: shell,
            origin: format!("source block beginning at line {line}"),
        });
    }
    Ok(())
}

pub(super) fn container(content: &str, file: &str) -> Result<Analysis> {
    let mut instructions = Vec::new();
    let mut current = String::new();
    let mut first_line = 0;
    for (offset, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if line.starts_with("# escape=") && line != "# escape=\\" {
                return Err(unsupported("non-backslash Containerfile escape directive"));
            }
            continue;
        }
        if current.is_empty() {
            first_line = offset + 1;
        }
        let continuation = line.ends_with('\\');
        current.push_str(line.strip_suffix('\\').unwrap_or(line));
        if continuation {
            current.push(' ');
        } else {
            instructions.push((first_line, std::mem::take(&mut current)));
        }
    }
    ensure!(current.is_empty(), "unfinished Containerfile continuation");
    let mut result = Analysis::default();
    let mut stages = BTreeSet::new();
    let mut shell = Language::Shell;
    let mut seen_from = false;
    for (line, instruction) in instructions {
        let (name, args) = instruction
            .split_once(char::is_whitespace)
            .ok_or_else(|| anyhow!("Containerfile instruction without arguments at line {line}"))?;
        let name = name.to_ascii_uppercase();
        let args = args.trim();
        ensure!(
            !args.is_empty(),
            "empty Containerfile instruction at line {line}"
        );
        if !seen_from && name != "FROM" && name != "ARG" {
            return Err(anyhow!(
                "Containerfile instruction before FROM at line {line}"
            ));
        }
        match name.as_str() {
            "FROM" => {
                let fields: Vec<_> = args
                    .split_whitespace()
                    .filter(|field| !field.starts_with("--platform="))
                    .collect();
                ensure!(
                    fields.len() == 1 || fields.len() == 3 && fields[1].eq_ignore_ascii_case("as"),
                    "invalid FROM instruction at line {line}"
                );
                let image = fields[0];
                let pinned = image.rsplit_once("@sha256:").is_some_and(|(_, digest)| {
                    digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
                });
                if image != "scratch" && !stages.contains(&image.to_ascii_lowercase()) && !pinned {
                    result.findings.push(finding(file, line, WeakPointCategory::SupplyChain, "Container base image lacks a complete SHA256 digest; local stage aliases are accepted"));
                }
                if fields.len() == 3 {
                    stages.insert(fields[2].to_ascii_lowercase());
                }
                seen_from = true;
                shell = Language::Shell;
            }
            "SHELL" => {
                let argv: Vec<String> = serde_json::from_str(args)?;
                shell = interpreter(
                    argv.first()
                        .ok_or_else(|| anyhow!("empty SHELL instruction"))?,
                )?;
            }
            "RUN" | "CMD" | "ENTRYPOINT" => {
                let mut command = args;
                while command.starts_with("--") {
                    command = command
                        .split_once(char::is_whitespace)
                        .ok_or_else(|| anyhow!("build command has only options"))?
                        .1
                        .trim_start();
                }
                if command.contains("<<") {
                    return Err(unsupported(
                        "Containerfile heredoc extraction is not implemented",
                    ));
                }
                command_input(command, line, shell, &mut result)?;
            }
            "HEALTHCHECK" => {
                if !args.eq_ignore_ascii_case("NONE") {
                    let (_, command) = args
                        .split_once("CMD ")
                        .ok_or_else(|| anyhow!("HEALTHCHECK has no CMD"))?;
                    command_input(command.trim(), line, shell, &mut result)?;
                }
            }
            "ADD" => {
                let checksum = args
                    .split_whitespace()
                    .find_map(|arg| arg.strip_prefix("--checksum=sha256:"));
                let pinned = checksum.is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
                if (args.contains("https://") || args.contains("http://")) && !pinned {
                    result.findings.push(finding(
                        file,
                        line,
                        WeakPointCategory::SupplyChain,
                        "Remote ADD has no SHA256 checksum",
                    ));
                }
            }
            "USER" => {
                if matches!(args.split(':').next(), Some("root" | "0")) {
                    result.findings.push(finding(
                        file,
                        line,
                        WeakPointCategory::ExcessivePermissions,
                        "Container explicitly selects the root user",
                    ));
                }
            }
            "ONBUILD" => {
                return Err(unsupported(
                    "deferred ONBUILD instruction analysis is not implemented",
                ))
            }
            "ARG" | "ENV" | "LABEL" | "COPY" | "WORKDIR" | "EXPOSE" | "VOLUME" | "STOPSIGNAL"
            | "MAINTAINER" => {}
            _ => {
                return Err(unsupported(&format!(
                    "unknown Containerfile instruction {name}"
                )))
            }
        }
    }
    ensure!(seen_from, "Containerfile contains no FROM instruction");
    Ok(result)
}

fn recipe_script(
    lines: &[(usize, String)],
    default: Language,
    result: &mut Analysis,
) -> Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut language = default;
    let script_mode = lines
        .first()
        .is_some_and(|(_, text)| text.starts_with("#!"));
    if let Some(first) = lines.first().filter(|(_, text)| text.starts_with("#!")) {
        let mut words = first.1[2..].split_whitespace();
        let first = words
            .next()
            .ok_or_else(|| anyhow!("empty recipe interpreter"))?;
        let executable = if first.ends_with("/env") {
            words
                .next()
                .ok_or_else(|| anyhow!("env recipe interpreter missing"))?
        } else {
            first
        };
        language = interpreter(executable)?;
    }
    result.scripts.push(EmbeddedScript {
        content: lines
            .iter()
            .map(|(_, text)| {
                if script_mode {
                    text.as_str()
                } else {
                    text.trim_start_matches('@')
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        language,
        origin: format!("source block beginning at line {}", lines[0].0),
    });
    Ok(())
}

pub(super) fn just(content: &str, _file: &str) -> Result<Analysis> {
    let mut result = Analysis::default();
    let mut default = Language::Shell;
    let mut in_recipe = false;
    let mut body = Vec::new();
    let mut indentation = None;
    for (offset, raw) in content.lines().enumerate() {
        let text = raw.trim();
        if text.is_empty() {
            continue;
        }
        if raw.starts_with(char::is_whitespace) {
            ensure!(
                in_recipe,
                "indented Just input outside a recipe at line {}",
                offset + 1
            );
            let leading = raw.len() - raw.trim_start().len();
            let prefix = *indentation.get_or_insert(leading);
            ensure!(
                leading >= prefix,
                "inconsistent Just recipe indentation at line {}",
                offset + 1
            );
            body.push((offset + 1, raw[prefix..].to_string()));
            continue;
        }
        if text.starts_with('#') {
            continue;
        }
        recipe_script(&body, default, &mut result)?;
        body.clear();
        indentation = None;
        in_recipe = false;
        if let Some(value) = text.strip_prefix("set shell :=") {
            let argv: Vec<String> = serde_json::from_str(value.trim())?;
            default = interpreter(argv.first().ok_or_else(|| anyhow!("empty Just shell"))?)?;
        } else if text.starts_with("set ") {
            if text.contains("interpreter") || text.contains("windows-shell") {
                return Err(unsupported(
                    "additional Just interpreter setting requires an adapter",
                ));
            }
        } else if text.starts_with("import ")
            || text.starts_with("import? ")
            || text.starts_with("mod ")
            || text.starts_with("mod? ")
            || text.starts_with("alias ")
        {
            // Inventory covers local *.just files independently. Imports and
            // variable interpolation are never executed or presented as checked.
        } else if text.starts_with('[') && text.ends_with(']') {
            if text.contains("script") {
                return Err(unsupported(
                    "Just script attributes require interpreter extraction",
                ));
            }
        } else if text.contains(":=") {
            if text.contains('`') || text.contains("shell(") {
                return Err(unsupported(
                    "executable Just variable expression is not extracted",
                ));
            }
        } else if text.contains(':') {
            in_recipe = true;
        } else {
            return Err(unsupported(&format!(
                "unrecognised Just declaration at line {}",
                offset + 1
            )));
        }
    }
    recipe_script(&body, default, &mut result)?;
    Ok(result)
}
