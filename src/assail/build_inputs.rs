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

/// Extract inline shell, Python or JavaScript source from an interpreter argv.
/// Returns `None` for invocations without inline source; later arguments are not
/// treated as source.
///
/// # Errors
/// Returns an error for unsupported interpreters or options and for options
/// requiring a missing argument or source.
fn inline_source(name: &str, argv: &[String]) -> Result<Option<String>> {
    let language = interpreter(name)?;
    let mut index = 1;
    let mut shell_command = false;
    while let Some(arg) = argv.get(index) {
        if arg == "--" {
            return if shell_command {
                Ok(Some(
                    argv.get(index + 1)
                        .ok_or_else(|| anyhow!("shell -c has no source"))?
                        .clone(),
                ))
            } else {
                Ok(None)
            };
        }
        if !arg.starts_with(['-', '+']) || arg == "-" {
            return Ok(shell_command.then(|| arg.clone()));
        }
        if language == Language::Shell {
            match arg.as_str() {
                "--noprofile" | "--norc" | "--posix" | "--restricted" | "--verbose" | "--login" => {
                }
                "--rcfile" | "--init-file" => {
                    index += 1;
                    ensure!(argv.get(index).is_some(), "shell option lacks its argument");
                }
                _ if !arg.starts_with("--") => {
                    let flags = &arg[1..];
                    for (offset, flag) in flags.char_indices() {
                        match flag {
                            'c' if arg.starts_with('-') => shell_command = true,
                            'o' | 'O' => {
                                if offset + 1 != flags.len() {
                                    return Err(unsupported(
                                        "attached named shell option is not extracted",
                                    ));
                                }
                                index += 1;
                                ensure!(
                                    argv.get(index).is_some(),
                                    "named shell option lacks its argument"
                                );
                            }
                            'a' | 'b' | 'e' | 'f' | 'h' | 'k' | 'm' | 'n' | 'p' | 't' | 'u'
                            | 'v' | 'x' | 'B' | 'C' | 'E' | 'H' | 'P' | 'T' | 'i' | 'l' | 'r'
                            | 's' | 'D' => {}
                            _ => return Err(unsupported("unrecognised shell invocation option")),
                        }
                    }
                }
                _ => return Err(unsupported("unrecognised shell invocation option")),
            }
        } else {
            let option = if language == Language::Python {
                "-c"
            } else {
                "-e"
            };
            if arg == option
                || language == Language::JavaScript
                    && matches!(arg.as_str(), "--eval" | "--print" | "-p")
            {
                return Ok(Some(
                    argv.get(index + 1)
                        .ok_or_else(|| anyhow!("inline interpreter option has no source"))?
                        .clone(),
                ));
            }
            if let Some(source) = arg.strip_prefix(option).filter(|s| !s.is_empty()) {
                return Ok(Some(source.into()));
            }
            if language == Language::JavaScript {
                if let Some(source) = arg
                    .strip_prefix("--eval=")
                    .or_else(|| arg.strip_prefix("--print="))
                    .or_else(|| arg.strip_prefix("-p").filter(|s| !s.is_empty()))
                {
                    return Ok(Some(source.into()));
                }
            }
            if matches!(arg.as_str(), "-m" | "--version" | "--help") {
                return Ok(None);
            }
            return Err(unsupported(
                "inline interpreter invocation options require an adapter",
            ));
        }
        index += 1;
    }
    ensure!(!shell_command, "shell -c has no source");
    Ok(None)
}

/// Append executable source from a build command, using `shell` for shell form.
/// `line` is the one-based start of the instruction. Malformed JSON and JSON
/// that is not an array fall back to shell form; direct exec arguments are not
/// treated as source unless they invoke a recognised inline interpreter.
///
/// # Errors
/// Returns an error for empty or non-string exec arrays and propagates inline
/// interpreter option errors.
fn command_input(text: &str, line: usize, shell: Language, result: &mut Analysis) -> Result<()> {
    // BuildKit's parseMaybeJSON falls back to shell form for malformed JSON
    // (including the POSIX `[` command), but rejects non-string array members.
    let array = text
        .starts_with('[')
        .then(|| serde_json::from_str::<serde_json::Value>(text).ok())
        .flatten();
    if let Some(serde_json::Value::Array(values)) = array {
        let argv: Vec<String> = values
            .into_iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("exec array contains a non-string argument"))
            })
            .collect::<Result<_>>()?;
        ensure!(!argv.is_empty(), "empty build command vector");
        let name = argv[0].rsplit('/').next().unwrap_or(&argv[0]);
        // A JSON exec vector is not a shell string. Only an explicit inline
        // interpreter invocation supplies executable source for these checks.
        if matches!(
            name,
            "sh" | "bash" | "zsh" | "fish" | "dash" | "python" | "python3" | "node" | "nodejs"
        ) {
            if let Some(source) = inline_source(name, &argv)? {
                result.scripts.push(EmbeddedScript {
                    content: source,
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

fn image_pinned(image: &str) -> bool {
    image.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty() && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// Declarative instruction words, with quotes/backslashes removed but no
/// environment expansion or command execution. Keep a backslash marker on a
/// literal dollar sign so reference recognition cannot erase escaped values.
/// Comments were removed earlier.
fn field_words(text: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in text.chars() {
        if escaped {
            if ch == '$' {
                word.push('\\');
            }
            word.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                if delimiter == '\'' && ch == '$' {
                    word.push('\\');
                }
                word.push(ch);
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(ch);
        }
    }
    ensure!(
        quote.is_none() && !escaped,
        "unfinished declarative instruction word"
    );
    if !word.is_empty() {
        words.push(word);
    }
    Ok(words)
}

fn simple_environment_reference(value: &str) -> bool {
    value.strip_prefix('$').is_some_and(|name| {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn literal_fields(
    args: &str,
    allow_unassigned: bool,
    file: &str,
    line: usize,
    result: &mut Analysis,
) -> Result<()> {
    let words = field_words(args)?;
    if words.is_empty() {
        return Ok(());
    }
    let fields = if !allow_unassigned && !words[0].contains('=') {
        ensure!(words.len() > 1, "declarative instruction has no value");
        vec![(words[0].clone(), words[1..].join(" "))]
    } else {
        let mut fields = Vec::new();
        for word in words {
            if let Some((name, value)) = word.split_once('=') {
                fields.push((name.into(), value.into()));
            } else {
                ensure!(
                    allow_unassigned,
                    "declarative assignment has no equals sign"
                );
            }
        }
        fields
    };
    for (name, value) in fields {
        // This syntax is expanded by the build-input format, unlike a plain
        // JSON string. Do not broaden the shared literal predicate for it.
        if simple_environment_reference(&value) {
            continue;
        }
        if let Some(finding) = super::configuration::literal_credential(
            file,
            &format!("build field at line {line}"),
            &name,
            &value,
        ) {
            result.findings.push(finding);
        }
    }
    Ok(())
}

/// Check supported Containerfile instructions and extract executable source.
/// Returns findings and scripts for later interpreter checks; no build is run.
///
/// # Errors
/// Returns errors for malformed instructions or command vectors, and unsupported
/// instructions, interpreters or constructs such as heredocs and `ONBUILD`.
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
    let mut stage_count = 0usize;
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
                let pinned = image_pinned(image);
                if image != "scratch" && !stages.contains(&image.to_ascii_lowercase()) && !pinned {
                    result.findings.push(finding(file, line, WeakPointCategory::SupplyChain, "Container base image lacks a complete SHA256 digest; local stage aliases are accepted"));
                }
                if fields.len() == 3 {
                    stages.insert(fields[2].to_ascii_lowercase());
                }
                seen_from = true;
                stage_count += 1;
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
            "COPY" => {
                let words = field_words(args)?;
                let mut source = None;
                let mut fields = words.iter();
                while let Some(field) = fields.next().filter(|field| field.starts_with("--")) {
                    let value = if field == "--from" {
                        Some(
                            fields
                                .next()
                                .ok_or_else(|| anyhow!("COPY --from has no value"))?
                                .as_str(),
                        )
                    } else {
                        field.strip_prefix("--from=")
                    };
                    if let Some(value) = value {
                        ensure!(
                            source.is_none() && !value.is_empty(),
                            "duplicate or empty COPY --from"
                        );
                        source = Some(value);
                    }
                }
                if let Some(source) = source {
                    if let Ok(index) = source.parse::<usize>() {
                        ensure!(index < stage_count, "COPY stage index does not exist");
                    } else if !stages.contains(&source.to_ascii_lowercase())
                        && !image_pinned(source)
                    {
                        if source.contains('$') || !source.contains([':', '/', '@']) {
                            return Err(unsupported("COPY source is an unresolved external image or named build context"));
                        }
                        result.findings.push(finding(
                            file,
                            line,
                            WeakPointCategory::SupplyChain,
                            "COPY external image lacks a complete SHA256 digest",
                        ));
                    }
                }
            }
            "USER" => {
                let user = args.split(':').next().unwrap_or("");
                if user == "root" || user.parse::<u32>().ok() == Some(0) {
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
            "ARG" | "ENV" | "LABEL" => {
                literal_fields(args, name == "ARG", file, line, &mut result)?
            }
            "WORKDIR" | "EXPOSE" | "VOLUME" | "STOPSIGNAL" | "MAINTAINER" => {}
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

/// Check recognised Just declarations and extract recipe bodies for later checks.
/// Imports and interpolation are not resolved and recipes are not run.
///
/// # Errors
/// Returns errors for malformed recipe indentation or shell settings, and for
/// unsupported declarations or interpreters.
pub(super) fn just(content: &str, file: &str) -> Result<Analysis> {
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
        let setting = text
            .strip_prefix("set")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map(str::trim_start);
        let shell_setting = setting
            .and_then(|rest| rest.strip_prefix("shell"))
            .map(str::trim_start)
            .and_then(|rest| rest.strip_prefix(":="));
        if let Some(value) = shell_setting {
            let argv: Vec<String> = serde_json::from_str(value.trim())?;
            default = interpreter(argv.first().ok_or_else(|| anyhow!("empty Just shell"))?)?;
        } else if let Some(setting) = setting {
            if setting.starts_with("shell")
                || setting.contains("interpreter")
                || setting.contains("windows-shell")
            {
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
            let (name, value) = text.split_once(":=").expect("assignment matched");
            let value = value.trim();
            if value.len() >= 2
                && (value.starts_with('"') && value.ends_with('"')
                    || value.starts_with('\'') && value.ends_with('\''))
            {
                if let Some(finding) = super::configuration::literal_credential(
                    file,
                    &format!("Just declaration at line {}", offset + 1),
                    name.trim().trim_start_matches("export ").trim(),
                    &value[1..value.len() - 1],
                ) {
                    result.findings.push(finding);
                }
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
