// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Forth lexical hazard probes. These do not validate stack effects or grammar.

use super::input_adapters::{Analysis, UnsupportedInput};
use crate::types::{Severity, WeakPoint, WeakPointCategory};
use anyhow::{ensure, Result};

/// The final flag distinguishes literal data from executable words. Keeping the
/// data lets named string constants receive credential checks without executing
/// or interpreting words embedded in those strings.
fn words(content: &str) -> Result<Vec<(usize, String, bool)>> {
    let mut result = Vec::new();
    let mut offset = 0;
    let mut line = 1;
    let bytes = content.as_bytes();
    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            if bytes[offset] == b'\n' {
                line += 1;
            }
            offset += 1;
            continue;
        }
        let start = offset;
        while offset < bytes.len() && !bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        let word = content[start..offset].to_ascii_lowercase();
        match word.as_str() {
            "\\" => {
                while offset < bytes.len() && bytes[offset] != b'\n' {
                    offset += 1;
                }
            }
            "(" => {
                while offset < bytes.len() && bytes[offset] != b')' {
                    if bytes[offset] == b'\n' {
                        line += 1;
                    }
                    offset += 1;
                }
                ensure!(
                    offset < bytes.len(),
                    "unterminated Forth parenthesised comment"
                );
                if offset < bytes.len() {
                    offset += 1;
                }
            }
            ".\"" | "s\"" | "c\"" | "s\\\"" | ".\\\"" | "abort\"" => {
                let escapes = matches!(word.as_str(), "s\\\"" | ".\\\"");
                let string_start = offset;
                let first_line = line;
                let mut string_end = offset;
                let mut closed = false;
                while offset < bytes.len() {
                    if bytes[offset] == b'\n' {
                        line += 1;
                    }
                    if escapes && bytes[offset] == b'\\' && offset + 1 < bytes.len() {
                        if bytes[offset + 1] == b'\n' {
                            line += 1;
                        }
                        offset += 2;
                        continue;
                    }
                    if bytes[offset] == b'"' {
                        string_end = offset;
                        offset += 1;
                        closed = true;
                        break;
                    }
                    offset += 1;
                }
                ensure!(closed, "unterminated Forth string");
                result.push((
                    first_line,
                    content[string_start..string_end].trim().into(),
                    true,
                ));
            }
            _ => result.push((line, word, false)),
        }
    }
    Ok(result)
}

/// A conservative witness for the ambiguous .fs suffix, not a Forth grammar.
/// Begin with a named colon definition and require matched definition
/// boundaries; independent F# annotation/list tokens are not a witness.
fn has_colon_definition(words: &[(usize, String, bool)]) -> bool {
    if !matches!(words.first(), Some((_, word, false)) if word == ":") {
        return false;
    }
    let mut open = false;
    let mut needs_name = false;
    let mut complete = false;
    for (_, word, literal) in words {
        if *literal {
            if needs_name {
                return false;
            }
            continue;
        }
        if needs_name {
            if matches!(word.as_str(), ":" | ";") {
                return false;
            }
            needs_name = false;
            continue;
        }
        match word.as_str() {
            ":" if !open => {
                open = true;
                needs_name = true;
            }
            ";" if open => {
                open = false;
                complete = true;
            }
            ":" | ";" => return false,
            _ => {}
        }
    }
    complete && !open && !needs_name
}

/// Check Forth words for execution and raw-memory hazards and named string
/// credentials. Comments, string contents and definition names are not treated
/// as executable words. This is a lexical check, not grammar or stack validation.
///
/// # Errors
/// Returns an error for unterminated comments or strings, or for an ambiguous
/// `.fs` input without a recognised colon definition.
pub(super) fn analyze(content: &str, file: &str) -> Result<Analysis> {
    let words = words(content)?;
    // .fs is shared with F#. Never infer Forth merely from that suffix.
    if std::path::Path::new(file)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("fs"))
        && !has_colon_definition(&words)
    {
        return Err(UnsupportedInput(
            "ambiguous .fs input has no recognised Forth colon definition; F# is unsupported"
                .into(),
        )
        .into());
    }
    let mut result = Analysis::default();
    let mut definition_name = false;
    for (index, (line, word, literal)) in words.iter().enumerate() {
        if *literal {
            if let (Some((_, binding, false)), Some((_, name, false))) =
                (words.get(index + 1), words.get(index + 2))
            {
                if matches!(
                    binding.as_str(),
                    "constant" | "2constant" | "value" | "2value"
                ) {
                    if let Some(finding) = super::configuration::literal_credential(
                        file,
                        &format!("Forth string binding at line {line}"),
                        name,
                        word,
                    ) {
                        result.findings.push(finding);
                    }
                }
            }
            continue;
        }
        if definition_name {
            definition_name = false;
            continue;
        }
        if word == ":" {
            definition_name = true;
            continue;
        }
        let hazard = match word.as_str() {
            "system" => Some((
                WeakPointCategory::CommandInjection,
                "Forth SYSTEM executes an external command",
            )),
            "evaluate" => Some((
                WeakPointCategory::DynamicCodeExecution,
                "Forth EVALUATE interprets source supplied at runtime",
            )),
            "!" | "c!" | "2!" | "move" | "fill" | "erase" => Some((
                WeakPointCategory::UnsafeCode,
                "Forth raw memory write requires address and size validation",
            )),
            _ => None,
        };
        if let Some((category, description)) = hazard {
            result.findings.push(WeakPoint {
                file: Some(file.into()),
                line: Some(*line as u32),
                category,
                location: Some(format!("{file}:{line}")),
                severity: Severity::High,
                description: description.into(),
                recommended_attack: Vec::new(),
                suppressed: false,
                test_context: None,
            });
        }
    }
    Ok(result)
}
