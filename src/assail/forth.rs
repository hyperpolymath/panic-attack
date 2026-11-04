// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Forth lexical hazard probes. These do not validate stack effects or grammar.

use super::input_adapters::{Analysis, UnsupportedInput};
use crate::types::{Severity, WeakPoint, WeakPointCategory};
use anyhow::{ensure, Result};

fn words(content: &str) -> Result<Vec<(usize, String)>> {
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
                let mut closed = false;
                while offset < bytes.len() {
                    if bytes[offset] == b'\n' {
                        line += 1;
                    }
                    if bytes[offset] == b'\\' && offset + 1 < bytes.len() {
                        offset += 2;
                        continue;
                    }
                    if bytes[offset] == b'"' {
                        offset += 1;
                        closed = true;
                        break;
                    }
                    offset += 1;
                }
                ensure!(closed, "unterminated Forth string");
            }
            _ => result.push((line, word)),
        }
    }
    Ok(result)
}

pub(super) fn analyze(content: &str, file: &str) -> Result<Analysis> {
    let words = words(content)?;
    // .fs is shared with F#. Never infer Forth merely from that suffix.
    if std::path::Path::new(file)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("fs"))
        && !(words.iter().any(|(_, word)| word == ":") && words.iter().any(|(_, word)| word == ";"))
    {
        return Err(UnsupportedInput(
            "ambiguous .fs input has no recognised Forth colon definition; F# is unsupported"
                .into(),
        )
        .into());
    }
    let mut result = Analysis::default();
    let mut definition_name = false;
    for (line, word) in words {
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
                line: Some(line as u32),
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
