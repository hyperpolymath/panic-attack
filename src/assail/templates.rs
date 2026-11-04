// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Parser-backed checks for markup and styles. A recovered error tree is a
//! coverage gap. Embedded scripts keep the existing JavaScript heuristic depth.

use super::input_adapters::{Analysis, EmbeddedScript, UnsupportedInput};
use crate::types::{Language, Severity, WeakPoint, WeakPointCategory};
use anyhow::{anyhow, ensure, Result};
use std::collections::BTreeMap;
use tree_sitter::{Node, Parser, Tree};

fn parsed(content: &str, language: tree_sitter::Language) -> Result<Tree> {
    let mut parser = Parser::new();
    parser.set_language(&language)?;
    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow!("markup parser returned no tree"))?;
    ensure!(
        !tree.root_node().has_error(),
        "markup parser recovered a syntax error; semantic checks are incomplete"
    );
    Ok(tree)
}

fn text<'a>(node: Node<'_>, source: &'a str) -> Result<&'a str> {
    Ok(node.utf8_text(source.as_bytes())?)
}

fn finding(
    file: &str,
    node: Node<'_>,
    category: WeakPointCategory,
    severity: Severity,
    description: &str,
) -> WeakPoint {
    WeakPoint {
        file: Some(file.into()),
        // Assail bounds each input to 16 MiB, so its line count fits u32.
        line: Some(node.start_position().row as u32 + 1),
        category,
        location: Some(format!("{}:{}", file, node.start_position().row + 1)),
        severity,
        description: description.into(),
        recommended_attack: Vec::new(),
        suppressed: false,
        test_context: None,
    }
}

pub(super) fn html(content: &str, file: &str) -> Result<Analysis> {
    let tree = parsed(content, tree_sitter_html::LANGUAGE.into())?;
    let mut result = Analysis::default();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        match node.kind() {
            "start_tag" | "self_closing_tag" => {
                let mut tag = String::new();
                let mut attributes = BTreeMap::new();
                for child in node.named_children(&mut node.walk()) {
                    if child.kind() == "tag_name" {
                        tag = text(child, content)?.to_ascii_lowercase();
                    }
                    if child.kind() != "attribute" {
                        continue;
                    }
                    let mut name = String::new();
                    let mut value = String::new();
                    for part in child.named_children(&mut child.walk()) {
                        match part.kind() {
                            "attribute_name" => name = text(part, content)?.to_ascii_lowercase(),
                            "attribute_value" | "quoted_attribute_value" => {
                                value = text(part, content)?.trim_matches(['\'', '"']).to_owned()
                            }
                            _ => {}
                        }
                    }
                    ensure!(
                        !attributes.contains_key(&name),
                        "duplicate HTML attribute {name}; browser interpretation is ambiguous"
                    );
                    if name.starts_with("on") && name.len() > 2 {
                        ensure_attribute_decoded(&value)?;
                        result.scripts.push(EmbeddedScript {
                            content: value.clone(),
                            language: Language::JavaScript,
                            origin: format!(
                                "source block beginning at line {}",
                                child.start_position().row + 1
                            ),
                        });
                    }
                    if name == "style" && !value.is_empty() {
                        ensure_attribute_decoded(&value)?;
                        let inline = css(&format!("element {{{value}}}"), file)?;
                        for mut finding in inline.findings {
                            finding.line = Some(child.start_position().row as u32 + 1);
                            finding.location =
                                Some(format!("{file}:{}", child.start_position().row + 1));
                            result.findings.push(finding);
                        }
                    }
                    if matches!(
                        name.as_str(),
                        "src" | "href" | "action" | "formaction" | "poster"
                    ) {
                        ensure_attribute_decoded(&value)?;
                        let lower = value.trim().to_ascii_lowercase();
                        if lower.starts_with("javascript:") || lower.starts_with("vbscript:") {
                            result.findings.push(finding(
                                file,
                                child,
                                WeakPointCategory::DynamicCodeExecution,
                                Severity::High,
                                "HTML attribute contains an executable URL scheme",
                            ));
                        }
                        if lower.starts_with("http://") {
                            result.findings.push(finding(
                                file,
                                child,
                                WeakPointCategory::InsecureProtocol,
                                Severity::Medium,
                                "HTML resource or navigation uses plaintext HTTP",
                            ));
                        }
                    }
                    if let Some(finding) = super::configuration::literal_credential(
                        file,
                        &format!("HTML attribute at line {}", child.start_position().row + 1),
                        name.strip_prefix("data-").unwrap_or(&name),
                        &value,
                    ) {
                        result.findings.push(finding);
                    }
                    attributes.insert(name, value);
                }
                if tag == "script"
                    && attributes.get("src").is_some_and(|src| {
                        src.to_ascii_lowercase().starts_with("https://")
                            || src.to_ascii_lowercase().starts_with("http://")
                            || src.starts_with("//")
                    })
                    && !attributes
                        .get("integrity")
                        .is_some_and(|value| usable_integrity(value))
                {
                    result.findings.push(finding(
                        file,
                        node,
                        WeakPointCategory::SupplyChain,
                        Severity::Medium,
                        "Remote script has no syntactically usable supported integrity digest",
                    ));
                }
            }
            "raw_text" => match node.parent().map(|parent| parent.kind()) {
                Some("script_element") => {
                    let kind = element_type(node.parent().expect("parent matched"), content)?;
                    match kind.as_str() {
                        "" | "module" | "text/javascript" | "application/javascript" => {
                            result.scripts.push(EmbeddedScript {
                                content: text(node, content)?.into(),
                                language: Language::JavaScript,
                                origin: format!(
                                    "source block beginning at line {}",
                                    node.start_position().row + 1
                                ),
                            })
                        }
                        "application/json" | "application/ld+json" | "importmap" => {
                            result.findings.extend(
                                super::configuration::Format::Json
                                    .analyze(text(node, content)?, file)?,
                            )
                        }
                        _ => {
                            return Err(UnsupportedInput(format!(
                                "embedded script type {kind:?} has no selected adapter"
                            ))
                            .into())
                        }
                    }
                }
                Some("style_element") => {
                    let kind = element_type(node.parent().expect("parent matched"), content)?;
                    if !kind.is_empty() && kind != "text/css" {
                        return Err(UnsupportedInput(format!(
                            "embedded style type {kind:?} is not CSS"
                        ))
                        .into());
                    }
                    let nested = css(text(node, content)?, file)?;
                    for mut finding in nested.findings {
                        let line = finding.line.unwrap_or(1) + node.start_position().row as u32;
                        finding.line = Some(line);
                        finding.location = Some(format!("{file}:{line}"));
                        result.findings.push(finding);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        pending.extend(node.named_children(&mut node.walk()));
    }
    Ok(result)
}

// SRI metadata needs a correctly sized supported base64 digest. This checks
// syntax only: it never fetches a resource or proves that its bytes match.
fn usable_integrity(metadata: &str) -> bool {
    metadata.split_ascii_whitespace().any(|token| {
        let expression = token.split('?').next().unwrap_or(token);
        let Some((algorithm, value)) = expression.split_once('-') else {
            return false;
        };
        let bytes = match algorithm.to_ascii_lowercase().as_str() {
            "sha256" => 32usize,
            "sha384" => 48,
            "sha512" => 64,
            _ => return false,
        };
        let digits = value.trim_end_matches('=');
        let padding = value.len() - digits.len();
        if digits.len() != (bytes * 8).div_ceil(6)
            || padding > 2
            || (padding > 0 && value.len() % 4 != 0)
        {
            return false;
        }
        let sextet = |byte: u8| match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        };
        if !digits.bytes().all(|b| sextet(b).is_some()) {
            return false;
        }
        let Some(last) = digits.bytes().last().and_then(sextet) else {
            return false;
        };
        match bytes % 3 {
            1 => last & 15 == 0,
            2 => last & 3 == 0,
            _ => padding == 0,
        }
    })
}

fn ensure_attribute_decoded(value: &str) -> Result<()> {
    // The grammar does not decode character references. Refuse a sensitive
    // attribute whose interpreted bytes differ instead of checking only its
    // raw spelling and acknowledging an unexamined executable URL or script.
    let named_entity = value.split('&').skip(1).any(|tail| {
        tail.split_once(';').is_some_and(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric())
        })
    });
    if value.contains("&#") || named_entity {
        return Err(UnsupportedInput(
            "HTML character-reference expansion in executable/URL attributes is not implemented"
                .into(),
        )
        .into());
    }
    Ok(())
}

fn element_type(element: Node<'_>, content: &str) -> Result<String> {
    for start in element
        .named_children(&mut element.walk())
        .filter(|node| node.kind() == "start_tag")
    {
        for attribute in start
            .named_children(&mut start.walk())
            .filter(|node| node.kind() == "attribute")
        {
            let mut name = String::new();
            let mut value = String::new();
            for part in attribute.named_children(&mut attribute.walk()) {
                match part.kind() {
                    "attribute_name" => name = text(part, content)?.to_ascii_lowercase(),
                    "attribute_value" | "quoted_attribute_value" => {
                        value = text(part, content)?
                            .trim_matches(['\'', '"'])
                            .to_ascii_lowercase()
                    }
                    _ => {}
                }
            }
            if name == "type" {
                return Ok(value);
            }
        }
    }
    Ok(String::new())
}

pub(super) fn css(content: &str, file: &str) -> Result<Analysis> {
    let tree = parsed(content, tree_sitter_css::LANGUAGE.into())?;
    let mut result = Analysis::default();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "declaration" {
            let mut name = String::new();
            for child in node.named_children(&mut node.walk()) {
                if child.kind() == "property_name" {
                    name = text(child, content)?.trim_start_matches('-').to_owned();
                } else if matches!(child.kind(), "plain_value" | "string_value") {
                    if let Some(finding) = super::configuration::literal_credential(
                        file,
                        &format!("CSS declaration at line {}", node.start_position().row + 1),
                        &name,
                        text(child, content)?.trim_matches(['\'', '"']),
                    ) {
                        result.findings.push(finding);
                    }
                }
            }
        }
        if node.kind() == "call_expression" {
            let value = text(node, content)?.to_ascii_lowercase();
            if value.starts_with("expression(") {
                result.findings.push(finding(
                    file,
                    node,
                    WeakPointCategory::DynamicCodeExecution,
                    Severity::High,
                    "CSS expression() embeds executable code in legacy browser engines",
                ));
            }
            if value.starts_with("url(")
                && (value.contains("http://") || value.contains("javascript:"))
            {
                result.findings.push(finding(
                    file,
                    node,
                    WeakPointCategory::InsecureProtocol,
                    Severity::Medium,
                    "CSS URL uses a plaintext or executable scheme",
                ));
            }
        }
        if node.kind() == "import_statement"
            && text(node, content)?
                .to_ascii_lowercase()
                .contains("http://")
        {
            result.findings.push(finding(
                file,
                node,
                WeakPointCategory::InsecureProtocol,
                Severity::Medium,
                "CSS import uses plaintext HTTP",
            ));
        }
        pending.extend(node.named_children(&mut node.walk()));
    }
    Ok(result)
}
