// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Native PHP parsing with deliberately local syntax checks. No taint proof.
use crate::types::{Severity, WeakPoint, WeakPointCategory};
use tree_sitter::Node;

/// Build a medium-severity finding at `path` and the node's one-based start line.
fn finding(
    path: &str,
    node: Node<'_>,
    category: WeakPointCategory,
    description: &str,
) -> WeakPoint {
    WeakPoint {
        category,
        location: Some(format!("{path}:{}", node.start_position().row + 1)),
        file: None,
        line: None,
        severity: Severity::Medium,
        description: description.into(),
        recommended_attack: Vec::new(),
        suppressed: false,
        test_context: None,
    }
}

/// Check a subtree for a function call whose source name matches `name`, ignoring
/// ASCII case and leading backslashes. `text` must be the tree's source text.
fn has_call(node: Node<'_>, text: &str, name: &str) -> bool {
    let mut pending = vec![node];
    while let Some(n) = pending.pop() {
        if n.kind() == "function_call_expression"
            && n.child_by_field_name("function")
                .and_then(|f| f.utf8_text(text.as_bytes()).ok())
                .is_some_and(|f| f.trim_start_matches('\\').eq_ignore_ascii_case(name))
        {
            return true;
        }
        let mut cursor = n.walk();
        pending.extend(n.named_children(&mut cursor));
    }
    false
}

/// Parse PHP/template source and return local syntax findings, possibly empty.
/// Checks cover empty or comment-only named functions/methods except constructors,
/// `blake3` callables containing a `sodium_crypto_generichash` call, and
/// `unserialize` calls with exactly one non-comment argument. These are
/// heuristics without name resolution or taint analysis. `path` labels finding
/// locations with one-based lines; it is not read from disk.
///
/// # Errors
/// Propagates parser language initialisation errors and returns an error if no
/// tree is produced or the tree contains syntax errors, rather than findings.
pub fn analyze(text: &str, path: &str) -> anyhow::Result<Vec<WeakPoint>> {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_php::LANGUAGE_PHP.into())?;
    let tree = parser
        .parse(text, None)
        .ok_or_else(|| anyhow::anyhow!("PHP parser produced no tree"))?;
    anyhow::ensure!(
        !tree.root_node().has_error(),
        "PHP syntax error: recovered trees are not analyzed"
    );
    let mut findings = Vec::new();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if matches!(node.kind(), "function_definition" | "method_declaration") {
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                let is_constructor = node
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                    .is_some_and(|n| n.eq_ignore_ascii_case("__construct"));
                if !is_constructor
                    && body
                        .named_children(&mut cursor)
                        .all(|n| n.kind() == "comment")
                {
                    findings.push(finding(path, node, WeakPointCategory::UncheckedError,
                        "PHP-EMPTY-CALLABLE: concrete callable has no executable body and may return null (T0 syntax heuristic; an intentional no-op may be valid)"));
                }
                let name = node
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                    .unwrap_or("");
                if name.eq_ignore_ascii_case("blake3")
                    && has_call(body, text, "sodium_crypto_generichash")
                {
                    findings.push(finding(path, node, WeakPointCategory::CryptoMisuse,
                        "PHP-ALGORITHM-SUBSTITUTION: blake3 callable invokes sodium_crypto_generichash (BLAKE2b); review exact algorithm/encoding contract (T0 syntax heuristic, not path proof)"));
                }
            }
        }
        if node.kind() == "function_call_expression" {
            let function = node
                .child_by_field_name("function")
                .and_then(|n| n.utf8_text(text.as_bytes()).ok())
                .unwrap_or("");
            if function
                .trim_start_matches('\\')
                .eq_ignore_ascii_case("unserialize")
            {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    if args
                        .named_children(&mut cursor)
                        .filter(|n| n.kind() != "comment")
                        .count()
                        == 1
                    {
                        findings.push(finding(path, node, WeakPointCategory::UnsafeDeserialization,
                            "PHP-UNSERIALIZE: call has no object-instantiation options; confirm input trust and allowed classes (T0 syntax heuristic; no source-to-sink proof)"));
                    }
                }
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.named_children(&mut cursor));
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_comment_only_callable_and_crypto_substitution() {
        let source = r#"<?php
        function encrypt($x) { /* TODO: encryption */ }
        class Crypto { public static function blake3($x) { return \sodium_crypto_generichash($x); } }
        "#;
        let findings = analyze(source, "fixture.php").unwrap();
        assert!(findings
            .iter()
            .any(|f| f.description.starts_with("PHP-EMPTY-CALLABLE:")));
        assert!(findings
            .iter()
            .any(|f| f.category == WeakPointCategory::CryptoMisuse));
    }
    #[test]
    fn parses_templates_namespaces_traits_and_closures_without_text_matches() {
        let source = r#"<?php namespace Demo;
        trait T { public function encode($x) { return json_encode($x); } }
        abstract class A { abstract function f(); }
        $fn = function ($x) { return $x; };
        $documentation = 'function blake3() { sodium_crypto_generichash(); }';
        // unserialize($untrusted);
        ?><p>Template</p>"#;
        assert!(analyze(source, "fixture.phtml").unwrap().is_empty());
    }
    #[test]
    fn parse_errors_do_not_become_empty_successes() {
        assert!(analyze("<?php function broken( {", "bad.php").is_err());
    }
    #[test]
    fn deserialization_options_are_distinguished() {
        assert_eq!(analyze("<?php unserialize($x);", "a.php").unwrap().len(), 1);
        assert!(analyze(
            "<?php unserialize($x, ['allowed_classes' => false]);",
            "b.php"
        )
        .unwrap()
        .is_empty());
    }
}
