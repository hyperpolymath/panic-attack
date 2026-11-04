// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
use panic_attack::assail;
use panic_attack::types::{AssailReport, WeakPointCategory};

fn scan(name: &str, source: &str) -> AssailReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, source).unwrap();
    assail::analyze(&path).unwrap()
}

#[test]
fn clean_markup_and_css_have_hashed_parser_coverage_without_findings() {
    for (name, source) in [
        ("index.html", "<!DOCTYPE html><html xmlns=\"http://www.w3.org/1999/xhtml\"><body><p>Example</p></body></html>"),
        ("style.css", "/* expression(alert(1)) url(http://comment.invalid) */ p { content: 'expression(alert(1))'; color: blue; }"),
    ] {
        let report = scan(name, source);
        assert_eq!(report.coverage.status, "complete", "{name}");
        assert!(report.coverage.inputs[0].analysis.as_deref().unwrap().starts_with("tree-sitter-"));
        assert_eq!(report.coverage.inputs[0].content_blake3.as_deref(), Some(blake3::hash(source.as_bytes()).to_hex().as_str()));
        assert!(report.weak_points.is_empty(), "{name}: {:?}", report.weak_points);
    }
}

#[test]
fn markup_checks_distinguish_uri_attributes_from_text_and_comments() {
    let report = scan("index.html", "<!-- <a href='javascript:evil()'> --> <p>javascript:example()</p><a href='javascript:alert(1)'>run</a><script src='https://cdn.invalid/app.js'></script>");
    assert_eq!(report.coverage.status, "complete");
    assert_eq!(
        report
            .weak_points
            .iter()
            .filter(|f| f.category == WeakPointCategory::DynamicCodeExecution)
            .count(),
        1
    );
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.category == WeakPointCategory::SupplyChain));
}

#[test]
fn embedded_javascript_and_css_are_actually_analyzed() {
    let report = scan("index.html", "<style>p { width: expression(alert(1)); background: url(http://remote.invalid/x); }</style><script>eval(userInput);</script>");
    assert_eq!(
        report.coverage.status, "complete",
        "{:?}",
        report.coverage.inputs
    );
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.description.contains("CSS expression")));
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.category == WeakPointCategory::InsecureProtocol));
    assert!(report
        .weak_points
        .iter()
        .any(|f| f.description.contains("embedded JavaScript")));
}

#[test]
fn malformed_or_ambiguous_markup_does_not_receive_complete_coverage() {
    for (name, source) in [
        ("bad.css", "p { color: rgb(; }"),
        (
            "bad.html",
            "<a href='https://safe.invalid' href='javascript:evil()'>x</a>",
        ),
        ("bad-style.html", "<style>p { color: rgb(; }</style>"),
    ] {
        let report = scan(name, source);
        assert!(report.coverage.incomplete(), "{name}");
        assert_eq!(report.coverage.inputs[0].status, "parse_error");
        assert!(report.coverage.inputs[0].content_blake3.is_some());
    }
}

#[test]
fn script_types_and_encoded_attributes_cannot_silently_bypass_an_adapter() {
    let report = scan(
        "data.html",
        "<script type='application/json'>{\"example\":\"eval(user_input)\"}</script>",
    );
    assert_eq!(report.coverage.status, "complete");
    assert!(!report
        .weak_points
        .iter()
        .any(|f| f.category == WeakPointCategory::DynamicCodeExecution));
    for content in [
        "<script type='text/unknown'>code</script>",
        "<a href='javascript&#58;alert(1)'>run</a>",
        "<button onclick='&#101;val(input)'>run</button>",
    ] {
        let report = scan("unknown.html", content);
        assert!(report.coverage.incomplete(), "{content}");
        assert_eq!(report.coverage.inputs[0].status, "unsupported");
    }
}
