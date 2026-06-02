// SPDX-License-Identifier: MPL-2.0

//! Inline suppression markers — v2.5.5 `comment_analysis` slice.
//!
//! Recognises operator-authored `panic-attack: accepted` markers in
//! source comments and exposes a helper to test whether a given line
//! (or its immediate neighbours) is suppressed.
//!
//! The marker is intentionally explicit: a maintainer is opting in to a
//! finding they've already audited. The detector still emits the
//! `WeakPoint` (so audits can count what's accepted vs unsuppressed),
//! but `WeakPoint.suppressed` is set to `true`.
//!
//! ## Recognised forms
//!
//! Cross-language line-comment leaders:
//!   `//`  C / C++ / Rust / Go / Java / JS / TS / Swift / Kotlin /
//!         Scala / Zig / Dart / OCaml-line-comment-style
//!   `#`   Python / Ruby / Shell / Perl / TOML / YAML
//!   `;`   Lisp / Scheme / Racket / Clojure / Common Lisp / Assembly
//!   `--`  Haskell / Idris / SQL / Lua / Ada / Elm
//!   `%`   Erlang / Prolog / MATLAB / LaTeX
//!
//! After the comment leader, we accept (whitespace tolerant):
//!
//!   `panic-attack: accepted`
//!   `panic-attack: accepted - <reason>`
//!   `panic-attack: accepted (PA005 — manual audit 2026-06-02)`
//!   `panicattack: accepted`
//!   `panic_attack: accepted`
//!
//! The reason text after `accepted` is preserved verbatim in the
//! returned `AcceptedMarker.reason` field. Audit consumers can render
//! it alongside the `WeakPoint`.

/// A parsed `panic-attack: accepted` suppression marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMarker {
    /// 1-indexed line number where the marker was found.
    pub line: u32,
    /// The reason text after `accepted`, trimmed and de-decorated. Empty
    /// string if the marker was bare (`// panic-attack: accepted`).
    pub reason: String,
}

/// Scan `content` for `panic-attack: accepted` markers and return them
/// in line order.
pub fn scan_markers(content: &str) -> Vec<AcceptedMarker> {
    let mut markers = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if let Some(reason) = parse_accepted_marker_in_line(line) {
            markers.push(AcceptedMarker {
                line: (idx + 1) as u32,
                reason,
            });
        }
    }
    markers
}

/// Returns true if the finding at `line` is suppressed by an inline
/// marker. A marker on the same line OR the immediately preceding line
/// suppresses the finding. (Following-line markers are NOT recognised
/// to avoid ambiguity with "this finding is in code, the comment below
/// is unrelated".)
pub fn is_suppressed_at(content: &str, line: u32) -> Option<AcceptedMarker> {
    let lines: Vec<&str> = content.lines().collect();
    if line == 0 || (line as usize) > lines.len() {
        return None;
    }
    let zero_indexed = (line - 1) as usize;

    // Same line: marker after the code.
    if let Some(reason) = parse_accepted_marker_in_line(lines[zero_indexed]) {
        return Some(AcceptedMarker { line, reason });
    }

    // Previous line: marker above the code.
    if zero_indexed > 0 {
        if let Some(reason) = parse_accepted_marker_in_line(lines[zero_indexed - 1]) {
            return Some(AcceptedMarker {
                line: line - 1,
                reason,
            });
        }
    }

    None
}

/// Parse a single line for a `panic-attack: accepted` marker. Returns
/// the reason text on match (empty string if bare).
fn parse_accepted_marker_in_line(line: &str) -> Option<String> {
    // Find the comment leader, then strip up to and including it.
    let after_leader = strip_to_after_comment_leader(line)?;
    let trimmed = after_leader.trim_start();

    // Accept any of these spellings (case-insensitive for the prefix).
    let prefixes = [
        "panic-attack: accepted",
        "panicattack: accepted",
        "panic_attack: accepted",
        "panic-attack:accepted",
        "panicattack:accepted",
        "panic_attack:accepted",
    ];
    let lower = trimmed.to_ascii_lowercase();
    for p in &prefixes {
        if lower.starts_with(p) {
            let rest = &trimmed[p.len()..];
            return Some(clean_reason(rest));
        }
    }
    None
}

/// Find a comment leader in `line` and return the substring AFTER the
/// leader. Recognises two classes:
///   * **Mid-line**: `//` (C-family) is the only sequence safe to scan
///     for mid-line because the other leaders (`;`, `%`, `--`, `#`)
///     have valid non-comment uses inside expressions (statement
///     terminators, modulo, decrement, attribute syntax). These four
///     are recognised ONLY at the start-of-line.
///   * **Start-of-line** (after whitespace): all of the above.
///
/// String literals are crudely skipped to avoid matching the marker
/// inside a `"..."` quoted string.
fn strip_to_after_comment_leader(line: &str) -> Option<&str> {
    let trimmed_start = line.trim_start();
    // Shebang is not a comment.
    if trimmed_start.starts_with("#!") {
        return None;
    }

    // Start-of-line cases (after whitespace).
    if let Some(rest) = trimmed_start.strip_prefix("///") {
        return Some(rest);
    }
    if let Some(rest) = trimmed_start.strip_prefix("//!") {
        return Some(rest);
    }
    if let Some(rest) = trimmed_start.strip_prefix("//") {
        return Some(rest);
    }
    if let Some(rest) = trimmed_start.strip_prefix("--") {
        return Some(rest);
    }
    if let Some(rest) = trimmed_start.strip_prefix("#") {
        return Some(rest);
    }
    // Lisp `;;` and friends — collapse the semicolon run.
    if trimmed_start.starts_with(';') {
        let stripped = trimmed_start.trim_start_matches(';');
        return Some(stripped);
    }
    if let Some(rest) = trimmed_start.strip_prefix("%") {
        return Some(rest);
    }

    // Mid-line: only C-style `//` is safe — the others have non-comment
    // valid uses in expressions.
    let bytes = line.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        // Skip past " ... " string literals naively.
        if bytes[i] == b'"' {
            i += 1;
            while i < n && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        // C-family `//` mid-line (with optional collapse of `///`, `//!`).
        if bytes[i] == b'/' && i + 1 < n && bytes[i + 1] == b'/' {
            let mut j = i + 2;
            while j < n && bytes[j] == b'/' {
                j += 1;
            }
            if j < n && bytes[j] == b'!' {
                j += 1;
            }
            return Some(&line[j..]);
        }
        i += 1;
    }
    None
}

/// Clean the reason text: strip leading `:`, ` - `, parens, whitespace.
fn clean_reason(s: &str) -> String {
    let mut s = s.trim();
    if let Some(stripped) = s.strip_prefix(':') {
        s = stripped.trim();
    }
    if let Some(stripped) = s.strip_prefix("- ") {
        s = stripped.trim();
    }
    if let Some(stripped) = s.strip_prefix('-') {
        s = stripped.trim();
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_line_comment_bare() {
        let m = parse_accepted_marker_in_line("    // panic-attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn rust_line_comment_with_reason() {
        let m = parse_accepted_marker_in_line("// panic-attack: accepted - test fixture");
        assert_eq!(m, Some("test fixture".to_string()));
    }

    #[test]
    fn rust_line_comment_with_paren_reason() {
        let m = parse_accepted_marker_in_line(
            "// panic-attack: accepted (PA005 — manual audit 2026-06-02)",
        );
        assert_eq!(
            m,
            Some("(PA005 — manual audit 2026-06-02)".to_string())
        );
    }

    #[test]
    fn underscored_form_accepted() {
        let m = parse_accepted_marker_in_line("// panic_attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn concatenated_form_accepted() {
        let m = parse_accepted_marker_in_line("// panicattack:accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn python_hash_comment() {
        let m = parse_accepted_marker_in_line("# panic-attack: accepted - dummy");
        assert_eq!(m, Some("dummy".to_string()));
    }

    #[test]
    fn haskell_dash_dash_comment() {
        let m = parse_accepted_marker_in_line("-- panic-attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn lisp_semicolon_comment() {
        let m = parse_accepted_marker_in_line(";; panic-attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn erlang_percent_comment() {
        let m = parse_accepted_marker_in_line("% panic-attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn rust_doc_comment_accepted() {
        let m = parse_accepted_marker_in_line("/// panic-attack: accepted");
        assert_eq!(m, Some(String::new()));
    }

    #[test]
    fn shebang_not_comment() {
        let m = parse_accepted_marker_in_line("#!/usr/bin/env bash");
        assert_eq!(m, None);
    }

    #[test]
    fn code_without_marker() {
        let m = parse_accepted_marker_in_line("    foo.unwrap();");
        assert_eq!(m, None);
    }

    #[test]
    fn comment_without_marker() {
        let m = parse_accepted_marker_in_line("// just a regular comment");
        assert_eq!(m, None);
    }

    #[test]
    fn scan_markers_multiple() {
        let content = "// panic-attack: accepted - first\nlet x = 1;\nlet y = 2; // panic-attack: accepted - third\n";
        let ms = scan_markers(content);
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].line, 1);
        assert_eq!(ms[0].reason, "first");
        assert_eq!(ms[1].line, 3);
        assert_eq!(ms[1].reason, "third");
    }

    #[test]
    fn is_suppressed_same_line() {
        let content = "let x = foo.unwrap(); // panic-attack: accepted - test\n";
        let m = is_suppressed_at(content, 1).expect("should be suppressed");
        assert_eq!(m.reason, "test");
    }

    #[test]
    fn is_suppressed_previous_line() {
        let content = "// panic-attack: accepted\nlet x = foo.unwrap();\n";
        let m = is_suppressed_at(content, 2).expect("should be suppressed");
        assert_eq!(m.reason, "");
        assert_eq!(m.line, 1);
    }

    #[test]
    fn is_not_suppressed_next_line() {
        // Markers on the NEXT line do NOT suppress.
        let content = "let x = foo.unwrap();\n// panic-attack: accepted\n";
        assert!(is_suppressed_at(content, 1).is_none());
    }

    #[test]
    fn is_not_suppressed_two_lines_above() {
        // Only the immediately-preceding line counts.
        let content = "// panic-attack: accepted\n// other comment\nlet x = foo.unwrap();\n";
        assert!(is_suppressed_at(content, 3).is_none());
    }

    #[test]
    fn out_of_range_line_returns_none() {
        let content = "let x = 1;\n";
        assert!(is_suppressed_at(content, 0).is_none());
        assert!(is_suppressed_at(content, 99).is_none());
    }
}
