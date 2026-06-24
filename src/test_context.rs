// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! Cross-language test-context detection (v2.5.5 `test_context` slice).
//!
//! Classifies a `(file_path, content)` pair as `TestContext::Production`,
//! `TestContext::TestOnly`, or `TestContext::Doc`. Detectors that emit
//! `WeakPointCategory::PanicPath` against `TestOnly` code should set
//! `WeakPoint.suppressed = true` since `unwrap` / `expect` / `assert!`
//! are idiomatic inside tests.
//!
//! The legacy in-detector `is_test_file` boolean in
//! `src/assail/analyzer.rs` covers the Rust / JavaScript / RSpec /
//! benchmark filename patterns. This module is the canonical source for
//! cross-language detection going forward and is what new detectors
//! should call. The analyzer's local boolean is kept for backward-compat
//! and will be migrated to this module over time.

use crate::types::TestContext;

/// Classify a single file by path. Pure-path heuristic — content-based
/// detection (for inline `#[cfg(test)] mod tests { … }` blocks etc.) is
/// the analyzer's responsibility, not this function's.
///
/// Recognised patterns (in order, first match wins):
///   * `Doc` — paths matching `/docs/examples/` or `*.example.{rs,py,ts}`
///   * `TestOnly` — language-canonical test paths
///   * `Production` — fallback
pub fn classify_path(file_path: &str) -> TestContext {
    if is_doc_path(file_path) {
        TestContext::Doc
    } else if is_test_path(file_path) {
        TestContext::TestOnly
    } else {
        TestContext::Production
    }
}

/// Returns true if `file_path` is a documentation-example file. These
/// are treated the same as tests for PanicPath suppression purposes.
fn is_doc_path(file_path: &str) -> bool {
    file_path.contains("docs/examples/")
        || file_path.contains("doc/examples/")
        || file_path.ends_with(".example.rs")
        || file_path.ends_with(".example.py")
        || file_path.ends_with(".example.ts")
        || file_path.ends_with(".example.js")
}

/// Returns true if `file_path` lives under a recognised cross-language
/// test scope. Mirrors and extends the analyzer's legacy `is_test_file`
/// boolean to cover Python / Go / Julia / Zig in addition to
/// Rust / JS / Elixir.
pub fn is_test_path(file_path: &str) -> bool {
    is_rust_test_path(file_path)
        || is_python_test_path(file_path)
        || is_go_test_path(file_path)
        || is_javascript_test_path(file_path)
        || is_julia_test_path(file_path)
        || is_elixir_test_path(file_path)
        || is_zig_test_path(file_path)
        || is_generic_test_path(file_path)
}

fn is_rust_test_path(p: &str) -> bool {
    p.contains("tests/")
        || p.ends_with("_test.rs")
        || p.ends_with("_tests.rs")
        || p.contains("benches/")
        || p.ends_with("_bench.rs")
}

fn is_python_test_path(p: &str) -> bool {
    // pytest canonical: tests/test_*.py, src/foo/tests.py, foo_test.py.
    let basename = p.rsplit('/').next().unwrap_or(p);
    basename.starts_with("test_") && basename.ends_with(".py")
        || basename == "tests.py"
        || (basename.ends_with("_test.py") && !basename.starts_with("_"))
        || p.contains("/tests/") && p.ends_with(".py")
        || p.starts_with("tests/") && p.ends_with(".py")
}

fn is_go_test_path(p: &str) -> bool {
    p.ends_with("_test.go")
}

fn is_javascript_test_path(p: &str) -> bool {
    // Jest/Vitest/Mocha canonical: foo.test.{js,ts,jsx,tsx},
    // foo.spec.{js,ts,jsx,tsx}, __tests__/foo.{js,ts}.
    let ext_test = [
        ".test.js",
        ".test.ts",
        ".test.jsx",
        ".test.tsx",
        ".test.mjs",
        ".test.cjs",
        ".spec.js",
        ".spec.ts",
        ".spec.jsx",
        ".spec.tsx",
        ".spec.mjs",
        ".spec.cjs",
    ];
    if ext_test.iter().any(|e| p.ends_with(e)) {
        return true;
    }
    p.contains("/__tests__/") || p.starts_with("__tests__/")
}

fn is_julia_test_path(p: &str) -> bool {
    // Julia canonical: test/runtests.jl, test/*.jl.
    (p.contains("/test/") || p.starts_with("test/")) && p.ends_with(".jl")
        || p.ends_with("/runtests.jl")
        || p == "runtests.jl"
}

fn is_elixir_test_path(p: &str) -> bool {
    // ExUnit canonical: test/foo_test.exs, foo/test/foo_test.exs.
    p.ends_with("_test.exs")
        || (p.contains("/test/") || p.starts_with("test/")) && p.ends_with(".exs")
}

fn is_zig_test_path(p: &str) -> bool {
    // Zig doesn't have a canonical test-file naming convention — `test`
    // blocks live inline in source files. Treat paths under `tests/`
    // or with `_test.zig` / `.test.zig` suffix as test-only.
    p.ends_with("_test.zig")
        || p.ends_with(".test.zig")
        || p.contains("/tests/") && p.ends_with(".zig")
}

fn is_generic_test_path(p: &str) -> bool {
    // Catch-all for benchmark / e2e / integration / mock / stub paths
    // that the legacy `is_test_file` boolean recognised regardless of
    // language. Kept for backward-compat.
    p.contains("_integration.")
        || p.contains("_e2e.")
        || p.contains("_unit.")
        || p.contains("_mock.")
        || p.contains("_stub.")
        || p.contains("/examples/")
        || p.contains("/samples/")
}

/// Returns true if the given `content` indicates an inline test scope
/// even when the file path itself looks like production code. Examples:
///   * Rust: `#[cfg(test)] mod tests` blocks (handled at-block level)
///   * Elixir: `use ExUnit.Case` at top of an unconventionally-named file
///   * Python: `class TestX(unittest.TestCase)` in a module not named
///     `test_*.py`
///
/// NOTE: This is a coarse signal. For Rust, the analyzer's
/// `strip_inline_cfg_test_modules` does block-level stripping which is
/// strictly more precise — prefer that for per-finding suppression.
/// This function is for the rare case where a whole file is logically
/// test-scoped despite a production-looking name.
pub fn content_indicates_test_scope(content: &str) -> bool {
    // Elixir
    if content.contains("use ExUnit.Case") {
        return true;
    }
    // Python — class-based unittest
    if content.contains("unittest.TestCase") || content.contains("(unittest.TestCase)") {
        return true;
    }
    // Pytest fixture-heavy modules
    if content.contains("@pytest.fixture") && content.contains("def test_") {
        return true;
    }
    // Julia
    if content.contains("using Test") && content.contains("@testset") {
        return true;
    }
    false
}

/// Convenience: classify a file accounting for both path and content.
/// `Doc` paths win over `TestOnly` paths win over content-based
/// `TestOnly` detection.
pub fn classify(file_path: &str, content: &str) -> TestContext {
    let by_path = classify_path(file_path);
    if by_path != TestContext::Production {
        return by_path;
    }
    if content_indicates_test_scope(content) {
        return TestContext::TestOnly;
    }
    TestContext::Production
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TestContext;

    #[test]
    fn rust_test_paths_classified() {
        assert_eq!(classify_path("src/foo.rs"), TestContext::Production);
        assert_eq!(classify_path("tests/foo.rs"), TestContext::TestOnly);
        assert_eq!(classify_path("src/foo_test.rs"), TestContext::TestOnly);
        assert_eq!(classify_path("src/foo_tests.rs"), TestContext::TestOnly);
        assert_eq!(classify_path("benches/bench.rs"), TestContext::TestOnly);
    }

    #[test]
    fn python_test_paths_classified() {
        assert_eq!(classify_path("foo/bar.py"), TestContext::Production);
        assert_eq!(
            classify_path("foo/tests/test_bar.py"),
            TestContext::TestOnly
        );
        assert_eq!(classify_path("test_bar.py"), TestContext::TestOnly);
        assert_eq!(classify_path("bar_test.py"), TestContext::TestOnly);
        assert_eq!(classify_path("tests.py"), TestContext::TestOnly);
    }

    #[test]
    fn go_test_paths_classified() {
        assert_eq!(classify_path("foo.go"), TestContext::Production);
        assert_eq!(classify_path("foo_test.go"), TestContext::TestOnly);
        assert_eq!(
            classify_path("internal/bar/baz_test.go"),
            TestContext::TestOnly
        );
    }

    #[test]
    fn javascript_test_paths_classified() {
        assert_eq!(classify_path("src/foo.ts"), TestContext::Production);
        assert_eq!(classify_path("src/foo.test.ts"), TestContext::TestOnly);
        assert_eq!(classify_path("src/foo.spec.js"), TestContext::TestOnly);
        assert_eq!(
            classify_path("__tests__/foo.tsx"),
            TestContext::TestOnly
        );
    }

    #[test]
    fn julia_test_paths_classified() {
        assert_eq!(classify_path("src/Foo.jl"), TestContext::Production);
        assert_eq!(classify_path("test/runtests.jl"), TestContext::TestOnly);
        assert_eq!(classify_path("test/Foo.jl"), TestContext::TestOnly);
    }

    #[test]
    fn zig_test_paths_classified() {
        assert_eq!(classify_path("src/main.zig"), TestContext::Production);
        assert_eq!(classify_path("src/main_test.zig"), TestContext::TestOnly);
        assert_eq!(classify_path("tests/integ.zig"), TestContext::TestOnly);
    }

    #[test]
    fn doc_paths_win_over_test() {
        assert_eq!(
            classify_path("docs/examples/hello.rs"),
            TestContext::Doc
        );
        assert_eq!(classify_path("foo.example.py"), TestContext::Doc);
    }

    #[test]
    fn content_promotes_test_scope() {
        let exunit = "defmodule MyTest do\n  use ExUnit.Case\nend\n";
        assert_eq!(classify("lib/my_module.exs", exunit), TestContext::TestOnly);
        let unittest = "class FooTest(unittest.TestCase):\n    pass\n";
        assert_eq!(classify("src/foo.py", unittest), TestContext::TestOnly);
    }

    #[test]
    fn doc_path_beats_content_test_marker() {
        let exunit = "use ExUnit.Case\n";
        assert_eq!(classify("docs/examples/x.exs", exunit), TestContext::Doc);
    }

    #[test]
    fn production_default() {
        let plain = "fn main() { println!(\"hi\"); }\n";
        assert_eq!(classify("src/main.rs", plain), TestContext::Production);
    }

    #[test]
    fn underscore_prefix_python_not_test() {
        // `_test_helpers.py` is a helper module, not a pytest entry.
        assert_eq!(
            classify_path("src/_test_helpers.py"),
            TestContext::Production
        );
    }
}
