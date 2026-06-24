// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! FFI subtyping (v2.5.5 `ffi_refinement` slice).
//!
//! `WeakPointCategory::UnsafeFFI` aggregates several semantically
//! distinct cases under one code (PA013). This module introduces
//! `FfiKind` to distinguish them so audits + suppressions can be
//! targeted.
//!
//! The current FFI detection emits PA013 whenever a Zig source file
//! has `@cImport(...)` calls or a Rust source file has `extern "C"`
//! blocks. But not every `@cImport` is equivalent:
//!
//!   * `build.zig` uses `@cImport` to discover compiler include
//!     paths — a **BuildSystem** use, not a runtime FFI exposure.
//!   * Library glue like `bindings/zig/cdef.zig` uses `@cImport` to
//!     declare the ABI surface — a **RuntimeABI** boundary the
//!     program will actually cross at runtime.
//!   * Test-only mock harnesses like `tests/mocks/c_stubs.zig` use
//!     `@cImport` to satisfy a stub-link — a **TestMock** use that
//!     doesn't ship.
//!
//! Distinguishing these reduces FPs against `build.zig` and lets
//! audits accept TestMock occurrences uniformly while still flagging
//! every RuntimeABI boundary.

use serde::{Deserialize, Serialize};

/// Subtype for `WeakPointCategory::UnsafeFFI` (PA013).
///
/// Stored on `WeakPoint` as optional metadata; `None` means the
/// detector did not classify the kind (legacy / pre-v2.5.5 emit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FfiKind {
    /// Build-system FFI: `@cImport` in `build.zig`, `bindgen` invocation
    /// in a Rust `build.rs`, similar uses where the FFI call is
    /// compile-time and does not survive into the produced binary.
    BuildSystem,
    /// Runtime ABI boundary: the program will actually call across this
    /// FFI at runtime. The highest-priority class for audit attention.
    RuntimeAbi,
    /// Test mock / stub: `@cImport` or `extern "C"` that exists to
    /// satisfy a test harness and is not shipped in release builds.
    TestMock,
    /// Could not classify the kind from path + content alone — the
    /// emit site should treat this as RuntimeAbi for safety (false
    /// positives are OK; false negatives are not).
    Unknown,
}

impl FfiKind {
    /// Classify an FFI usage by its file path. This is the path-only
    /// heuristic — content-based classification (e.g. `@cImport` in a
    /// `#[cfg(test)]` Rust module that lives in a production source
    /// file) is handled at the analyser level using
    /// `crate::test_context::classify`.
    pub fn classify_by_path(file_path: &str) -> Self {
        if is_build_system_path(file_path) {
            FfiKind::BuildSystem
        } else if is_test_mock_path(file_path) {
            FfiKind::TestMock
        } else if is_runtime_abi_path(file_path) {
            FfiKind::RuntimeAbi
        } else {
            FfiKind::Unknown
        }
    }

    /// Returns true if this FFI kind should drive `WeakPoint.suppressed`
    /// to true. BuildSystem and TestMock are accepted by default; the
    /// build-time / test-time usage doesn't represent a runtime risk.
    pub fn is_audit_accepted_by_default(self) -> bool {
        matches!(self, FfiKind::BuildSystem | FfiKind::TestMock)
    }
}

fn is_build_system_path(p: &str) -> bool {
    // build.zig / build.rs are the build-system entry points for Zig
    // and Rust. Their `@cImport` / `extern` / `bindgen!` calls do not
    // produce code in the shipping binary.
    let basename = p.rsplit('/').next().unwrap_or(p);
    matches!(basename, "build.zig" | "build.rs")
        || p.contains("build.zig.zon")
        || p.contains("build/cmake/")
        || p.contains("build.cargo/")
}

fn is_test_mock_path(p: &str) -> bool {
    // Test mocks live under tests/ AND have "mock" or "stub" in the
    // path. Plain test files are still RuntimeAbi if they call the
    // real FFI surface (they exercise it).
    let has_test_scope = p.contains("tests/") || p.contains("test/");
    let has_mock_indicator =
        p.contains("/mocks/") || p.contains("_mock.") || p.contains("/stubs/") || p.contains("_stub.");
    has_test_scope && has_mock_indicator
}

fn is_runtime_abi_path(p: &str) -> bool {
    // Heuristic: anything named bindings/, ffi/, sys/, ABI/, *.sys.rs,
    // *.bindings.zig is shipped-as-ABI.
    p.contains("/bindings/")
        || p.starts_with("bindings/")
        || p.contains("/ffi/")
        || p.starts_with("ffi/")
        || p.contains("/sys/")
        || p.starts_with("sys/")
        || p.contains("/abi/")
        || p.starts_with("abi/")
        || p.ends_with(".sys.rs")
        || p.ends_with(".bindings.zig")
        || p.ends_with("cdef.zig")
        || p.ends_with("extern.zig")
}

/// Cross-reference helper: returns true if `file_path` is listed in a
/// project's pre-approved FFI boundary audit (typically
/// `audits/audit-ffi-unsafe.md`).
///
/// Implementation note: this is a placeholder that parses the audit
/// file when present and returns false otherwise. Wire-in to the
/// analyzer happens in the follow-up PR.
pub fn is_audited_boundary(audit_text: &str, file_path: &str) -> bool {
    // The audit file's convention is a `## Approved boundaries` section
    // with a markdown list of `- file/path/here.zig — rationale` lines.
    let mut in_approved_section = false;
    for line in audit_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("## ") {
            in_approved_section =
                trimmed.eq_ignore_ascii_case("## Approved boundaries")
                    || trimmed.eq_ignore_ascii_case("## Approved FFI boundaries")
                    || trimmed.eq_ignore_ascii_case("## Pre-approved boundaries");
            continue;
        }
        if !in_approved_section {
            continue;
        }
        // Match `- <path>` or `- <path> — reason` or backticked form.
        let after_dash = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .unwrap_or(trimmed);
        let path_token = after_dash
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('`');
        if !path_token.is_empty() && file_path == path_token {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_zig_classified_build_system() {
        assert_eq!(
            FfiKind::classify_by_path("build.zig"),
            FfiKind::BuildSystem
        );
        assert_eq!(
            FfiKind::classify_by_path("src/foo/build.zig"),
            FfiKind::BuildSystem
        );
    }

    #[test]
    fn build_rs_classified_build_system() {
        assert_eq!(FfiKind::classify_by_path("build.rs"), FfiKind::BuildSystem);
    }

    #[test]
    fn bindings_classified_runtime_abi() {
        assert_eq!(
            FfiKind::classify_by_path("bindings/rust/src/lib.rs"),
            FfiKind::RuntimeAbi
        );
        assert_eq!(
            FfiKind::classify_by_path("ffi/zig/cdef.zig"),
            FfiKind::RuntimeAbi
        );
        assert_eq!(
            FfiKind::classify_by_path("src/sys/glibc.sys.rs"),
            FfiKind::RuntimeAbi
        );
    }

    #[test]
    fn test_mock_classified() {
        assert_eq!(
            FfiKind::classify_by_path("tests/mocks/c_stubs.zig"),
            FfiKind::TestMock
        );
        assert_eq!(
            FfiKind::classify_by_path("test/stubs/external_mock.zig"),
            FfiKind::TestMock
        );
        assert_eq!(
            FfiKind::classify_by_path("tests/integration/foo_mock.rs"),
            FfiKind::TestMock
        );
    }

    #[test]
    fn unrecognised_path_is_unknown() {
        assert_eq!(
            FfiKind::classify_by_path("src/main.rs"),
            FfiKind::Unknown
        );
        assert_eq!(
            FfiKind::classify_by_path("examples/hello.zig"),
            FfiKind::Unknown
        );
    }

    #[test]
    fn build_and_test_default_suppressed() {
        assert!(FfiKind::BuildSystem.is_audit_accepted_by_default());
        assert!(FfiKind::TestMock.is_audit_accepted_by_default());
        assert!(!FfiKind::RuntimeAbi.is_audit_accepted_by_default());
        assert!(!FfiKind::Unknown.is_audit_accepted_by_default());
    }

    #[test]
    fn audited_boundary_match_dash_form() {
        let audit = "# audit\n\n## Approved boundaries\n\n- ffi/zig/cdef.zig — sodium bindings\n- src/sys/glibc.sys.rs — autogen by bindgen\n";
        assert!(is_audited_boundary(audit, "ffi/zig/cdef.zig"));
        assert!(is_audited_boundary(audit, "src/sys/glibc.sys.rs"));
        assert!(!is_audited_boundary(audit, "src/main.rs"));
    }

    #[test]
    fn audited_boundary_match_backtick_form() {
        let audit = "## Pre-approved boundaries\n\n- `ffi/zig/cdef.zig` — sodium\n";
        assert!(is_audited_boundary(audit, "ffi/zig/cdef.zig"));
    }

    #[test]
    fn audited_boundary_outside_approved_section_no_match() {
        let audit = "## Banned boundaries\n\n- bad/ffi.zig — deprecated\n";
        assert!(!is_audited_boundary(audit, "bad/ffi.zig"));
    }
}
