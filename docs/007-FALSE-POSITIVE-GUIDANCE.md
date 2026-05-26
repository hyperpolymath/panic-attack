# 007 False Positive Guidance for Panic-Attack

This document explains common false positives encountered when running panic-attack on the 007 repository and how to avoid them in future.

## Current State (2026-04-15)

After addressing critical findings, the following categories remain:

### 1. PanicPath (28 findings) - Medium Severity
**Issue**: unwrap/expect calls across many files
**Files affected**: adapters.rs, agent_api.rs, backends.rs, and 25+ others
**Status**: Documented but not yet refactored

**Why these are currently acceptable**:
- Many are in test code where panic is acceptable
- Some are in prototype/early-stage features
- The codebase uses explicit panic for "this should never happen" scenarios

**Next steps**:
- Replace with proper error handling in production code paths
- Use `?` operator or `match` for recoverable errors
- Keep explicit panics only for truly unrecoverable conditions

### 2. UncheckedError (15 findings) - Low Severity
**Issue**: TODO/FIXME/HACK markers in code
**Files affected**: backends.rs, codegen_cranelift.rs, codegen_elixir_tests.rs, and 12+ others
**Status**: Documented but not yet cleaned up

**Why these are currently acceptable**:
- Act as in-code documentation of known issues
- Help track technical debt
- Some mark future enhancements rather than bugs

**Next steps**:
- Convert to GitHub issues where appropriate
- Remove markers when issues are resolved
- Keep only for critical known limitations

### 3. UnsafeCode (5 findings) - High Severity
**Issue**: Legitimate unsafe blocks that need documentation
**Files affected**:
- aspect_tests.rs (false positive - mentions unsafe in comments only)
- jit_compiler.rs (JIT compilation requires unsafe)
- zig_bridge.rs (FFI boundaries - already documented)

**Status**: Mostly addressed with suppression comments

**Why these are acceptable**:
- JIT compilation inherently requires unsafe for function pointer manipulation
- FFI boundaries are properly documented and audited
- False positives from comment text need better detection

### 4. UnsafeFFI (1 finding) - High Severity
**Issue**: C interop in compiler-core/build.zig
**Status**: False positive - no actual C interop found

**Why this is a false positive**:
- The file only contains `@import("std")` for Zig standard library
- Comments mention C ABI but no actual `@cImport` calls exist
- Build system files often trigger FFI detectors incorrectly

### 5. InsecureProtocol (1 finding) - Medium Severity
**Issue**: HTTP URL in integration_tests.rs
**Status**: Addressed with suppression comment

**Why this is acceptable**:
- Test data for capability-gated HTTP backend
- Not actual HTTP usage - just string literals
- Tests that backend rejects requests without proper capabilities

## How to Avoid False Positives in Future

### 1. Unsafe Code Detection
**Problem**: Panic-attack flags legitimate unsafe blocks in JIT and FFI code.

**Solutions**:
- Add `// panic-attack: accepted (reason)` comments above unsafe blocks
- For JIT: Explain why the unsafe is necessary for compilation
- For FFI: Reference the audit document (audits/audit-ffi-unsafe.md)
- For tests: Note when unsafe is in test-only code paths

**Example**:
```rust
// panic-attack: accepted (legitimate JIT function pointer transmute)
// SAFETY: Function pointer from verified Cranelift JIT compilation
unsafe {
    let f: fn() -> i64 = std::mem::transmute(ptr);
    f()
}
```

### 2. FFI Detection in Build Files
**Problem**: Build system files trigger FFI warnings incorrectly.

**Solutions**:
- Add suppression comments for build.zig and similar files
- Distinguish between actual FFI calls and documentation
- Improve panic-attack's Zig analyzer to recognize build system patterns

**Example**:
```zig
// panic-attack: accepted (build system file, no actual FFI calls)
// This file only imports Zig standard library, not C headers
const std = @import("std");
```

### 3. Test Data vs Real Usage
**Problem**: Test files with HTTP URLs or other "unsafe" patterns get flagged.

**Solutions**:
- Add context comments explaining test purpose
- Use clearly marked test data sections
- Consider test-specific suppression patterns

**Example**:
```rust
// Test data section - these URLs are never actually requested
// panic-attack: accepted (test data for capability-gated backend)
const TEST_URLS = [
    "http://example.com",  // Tests HTTP backend rejection
    "https://secure.example.com", // Tests HTTPS handling
];
```

### 4. Comment-Based False Positives
**Problem**: Comments mentioning "unsafe" trigger warnings.

**Solutions**:
- Improve panic-attack to distinguish code from comments
- Use more specific terminology in documentation
- Add suppression when documenting security aspects

**Example**:
```rust
/// This test verifies the absence of unsafe code.
/// The word "unsafe" in this comment refers to Rust's unsafe{} construct,
/// not to any actual unsafe operations in this test.
// panic-attack: accepted (documenting security aspect, no actual unsafe code)
#[test]
fn test_no_unsafe_code() {
    // Test implementation
}
```

## Roadmap for Addressing Remaining Findings

### Phase 1: Documentation and Suppression (COMPLETE)
- ✅ Add suppression comments to legitimate unsafe code
- ✅ Document false positives
- ✅ Create this guidance document

### Phase 2: Code Quality Improvements (NEXT)
- [ ] Replace unwrap/expect with proper error handling in 5 key files
- [ ] Convert TODO/FIXME markers to GitHub issues (15 markers)
- [ ] Improve panic-attack's comment analysis to reduce false positives

### Phase 3: Systematic Refactoring (FUTURE)
- [ ] Eliminate unwrap/expect from production code paths
- [ ] Replace remaining TODO/FIXME with proper documentation
- [ ] Enhance panic-attack's context awareness for test files

### Phase 4: Prevention (CONTINUOUS)
- [ ] Add CI check for new unwrap/expect in production code
- [ ] Require suppression comments for all unsafe blocks
- [ ] Regular audit of TODO/FIXME markers

## Checking Progress

To verify the current state:
```bash
cd /var/mnt/eclipse/repos/007
panic-attack assail .
```

Expected output should show:
- UnsafeCode: 5 (mostly addressed with comments)
- UnsafeFFI: 1 (false positive, documented)
- InsecureProtocol: 1 (addressed with comment)
- PanicPath: 28 (documented for future refactoring)
- UncheckedError: 15 (documented for future cleanup)

Total: ~50 findings (mostly documented and planned for resolution)

## Maintaining This Document

Update this file when:
1. New categories of false positives are discovered
2. Existing false positives are properly addressed
3. Panic-attacker's analysis improves to reduce false positives
4. Major refactoring completes that resolves documented issues

Last updated: 2026-04-15
Status: Phase 1 complete, Phase 2 in progress