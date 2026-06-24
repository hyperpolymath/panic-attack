// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>

//! JIT-compilation context detection (v2.5.5 `jit_context` slice).
//!
//! Some `mem::transmute` / `mem::transmute_copy` calls are the canonical
//! way to invoke a JIT-emitted function pointer — there is no
//! `unsafe`-free way to call into code that wasn't visible to the Rust
//! compiler at build time. In that context, the `UnsafeCode` finding is
//! a hard requirement of the JIT pattern rather than an avoidable
//! type-pun.
//!
//! This module factors the per-language JIT-context detection out of
//! the analyzer so emit sites can ask:
//!
//! ```ignore
//! use panic_attack::jit_context::{JitContext, classify_rust};
//! let ctx = classify_rust(file_content);
//! if ctx == JitContext::Cranelift && targets_fn_ptr(span) {
//!     wp.suppressed = true;
//!     wp.severity = Severity::High; // not Critical
//! }
//! ```
//!
//! The existing analyzer at `src/assail/analyzer.rs:1117..1129` already
//! performs this check inline for the Rust mem::transmute site; this
//! module is the canonical home so subsequent JIT-related detectors
//! (LLVM `MCJIT`, V8/CoreCLR embeddings) can share the classifier.

use serde::{Deserialize, Serialize};

/// JIT-compilation framework recognised in a source file.
///
/// Used as metadata on `WeakPoint` to communicate that an `UnsafeCode`
/// or `UnsafeTypeCoercion` finding sits inside a JIT dispatch surface
/// where the unsafe-ness is structural to the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JitContext {
    /// Cranelift JIT (`cranelift-jit` / `cranelift-module` crates).
    /// Detected via use of `JITModule`, `cranelift_jit::*`, or
    /// `get_finalized_function`.
    Cranelift,
    /// LLVM JIT (`inkwell` or raw `llvm-sys` bindings, MCJIT/OrcJIT).
    /// Detected via use of `inkwell::execution_engine` or `LLVMOrcJIT*`.
    Llvm,
    /// WebAssembly engine embedding (`wasmtime` / `wasmer`). The
    /// `Module::new` / `Instance::new` boundary returns function
    /// references that must be reinterpreted before invocation.
    Wasm,
    /// V8 / SpiderMonkey / JavaScriptCore embedding (typically via
    /// `rusty_v8` / `boa_engine`). Same fn-ptr / value-conversion
    /// idioms apply.
    Javascript,
    /// No JIT context detected.
    None,
}

impl JitContext {
    /// Returns true if a `transmute` to a function-pointer type inside
    /// this context is the canonical JIT-dispatch idiom and should be
    /// downgraded from Critical to High severity.
    pub fn permits_fn_ptr_transmute(self) -> bool {
        !matches!(self, JitContext::None)
    }
}

/// Classify a Rust source file's JIT context. Pure-content heuristic —
/// detects imports / API surface usage without parsing.
pub fn classify_rust(content: &str) -> JitContext {
    if is_cranelift(content) {
        JitContext::Cranelift
    } else if is_llvm(content) {
        JitContext::Llvm
    } else if is_wasm(content) {
        JitContext::Wasm
    } else if is_javascript_embedding(content) {
        JitContext::Javascript
    } else {
        JitContext::None
    }
}

fn is_cranelift(content: &str) -> bool {
    content.contains("cranelift_jit::JITModule")
        || content.contains("cranelift_module::Module")
        || content.contains("JITModule::new(")
        || (content.contains("cranelift_jit")
            && content.contains("get_finalized_function"))
        || content.contains("use cranelift_jit")
        || content.contains("use cranelift_module")
}

fn is_llvm(content: &str) -> bool {
    content.contains("inkwell::execution_engine")
        || content.contains("LLVMOrcJIT")
        || content.contains("LLVMCreateExecutionEngine")
        || content.contains("MCJIT")
        || content.contains("OrcJITStack")
}

fn is_wasm(content: &str) -> bool {
    content.contains("wasmtime::Module")
        || content.contains("wasmtime::Instance")
        || content.contains("wasmer::Module")
        || content.contains("wasmer::Instance")
        || (content.contains("wasmtime") && content.contains("get_typed_func"))
}

fn is_javascript_embedding(content: &str) -> bool {
    content.contains("rusty_v8::Isolate")
        || content.contains("boa_engine::Context")
        || content.contains("rusty_jsc::JSContext")
        || (content.contains("v8::") && content.contains("Function::call"))
}

/// True if a `mem::transmute` (or `transmute_copy`) in this content
/// targets a function-pointer type. Pattern-matches the standard
/// turbofish forms and let-binding forms documented in
/// `src/assail/analyzer.rs:1110..1129`.
pub fn transmute_targets_fn_ptr(content: &str) -> bool {
    // Turbofish forms — unambiguous.
    if content.contains("transmute::<_, fn(")
        || content.contains("transmute::<_, unsafe fn(")
        || content.contains("transmute::<*const u8, fn(")
        || content.contains("transmute::<*mut u8, fn(")
    {
        return true;
    }
    // Let-binding forms — accept when a `: fn(...)` (or
    // `: unsafe fn(...)`) annotation co-occurs with a `transmute(`
    // call. The `=` may have intervening tokens (`unsafe { ... }`,
    // closure wrappers, etc.), so we don't require it adjacent.
    let has_fn_annotation =
        content.contains(": fn(") || content.contains(": unsafe fn(");
    let has_transmute_call = content.contains("transmute(")
        || content.contains("mem::transmute(")
        || content.contains("std::mem::transmute(");
    has_fn_annotation && has_transmute_call
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cranelift_module_use_classified() {
        let src = "use cranelift_jit::JITModule;\nfn main() {}\n";
        assert_eq!(classify_rust(src), JitContext::Cranelift);
    }

    #[test]
    fn cranelift_fully_qualified_classified() {
        let src = "fn build() -> cranelift_module::Module { todo!() }";
        assert_eq!(classify_rust(src), JitContext::Cranelift);
    }

    #[test]
    fn llvm_inkwell_classified() {
        let src =
            "use inkwell::execution_engine::ExecutionEngine;\nfn run() {}\n";
        assert_eq!(classify_rust(src), JitContext::Llvm);
    }

    #[test]
    fn wasmtime_classified() {
        let src = "use wasmtime::Instance;\nfn host() {}\n";
        assert_eq!(classify_rust(src), JitContext::Wasm);
    }

    #[test]
    fn wasmer_classified() {
        let src = "use wasmer::Module;\nfn host() {}\n";
        assert_eq!(classify_rust(src), JitContext::Wasm);
    }

    #[test]
    fn rusty_v8_classified() {
        let src = "use rusty_v8::Isolate;\nfn embed() {}\n";
        assert_eq!(classify_rust(src), JitContext::Javascript);
    }

    #[test]
    fn boa_classified() {
        let src = "use boa_engine::Context;\nfn embed() {}\n";
        assert_eq!(classify_rust(src), JitContext::Javascript);
    }

    #[test]
    fn no_jit_context() {
        let src = "fn main() { println!(\"hi\"); }\n";
        assert_eq!(classify_rust(src), JitContext::None);
    }

    #[test]
    fn cranelift_priority_over_llvm_if_both_present() {
        // Cranelift can target LLVM IR internally — if both are
        // referenced, we report Cranelift because that's the higher-level
        // engine being used.
        let src = "use cranelift_jit::JITModule;\n// also uses LLVMOrcJIT internally\n";
        assert_eq!(classify_rust(src), JitContext::Cranelift);
    }

    #[test]
    fn transmute_to_fn_ptr_turbofish_recognised() {
        let src =
            "let f: fn() = unsafe { std::mem::transmute::<_, fn()>(ptr) };";
        assert!(transmute_targets_fn_ptr(src));
    }

    #[test]
    fn transmute_to_fn_ptr_let_binding_recognised() {
        let src =
            "let f: fn(i64) -> i64 = unsafe { mem::transmute(raw_ptr) };";
        assert!(transmute_targets_fn_ptr(src));
    }

    #[test]
    fn transmute_to_unsafe_fn_recognised() {
        let src = "let f: unsafe fn() = unsafe { transmute(raw) };";
        assert!(transmute_targets_fn_ptr(src));
    }

    #[test]
    fn transmute_to_non_fn_not_recognised() {
        let src =
            "let n: u64 = unsafe { std::mem::transmute::<_, u64>(value) };";
        assert!(!transmute_targets_fn_ptr(src));
    }

    #[test]
    fn permits_flag_consistent() {
        assert!(JitContext::Cranelift.permits_fn_ptr_transmute());
        assert!(JitContext::Llvm.permits_fn_ptr_transmute());
        assert!(JitContext::Wasm.permits_fn_ptr_transmute());
        assert!(JitContext::Javascript.permits_fn_ptr_transmute());
        assert!(!JitContext::None.permits_fn_ptr_transmute());
    }
}
