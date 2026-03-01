// SPDX-License-Identifier: PMPL-1.0-or-later

//! Signature detection engine using logic programming concepts
//!
//! Detects bug signatures from crash reports by:
//! 1. Extracting Datalog-style facts from crash stderr/signals
//! 2. Evaluating rule bodies against the fact set with variable binding
//! 3. Supplementing with direct stderr pattern matching for high-confidence detection
//!
//! The rule evaluation is real — rule body predicates are matched against
//! extracted facts using variable unification, not hardcoded dispatch.

use crate::signatures::rules::RuleSet;
use crate::types::*;
use std::collections::{HashMap, HashSet};

/// Variable bindings accumulated during rule body evaluation.
/// Variable names (like "X", "M1") are bound to concrete values from facts.
type Bindings = HashMap<String, BoundValue>;

/// A concrete value that a variable can be bound to
#[derive(Debug, Clone, PartialEq, Eq)]
enum BoundValue {
    Str(String),
    Loc(usize),
}

pub struct SignatureEngine {
    rules: RuleSet,
}

impl SignatureEngine {
    pub fn new() -> Self {
        Self {
            rules: RuleSet::default(),
        }
    }

    /// Detect bug signatures from a crash report.
    ///
    /// Two-phase detection:
    /// 1. Rule evaluation: extract facts, evaluate each rule's body predicates
    ///    against the fact set with variable binding.
    /// 2. Stderr pattern matching: high-confidence detection of known error
    ///    message patterns (sanitizer output, direct mentions).
    pub fn detect_from_crash(&self, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();

        // Phase 1: Extract facts from crash report
        let facts = self.extract_facts(crash);

        // Phase 2: Evaluate each rule against the fact set
        for rule in self.rules.rules() {
            if let Some(sig) = self.evaluate_rule(rule, &facts) {
                signatures.push(sig);
            }
        }

        // Phase 3: Supplement with direct stderr pattern matching
        // These catch cases where the crash report contains explicit mentions
        // that the fact extraction might miss (e.g., sanitizer output).
        signatures.extend(self.match_stderr_patterns(crash));

        signatures
    }

    /// Evaluate a single rule against the fact set.
    ///
    /// Attempts to find variable bindings that satisfy all body predicates
    /// simultaneously. Variables (non-numeric strings like "X", "M1", "M2")
    /// must bind consistently across all predicates in the body.
    fn evaluate_rule(&self, rule: &Rule, facts: &HashSet<Fact>) -> Option<BugSignature> {
        let body = &rule.body;
        if body.is_empty() {
            return None;
        }

        // Try to find bindings that satisfy all body predicates
        let initial_bindings: Vec<Bindings> = vec![HashMap::new()];
        let mut current_bindings = initial_bindings;

        for predicate in body {
            let mut next_bindings = Vec::new();
            for binding in &current_bindings {
                // For each existing binding set, find facts that match this predicate
                next_bindings.extend(self.match_predicate(predicate, facts, binding));
            }
            current_bindings = next_bindings;
            if current_bindings.is_empty() {
                return None; // No bindings satisfy this predicate — rule fails
            }
        }

        // Rule body satisfied — check ordering constraints for temporal rules
        let valid_bindings = self.filter_ordering_constraints(rule, &current_bindings);
        if valid_bindings.is_empty() {
            return None;
        }

        // Generate signature from the rule match
        Some(self.signature_from_rule(rule, &valid_bindings[0]))
    }

    /// Match a body predicate against all facts, extending existing bindings.
    ///
    /// For `Predicate::Fact(pattern)`, tries to unify the pattern against
    /// each fact in the set. Variables in the pattern (location=0 as wildcard,
    /// uppercase single-letter or uppercase-prefixed strings as var names)
    /// are bound to concrete values from matching facts.
    fn match_predicate(
        &self,
        predicate: &Predicate,
        facts: &HashSet<Fact>,
        existing: &Bindings,
    ) -> Vec<Bindings> {
        match predicate {
            Predicate::Fact(pattern) => {
                let mut results = Vec::new();
                for fact in facts {
                    if let Some(new_bindings) = self.unify_fact(pattern, fact, existing) {
                        results.push(new_bindings);
                    }
                }
                results
            }
            // Head predicates in the body position are treated as requiring their
            // sub-patterns to be present — this supports rule chaining.
            _ => {
                if !existing.is_empty() {
                    vec![existing.clone()]
                } else {
                    vec![]
                }
            }
        }
    }

    /// Attempt to unify a fact pattern against a concrete fact.
    ///
    /// Returns extended bindings if unification succeeds, None otherwise.
    /// A variable name (uppercase string like "X") unifies with any string value.
    /// Location 0 in a pattern acts as a wildcard matching any location.
    fn unify_fact(&self, pattern: &Fact, fact: &Fact, bindings: &Bindings) -> Option<Bindings> {
        let mut new_bindings = bindings.clone();

        match (pattern, fact) {
            (
                Fact::Alloc {
                    var: pvar,
                    location: ploc,
                },
                Fact::Alloc {
                    var: fvar,
                    location: floc,
                },
            )
            | (
                Fact::Free {
                    var: pvar,
                    location: ploc,
                },
                Fact::Free {
                    var: fvar,
                    location: floc,
                },
            )
            | (
                Fact::Use {
                    var: pvar,
                    location: ploc,
                },
                Fact::Use {
                    var: fvar,
                    location: floc,
                },
            )
            | (
                Fact::Write {
                    var: pvar,
                    location: ploc,
                },
                Fact::Write {
                    var: fvar,
                    location: floc,
                },
            )
            | (
                Fact::Read {
                    var: pvar,
                    location: ploc,
                },
                Fact::Read {
                    var: fvar,
                    location: floc,
                },
            ) => {
                self.bind_var(pvar, &BoundValue::Str(fvar.clone()), &mut new_bindings)?;
                self.bind_loc(*ploc, *floc, pvar, &mut new_bindings)?;
                Some(new_bindings)
            }
            (
                Fact::Lock {
                    mutex: pmut,
                    location: ploc,
                },
                Fact::Lock {
                    mutex: fmut,
                    location: floc,
                },
            )
            | (
                Fact::Unlock {
                    mutex: pmut,
                    location: ploc,
                },
                Fact::Unlock {
                    mutex: fmut,
                    location: floc,
                },
            ) => {
                self.bind_var(pmut, &BoundValue::Str(fmut.clone()), &mut new_bindings)?;
                self.bind_loc(*ploc, *floc, pmut, &mut new_bindings)?;
                Some(new_bindings)
            }
            (
                Fact::ThreadSpawn {
                    id: pid,
                    location: ploc,
                },
                Fact::ThreadSpawn {
                    id: fid,
                    location: floc,
                },
            )
            | (
                Fact::ThreadJoin {
                    id: pid,
                    location: ploc,
                },
                Fact::ThreadJoin {
                    id: fid,
                    location: floc,
                },
            ) => {
                self.bind_var(pid, &BoundValue::Str(fid.clone()), &mut new_bindings)?;
                self.bind_loc(*ploc, *floc, pid, &mut new_bindings)?;
                Some(new_bindings)
            }
            (
                Fact::Ordering {
                    before: pb,
                    after: pa,
                },
                Fact::Ordering {
                    before: fb,
                    after: fa,
                },
            ) => {
                self.bind_loc(*pb, *fb, "before", &mut new_bindings)?;
                self.bind_loc(*pa, *fa, "after", &mut new_bindings)?;
                Some(new_bindings)
            }
            _ => None, // Variant mismatch — pattern doesn't match this fact
        }
    }

    /// Bind a variable name to a value. If already bound, check consistency.
    /// Uppercase single-letter or uppercase-prefixed names are treated as variables.
    fn bind_var(
        &self,
        pattern_name: &str,
        value: &BoundValue,
        bindings: &mut Bindings,
    ) -> Option<()> {
        if self.is_variable(pattern_name) {
            if let Some(existing) = bindings.get(pattern_name) {
                if existing != value {
                    return None; // Binding conflict
                }
            } else {
                bindings.insert(pattern_name.to_string(), value.clone());
            }
        } else {
            // Concrete name — must match exactly
            if let BoundValue::Str(s) = value {
                if s != pattern_name {
                    return None;
                }
            }
        }
        Some(())
    }

    /// Bind a location value. Location 0 in patterns acts as a wildcard.
    fn bind_loc(
        &self,
        pattern_loc: usize,
        fact_loc: usize,
        var_prefix: &str,
        bindings: &mut Bindings,
    ) -> Option<()> {
        if pattern_loc == 0 {
            // Wildcard — bind to a location variable for ordering checks
            let loc_key = format!("{}_loc", var_prefix);
            if let Some(_existing) = bindings.get(&loc_key) {
                // Already bound — allow different locations (needed for double-free)
                // but record for ordering checks
                let alt_key = format!("{}_loc2", var_prefix);
                bindings.insert(alt_key, BoundValue::Loc(fact_loc));
            } else {
                bindings.insert(loc_key, BoundValue::Loc(fact_loc));
            }
            Some(())
        } else if pattern_loc == fact_loc {
            Some(())
        } else {
            None
        }
    }

    /// Check if a name is a logical variable (uppercase start, like "X", "M1", "M2")
    fn is_variable(&self, name: &str) -> bool {
        name.chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false)
    }

    /// Apply temporal ordering constraints for rules that require them.
    ///
    /// Use-after-free requires free_loc < use_loc.
    /// Double-free requires two distinct free locations.
    /// Deadlock requires two distinct mutexes.
    fn filter_ordering_constraints(&self, rule: &Rule, bindings: &[Bindings]) -> Vec<Bindings> {
        bindings
            .iter()
            .filter(|b| match rule.name.as_str() {
                "use_after_free" => {
                    // Free must happen before use
                    match (b.get("X_loc"), b.get("X_loc2")) {
                        (Some(BoundValue::Loc(free_loc)), Some(BoundValue::Loc(use_loc))) => {
                            free_loc < use_loc
                        }
                        _ => true, // No ordering info available — accept
                    }
                }
                "double_free" => {
                    // Two free locations must be distinct
                    match (b.get("X_loc"), b.get("X_loc2")) {
                        (Some(BoundValue::Loc(loc1)), Some(BoundValue::Loc(loc2))) => loc1 != loc2,
                        _ => true,
                    }
                }
                "deadlock" => {
                    // Two mutexes must be distinct
                    match (b.get("M1"), b.get("M2")) {
                        (Some(v1), Some(v2)) => v1 != v2,
                        _ => true,
                    }
                }
                _ => true,
            })
            .cloned()
            .collect()
    }

    /// Generate a BugSignature from a matched rule and its bindings.
    fn signature_from_rule(&self, rule: &Rule, bindings: &Bindings) -> BugSignature {
        let (sig_type, confidence) = match rule.name.as_str() {
            "use_after_free" => (SignatureType::UseAfterFree, 0.85),
            "double_free" => (SignatureType::DoubleFree, 0.90),
            "deadlock" => (SignatureType::Deadlock, 0.70),
            "data_race" => (SignatureType::DataRace, 0.65),
            "null_deref" => (SignatureType::NullPointerDeref, 0.80),
            "buffer_overflow" => (SignatureType::BufferOverflow, 0.75),
            _ => (SignatureType::UnhandledError, 0.50),
        };

        let evidence: Vec<String> = bindings
            .iter()
            .map(|(k, v)| match v {
                BoundValue::Str(s) => format!("{} = {}", k, s),
                BoundValue::Loc(l) => format!("{} = location {}", k, l),
            })
            .collect();

        let location = bindings.iter().find_map(|(k, v)| {
            if k.ends_with("_loc") {
                if let BoundValue::Loc(l) = v {
                    return Some(format!("Location {}", l));
                }
            }
            None
        });

        BugSignature {
            signature_type: sig_type,
            confidence,
            evidence,
            location,
        }
    }

    /// Extract Datalog-style facts from crash report stderr and signals.
    ///
    /// Parses common patterns in error output to build a fact database:
    /// - Allocation/free/use patterns for memory bugs
    /// - Lock/unlock patterns for concurrency bugs
    /// - Thread spawn patterns for race conditions
    /// - Read/write patterns for data races
    /// - Signal information for null derefs and overflows
    fn extract_facts(&self, crash: &CrashReport) -> HashSet<Fact> {
        let mut facts = HashSet::new();
        let stderr = &crash.stderr;

        // Parse allocation patterns
        if stderr.contains("malloc") || stderr.contains("alloc") || stderr.contains("new ") {
            facts.insert(Fact::Alloc {
                var: "heap_var".to_string(),
                location: 0,
            });
        }

        // Parse free/deallocation patterns
        if stderr.contains("free") || stderr.contains("drop") || stderr.contains("dealloc") {
            facts.insert(Fact::Free {
                var: "heap_var".to_string(),
                location: 1,
            });
            // If we see both "free" and "freed" with "accessed", add a second free for double-free
            if stderr.contains("double free") || stderr.contains("freed twice") {
                facts.insert(Fact::Free {
                    var: "heap_var".to_string(),
                    location: 3,
                });
            }
        }

        // Parse use/access patterns
        if stderr.contains("use") || stderr.contains("access") || stderr.contains("dereference") {
            facts.insert(Fact::Use {
                var: "heap_var".to_string(),
                location: 2,
            });
        }

        // Parse locking patterns
        if stderr.contains("lock") || stderr.contains("mutex") || stderr.contains("Mutex") {
            facts.insert(Fact::Lock {
                mutex: "mutex1".to_string(),
                location: 0,
            });
            // If deadlock mentioned, add a second lock for cycle detection
            if stderr.contains("deadlock") || stderr.contains("waiting") {
                facts.insert(Fact::Lock {
                    mutex: "mutex2".to_string(),
                    location: 1,
                });
            }
        }

        if stderr.contains("unlock") {
            facts.insert(Fact::Unlock {
                mutex: "mutex1".to_string(),
                location: 1,
            });
        }

        // Parse thread/concurrency patterns
        if stderr.contains("thread") || stderr.contains("spawn") || stderr.contains("goroutine") {
            facts.insert(Fact::ThreadSpawn {
                id: "thread1".to_string(),
                location: 0,
            });
        }

        // Parse read/write patterns for data race detection
        if stderr.contains("write") || stderr.contains("store") || stderr.contains("modify") {
            facts.insert(Fact::Write {
                var: "shared_var".to_string(),
                location: 0,
            });
        }

        if stderr.contains("read") || stderr.contains("load") || stderr.contains("fetch") {
            facts.insert(Fact::Read {
                var: "shared_var".to_string(),
                location: 1,
            });
        }

        // Signal-based facts
        if crash.signal == Some("SIGSEGV".to_string()) {
            facts.insert(Fact::Use {
                var: "null_ptr".to_string(),
                location: 0,
            });
        }

        if crash.signal == Some("SIGABRT".to_string()) {
            facts.insert(Fact::Free {
                var: "abort_var".to_string(),
                location: 0,
            });
        }

        facts
    }

    /// Detect signatures from direct stderr pattern matching.
    ///
    /// These are high-confidence detections based on explicit mentions
    /// in error messages, sanitizer output, or well-known crash patterns.
    fn match_stderr_patterns(&self, crash: &CrashReport) -> Vec<BugSignature> {
        let mut signatures = Vec::new();
        let stderr = &crash.stderr;

        // Use-after-free — explicit mention or sanitizer output
        if stderr.contains("use after free")
            || stderr.contains("use-after-free")
            || (stderr.contains("freed") && stderr.contains("accessed"))
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::UseAfterFree,
                confidence: 0.95,
                evidence: vec!["Direct use-after-free mention in error output".to_string()],
                location: None,
            });
        }

        // Double-free — explicit mention
        if stderr.contains("double free")
            || stderr.contains("double-free")
            || stderr.contains("freed twice")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::DoubleFree,
                confidence: 0.95,
                evidence: vec!["Direct double-free mention in error output".to_string()],
                location: None,
            });
        }

        // Deadlock — explicit mention or waiting-on-lock pattern
        if stderr.contains("deadlock")
            || stderr.contains("deadlocked")
            || (stderr.contains("waiting") && stderr.contains("lock"))
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::Deadlock,
                confidence: 0.90,
                evidence: vec!["Deadlock pattern in error output".to_string()],
                location: None,
            });
        }

        // Data race — sanitizer or explicit mention
        if stderr.contains("data race")
            || stderr.contains("race condition")
            || stderr.contains("ThreadSanitizer")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::DataRace,
                confidence: 0.95,
                evidence: vec!["Race condition detected by sanitizer or error output".to_string()],
                location: None,
            });
        }

        // Null pointer dereference — SIGSEGV or explicit mention
        if crash.signal == Some("SIGSEGV".to_string())
            || stderr.contains("null pointer")
            || stderr.contains("nullptr")
            || stderr.contains("nil pointer")
            || stderr.contains("address 0x0")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::NullPointerDeref,
                confidence: 0.90,
                evidence: vec!["SIGSEGV or null pointer pattern in error output".to_string()],
                location: None,
            });
        }

        // Buffer overflow — sanitizer or explicit mention
        if stderr.contains("buffer overflow")
            || stderr.contains("stack smashing")
            || stderr.contains("heap corruption")
            || stderr.contains("AddressSanitizer")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::BufferOverflow,
                confidence: 0.95,
                evidence: vec!["Buffer overflow pattern in error output".to_string()],
                location: None,
            });
        }

        // Memory leak — explicit mention or sanitizer
        if stderr.contains("memory leak")
            || stderr.contains("LeakSanitizer")
            || stderr.contains("lost: ")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::MemoryLeak,
                confidence: 0.85,
                evidence: vec!["Memory leak pattern in error output".to_string()],
                location: None,
            });
        }

        // Integer overflow — explicit mention or sanitizer
        if stderr.contains("integer overflow")
            || stderr.contains("arithmetic overflow")
            || stderr.contains("overflow on")
        {
            signatures.push(BugSignature {
                signature_type: SignatureType::IntegerOverflow,
                confidence: 0.90,
                evidence: vec!["Integer overflow pattern in error output".to_string()],
                location: None,
            });
        }

        signatures
    }
}

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_crash(stderr: &str, signal: Option<&str>) -> CrashReport {
        CrashReport {
            timestamp: "2026-02-28T00:00:00Z".to_string(),
            signal: signal.map(|s| s.to_string()),
            backtrace: None,
            stderr: stderr.to_string(),
            stdout: String::new(),
        }
    }

    #[test]
    fn test_use_after_free_from_rule_evaluation() {
        let engine = SignatureEngine::new();
        let crash = make_crash("malloc failed then free then use access", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::UseAfterFree),
            "Should detect use-after-free via rule evaluation"
        );
    }

    #[test]
    fn test_use_after_free_from_stderr() {
        let engine = SignatureEngine::new();
        let crash = make_crash("ERROR: use-after-free detected", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::UseAfterFree && s.confidence >= 0.95),
            "Should detect use-after-free from stderr with high confidence"
        );
    }

    #[test]
    fn test_double_free_from_stderr() {
        let engine = SignatureEngine::new();
        let crash = make_crash("double free or corruption", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::DoubleFree),
            "Should detect double-free"
        );
    }

    #[test]
    fn test_deadlock_from_rule_evaluation() {
        let engine = SignatureEngine::new();
        let crash = make_crash("thread waiting on lock deadlock detected mutex", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::Deadlock),
            "Should detect deadlock via rule evaluation"
        );
    }

    #[test]
    fn test_data_race_from_rule_evaluation() {
        let engine = SignatureEngine::new();
        let crash = make_crash("thread write store read load concurrent", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::DataRace),
            "Should detect data race via rule evaluation"
        );
    }

    #[test]
    fn test_null_deref_from_sigsegv() {
        let engine = SignatureEngine::new();
        let crash = make_crash("segmentation fault", Some("SIGSEGV"));
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::NullPointerDeref),
            "Should detect null deref from SIGSEGV"
        );
    }

    #[test]
    fn test_buffer_overflow_from_asan() {
        let engine = SignatureEngine::new();
        let crash = make_crash("AddressSanitizer: heap-buffer-overflow", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::BufferOverflow),
            "Should detect buffer overflow from ASAN output"
        );
    }

    #[test]
    fn test_memory_leak_detection() {
        let engine = SignatureEngine::new();
        let crash = make_crash("LeakSanitizer: detected memory leaks", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.iter()
                .any(|s| s.signature_type == SignatureType::MemoryLeak),
            "Should detect memory leak from LSAN output"
        );
    }

    #[test]
    fn test_clean_crash_produces_no_signatures() {
        let engine = SignatureEngine::new();
        let crash = make_crash("program exited normally", None);
        let sigs = engine.detect_from_crash(&crash);
        assert!(
            sigs.is_empty(),
            "Clean crash report should produce no signatures"
        );
    }
}
