// SPDX-License-Identifier: PMPL-1.0-or-later

//! Core relational logic engine
//!
//! A miniKanren-inspired engine using substitution-based unification
//! and forward/backward chaining for deriving vulnerability facts.

use crate::types::*;
use std::collections::{HashMap, HashSet};

/// A logic term in the fact database
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Term {
    /// Logic variable (unbound)
    Var(u32),
    /// String atom
    Atom(String),
    /// Integer value
    Int(i64),
    /// Compound term: functor(args...)
    Compound(String, Vec<Term>),
}

impl Term {
    pub fn atom(s: &str) -> Self {
        Term::Atom(s.to_string())
    }

    pub fn compound(name: &str, args: Vec<Term>) -> Self {
        Term::Compound(name.to_string(), args)
    }

    #[cfg(test)]
    pub fn is_var(&self) -> bool {
        matches!(self, Term::Var(_))
    }
}

/// Substitution: mapping from variable IDs to terms
#[derive(Debug, Clone, Default)]
pub struct Substitution {
    bindings: HashMap<u32, Term>,
}

impl Substitution {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk a term through the substitution, resolving variables
    pub fn walk(&self, term: &Term) -> Term {
        match term {
            Term::Var(id) => {
                if let Some(bound) = self.bindings.get(id) {
                    self.walk(bound)
                } else {
                    term.clone()
                }
            }
            _ => term.clone(),
        }
    }

    /// Unify two terms, extending the substitution if successful
    pub fn unify(&self, t1: &Term, t2: &Term) -> Option<Substitution> {
        let t1 = self.walk(t1);
        let t2 = self.walk(t2);

        match (&t1, &t2) {
            // Same term
            (a, b) if a == b => Some(self.clone()),

            // Variable binding
            (Term::Var(id), _) => {
                let mut new_subst = self.clone();
                new_subst.bindings.insert(*id, t2);
                Some(new_subst)
            }
            (_, Term::Var(id)) => {
                let mut new_subst = self.clone();
                new_subst.bindings.insert(*id, t1);
                Some(new_subst)
            }

            // Compound term unification
            (Term::Compound(f1, args1), Term::Compound(f2, args2)) => {
                if f1 != f2 || args1.len() != args2.len() {
                    return None;
                }
                let mut subst = self.clone();
                for (a1, a2) in args1.iter().zip(args2.iter()) {
                    subst = subst.unify(a1, a2)?;
                }
                Some(subst)
            }

            // No unification possible
            _ => None,
        }
    }

    /// Extract the resolved value of a variable
    #[cfg(test)]
    pub fn resolve(&self, var_id: u32) -> Option<Term> {
        let term = Term::Var(var_id);
        let resolved = self.walk(&term);
        if resolved.is_var() {
            None
        } else {
            Some(resolved)
        }
    }
}

/// A fact in the database (ground term - no variables)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogicFact {
    pub relation: String,
    pub args: Vec<Term>,
}

impl LogicFact {
    pub fn new(relation: &str, args: Vec<Term>) -> Self {
        Self {
            relation: relation.to_string(),
            args,
        }
    }

    /// Convert to a compound term for unification
    pub fn to_term(&self) -> Term {
        Term::compound(&self.relation, self.args.clone())
    }
}

/// Metadata for inference rules
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub confidence: f64,
    pub priority: u32,
    pub tags: Vec<String>,
    pub risk_tier: Option<String>,
}

impl RuleMetadata {
    #[allow(dead_code)]
    pub fn new(
        confidence: f64,
        priority: u32,
        tags: Vec<String>,
        risk_tier: Option<String>,
    ) -> Self {
        Self {
            confidence,
            priority,
            tags,
            risk_tier,
        }
    }
}

impl Default for RuleMetadata {
    fn default() -> Self {
        Self {
            confidence: 0.5,
            priority: 0,
            tags: Vec::new(),
            risk_tier: None,
        }
    }
}

/// A rule: head :- body (if all body facts hold, derive head)
#[derive(Debug, Clone)]
pub struct LogicRule {
    pub name: String,
    pub head: LogicFact,
    pub body: Vec<LogicFact>,
    pub metadata: RuleMetadata,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuleApplication {
    pub name: String,
    pub confidence: f64,
    pub priority: u32,
    pub tags: Vec<String>,
    pub risk_tier: Option<String>,
    pub derived: usize,
}

impl LogicRule {
    pub fn with_metadata(
        name: String,
        head: LogicFact,
        body: Vec<LogicFact>,
        metadata: RuleMetadata,
    ) -> Self {
        Self {
            name,
            head,
            body,
            metadata,
        }
    }
}

/// The fact database with forward chaining
#[derive(Debug, Default)]
pub struct FactDB {
    facts: HashSet<LogicFact>,
    rules: Vec<LogicRule>,
}

impl FactDB {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assert a new fact
    pub fn assert_fact(&mut self, fact: LogicFact) {
        self.facts.insert(fact);
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: LogicRule) {
        self.rules.push(rule);
    }

    /// Assert a convenience fact from relation name and string args
    #[cfg(test)]
    pub fn assert(&mut self, relation: &str, args: Vec<&str>) {
        self.assert_fact(LogicFact::new(
            relation,
            args.into_iter().map(Term::atom).collect(),
        ));
    }

    /// Query the database: find all substitutions matching a pattern
    #[cfg(test)]
    pub fn query(&self, relation: &str, pattern: &[Term]) -> Vec<Substitution> {
        let query_term = Term::Compound(relation.to_string(), pattern.to_vec());
        let mut results = Vec::new();

        for fact in &self.facts {
            if fact.relation != relation || fact.args.len() != pattern.len() {
                continue;
            }
            let subst = Substitution::new();
            if let Some(unified) = subst.unify(&query_term, &fact.to_term()) {
                results.push(unified);
            }
        }

        results
    }

    /// Forward chaining: apply all rules to derive new facts
    /// Returns the number of new facts derived plus rule applications
    pub fn forward_chain(&mut self) -> (usize, Vec<RuleApplication>) {
        let mut new_facts = Vec::new();
        let mut total_derived = 0;
        let mut applications = Vec::new();

        loop {
            new_facts.clear();

            for rule in &self.rules {
                // Evaluate each rule against the current fixpoint snapshot.
                let matches = self.match_body(&rule.body);
                let mut derived_this_rule = 0;

                for subst in matches {
                    let derived = self.apply_substitution_to_fact(&rule.head, &subst);
                    if !self.facts.contains(&derived) {
                        new_facts.push(derived);
                        derived_this_rule += 1;
                    }
                }

                if derived_this_rule > 0 {
                    applications.push(RuleApplication {
                        name: rule.name.clone(),
                        confidence: rule.metadata.confidence,
                        priority: rule.metadata.priority,
                        tags: rule.metadata.tags.clone(),
                        risk_tier: rule.metadata.risk_tier.clone(),
                        derived: derived_this_rule,
                    });
                }
            }

            // Reaching zero derivations means the fact set is at a stable fixpoint.
            if new_facts.is_empty() {
                break;
            }

            total_derived += new_facts.len();
            for fact in new_facts.drain(..) {
                self.facts.insert(fact);
            }
        }

        (total_derived, applications)
    }

    /// Match a conjunction of body facts against the database
    fn match_body(&self, body: &[LogicFact]) -> Vec<Substitution> {
        if body.is_empty() {
            return vec![Substitution::new()];
        }

        // Start with the empty substitution and progressively constrain it per body atom.
        let mut current_substs = vec![Substitution::new()];

        for body_fact in body {
            let mut next_substs = Vec::new();

            for subst in &current_substs {
                // Resolve currently known bindings before matching the next relation.
                let resolved_fact = self.apply_substitution_to_fact(body_fact, subst);

                // Attempt unification against all facts with compatible relation/arity.
                for db_fact in &self.facts {
                    if db_fact.relation != resolved_fact.relation
                        || db_fact.args.len() != resolved_fact.args.len()
                    {
                        continue;
                    }

                    let query = resolved_fact.to_term();
                    let target = db_fact.to_term();

                    if let Some(unified) = subst.unify(&query, &target) {
                        next_substs.push(unified);
                    }
                }
            }

            current_substs = next_substs;
            if current_substs.is_empty() {
                break;
            }
        }

        current_substs
    }

    /// Apply a substitution to a fact template
    fn apply_substitution_to_fact(&self, fact: &LogicFact, subst: &Substitution) -> LogicFact {
        LogicFact {
            relation: fact.relation.clone(),
            args: fact.args.iter().map(|arg| subst.walk(arg)).collect(),
        }
    }

    /// Count facts by relation
    #[cfg(test)]
    pub fn fact_count(&self, relation: &str) -> usize {
        self.facts.iter().filter(|f| f.relation == relation).count()
    }

    /// Get all facts for a relation
    pub fn get_facts(&self, relation: &str) -> Vec<&LogicFact> {
        self.facts
            .iter()
            .filter(|f| f.relation == relation)
            .collect()
    }

    /// Total fact count
    pub fn total_facts(&self) -> usize {
        self.facts.len()
    }

    /// Total rule count
    #[cfg(test)]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// The main logic engine combining FactDB with inference
pub struct LogicEngine {
    pub db: FactDB,
}

impl LogicEngine {
    pub fn new() -> Self {
        Self { db: FactDB::new() }
    }

    /// Extract facts from an Assail report
    pub fn ingest_report(&mut self, report: &AssailReport) {
        // Ingestion normalizes static report output into relational facts.
        // Downstream taint/cross-language analyzers assume this canonical shape.
        // Assert language fact
        self.db.assert_fact(LogicFact::new(
            "language",
            vec![Term::atom(&format!("{:?}", report.language))],
        ));

        // Assert framework facts
        for fw in &report.frameworks {
            self.db.assert_fact(LogicFact::new(
                "framework",
                vec![Term::atom(&format!("{:?}", fw))],
            ));
        }

        // Assert weak point facts
        for wp in &report.weak_points {
            let loc = wp.location.as_deref().unwrap_or("unknown");
            self.db.assert_fact(LogicFact::new(
                "weak_point",
                vec![
                    Term::atom(&format!("{:?}", wp.category)),
                    Term::atom(loc),
                    Term::atom(&format!("{:?}", wp.severity)),
                ],
            ));
        }

        // Assert file statistics
        for fs in &report.file_statistics {
            self.db.assert_fact(LogicFact::new(
                "file_risk",
                vec![
                    Term::atom(&fs.file_path),
                    Term::Int(
                        (fs.unsafe_blocks * 3
                            + fs.panic_sites * 2
                            + fs.unwrap_calls
                            + fs.threading_constructs * 2) as i64,
                    ),
                ],
            ));
        }
    }

    /// Load standard vulnerability rules
    pub fn load_standard_rules(&mut self) {
        // Rule: tainted_path(Source, Sink) :-
        //   taint_source(File, Source),
        //   data_flow(File, File2),
        //   taint_sink(File2, Sink).
        let v0 = Term::Var(100);
        let v1 = Term::Var(101);
        let v2 = Term::Var(102);
        let v3 = Term::Var(103);

        self.db.add_rule(LogicRule::with_metadata(
            "tainted_path".into(),
            LogicFact::new(
                "tainted_path",
                vec![v0.clone(), v1.clone(), v2.clone(), v3.clone()],
            ),
            vec![
                LogicFact::new("taint_source", vec![v0.clone(), v1.clone()]),
                LogicFact::new("data_flow", vec![v0.clone(), v2.clone()]),
                LogicFact::new("taint_sink", vec![v2.clone(), v3.clone()]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: vulnerability_chain(File, Category) :-
        //   weak_point(Category, File, Severity),
        //   Severity = "Critical" | "High"
        let v4 = Term::Var(104);
        let v5 = Term::Var(105);
        self.db.add_rule(LogicRule::with_metadata(
            "critical_vuln".into(),
            LogicFact::new("critical_vuln", vec![v4.clone(), v5.clone()]),
            vec![LogicFact::new(
                "weak_point",
                vec![v4.clone(), v5.clone(), Term::atom("Critical")],
            )],
            RuleMetadata::default(),
        ));

        self.db.add_rule(LogicRule::with_metadata(
            "high_vuln".into(),
            LogicFact::new("high_vuln", vec![v4.clone(), v5.clone()]),
            vec![LogicFact::new(
                "weak_point",
                vec![v4.clone(), v5.clone(), Term::atom("High")],
            )],
            RuleMetadata::default(),
        ));

        // Rule: cross_lang_vuln(CallerFile, CalleeFile, Mechanism) :-
        //   cross_lang_call(CallerFile, CalleeFile, Mechanism),
        //   taint_source(CallerFile, _),
        //   taint_sink(CalleeFile, _).
        let v6 = Term::Var(106);
        let v7 = Term::Var(107);
        let v8 = Term::Var(108);
        let v9 = Term::Var(109);
        let v10 = Term::Var(110);

        self.db.add_rule(LogicRule::with_metadata(
            "cross_lang_vuln".into(),
            LogicFact::new("cross_lang_vuln", vec![v6.clone(), v7.clone(), v8.clone()]),
            vec![
                LogicFact::new("cross_lang_call", vec![v6.clone(), v7.clone(), v8.clone()]),
                LogicFact::new("taint_source", vec![v6.clone(), v9]),
                LogicFact::new("taint_sink", vec![v7.clone(), v10]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: excessive_risk(File) :-
        //   file_risk(File, Score),
        //   Score > 10
        // (Implemented as post-query filter since we don't have arithmetic in rules)
    }

    /// Load context-aware suppression rules for false positive reduction.
    ///
    /// These rules detect defensive patterns in the source code that make
    /// a weak point a false positive. When a suppression fact is derived,
    /// the corresponding weak point should be downgraded or removed.
    ///
    /// 10 rules targeting ~5-6% FP reduction (from 8% to 2-3%):
    ///
    /// 1. Null-check guarding (malloc → if-null)
    /// 2. Error propagation boundary (unwrap in Result-returning fn)
    /// 3. Validated deserialization (deser → schema check)
    /// 4. Whitelisted command args (cmd from enum/static set)
    /// 5. Synchronized access (mutex/rwlock guards)
    /// 6. Timeout-protected locks (deadlock with timeout)
    /// 7. Canonicalized paths (path traversal with realpath)
    /// 8. Constant string propagation (injection from hardcoded)
    /// 9. Test-file exclusion (findings in test/ or _test files)
    /// 10. RAII resource management (resource leak with Drop/defer)
    pub fn load_suppression_rules(&mut self) {
        // Rule 1: suppress_unchecked_alloc(File, Line) :-
        //   weak_point(UncheckedAllocation, File, _Severity),
        //   context(File, "null_checked").
        let v0 = Term::Var(200);
        let v1 = Term::Var(201);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_unchecked_alloc".into(),
            LogicFact::new("suppressed", vec![Term::atom("UncheckedAllocation"), v0.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("UncheckedAllocation"), v0.clone(), v1.clone()]),
                LogicFact::new("context", vec![v0.clone(), Term::atom("null_checked")]),
            ],
            RuleMetadata { confidence: 0.95, ..Default::default() },
        ));

        // Rule 2: suppress_unwrap_boundary(File) :-
        //   weak_point(PanicPath, File, _),
        //   context(File, "result_returning_fn").
        let v2 = Term::Var(202);
        let v3 = Term::Var(203);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_unwrap_boundary".into(),
            LogicFact::new("suppressed", vec![Term::atom("PanicPath"), v2.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("PanicPath"), v2.clone(), v3]),
                LogicFact::new("context", vec![v2.clone(), Term::atom("result_returning_fn")]),
            ],
            RuleMetadata { confidence: 0.90, ..Default::default() },
        ));

        // Rule 3: suppress_validated_deser(File) :-
        //   weak_point(UnsafeDeserialization, File, _),
        //   context(File, "schema_validated").
        let v4 = Term::Var(204);
        let v5 = Term::Var(205);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_validated_deser".into(),
            LogicFact::new("suppressed", vec![Term::atom("UnsafeDeserialization"), v4.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("UnsafeDeserialization"), v4.clone(), v5]),
                LogicFact::new("context", vec![v4.clone(), Term::atom("schema_validated")]),
            ],
            RuleMetadata { confidence: 0.85, ..Default::default() },
        ));

        // Rule 4: suppress_whitelisted_cmd(File) :-
        //   weak_point(CommandInjection, File, _),
        //   context(File, "enum_args").
        let v6 = Term::Var(206);
        let v7 = Term::Var(207);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_whitelisted_cmd".into(),
            LogicFact::new("suppressed", vec![Term::atom("CommandInjection"), v6.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("CommandInjection"), v6.clone(), v7]),
                LogicFact::new("context", vec![v6.clone(), Term::atom("enum_args")]),
            ],
            RuleMetadata { confidence: 0.90, ..Default::default() },
        ));

        // Rule 5: suppress_synchronized(File) :-
        //   weak_point(RaceCondition, File, _),
        //   context(File, "mutex_guarded").
        let v8 = Term::Var(208);
        let v9 = Term::Var(209);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_synchronized".into(),
            LogicFact::new("suppressed", vec![Term::atom("RaceCondition"), v8.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("RaceCondition"), v8.clone(), v9]),
                LogicFact::new("context", vec![v8.clone(), Term::atom("mutex_guarded")]),
            ],
            RuleMetadata { confidence: 0.95, ..Default::default() },
        ));

        // Rule 6: suppress_timeout_lock(File) :-
        //   weak_point(DeadlockPotential, File, _),
        //   context(File, "timeout_protected").
        let v10 = Term::Var(210);
        let v11 = Term::Var(211);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_timeout_lock".into(),
            LogicFact::new("suppressed", vec![Term::atom("DeadlockPotential"), v10.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("DeadlockPotential"), v10.clone(), v11]),
                LogicFact::new("context", vec![v10.clone(), Term::atom("timeout_protected")]),
            ],
            RuleMetadata { confidence: 0.85, ..Default::default() },
        ));

        // Rule 7: suppress_canonicalized_path(File) :-
        //   weak_point(PathTraversal, File, _),
        //   context(File, "path_canonicalized").
        let v12 = Term::Var(212);
        let v13 = Term::Var(213);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_canonicalized_path".into(),
            LogicFact::new("suppressed", vec![Term::atom("PathTraversal"), v12.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("PathTraversal"), v12.clone(), v13]),
                LogicFact::new("context", vec![v12.clone(), Term::atom("path_canonicalized")]),
            ],
            RuleMetadata { confidence: 0.90, ..Default::default() },
        ));

        // Rule 8: suppress_constant_injection(File) :-
        //   weak_point(CommandInjection, File, _),
        //   context(File, "constant_args").
        let v14 = Term::Var(214);
        let v15 = Term::Var(215);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_constant_injection".into(),
            LogicFact::new("suppressed", vec![Term::atom("CommandInjection"), v14.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("CommandInjection"), v14.clone(), v15]),
                LogicFact::new("context", vec![v14.clone(), Term::atom("constant_args")]),
            ],
            RuleMetadata { confidence: 0.95, ..Default::default() },
        ));

        // Rule 9: suppress_test_file(File, Category) :-
        //   weak_point(Category, File, _),
        //   context(File, "test_file").
        let v16 = Term::Var(216);
        let v17 = Term::Var(217);
        let v18 = Term::Var(218);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_test_file".into(),
            LogicFact::new("suppressed", vec![v16.clone(), v17.clone()]),
            vec![
                LogicFact::new("weak_point", vec![v16.clone(), v17.clone(), v18]),
                LogicFact::new("context", vec![v17.clone(), Term::atom("test_file")]),
            ],
            RuleMetadata { confidence: 0.99, ..Default::default() },
        ));

        // Rule 10: suppress_raii_leak(File) :-
        //   weak_point(ResourceLeak, File, _),
        //   context(File, "raii_managed").
        let v19 = Term::Var(219);
        let v20 = Term::Var(220);
        self.db.add_rule(LogicRule::with_metadata(
            "suppress_raii_leak".into(),
            LogicFact::new("suppressed", vec![Term::atom("ResourceLeak"), v19.clone()]),
            vec![
                LogicFact::new("weak_point", vec![Term::atom("ResourceLeak"), v19.clone(), v20]),
                LogicFact::new("context", vec![v19.clone(), Term::atom("raii_managed")]),
            ],
            RuleMetadata { confidence: 0.90, ..Default::default() },
        ));
    }

    /// Extract context facts from source code for FP suppression.
    ///
    /// Scans file statistics and weak point descriptions for defensive patterns
    /// (null checks, mutex guards, schema validation, path canonicalization,
    /// timeout protection, enum/constant args, etc.) and asserts context facts
    /// into the FactDB. The 10 suppression rules loaded by `load_suppression_rules()`
    /// depend on these context facts to fire.
    ///
    /// **Phase 1 — file_statistics-based detection:**
    /// - `test_file`: path contains test/spec indicators
    /// - `mutex_guarded`: file has threading constructs
    /// - `raii_managed`: Rust files (RAII by default)
    /// - `result_returning_fn`: Rust files with unwrap calls
    ///
    /// **Phase 2 — weak_point description-based detection:**
    /// - `null_checked`: description mentions null/nil check patterns
    /// - `schema_validated`: description mentions schema/validation/serde patterns
    /// - `enum_args`: description mentions enum/whitelist/match for command args
    /// - `timeout_protected`: description mentions timeout/try_lock/deadline patterns
    /// - `path_canonicalized`: description mentions canonicalize/realpath/normalize
    /// - `constant_args`: description mentions literal/const/hardcoded near commands
    pub fn extract_context_facts(&mut self, report: &AssailReport) {
        // Phase 1: File-statistics-based context detection
        for fs in &report.file_statistics {
            let path = &fs.file_path;

            // Test file detection
            if path.contains("/test") || path.contains("_test.")
                || path.contains("/tests/") || path.contains("/spec/")
                || path.contains("test_") || path.ends_with("_test.rs")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(path), Term::atom("test_file")],
                ));
            }

            // Mutex/sync detection (from file stats)
            if fs.threading_constructs > 0 {
                // Files with threading constructs that also have mutex/lock patterns
                // are likely synchronized
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(path), Term::atom("mutex_guarded")],
                ));
            }

            // RAII detection: Rust files inherently use RAII
            let is_rust = path.ends_with(".rs");
            if is_rust {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(path), Term::atom("raii_managed")],
                ));
            }

            // Result-returning function detection (Rust files with unwrap)
            if is_rust && fs.unwrap_calls > 0 {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(path), Term::atom("result_returning_fn")],
                ));
            }
        }

        // Phase 2: Weak-point description-based context detection.
        //
        // Build a map from file location to aggregated description text and
        // category set, so we can detect defensive patterns mentioned in any
        // weak point associated with a file.
        let mut file_descriptions: HashMap<String, (String, HashSet<String>)> = HashMap::new();
        for wp in &report.weak_points {
            let loc = wp.location.as_deref().unwrap_or("unknown");
            let entry = file_descriptions
                .entry(loc.to_string())
                .or_insert_with(|| (String::new(), HashSet::new()));
            // Accumulate descriptions (space-separated) for pattern matching
            if !entry.0.is_empty() {
                entry.0.push(' ');
            }
            entry.0.push_str(&wp.description);
            entry.1.insert(format!("{:?}", wp.category));
        }

        for (file_loc, (desc_text, categories)) in &file_descriptions {
            let desc_lower = desc_text.to_lowercase();

            // null_checked: description mentions null/nil checking patterns,
            // OR the file has allocation patterns but no UncheckedAllocation
            // weak points (implying checks are already in place).
            if desc_lower.contains("null check")
                || desc_lower.contains("nil check")
                || desc_lower.contains("if null")
                || desc_lower.contains("!= null")
                || desc_lower.contains("!= nil")
                || desc_lower.contains("is_null")
                || desc_lower.contains("null_ptr")
                || desc_lower.contains("nullptr")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("null_checked")],
                ));
            }

            // Also assert null_checked when file_statistics shows allocations
            // but no UncheckedAllocation weak point exists for this file.
            if !categories.contains("UncheckedAllocation") {
                let has_allocs = report
                    .file_statistics
                    .iter()
                    .any(|fs| fs.file_path == *file_loc && fs.allocation_sites > 0);
                if has_allocs {
                    self.db.assert_fact(LogicFact::new(
                        "context",
                        vec![Term::atom(file_loc), Term::atom("null_checked")],
                    ));
                }
            }

            // schema_validated: description mentions schema validation,
            // serde deserialization with validation, or structured parsing.
            if desc_lower.contains("schema")
                || desc_lower.contains("validate")
                || desc_lower.contains("validated")
                || desc_lower.contains("serde")
                || desc_lower.contains("from_str")
                || desc_lower.contains("deserialize")
                || desc_lower.contains("json_schema")
                || desc_lower.contains("type_check")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("schema_validated")],
                ));
            }

            // enum_args: description mentions enum-based, static, or
            // whitelisted command argument construction.
            if desc_lower.contains("enum")
                || desc_lower.contains("whitelist")
                || desc_lower.contains("allowlist")
                || desc_lower.contains("match ")
                || desc_lower.contains("static set")
                || desc_lower.contains("known values")
                || desc_lower.contains("predefined")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("enum_args")],
                ));
            }

            // timeout_protected: description mentions timeout or timed
            // lock acquisition patterns that prevent deadlocks.
            if desc_lower.contains("timeout")
                || desc_lower.contains("try_lock")
                || desc_lower.contains("timed")
                || desc_lower.contains("deadline")
                || desc_lower.contains("duration")
                || desc_lower.contains("wait_timeout")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("timeout_protected")],
                ));
            }

            // path_canonicalized: description mentions path normalization
            // or canonicalization that prevents traversal attacks.
            if desc_lower.contains("canonicalize")
                || desc_lower.contains("canonicalized")
                || desc_lower.contains("realpath")
                || desc_lower.contains("resolve")
                || desc_lower.contains("normalize")
                || desc_lower.contains("absolute path")
                || desc_lower.contains("clean_path")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("path_canonicalized")],
                ));
            }

            // constant_args: description mentions literal, constant, or
            // hardcoded values near command execution (safe injection).
            // Also fire when a file has CommandInjection but description
            // indicates the arguments originate from constants.
            if desc_lower.contains("literal")
                || desc_lower.contains("hardcoded")
                || desc_lower.contains("hard-coded")
                || desc_lower.contains("constant")
                || desc_lower.contains("static string")
                || desc_lower.contains("compile-time")
                || desc_lower.contains("const ")
            {
                self.db.assert_fact(LogicFact::new(
                    "context",
                    vec![Term::atom(file_loc), Term::atom("constant_args")],
                ));
            }

            // Cross-pattern detection: if a file has CommandInjection weak
            // points but descriptions across ALL its weak points suggest the
            // command args are constructed from static/const sources, assert
            // constant_args even if no single description explicitly says so.
            if categories.contains("CommandInjection") {
                let all_static = report
                    .weak_points
                    .iter()
                    .filter(|wp| {
                        wp.location.as_deref().unwrap_or("unknown") == file_loc
                            && format!("{:?}", wp.category) == "CommandInjection"
                    })
                    .all(|wp| {
                        let d = wp.description.to_lowercase();
                        d.contains("static")
                            || d.contains("const")
                            || d.contains("fixed")
                            || d.contains("known")
                            || d.contains("predefined")
                    });
                if all_static {
                    self.db.assert_fact(LogicFact::new(
                        "context",
                        vec![Term::atom(file_loc), Term::atom("constant_args")],
                    ));
                }
            }
        }
    }

    /// Run forward chaining and collect results
    pub fn analyze(&mut self) -> EngineResults {
        self.load_standard_rules();
        self.load_suppression_rules();
        let (derived, _) = self.db.forward_chain();

        // Result metrics are relation-cardinality snapshots used for triage dashboards.
        let tainted_paths = self.db.get_facts("tainted_path").len();
        let critical_vulns = self.db.get_facts("critical_vuln").len();
        let high_vulns = self.db.get_facts("high_vuln").len();
        let cross_lang = self.db.get_facts("cross_lang_vuln").len();
        let suppressed = self.db.get_facts("suppressed").len();

        EngineResults {
            total_facts: self.db.total_facts(),
            derived_facts: derived,
            tainted_paths,
            critical_vulnerabilities: critical_vulns,
            high_vulnerabilities: high_vulns,
            cross_language_vulns: cross_lang,
            suppressed_false_positives: suppressed,
        }
    }
}

/// Results from the logic engine analysis
#[derive(Debug, Clone)]
pub struct EngineResults {
    pub total_facts: usize,
    pub derived_facts: usize,
    pub tainted_paths: usize,
    pub critical_vulnerabilities: usize,
    pub high_vulnerabilities: usize,
    pub cross_language_vulns: usize,
    /// Number of weak points suppressed by context-aware FP rules
    pub suppressed_false_positives: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_unification_atoms() {
        let subst = Substitution::new();
        let t1 = Term::atom("hello");
        let t2 = Term::atom("hello");
        assert!(subst.unify(&t1, &t2).is_some());

        let t3 = Term::atom("world");
        assert!(subst.unify(&t1, &t3).is_none());
    }

    #[test]
    fn test_unification_variables() {
        let subst = Substitution::new();
        let var = Term::Var(0);
        let atom = Term::atom("test");
        let result = subst.unify(&var, &atom).unwrap();
        assert_eq!(result.resolve(0), Some(Term::atom("test")));
    }

    #[test]
    fn test_compound_unification() {
        let subst = Substitution::new();
        let t1 = Term::compound("f", vec![Term::Var(0), Term::atom("b")]);
        let t2 = Term::compound("f", vec![Term::atom("a"), Term::atom("b")]);
        let result = subst.unify(&t1, &t2).unwrap();
        assert_eq!(result.resolve(0), Some(Term::atom("a")));
    }

    #[test]
    fn test_fact_query() {
        let mut db = FactDB::new();
        db.assert("parent", vec!["tom", "bob"]);
        db.assert("parent", vec!["tom", "liz"]);
        db.assert("parent", vec!["bob", "ann"]);

        let results = db.query("parent", &[Term::atom("tom"), Term::Var(0)]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_forward_chaining() {
        let mut db = FactDB::new();
        db.assert("parent", vec!["tom", "bob"]);
        db.assert("parent", vec!["bob", "ann"]);

        // Rule: grandparent(X, Z) :- parent(X, Y), parent(Y, Z)
        db.add_rule(LogicRule::with_metadata(
            "grandparent".into(),
            LogicFact::new("grandparent", vec![Term::Var(0), Term::Var(2)]),
            vec![
                LogicFact::new("parent", vec![Term::Var(0), Term::Var(1)]),
                LogicFact::new("parent", vec![Term::Var(1), Term::Var(2)]),
            ],
            RuleMetadata::default(),
        ));

        let (derived, _) = db.forward_chain();
        assert!(derived > 0);
        assert_eq!(db.fact_count("grandparent"), 1);
    }

    /// Helper: build a minimal AssailReport for context-extraction tests.
    fn make_test_report(
        file_statistics: Vec<FileStatistics>,
        weak_points: Vec<WeakPoint>,
    ) -> AssailReport {
        AssailReport {
            program_path: PathBuf::from("/tmp/test"),
            language: Language::Rust,
            frameworks: vec![],
            weak_points,
            statistics: ProgramStatistics::default(),
            file_statistics,
            recommended_attacks: vec![],
            dependency_graph: DependencyGraph::default(),
            taint_matrix: TaintMatrix::default(),
            migration_metrics: None,
        }
    }

    /// Helper: build a WeakPoint with a given category, location, and description.
    fn make_weak_point(
        category: WeakPointCategory,
        location: &str,
        description: &str,
    ) -> WeakPoint {
        WeakPoint {
            category,
            location: Some(location.to_string()),
            severity: Severity::Medium,
            description: description.to_string(),
            recommended_attack: vec![],
        }
    }

    /// Helper: check whether a context fact exists in the engine's FactDB.
    fn has_context(engine: &LogicEngine, file: &str, ctx: &str) -> bool {
        engine.db.get_facts("context").iter().any(|f| {
            f.args.len() == 2
                && f.args[0] == Term::atom(file)
                && f.args[1] == Term::atom(ctx)
        })
    }

    #[test]
    fn test_extract_context_null_checked_from_description() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::UncheckedAllocation,
                "src/alloc.c",
                "malloc result used without null check guard",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/alloc.c", "null_checked"),
            "Should detect null_checked from description mentioning 'null check'"
        );
    }

    #[test]
    fn test_extract_context_null_checked_from_alloc_without_weakness() {
        // File has allocation_sites but NO UncheckedAllocation weak point,
        // implying the allocations are already guarded.
        let report = make_test_report(
            vec![FileStatistics {
                file_path: "src/safe_alloc.c".to_string(),
                lines: 100,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 0,
                allocation_sites: 5,
                io_operations: 0,
                threading_constructs: 0,
            }],
            vec![make_weak_point(
                WeakPointCategory::PanicPath,
                "src/safe_alloc.c",
                "possible abort path",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/safe_alloc.c", "null_checked"),
            "Should detect null_checked when file has allocations but no UncheckedAllocation"
        );
    }

    #[test]
    fn test_extract_context_schema_validated() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::UnsafeDeserialization,
                "src/api/handler.rs",
                "serde deserialize call with schema validation",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/api/handler.rs", "schema_validated"),
            "Should detect schema_validated from description mentioning 'schema' and 'serde'"
        );
    }

    #[test]
    fn test_extract_context_enum_args() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::CommandInjection,
                "src/runner.rs",
                "command built from enum variant, whitelist of allowed tools",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/runner.rs", "enum_args"),
            "Should detect enum_args from description mentioning 'enum' and 'whitelist'"
        );
    }

    #[test]
    fn test_extract_context_timeout_protected() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::DeadlockPotential,
                "src/sync.rs",
                "lock acquired with try_lock and timeout fallback",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/sync.rs", "timeout_protected"),
            "Should detect timeout_protected from description mentioning 'try_lock' and 'timeout'"
        );
    }

    #[test]
    fn test_extract_context_path_canonicalized() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::PathTraversal,
                "src/fs/loader.rs",
                "path is passed through canonicalize before opening",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/fs/loader.rs", "path_canonicalized"),
            "Should detect path_canonicalized from description mentioning 'canonicalize'"
        );
    }

    #[test]
    fn test_extract_context_constant_args_from_description() {
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::CommandInjection,
                "src/build.rs",
                "shell invocation uses hardcoded binary path",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/build.rs", "constant_args"),
            "Should detect constant_args from description mentioning 'hardcoded'"
        );
    }

    #[test]
    fn test_extract_context_constant_args_cross_pattern() {
        // All CommandInjection weak points for the file have "static"/"const"
        // in descriptions — cross-pattern detection should fire.
        let report = make_test_report(
            vec![],
            vec![
                make_weak_point(
                    WeakPointCategory::CommandInjection,
                    "src/deploy.rs",
                    "process::Command with static binary name",
                ),
                make_weak_point(
                    WeakPointCategory::CommandInjection,
                    "src/deploy.rs",
                    "arguments from known fixed set",
                ),
            ],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(
            has_context(&engine, "src/deploy.rs", "constant_args"),
            "Should detect constant_args via cross-pattern when all CmdInjection descs are static"
        );
    }

    #[test]
    fn test_extract_context_no_false_detection() {
        // A weak point whose description contains none of the defensive
        // pattern keywords should NOT trigger any of the 6 new context facts.
        let report = make_test_report(
            vec![],
            vec![make_weak_point(
                WeakPointCategory::CommandInjection,
                "src/evil.py",
                "user input passed directly to subprocess",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);
        assert!(!has_context(&engine, "src/evil.py", "null_checked"));
        assert!(!has_context(&engine, "src/evil.py", "schema_validated"));
        assert!(!has_context(&engine, "src/evil.py", "enum_args"));
        assert!(!has_context(&engine, "src/evil.py", "timeout_protected"));
        assert!(!has_context(&engine, "src/evil.py", "path_canonicalized"));
        assert!(!has_context(&engine, "src/evil.py", "constant_args"));
    }

    #[test]
    fn test_extract_context_existing_facts_preserved() {
        // Verify that the original 4 context types still work alongside
        // the 6 new ones.
        let report = make_test_report(
            vec![FileStatistics {
                file_path: "tests/integration_test.rs".to_string(),
                lines: 200,
                unsafe_blocks: 0,
                panic_sites: 0,
                unwrap_calls: 3,
                allocation_sites: 0,
                io_operations: 1,
                threading_constructs: 2,
            }],
            vec![make_weak_point(
                WeakPointCategory::DeadlockPotential,
                "tests/integration_test.rs",
                "lock with timeout guard and deadline check",
            )],
        );
        let mut engine = LogicEngine::new();
        engine.extract_context_facts(&report);

        // Original 4 context facts
        assert!(has_context(&engine, "tests/integration_test.rs", "test_file"));
        assert!(has_context(&engine, "tests/integration_test.rs", "mutex_guarded"));
        assert!(has_context(&engine, "tests/integration_test.rs", "raii_managed"));
        assert!(has_context(&engine, "tests/integration_test.rs", "result_returning_fn"));

        // New description-based fact
        assert!(has_context(&engine, "tests/integration_test.rs", "timeout_protected"));
    }
}
