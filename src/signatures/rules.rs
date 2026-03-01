// SPDX-License-Identifier: PMPL-1.0-or-later

//! Datalog-style rule definitions for bug detection
//!
//! Each rule has a head predicate (what it concludes) and body predicates
//! (what must be true). The engine evaluates bodies against the fact set
//! with variable binding — variable names like "X", "M1", "M2" are unified
//! with concrete values from extracted facts.
//!
//! Location 0 in body predicates acts as a wildcard (matches any location).

use crate::types::*;

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self {
            rules: Self::build_rules(),
        }
    }

    /// Build the complete rule set for bug detection.
    ///
    /// Each rule's body predicates use variable names and wildcard locations
    /// that the engine binds to concrete values during evaluation.
    fn build_rules() -> Vec<Rule> {
        vec![
            // Use-after-free: variable freed then used
            // Body: find a Free and a Use of the same variable
            // Engine applies ordering constraint: free_loc < use_loc
            Rule {
                name: "use_after_free".to_string(),
                head: Predicate::UseAfterFree {
                    var: "X".to_string(),
                    use_loc: 0,
                    free_loc: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Use {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Double-free: variable freed at two distinct locations
            // Engine applies ordering constraint: loc1 != loc2
            Rule {
                name: "double_free".to_string(),
                head: Predicate::DoubleFree {
                    var: "X".to_string(),
                    loc1: 0,
                    loc2: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Free {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Deadlock: two distinct mutexes locked (potential circular wait)
            // Engine applies ordering constraint: M1 != M2
            Rule {
                name: "deadlock".to_string(),
                head: Predicate::Deadlock {
                    m1: "M1".to_string(),
                    m2: "M2".to_string(),
                },
                body: vec![
                    Predicate::Fact(Fact::Lock {
                        mutex: "M1".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Lock {
                        mutex: "M2".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Data race: concurrent write and read of the same variable
            // with thread activity present
            Rule {
                name: "data_race".to_string(),
                head: Predicate::DataRace {
                    var: "X".to_string(),
                    loc1: 0,
                    loc2: 0,
                },
                body: vec![
                    Predicate::Fact(Fact::Write {
                        var: "X".to_string(),
                        location: 0,
                    }),
                    Predicate::Fact(Fact::Read {
                        var: "X".to_string(),
                        location: 0,
                    }),
                ],
            },
            // Null pointer dereference: use of a variable with no prior allocation
            Rule {
                name: "null_deref".to_string(),
                head: Predicate::UseAfterFree {
                    var: "X".to_string(),
                    use_loc: 0,
                    free_loc: 0,
                },
                body: vec![Predicate::Fact(Fact::Use {
                    var: "X".to_string(),
                    location: 0,
                })],
            },
            // Buffer overflow: allocation followed by out-of-bounds use pattern
            Rule {
                name: "buffer_overflow".to_string(),
                head: Predicate::UseAfterFree {
                    var: "X".to_string(),
                    use_loc: 0,
                    free_loc: 0,
                },
                body: vec![Predicate::Fact(Fact::Alloc {
                    var: "X".to_string(),
                    location: 0,
                })],
            },
        ]
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ruleset_creation() {
        let ruleset = RuleSet::new();
        assert!(!ruleset.rules().is_empty());
        assert!(
            ruleset.rules().len() >= 6,
            "Expected at least 6 rules, got {}",
            ruleset.rules().len()
        );
    }

    #[test]
    fn test_rule_names() {
        let ruleset = RuleSet::new();
        let names: Vec<_> = ruleset.rules().iter().map(|r| r.name.as_str()).collect();

        assert!(names.contains(&"use_after_free"));
        assert!(names.contains(&"double_free"));
        assert!(names.contains(&"deadlock"));
        assert!(names.contains(&"data_race"));
        assert!(names.contains(&"null_deref"));
        assert!(names.contains(&"buffer_overflow"));
    }

    #[test]
    fn test_all_rules_have_body_predicates() {
        let ruleset = RuleSet::new();
        for rule in ruleset.rules() {
            assert!(
                !rule.body.is_empty(),
                "Rule '{}' has empty body",
                rule.name
            );
        }
    }
}
