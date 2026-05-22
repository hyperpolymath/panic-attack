// SPDX-License-Identifier: MPL-2.0

//! Taint analysis via relational logic
//!
//! Tracks data flow from taint sources (user input, network, file I/O)
//! to taint sinks (eval, system calls, SQL queries) using the miniKanren
//! fact database and forward chaining.

use crate::kanren::core::{FactDB, LogicFact, LogicRule, RuleMetadata, Term};
use crate::types::*;

/// Categories of taint sources — where untrusted data enters
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSource {
    /// User input (stdin, CLI args, form data)
    UserInput,
    /// Network data (HTTP request, socket read)
    NetworkRead,
    /// File read from disk
    FileRead,
    /// Environment variable access
    EnvVar,
    /// Database query result
    DatabaseRead,
    /// Deserialized data (JSON.parse, Marshal.load)
    Deserialization,
    /// FFI return value from foreign code
    ForeignReturn,
    /// Message received (Erlang mailbox, channel recv)
    MessageReceive,
}

/// Categories of taint sinks — where untrusted data is dangerous
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSink {
    /// Code execution (eval, exec, system)
    CodeExecution,
    /// SQL query construction
    SqlQuery,
    /// Command injection (shell exec, Process.spawn)
    ShellCommand,
    /// File path construction (path traversal)
    FilePath,
    /// Network send (response body, socket write)
    NetworkWrite,
    /// Unsafe type cast or coercion
    UnsafeCast,
    /// Memory operation (raw pointer, unsafe block)
    MemoryOperation,
    /// Atom creation from untrusted data (BEAM)
    AtomCreation,
    /// Deserialization of untrusted input
    DeserializeSink,
    /// Log injection
    LogOutput,
}

/// Taint flow: a connection from source to sink through a file
#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub source_file: String,
    pub sink_file: String,
    pub confidence: f64,
}

/// The taint analyzer extracts source/sink facts from scan results
/// and asserts them into the logic engine's fact database.
pub struct TaintAnalyzer;

impl TaintAnalyzer {
    /// Extract taint facts from an Assail report and assert them into the DB
    pub fn extract_facts(db: &mut FactDB, report: &AssailReport) {
        for wp in &report.weak_points {
            let file = wp.location.as_deref().unwrap_or("unknown");

            // Map weak point categories to taint sources and sinks
            match wp.category {
                WeakPointCategory::CommandInjection => {
                    Self::assert_source(db, file, TaintSource::UserInput);
                    Self::assert_sink(db, file, TaintSink::ShellCommand);
                }
                WeakPointCategory::UnsafeDeserialization => {
                    Self::assert_source(db, file, TaintSource::Deserialization);
                    Self::assert_sink(db, file, TaintSink::DeserializeSink);
                }
                WeakPointCategory::DynamicCodeExecution => {
                    Self::assert_source(db, file, TaintSource::UserInput);
                    Self::assert_sink(db, file, TaintSink::CodeExecution);
                }
                WeakPointCategory::UnsafeFFI => {
                    Self::assert_source(db, file, TaintSource::ForeignReturn);
                    Self::assert_sink(db, file, TaintSink::MemoryOperation);
                }
                WeakPointCategory::AtomExhaustion => {
                    Self::assert_source(db, file, TaintSource::NetworkRead);
                    Self::assert_sink(db, file, TaintSink::AtomCreation);
                }
                WeakPointCategory::PathTraversal => {
                    Self::assert_source(db, file, TaintSource::UserInput);
                    Self::assert_sink(db, file, TaintSink::FilePath);
                }
                WeakPointCategory::InsecureProtocol => {
                    Self::assert_source(db, file, TaintSource::NetworkRead);
                    Self::assert_sink(db, file, TaintSink::NetworkWrite);
                }
                WeakPointCategory::UnsafeCode => {
                    Self::assert_sink(db, file, TaintSink::MemoryOperation);
                }
                WeakPointCategory::HardcodedSecret => {
                    Self::assert_source(db, file, TaintSource::EnvVar);
                    Self::assert_sink(db, file, TaintSink::LogOutput);
                }
                WeakPointCategory::UnsafeTypeCoercion => {
                    Self::assert_sink(db, file, TaintSink::UnsafeCast);
                }
                _ => {}
            }
        }

        // Assert data flow edges between files that share frameworks
        Self::infer_data_flows(db, report);
    }

    /// Assert a taint source fact
    fn assert_source(db: &mut FactDB, file: &str, source: TaintSource) {
        db.assert_fact(LogicFact::new(
            "taint_source",
            vec![Term::atom(file), Term::atom(&format!("{:?}", source))],
        ));
    }

    /// Assert a taint sink fact
    fn assert_sink(db: &mut FactDB, file: &str, sink: TaintSink) {
        db.assert_fact(LogicFact::new(
            "taint_sink",
            vec![Term::atom(file), Term::atom(&format!("{:?}", sink))],
        ));
    }

    /// Infer data flow edges between files
    ///
    /// Heuristic: files in the same directory or using the same framework
    /// likely have data flow between them. More precise analysis would
    /// require import graph parsing.
    fn infer_data_flows(db: &mut FactDB, report: &AssailReport) {
        let files_with_sources: Vec<String> = report
            .weak_points
            .iter()
            .filter(|wp| {
                matches!(
                    wp.category,
                    WeakPointCategory::CommandInjection
                        | WeakPointCategory::UnsafeDeserialization
                        | WeakPointCategory::DynamicCodeExecution
                        | WeakPointCategory::InsecureProtocol
                )
            })
            .filter_map(|wp| wp.location.clone())
            .collect();

        let files_with_sinks: Vec<String> = report
            .weak_points
            .iter()
            .filter(|wp| {
                matches!(
                    wp.category,
                    WeakPointCategory::UnsafeCode
                        | WeakPointCategory::UnsafeFFI
                        | WeakPointCategory::AtomExhaustion
                        | WeakPointCategory::PathTraversal
                )
            })
            .filter_map(|wp| wp.location.clone())
            .collect();

        // Connect source files to sink files (conservative: same directory)
        for src_file in &files_with_sources {
            let src_dir = std::path::Path::new(src_file)
                .parent()
                .and_then(|p| p.to_str())
                .unwrap_or("");

            for sink_file in &files_with_sinks {
                if src_file == sink_file {
                    // Same file: definite data flow
                    db.assert_fact(LogicFact::new(
                        "data_flow",
                        vec![Term::atom(src_file), Term::atom(sink_file)],
                    ));
                } else {
                    let sink_dir = std::path::Path::new(sink_file)
                        .parent()
                        .and_then(|p| p.to_str())
                        .unwrap_or("");

                    if src_dir == sink_dir {
                        // Same directory: probable data flow
                        db.assert_fact(LogicFact::new(
                            "data_flow",
                            vec![Term::atom(src_file), Term::atom(sink_file)],
                        ));
                    }
                }
            }
        }
    }

    /// Load taint propagation rules into the database
    pub fn load_rules(db: &mut FactDB) {
        // Rule: transitive data flow
        // data_flow(A, C) :- data_flow(A, B), data_flow(B, C)
        db.add_rule(LogicRule::with_metadata(
            "data_flow".into(),
            LogicFact::new("data_flow", vec![Term::Var(300), Term::Var(302)]),
            vec![
                LogicFact::new("data_flow", vec![Term::Var(300), Term::Var(301)]),
                LogicFact::new("data_flow", vec![Term::Var(301), Term::Var(302)]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: taint propagation through data flow
        // tainted_file(Dest, Source) :- taint_source(Src, Source), data_flow(Src, Dest)
        db.add_rule(LogicRule::with_metadata(
            "tainted_file".into(),
            LogicFact::new("tainted_file", vec![Term::Var(310), Term::Var(311)]),
            vec![
                LogicFact::new("taint_source", vec![Term::Var(312), Term::Var(311)]),
                LogicFact::new("data_flow", vec![Term::Var(312), Term::Var(310)]),
            ],
            RuleMetadata::default(),
        ));

        // Rule: exploitable path — tainted file has a sink
        // exploitable(File, Source, SinkType) :-
        //   tainted_file(File, Source), taint_sink(File, SinkType)
        db.add_rule(LogicRule::with_metadata(
            "exploitable".into(),
            LogicFact::new(
                "exploitable",
                vec![Term::Var(320), Term::Var(321), Term::Var(322)],
            ),
            vec![
                LogicFact::new("tainted_file", vec![Term::Var(320), Term::Var(321)]),
                LogicFact::new("taint_sink", vec![Term::Var(320), Term::Var(322)]),
            ],
            RuleMetadata::default(),
        ));
    }

    /// Query the database for discovered taint flows
    pub fn query_flows(db: &FactDB) -> Vec<TaintFlow> {
        let mut flows = Vec::new();

        for fact in db.get_facts("tainted_path") {
            if fact.args.len() >= 4 {
                if let (
                    Term::Atom(src_file),
                    Term::Atom(source),
                    Term::Atom(sink_file),
                    Term::Atom(sink),
                ) = (&fact.args[0], &fact.args[1], &fact.args[2], &fact.args[3])
                {
                    flows.push(TaintFlow {
                        source: Self::parse_source(source),
                        sink: Self::parse_sink(sink),
                        source_file: src_file.clone(),
                        sink_file: sink_file.clone(),
                        confidence: 0.85,
                    });
                }
            }
        }

        // Also collect exploitable paths
        for fact in db.get_facts("exploitable") {
            if fact.args.len() >= 3 {
                if let (Term::Atom(file), Term::Atom(source), Term::Atom(sink)) =
                    (&fact.args[0], &fact.args[1], &fact.args[2])
                {
                    flows.push(TaintFlow {
                        source: Self::parse_source(source),
                        sink: Self::parse_sink(sink),
                        source_file: file.clone(),
                        sink_file: file.clone(),
                        confidence: 0.80,
                    });
                }
            }
        }

        flows
    }

    fn parse_source(s: &str) -> TaintSource {
        match s {
            "UserInput" => TaintSource::UserInput,
            "NetworkRead" => TaintSource::NetworkRead,
            "FileRead" => TaintSource::FileRead,
            "EnvVar" => TaintSource::EnvVar,
            "DatabaseRead" => TaintSource::DatabaseRead,
            "Deserialization" => TaintSource::Deserialization,
            "ForeignReturn" => TaintSource::ForeignReturn,
            "MessageReceive" => TaintSource::MessageReceive,
            _ => TaintSource::UserInput,
        }
    }

    fn parse_sink(s: &str) -> TaintSink {
        match s {
            "CodeExecution" => TaintSink::CodeExecution,
            "SqlQuery" => TaintSink::SqlQuery,
            "ShellCommand" => TaintSink::ShellCommand,
            "FilePath" => TaintSink::FilePath,
            "NetworkWrite" => TaintSink::NetworkWrite,
            "UnsafeCast" => TaintSink::UnsafeCast,
            "MemoryOperation" => TaintSink::MemoryOperation,
            "AtomCreation" => TaintSink::AtomCreation,
            "DeserializeSink" => TaintSink::DeserializeSink,
            "LogOutput" => TaintSink::LogOutput,
            _ => TaintSink::CodeExecution,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_source_sink_assertion() {
        let mut db = FactDB::new();
        TaintAnalyzer::assert_source(&mut db, "src/api.rs", TaintSource::NetworkRead);
        TaintAnalyzer::assert_sink(&mut db, "src/api.rs", TaintSink::SqlQuery);

        assert_eq!(db.fact_count("taint_source"), 1);
        assert_eq!(db.fact_count("taint_sink"), 1);
    }

    #[test]
    fn test_taint_propagation_rule() {
        let mut db = FactDB::new();

        // Source in file A
        TaintAnalyzer::assert_source(&mut db, "handler.ex", TaintSource::NetworkRead);

        // Data flows A -> B
        db.assert_fact(LogicFact::new(
            "data_flow",
            vec![Term::atom("handler.ex"), Term::atom("query.ex")],
        ));

        // Sink in file B
        TaintAnalyzer::assert_sink(&mut db, "query.ex", TaintSink::SqlQuery);

        // Load rules and chain
        TaintAnalyzer::load_rules(&mut db);
        let (derived, _) = db.forward_chain();

        assert!(
            derived > 0,
            "should derive tainted_file and exploitable facts"
        );
        assert!(db.fact_count("tainted_file") > 0);
    }
}
