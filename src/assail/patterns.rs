// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//! Pattern detection for common program types
//!
//! Attack patterns for 40+ programming languages.

use crate::types::*;

pub struct PatternDetector;

impl PatternDetector {
    /// Get attack patterns for a specific program type
    pub fn patterns_for(language: Language, frameworks: &[Framework]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Language-specific patterns
        match language {
            Language::Rust => patterns.extend(Self::rust_patterns()),
            Language::C | Language::Cpp => patterns.extend(Self::c_cpp_patterns()),
            Language::Go => patterns.extend(Self::go_patterns()),
            Language::Python => patterns.extend(Self::python_patterns()),
            Language::JavaScript | Language::ReScript => {
                patterns.extend(Self::javascript_patterns())
            }
            Language::Elixir | Language::Erlang | Language::Gleam => {
                patterns.extend(Self::beam_patterns())
            }
            Language::Haskell | Language::PureScript => patterns.extend(Self::haskell_patterns()),
            Language::OCaml | Language::StandardML => patterns.extend(Self::ml_patterns()),
            Language::Zig => patterns.extend(Self::zig_patterns()),
            Language::Ada => patterns.extend(Self::ada_patterns()),
            Language::Shell => patterns.extend(Self::shell_patterns()),
            Language::Julia => patterns.extend(Self::julia_patterns()),
            Language::Nim => patterns.extend(Self::nim_patterns()),
            Language::DLang => patterns.extend(Self::dlang_patterns()),
            Language::Scheme | Language::Racket => patterns.extend(Self::lisp_patterns()),
            Language::Prolog | Language::Logtalk | Language::Datalog => {
                patterns.extend(Self::logic_patterns())
            }
            Language::Idris | Language::Lean | Language::Agda => {
                patterns.extend(Self::proof_patterns())
            }
            _ => {}
        }

        // Framework-specific patterns, with language-lock guards.
        // Phoenix / OTP / Ecto are BEAM-ecosystem frameworks — they must not
        // fire on non-BEAM languages even if the framework was detected from
        // a top-level mix.exs that sits alongside a polyglot source tree.
        let is_beam = matches!(
            language,
            Language::Elixir | Language::Erlang | Language::Gleam
        );
        for framework in frameworks {
            match framework {
                Framework::WebServer => patterns.extend(Self::webserver_patterns()),
                Framework::Database => patterns.extend(Self::database_patterns()),
                Framework::Concurrent => patterns.extend(Self::concurrency_patterns()),
                Framework::Phoenix if is_beam => patterns.extend(Self::phoenix_patterns()),
                Framework::OTP if is_beam => patterns.extend(Self::otp_patterns()),
                _ => {}
            }
        }

        // We intentionally do not deduplicate here; repeated hits can indicate
        // that both language and framework heuristics agree on the same pressure point.
        patterns
    }

    fn rust_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Memory Exhaustion".to_string(),
                description: "Allocate large vectors to trigger OOM".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Rust],
                applicable_frameworks: vec![],
                command_template: "RUST_BACKTRACE=1 timeout {duration} {program} --large-input"
                    .to_string(),
            },
            AttackPattern {
                name: "Panic Trigger".to_string(),
                description: "Send invalid inputs to trigger panics".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
                applicable_languages: vec![Language::Rust],
                applicable_frameworks: vec![],
                command_template: "echo 'invalid' | {program}".to_string(),
            },
        ]
    }

    fn c_cpp_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Buffer Overflow".to_string(),
                description: "Send oversized inputs to trigger buffer overflows".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::C, Language::Cpp],
                applicable_frameworks: vec![],
                command_template: "printf '%0.s\\x41' $(seq 1 10000) | {program}".to_string(),
            },
            AttackPattern {
                name: "Use-After-Free".to_string(),
                description: "Trigger rapid allocation/deallocation cycles".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                applicable_languages: vec![Language::C, Language::Cpp],
                applicable_frameworks: vec![],
                command_template: "{program} --stress-memory".to_string(),
            },
        ]
    }

    fn go_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Goroutine Leak".to_string(),
            description: "Spawn many concurrent operations".to_string(),
            applicable_axes: vec![AttackAxis::Concurrency],
            applicable_languages: vec![Language::Go],
            applicable_frameworks: vec![],
            command_template: "{program} --concurrent-requests 10000".to_string(),
        }]
    }

    fn python_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "CPU Spin".to_string(),
            description: "Trigger compute-heavy operations".to_string(),
            applicable_axes: vec![AttackAxis::Cpu],
            applicable_languages: vec![Language::Python],
            applicable_frameworks: vec![],
            command_template: "{program} --iterations 1000000".to_string(),
        }]
    }

    fn javascript_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Prototype Pollution".to_string(),
                description: "Send nested objects to pollute prototypes".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
                applicable_languages: vec![Language::JavaScript, Language::ReScript],
                applicable_frameworks: vec![],
                command_template: "echo '{{\"__proto__\":{{\"polluted\":true}}}}' | {program}"
                    .to_string(),
            },
            AttackPattern {
                name: "ReDoS".to_string(),
                description: "Send inputs that trigger catastrophic regex backtracking".to_string(),
                applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Time],
                applicable_languages: vec![Language::JavaScript, Language::ReScript],
                applicable_frameworks: vec![],
                command_template: "echo 'aaaaaaaaaaaaaaaaaaaaaaaaa!' | {program}".to_string(),
            },
        ]
    }

    fn beam_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Process Flood".to_string(),
                description: "Spawn many BEAM processes to exhaust process table".to_string(),
                applicable_axes: vec![AttackAxis::Concurrency, AttackAxis::Memory],
                applicable_languages: vec![Language::Elixir, Language::Erlang, Language::Gleam],
                applicable_frameworks: vec![],
                command_template: "timeout {duration} {program} --processes 1000000".to_string(),
            },
            AttackPattern {
                name: "Atom Table Exhaustion".to_string(),
                description: "Generate unique atoms to exhaust the atom table".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Elixir, Language::Erlang],
                applicable_frameworks: vec![],
                command_template: "{program} --unique-atoms 2000000".to_string(),
            },
            AttackPattern {
                name: "Message Queue Overflow".to_string(),
                description: "Send messages faster than process can consume".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Concurrency],
                applicable_languages: vec![Language::Elixir, Language::Erlang],
                applicable_frameworks: vec![],
                command_template: "{program} --flood-mailbox 100000".to_string(),
            },
        ]
    }

    fn haskell_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Space Leak".to_string(),
                description: "Trigger lazy thunk accumulation".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Haskell],
                applicable_frameworks: vec![],
                command_template: "timeout {duration} {program} +RTS -M512m -RTS --large-list"
                    .to_string(),
            },
            AttackPattern {
                name: "Stack Overflow".to_string(),
                description: "Trigger deep recursion via non-tail-recursive functions".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
                applicable_languages: vec![Language::Haskell, Language::PureScript],
                applicable_frameworks: vec![],
                command_template: "{program} +RTS -K1m -RTS --deep-recursion".to_string(),
            },
        ]
    }

    fn ml_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Stack Overflow via Recursion".to_string(),
            description: "Trigger deep non-tail-recursive calls".to_string(),
            applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
            applicable_languages: vec![Language::OCaml, Language::StandardML],
            applicable_frameworks: vec![],
            command_template: "{program} --depth 1000000".to_string(),
        }]
    }

    fn zig_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Allocator Stress".to_string(),
                description: "Trigger allocator failures via memory pressure".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Zig],
                applicable_frameworks: vec![],
                command_template: "timeout {duration} {program} --alloc-stress".to_string(),
            },
            AttackPattern {
                name: "Safety Check Bypass".to_string(),
                description: "Test undefined behavior via pointer arithmetic".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
                applicable_languages: vec![Language::Zig],
                applicable_frameworks: vec![],
                command_template: "{program} --boundary-input".to_string(),
            },
        ]
    }

    fn ada_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Constraint Error".to_string(),
            description: "Trigger range check violations and constraint errors".to_string(),
            applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Memory],
            applicable_languages: vec![Language::Ada],
            applicable_frameworks: vec![],
            command_template: "{program} --out-of-range-input".to_string(),
        }]
    }

    fn shell_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Injection Probe".to_string(),
            description: "Send shell metacharacters to test for injection".to_string(),
            applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Disk],
            applicable_languages: vec![Language::Shell],
            applicable_frameworks: vec![],
            command_template: "echo '; echo INJECTED #' | {program}".to_string(),
        }]
    }

    fn julia_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Type Instability".to_string(),
            description: "Trigger JIT recompilation via type-unstable code".to_string(),
            applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Memory],
            applicable_languages: vec![Language::Julia],
            applicable_frameworks: vec![],
            command_template: "julia --compile=min {program} --mixed-types".to_string(),
        }]
    }

    fn nim_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "GC Pressure".to_string(),
            description: "Create many short-lived objects to stress garbage collector".to_string(),
            applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
            applicable_languages: vec![Language::Nim],
            applicable_frameworks: vec![],
            command_template: "timeout {duration} {program} --gc-stress".to_string(),
        }]
    }

    fn dlang_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "GC Pause".to_string(),
            description: "Trigger long GC pauses via allocation pressure".to_string(),
            applicable_axes: vec![AttackAxis::Memory, AttackAxis::Time],
            applicable_languages: vec![Language::DLang],
            applicable_frameworks: vec![],
            command_template: "{program} --alloc-burst".to_string(),
        }]
    }

    fn lisp_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Continuation Bomb".to_string(),
            description: "Create deep continuation chains to exhaust memory".to_string(),
            applicable_axes: vec![AttackAxis::Memory, AttackAxis::Cpu],
            applicable_languages: vec![Language::Scheme, Language::Racket],
            applicable_frameworks: vec![],
            command_template: "{program} --deep-continuations 100000".to_string(),
        }]
    }

    fn logic_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Infinite Unification".to_string(),
            description: "Send queries that cause unbounded search".to_string(),
            applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Memory],
            applicable_languages: vec![Language::Prolog, Language::Logtalk, Language::Datalog],
            applicable_frameworks: vec![],
            command_template: "{program} --query 'ancestor(X,Y),ancestor(Y,X)'".to_string(),
        }]
    }

    fn proof_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Type Checker Stress".to_string(),
            description: "Send complex terms that stress the type checker/elaborator".to_string(),
            applicable_axes: vec![AttackAxis::Cpu, AttackAxis::Memory],
            applicable_languages: vec![Language::Idris, Language::Lean, Language::Agda],
            applicable_frameworks: vec![],
            command_template: "{program} --complex-term".to_string(),
        }]
    }

    fn webserver_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "HTTP Flood".to_string(),
                description: "Send many concurrent HTTP requests".to_string(),
                applicable_axes: vec![AttackAxis::Network, AttackAxis::Concurrency],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::WebServer],
                command_template: "wrk -t12 -c400 -d{duration}s http://localhost:8080/".to_string(),
            },
            AttackPattern {
                name: "Large POST".to_string(),
                description: "Send very large POST bodies".to_string(),
                applicable_axes: vec![AttackAxis::Memory, AttackAxis::Network],
                applicable_languages: vec![],
                applicable_frameworks: vec![Framework::WebServer],
                command_template:
                    "curl -X POST -d @/dev/zero --max-time {duration} http://localhost:8080/"
                        .to_string(),
            },
        ]
    }

    fn database_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Query Storm".to_string(),
            description: "Execute many concurrent queries".to_string(),
            applicable_axes: vec![AttackAxis::Disk, AttackAxis::Concurrency],
            applicable_languages: vec![],
            applicable_frameworks: vec![Framework::Database],
            command_template: "{program} --query-load 1000".to_string(),
        }]
    }

    fn concurrency_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Deadlock Induction".to_string(),
            description: "Trigger concurrent operations that may deadlock".to_string(),
            applicable_axes: vec![AttackAxis::Concurrency],
            applicable_languages: vec![],
            applicable_frameworks: vec![Framework::Concurrent],
            command_template: "{program} --threads 100 --contention high".to_string(),
        }]
    }

    fn phoenix_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Channel Flood".to_string(),
                description: "Flood Phoenix channels with messages".to_string(),
                applicable_axes: vec![AttackAxis::Network, AttackAxis::Memory],
                applicable_languages: vec![Language::Elixir],
                applicable_frameworks: vec![Framework::Phoenix],
                command_template: "{program} --channel-flood 10000".to_string(),
            },
            AttackPattern {
                name: "LiveView State Explosion".to_string(),
                description: "Grow LiveView state to exhaust process memory".to_string(),
                applicable_axes: vec![AttackAxis::Memory],
                applicable_languages: vec![Language::Elixir],
                applicable_frameworks: vec![Framework::Phoenix],
                command_template: "{program} --liveview-state-grow".to_string(),
            },
        ]
    }

    fn otp_patterns() -> Vec<AttackPattern> {
        vec![AttackPattern {
            name: "Supervisor Crash Cascade".to_string(),
            description: "Trigger rapid crashes to hit supervisor restart limits".to_string(),
            applicable_axes: vec![AttackAxis::Concurrency, AttackAxis::Cpu],
            applicable_languages: vec![Language::Elixir, Language::Erlang],
            applicable_frameworks: vec![Framework::OTP],
            command_template: "{program} --crash-cascade".to_string(),
        }]
    }
}
