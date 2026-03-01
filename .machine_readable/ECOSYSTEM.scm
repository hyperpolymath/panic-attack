;; SPDX-License-Identifier: PMPL-1.0-or-later
;; Ecosystem position for panic-attack (formerly panic-attacker)
;; Media Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "panic-attack")
  (type "tool")
  (purpose "Universal static analysis and logic-based bug signature detection for 47 languages")

  (position-in-ecosystem
    (layer "development-tools")
    (category "testing-quality")
    (subcategory "static-analysis-stress-testing")
    (maturity "stable")
    (adoption "internal"))

  (related-projects
    (project
      (name "panll")
      (relationship "consumer")
      (integration "exports ambush timeline/event-chain reports in PanLL format")
      (url "https://github.com/hyperpolymath/panll")
      (description "Human-Things Interface for neurosymbolic co-working and event-chain visualisation"))

    (project
      (name "verisimdb")
      (relationship "data-store")
      (integration "panic-attack scan results stored as hexads in verisimdb")
      (url "https://github.com/hyperpolymath/verisimdb")
      (description "Verification-similarity database for code quality metrics"))

    (project
      (name "verisimdb-data")
      (relationship "data-pipeline")
      (integration "scan JSON ingested via ingest-scan.sh into verisimdb-data repo")
      (url "https://github.com/hyperpolymath/verisimdb-data")
      (description "Git-based data store for verisimdb scan results"))

    (project
      (name "hypatia")
      (relationship "consumer")
      (integration "uses panic-attack for repository health assessment, VeriSimDB connector")
      (url "https://github.com/hyperpolymath/hypatia")
      (description "Neurosymbolic CI/CD intelligence"))

    (project
      (name "gitbot-fleet")
      (relationship "consumer")
      (integration "bots can trigger panic-attack scans via repository_dispatch")
      (url "https://github.com/hyperpolymath/gitbot-fleet")
      (description "Repository automation bots (rhodibot, echidnabot, panicbot, etc.)"))

    (project
      (name "panicbot")
      (relationship "direct-consumer")
      (integration "invokes `panic-attack assail --output-format json`, translates WeakPoints to fleet Findings via PA001–PA020 rule mapping")
      (url "https://github.com/hyperpolymath/gitbot-fleet")
      (description "Tier-4 verifier bot in gitbot-fleet — static analysis auditing via panic-attack")
      (interface
        (protocol "subprocess")
        (command "panic-attack assail <target> --output-format json")
        (output-format "AssailReport JSON (flat or assault envelope)")
        (category-mapping "WeakPointCategory → PA001–PA020 rule IDs")
        (severity-mapping "PascalCase → lowercase → fleet severity levels")
        (directives ".machine_readable/bot_directives/panicbot.scm")))

    (project
      (name "ambientops")
      (relationship "sibling-tool")
      (integration "hospital model: panic-attack is diagnostic tool, ambientops is operating room")
      (url "https://github.com/hyperpolymath/ambientops")
      (description "AmbientOps hospital model for software health"))

    (project
      (name "hardware-crash-team")
      (relationship "sibling-tool")
      (integration "panic-attack handles software diagnostics, hardware-crash-team handles hardware")
      (url "https://github.com/hyperpolymath/hardware-crash-team")
      (description "Hardware health diagnostics"))

    (project
      (name "echidna")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attack testing (15 weak points)")
      (url "https://github.com/hyperpolymath/echidna")
      (description "Automated theorem proving orchestrator"))

    (project
      (name "eclexia")
      (relationship "test-subject")
      (integration "used as benchmark for panic-attack testing")
      (url "https://github.com/hyperpolymath/eclexia")
      (description "Resource-aware adaptive programming language"))

    (project
      (name "rsr-template-repo")
      (relationship "template-provider")
      (integration "panic-attack follows RSR standards")
      (url "https://github.com/hyperpolymath/rsr-template-repo")
      (description "RSR-compliant repository template"))

    (project
      (name "0-ai-gatekeeper-protocol")
      (relationship "standard-provider")
      (integration "panic-attack implements AI manifest protocol")
      (url "https://github.com/hyperpolymath/0-ai-gatekeeper-protocol")
      (description "Universal AI manifest system"))

    (project
      (name "robot-repo-automaton")
      (relationship "potential-consumer")
      (integration "could use panic-attack for automated quality checks")
      (url "https://github.com/hyperpolymath/robot-repo-automaton")
      (description "Automated repository fixes with confidence thresholds")))

  (dependencies
    (runtime
      (dependency (name "clap") (version "4.5") (purpose "CLI argument parsing"))
      (dependency (name "serde") (version "1.0") (purpose "JSON/YAML serialization"))
      (dependency (name "serde_json") (version "1.0") (purpose "JSON output"))
      (dependency (name "serde_yaml") (version "0.9") (purpose "YAML output"))
      (dependency (name "anyhow") (version "1.0") (purpose "Error handling"))
      (dependency (name "regex") (version "1.10") (purpose "Pattern matching in source code"))
      (dependency (name "colored") (version "2.1") (purpose "Terminal output formatting"))
      (dependency (name "chrono") (version "0.4") (purpose "Timestamp generation"))
      (dependency (name "encoding_rs") (version "0.8") (purpose "Latin-1 fallback for non-UTF-8 files"))
      (dependency (name "rayon") (version "1.10") (purpose "Parallel batch scanning"))
      (dependency (name "blake3") (version "1.5") (purpose "Source fingerprinting for incremental scans"))
      (dependency (name "sha2") (version "0.10") (purpose "Attestation hashing"))
      (dependency (name "hex") (version "0.4") (purpose "Hex encoding for attestation"))
      (dependency (name "getrandom") (version "0.2") (purpose "Attestation nonce generation"))
      (dependency (name "crossterm") (version "0.26") (purpose "TUI terminal control"))
      (dependency (name "eframe") (version "0.27") (purpose "GUI viewer"))
      (dependency (name "filetime") (version "0.2") (purpose "Abduct timestamp manipulation"))
      (dependency (name "ed25519-dalek") (version "2.1") (purpose "Optional Ed25519 signing for attestation")))

    (development
      (dependency (name "tempfile") (version "3.8") (purpose "Temporary files in tests"))))

  (future-integrations
    (integration
      (name "verisimdb API push")
      (status "planned-v2.1")
      (description "Push scan results as hexads directly to verisimdb API"))

    (integration
      (name "hypatia pipeline")
      (status "planned-v2.2")
      (description "Feed kanren facts as Logtalk predicates to hypatia rule engine via PanLL"))

    (integration
      (name "kanren context-facts")
      (status "planned-v2.2")
      (description "~10 context rules for false positive suppression (8% -> 2-3%)"))

    (integration
      (name "crates.io")
      (status "planned-v3.0")
      (description "Publish as cargo-installable tool")))

  (ecosystem-contributions
    (contribution
      (type "tool")
      (value "Universal static analysis combining assail scan + miniKanren logic engine + multi-axis stress testing"))

    (contribution
      (type "pattern")
      (value "miniKanren-inspired relational reasoning for taint analysis and cross-language vulnerability detection in Rust"))

    (contribution
      (type "benchmark")
      (value "Provides quality metrics for hyperpolymath projects across 47 languages"))

    (contribution
      (type "standard")
      (value "Follows and validates RSR compliance patterns")))

  (metadata
    (created "2026-02-07")
    (updated "2026-03-01")
    (maintainer "Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>")
    (license "PMPL-1.0-or-later")
    (repository "https://github.com/hyperpolymath/panic-attacker")))
