;; SPDX-License-Identifier: PMPL-1.0-or-later
;; State checkpoint for panic-attack (formerly panic-attacker)
;; Media Type: application/vnd.state+scm
;; Last Updated: 2026-02-09

(state
  (metadata
    (version "1.0")
    (project "panic-attack")
    (last-updated "2026-03-02T20:30:00Z")
    (session-count 10))

  (project-context
    (name "panic-attack")
    (tagline "Universal static analysis and logic-based bug signature detection")
    (language "Rust")
    (type "CLI tool + library")
    (purpose "Multi-language static analysis with miniKanren-inspired logic engine for taint analysis, cross-language reasoning, and search strategies")
    (current-version "2.1.0")
    (next-milestone "v2.2.0")
    (lines-of-code 9000))

  (naming
    (note "Renamed from panic-attacker on 2026-02-08")
    (binary "panic-attack")
    (crate "panic-attack")
    (subcommand "assail")
    (report-type "AssailReport")
    (module-dir "src/assail/"))

  (current-position
    (phase "active-development")
    (milestone "v2.0.0")
    (completion-percentage 100)
    (status "released")
    (health "green")

    (completed-milestones
      (milestone
        (id "v0.1.0")
        (date "2026-02-06")
        (description "Proof-of-concept: assail + 6-axis attacks + signature detection"))
      (milestone
        (id "v0.2.0")
        (date "2026-02-07")
        (description "Quality fixes: per-file stats, locations, zero warnings"))
      (milestone
        (id "v1.0.0")
        (date "2026-02-08")
        (description "Rename: xray->assail, panic-attacker->panic-attack"))
      (milestone
        (id "v1.0.1")
        (date "2026-02-08")
        (description "Bugfix: JSON output confirmed working, installed to PATH"))
      (milestone
        (id "v2.0.0")
        (date "2026-02-08")
        (description "47-language support + miniKanren logic engine + taint analysis + cross-language reasoning + search strategies")))

    (current-capabilities
      "Assail static analysis (47 languages: BEAM, ML, Lisp, functional, proof, logic, systems, config, scripting, nextgen DSLs)"
      "20 weak point categories (UnsafeCode, CommandInjection, UnsafeDeserialization, AtomExhaustion, UnsafeFFI, PathTraversal, HardcodedSecret, etc.)"
      "miniKanren-inspired logic engine with substitution-based unification"
      "Taint analysis: source-to-sink data flow tracking"
      "Cross-language vulnerability chain detection (FFI, NIF, Port, subprocess boundaries)"
      "Search strategy optimisation (RiskWeighted, BoundaryFirst, LanguageFamily, BreadthFirst, DepthFirst)"
      "Forward chaining: derives vulnerability facts from rules"
      "Backward queries: find files by vulnerability category"
      "6-axis stress testing (CPU, memory, disk, network, concurrency, time)"
      "Logic-based bug detection (use-after-free, double-free, deadlock, data-race)"
      "Per-file language detection and risk scoring"
      "JSON, YAML, and Nickel output formats"
      "Report views (summary, accordion, dashboard, matrix) + TUI viewer"
      "PanLL event-chain export for external timeline visualisation"
      "Ambush timeline scheduling (plan-only) for stressor sequencing"
      "Optional verisimdb storage integration"
      "SARIF output format for GitHub Security tab"
      "Assemblyline batch scanning with rayon parallelism + BLAKE3 fingerprinting"
      "Notification pipeline (markdown + critical-only filtering)"
      "Panicbot integration (JSON contract verified, bot directives, diagnostics check)"
      "Cryptographic attestation chain (intent → evidence → seal)"
      "i18n support (ISO 639-1, 10 languages)"
      "Machine-verifiable readiness tests (CRG D/C/B grades)"))

  (route-to-mvp
    (target "v2.1.0: Bulk scanning + verisimdb integration")
    (strategy "Add sweep subcommand for directory-of-repos scanning, push results to verisimdb")

    (milestones
      (milestone
        (id "sweep-subcommand")
        (status "planned")
        (priority "critical")
        (tasks
          "Add `sweep` subcommand for scanning directory of git repos"
          "Auto-detect repos by .git presence"
          "Aggregate results across repos"
          "Push results to verisimdb API as hexads"))

      (milestone
        (id "hypatia-integration")
        (status "planned")
        (priority "high")
        (tasks
          "Feed scan results to hypatia rule engine"
          "Export kanren facts as Logtalk predicates"
          "Support echidnabot proof verification"))

      (milestone
        (id "sarif-output")
        (status "completed")
        (priority "medium")
        (completed-date "2026-03-01")
        (tasks
          "SARIF output for GitHub Security tab"
          "Integration with CodeQL workflow"))))

  (blockers-and-issues)

  (critical-next-actions
    (action
      (priority "1")
      (description "verisimdb API integration: push scan results as hexads directly")
      (estimated-effort "2-3 hours"))
    (action
      (priority "2")
      (description "Incremental assemblyline: BLAKE3 delta scanning to skip unchanged repos")
      (estimated-effort "1-2 hours"))
    (action
      (priority "3")
      (description "kanren context-facts for FP suppression (~10 rules, 8% -> 2-3%)")
      (estimated-effort "2-3 hours"))
    (action
      (priority "4")
      (description "Export kanren facts as Logtalk predicates for hypatia via PanLL")
      (estimated-effort "1-2 hours")))

  (session-history
    (session
      (id "9")
      (date "2026-03-01")
      (duration "1h")
      (focus "Panicbot integration")
      (outcomes
        "Added panicbot to AI.a2ml integration section"
        "Created .machine_readable/bot_directives/panicbot.scm"
        "Added panicbot health check to diagnostics.rs (JSON contract verification)"
        "Added panicbot to ECOSYSTEM.scm with interface documentation"
        "Added readiness tests: diagnostics output, JSON contract (PA001–PA020)"
        "Updated STATE.scm with all session 8+9 capabilities"))

    (session
      (id "8")
      (date "2026-03-01")
      (duration "4h")
      (focus "Assemblyline, notification pipeline, SARIF, attestation, i18n, readiness tests")
      (outcomes
        "Implemented SARIF output format"
        "Added assemblyline batch scanning with rayon parallelism (17.7x speedup)"
        "Added BLAKE3 fingerprinting for incremental scanning"
        "Built notification pipeline (markdown + GitHub issues + critical-only)"
        "Added cryptographic attestation chain (intent/evidence/seal)"
        "Added i18n support (10 languages)"
        "Fixed framework detection false positives (manifest-first approach)"
        "Spot-checked FP rate: ~8% across 4 repos"
        "Built machine-verifiable readiness test suite (16 tests, CRG D/C/B grades)"
        "Added justfile with readiness/readiness-summary recipes"
        "Fixed all compiler warnings (0 warnings in release + test builds)"
        "Updated README.md and CLAUDE.md documentation"
        "267 tests, 0 failures"))

    (session
      (id "7")
      (date "2026-02-12")
      (duration "30m")
      (focus "Workflow automation: VERISIMDB_PAT support")
      (outcomes
        "Updated scan-and-report.yml to accept optional VERISIMDB_PAT secret"
        "Added GITHUB_TOKEN fallback for dispatch token"
        "Added -sf flag to curl for silent failure detection"
        "Pushed to GitHub"))

    (session
      (id "6")
      (date "2026-02-09")
      (duration "2h")
      (focus "PanLL integration + report UX expansion")
      (outcomes
        "Added PanLL event-chain export format and docs"
        "Added ambush timeline planning + parser"
        "Added report views (accordion, dashboard, matrix) and TUI viewer"
        "Added Nickel output and report metadata wiring"))
    (session
      (id "5")
      (date "2026-02-08")
      (duration "3h")
      (focus "v2.0.0: 47-language support + miniKanren logic engine")
      (outcomes
        "Expanded from 8 to 47 languages"
        "Added 20 weak point categories"
        "Implemented miniKanren-inspired logic engine (kanren module)"
        "Added taint analysis: source->sink tracking"
        "Added cross-language vulnerability chain detection"
        "Added search strategy optimisation (auto-select)"
        "Renamed xray module to assail throughout"
        "Renamed XRayReport type to AssailReport"
        "All 30 tests passing"
        "Updated all documentation"))

    (session
      (id "4")
      (date "2026-02-08")
      (duration "1h")
      (focus "Rename + bulk scanning + system crash diagnosis")
      (outcomes
        "Renamed xray->assail, panic-attacker->panic-attack across all files"
        "Built v1.0.1, installed to PATH"
        "Scanned 21 Eclipse repos, loaded results into verisimdb"))

    (session
      (id "3")
      (date "2026-02-07")
      (duration "2h")
      (focus "v0.2.0 implementation + v1.0 planning")
      (outcomes
        "Implemented v0.2.0 (per-file stats, locations, Latin-1 fallback, patterns)"
        "Zero compiler warnings achieved"
        "Created AI manifest and SCM files"))))
