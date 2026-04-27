K9!
# SPDX-License-Identifier: PMPL-1.0-or-later
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
# K9 Kennel-level guard: panic-attacker project metadata and analysis invariants
# Security Level: Kennel (data-only, no execution)
# No signature required

{
  pedigree = {
    schema_version = "1.0.0",
    component_type = "security-tool-metadata",
    security = {
      leash = 'Kennel,
      trust_level = "data-only",
      allow_network = false,
      allow_filesystem_write = false,
      allow_subprocess = false,
    },
    metadata = {
      name = "panic-attacker-metadata",
      version = "2.1.0",
      description = "panic-attack: universal static analysis and bug signature detection — project invariants",
      author = "Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>",
    },
  },

  # Project configuration
  config = {
    # Supported language count (informational)
    supported_languages = 47,

    # Safety invariants for the analysis engine itself
    safety = {
      # No panics in production analysis paths
      forbidden_in_analysis = [
        "unwrap()",
        "expect()",
        "todo!()",
        "unimplemented!()",
      ],
      # unsafe blocks must be audited
      unsafe_blocks_must_be_audited = true,
    },

    # Test requirements
    tests = {
      min_unit_tests = 100,
      min_integration_tests = 10,
      property_tests_required = true,
      # Each language rule module should have test coverage
      rule_coverage_required = true,
    },

    # Build configuration
    build = {
      edition = "2021",
      msrv = "1.85.0",
    },

    # Language policy
    banned_files = ["Makefile", "Dockerfile"],
    banned_languages = ["python", "typescript", "javascript", "go"],

    # Analysis output invariants
    output = {
      # Output must always be valid JSON when --json flag used
      json_output_must_be_valid = true,
      # Exit code 0 = clean, 1 = violations found, 2 = tool error
      exit_codes = {
        clean = 0,
        violations = 1,
        tool_error = 2,
      },
    },
  },

  # RSR compliance
  rsr = {
    explainme = true,
    ai_manifest = true,
    machine_readable = true,
    spdx_headers_required = true,
    security_md_required = true,
    idris2_abi = true,
    zig_ffi = true,
  },
}
