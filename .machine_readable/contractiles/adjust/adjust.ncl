# SPDX-License-Identifier: MPL-2.0
# adjust.ncl — runner for the ADJUST contractile (calibration and tuning)
# Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# Pairs with: Adjustfile.a2ml (same directory)
# Verb:       adjust
# Semantics:  verify that declared detector thresholds and calibration
#             values are still wired into the source code. Flags threshold
#             drift (declared ≠ live) so it can be resolved consciously.
# CLI:        `contractile adjust check`  → list calibration checks + status

let checks = [
  { name = "adjustfile-present",
    cmd = "test -f .machine_readable/contractiles/adjust/Adjustfile.a2ml" },
  { name = "panic-path-unwrap-threshold-wired",
    cmd = "grep -qE 'unwrap_threshold|unwrap_calls > [0-9]' src/assail/analyzer.rs src/report/generator.rs 2>/dev/null" },
  { name = "panic-path-panic-threshold-wired",
    cmd = "grep -qE 'panic_threshold|panic_sites > [0-9]' src/assail/analyzer.rs 2>/dev/null" },
  { name = "safe-unwrap-excluded-from-pa006",
    cmd = "grep -q 'safe_unwrap_calls' src/assail/analyzer.rs" },
  { name = "safe-unwrap-field-in-statistics",
    cmd = "grep -q 'safe_unwrap_calls' src/types.rs" },
  { name = "fp-suppression-rules-present",
    cmd = "grep -qE 'suppression_rule|load_suppression_rules|SuppressionRule' src/kanren/core.rs 2>/dev/null" },
  { name = "schema-version-consistent-across-reports",
    cmd = "grep -l '\"2\\.5\"' src/types.rs src/assemblyline.rs src/adjudicate/mod.rs src/amuck/mod.rs src/abduct/mod.rs src/axial/mod.rs 2>/dev/null | wc -l | grep -qE '^[6-9]|^[1-9][0-9]'" },
  { name = "seam-contract-tests-exist",
    cmd = "test -f tests/seam_contract_tests.rs" },
] in

checks
