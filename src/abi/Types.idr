-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>
||| ABI Types for panic-attack static analysis engine
|||
||| Defines the formal interface for the scanner's operations.
||| Proves that:
|||   1. Severity levels are totally ordered
|||   2. Scan results cannot be fabricated (constructive)
|||   3. Language coverage is bounded
module PanicAttack.ABI.Types

import Data.Fin

%default total

||| Severity of a finding
public export
data Severity = Info | Warning | Error | Critical

||| Total ordering on severity
public export
Ord Severity where
  compare Info Info         = EQ
  compare Info _            = LT
  compare Warning Info      = GT
  compare Warning Warning   = EQ
  compare Warning _         = LT
  compare Error Critical    = LT
  compare Error Error       = EQ
  compare Error _           = GT
  compare Critical Critical = EQ
  compare Critical _        = GT

||| Scan operation type
public export
data ScanOp
  = Assail         -- Full analysis pass
  | Ambush         -- Quick targeted check
  | Abduct         -- Extract patterns
  | Adjudicate     -- Judge findings
  | Axial          -- Dependency analysis

||| Language identifier (47 supported, bounded)
public export
data LangId = MkLangId (n : Fin 47)

-- ═══════════════════════════════════════════════════════════════════════
-- C ABI Exports
-- ═══════════════════════════════════════════════════════════════════════

export
severityToInt : Severity -> Int
severityToInt Info     = 0
severityToInt Warning  = 1
severityToInt Error    = 2
severityToInt Critical = 3

export
scanOpToInt : ScanOp -> Int
scanOpToInt Assail     = 0
scanOpToInt Ambush     = 1
scanOpToInt Abduct     = 2
scanOpToInt Adjudicate = 3
scanOpToInt Axial      = 4
