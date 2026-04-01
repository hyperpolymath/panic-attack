-- SPDX-License-Identifier: PMPL-1.0-or-later
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Classification Soundness Proofs
|||
||| Proves that the scanner's severity classification is sound:
||| 1. Severity levels form a total order (Low <= Medium <= High <= Critical)
||| 2. Severity assignment is monotone: combining findings never lowers severity
||| 3. The numeric encoding preserves ordering (for C ABI export)
|||
||| These proofs guarantee that the scanner cannot misclassify a Critical
||| finding as Medium, and that aggregation (e.g., max severity across files)
||| produces correct results.
module PanicAttack.ABI.ClassificationSoundness

%default total

-- ═══════════════════════════════════════════════════════════════════════
-- Severity type (mirrors src/types.rs Severity enum)
-- ═══════════════════════════════════════════════════════════════════════

||| Scanner severity levels. Order: Low < Medium < High < Critical.
||| Mirrors the Rust enum's derived PartialOrd/Ord ordering.
public export
data Severity = Low | Medium | High | Critical

-- ═══════════════════════════════════════════════════════════════════════
-- Numeric encoding (for C ABI / JSON serialization)
-- ═══════════════════════════════════════════════════════════════════════

||| Map severity to a numeric value. Must be strictly monotone.
public export
severityToNat : Severity -> Nat
severityToNat Low      = 0
severityToNat Medium   = 1
severityToNat High     = 2
severityToNat Critical = 3

-- ═══════════════════════════════════════════════════════════════════════
-- Ordering relation
-- ═══════════════════════════════════════════════════════════════════════

||| Less-than-or-equal ordering on Severity.
||| Defined inductively to enable structural proofs.
public export
data SevLTE : Severity -> Severity -> Type where
  ||| Every severity is <= itself (reflexivity)
  SevRefl  : SevLTE s s
  ||| Low <= Medium
  LowMed   : SevLTE Low Medium
  ||| Low <= High
  LowHigh  : SevLTE Low High
  ||| Low <= Critical
  LowCrit  : SevLTE Low Critical
  ||| Medium <= High
  MedHigh  : SevLTE Medium High
  ||| Medium <= Critical
  MedCrit  : SevLTE Medium Critical
  ||| High <= Critical
  HighCrit : SevLTE High Critical

-- ═══════════════════════════════════════════════════════════════════════
-- Decidable equality
-- ═══════════════════════════════════════════════════════════════════════

public export
Eq Severity where
  Low      == Low      = True
  Medium   == Medium   = True
  High     == High     = True
  Critical == Critical = True
  _        == _        = False

-- ═══════════════════════════════════════════════════════════════════════
-- Total ordering proofs
-- ═══════════════════════════════════════════════════════════════════════

||| Reflexivity: every severity is <= itself.
public export
sevRefl : (s : Severity) -> SevLTE s s
sevRefl _ = SevRefl

||| Antisymmetry: if a <= b and b <= a then a = b.
public export
sevAntisym : SevLTE a b -> SevLTE b a -> a = b
sevAntisym SevRefl  _        = Refl
sevAntisym _        SevRefl  = Refl
-- All non-reflexive cases are contradictory pairs (e.g., LowMed + MedLow)
-- which cannot be constructed, so they are vacuously true.

||| Transitivity: if a <= b and b <= c then a <= c.
public export
sevTrans : SevLTE a b -> SevLTE b c -> SevLTE a c
sevTrans SevRefl  q        = q
sevTrans p        SevRefl  = p
sevTrans LowMed   MedHigh  = LowHigh
sevTrans LowMed   MedCrit  = LowCrit
sevTrans LowHigh  HighCrit = LowCrit
sevTrans MedHigh  HighCrit = MedCrit

||| Totality: for any two severities, either a <= b or b <= a.
public export
sevTotal : (a : Severity) -> (b : Severity) -> Either (SevLTE a b) (SevLTE b a)
sevTotal Low      Low      = Left SevRefl
sevTotal Low      Medium   = Left LowMed
sevTotal Low      High     = Left LowHigh
sevTotal Low      Critical = Left LowCrit
sevTotal Medium   Low      = Right LowMed
sevTotal Medium   Medium   = Left SevRefl
sevTotal Medium   High     = Left MedHigh
sevTotal Medium   Critical = Left MedCrit
sevTotal High     Low      = Right LowHigh
sevTotal High     Medium   = Right MedHigh
sevTotal High     High     = Left SevRefl
sevTotal High     Critical = Left HighCrit
sevTotal Critical Low      = Right LowCrit
sevTotal Critical Medium   = Right MedCrit
sevTotal Critical High     = Right HighCrit
sevTotal Critical Critical = Left SevRefl

-- ═══════════════════════════════════════════════════════════════════════
-- Monotonicity of numeric encoding
-- ═══════════════════════════════════════════════════════════════════════

||| The numeric encoding preserves ordering:
||| if a <= b then severityToNat a <= severityToNat b.
public export
encodingMonotone : SevLTE a b -> LTE (severityToNat a) (severityToNat b)
encodingMonotone SevRefl  = lteRefl
encodingMonotone LowMed   = LTESucc LTEZero
encodingMonotone LowHigh  = LTESucc LTEZero
encodingMonotone LowCrit  = LTESucc LTEZero
encodingMonotone MedHigh  = LTESucc (LTESucc LTEZero)
encodingMonotone MedCrit  = LTESucc (LTESucc LTEZero)
encodingMonotone HighCrit = LTESucc (LTESucc (LTESucc LTEZero))

-- ═══════════════════════════════════════════════════════════════════════
-- Maximum (aggregation) soundness
-- ═══════════════════════════════════════════════════════════════════════

||| Compute the maximum of two severities.
public export
sevMax : Severity -> Severity -> Severity
sevMax Low      b        = b
sevMax a        Low      = a
sevMax Medium   b        = b
sevMax a        Medium   = a
sevMax High     Critical = Critical
sevMax Critical High     = Critical
sevMax High     High     = High
sevMax Critical Critical = Critical

||| The maximum is an upper bound: a <= max(a, b).
public export
sevMaxUpperLeft : (a : Severity) -> (b : Severity) -> SevLTE a (sevMax a b)
sevMaxUpperLeft Low      Low      = SevRefl
sevMaxUpperLeft Low      Medium   = LowMed
sevMaxUpperLeft Low      High     = LowHigh
sevMaxUpperLeft Low      Critical = LowCrit
sevMaxUpperLeft Medium   Low      = SevRefl
sevMaxUpperLeft Medium   Medium   = SevRefl
sevMaxUpperLeft Medium   High     = MedHigh
sevMaxUpperLeft Medium   Critical = MedCrit
sevMaxUpperLeft High     Low      = SevRefl
sevMaxUpperLeft High     Medium   = SevRefl
sevMaxUpperLeft High     High     = SevRefl
sevMaxUpperLeft High     Critical = HighCrit
sevMaxUpperLeft Critical Low      = SevRefl
sevMaxUpperLeft Critical Medium   = SevRefl
sevMaxUpperLeft Critical High     = SevRefl
sevMaxUpperLeft Critical Critical = SevRefl

||| The maximum is an upper bound: b <= max(a, b).
public export
sevMaxUpperRight : (a : Severity) -> (b : Severity) -> SevLTE b (sevMax a b)
sevMaxUpperRight Low      b        = SevRefl
sevMaxUpperRight Medium   Low      = LowMed
sevMaxUpperRight Medium   Medium   = SevRefl
sevMaxUpperRight Medium   High     = SevRefl
sevMaxUpperRight Medium   Critical = SevRefl
sevMaxUpperRight High     Low      = LowHigh
sevMaxUpperRight High     Medium   = MedHigh
sevMaxUpperRight High     High     = SevRefl
sevMaxUpperRight High     Critical = SevRefl
sevMaxUpperRight Critical Low      = LowCrit
sevMaxUpperRight Critical Medium   = MedCrit
sevMaxUpperRight Critical High     = HighCrit
sevMaxUpperRight Critical Critical = SevRefl

-- ═══════════════════════════════════════════════════════════════════════
-- Monotonicity of severity assignment
-- ═══════════════════════════════════════════════════════════════════════

||| Aggregating findings (taking the max) never lowers severity.
||| Given an existing severity `old` and a new finding's severity `new`,
||| the result `max(old, new)` is >= both inputs.
public export
aggregationNeverLowers : (old : Severity) -> (new : Severity)
                      -> (SevLTE old (sevMax old new), SevLTE new (sevMax old new))
aggregationNeverLowers old new = (sevMaxUpperLeft old new, sevMaxUpperRight old new)

-- ═══════════════════════════════════════════════════════════════════════
-- Critical findings are never downgraded
-- ═══════════════════════════════════════════════════════════════════════

||| If any finding is Critical, the aggregate is Critical.
||| This is the key safety property: critical issues cannot be hidden.
public export
criticalNeverDowngraded : (other : Severity) -> sevMax Critical other = Critical
criticalNeverDowngraded Low      = Refl
criticalNeverDowngraded Medium   = Refl
criticalNeverDowngraded High     = Refl
criticalNeverDowngraded Critical = Refl

||| Symmetric: max(other, Critical) = Critical.
public export
criticalNeverDowngradedSym : (other : Severity) -> sevMax other Critical = Critical
criticalNeverDowngradedSym Low      = Refl
criticalNeverDowngradedSym Medium   = Refl
criticalNeverDowngradedSym High     = Refl
criticalNeverDowngradedSym Critical = Refl
