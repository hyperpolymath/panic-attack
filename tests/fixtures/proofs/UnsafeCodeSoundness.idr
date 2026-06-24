-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-- @name "UnsafeCode detector soundness (Idris2)"
-- @covers sound:category:UnsafeCode
|||
||| A closed Idris2 soundness witness for panic-attack's UnsafeCode (PA001)
||| detector, in the exact shape `panic-attack aggregate` folds: no escape
||| hatches, a total proof that a positive detection is backed by a genuine
||| occurrence -- the detector raises no UnsafeCode finding on a token stream
||| that contains no unsafe construct (no false positives).
|||
||| `aggregate` records this artifact by BLAKE3 hash and does NOT re-check it;
||| the recorded verdict is conditioned on the Idris2 checker, whose input this
||| file is. The `@covers sound:category:UnsafeCode` annotation marks any
||| overlapping UnsafeCode finding in a base report as proof-Backed.
module UnsafeCodeSoundness

%default total

||| A scanned token: ordinary code, or an unsafe construct (e.g. a Rust
||| `unsafe` block) -- the minimal model the UnsafeCode detector reasons over.
public export
data Tok = Ordinary | Unsafe

||| The detector under study: positive on the first unsafe construct seen.
||| Structurally the per-file first-hit scan the real analyzer performs.
public export
detect : List Tok -> Bool
detect []               = False
detect (Unsafe   :: _)  = True
detect (Ordinary :: ts) = detect ts

||| A structural witness that an `Unsafe` token genuinely occurs in the stream.
public export
data Occurs : List Tok -> Type where
  Here  : Occurs (Unsafe :: ts)
  There : Occurs ts -> Occurs (x :: ts)

||| SOUNDNESS (no false positives): every positive detection is backed by a
||| real `Unsafe` occurrence -- exactly the `sound` claim that `aggregate`
||| reconciles as `Backed` against an overlapping UnsafeCode finding.
export
detectSound : (ts : List Tok) -> detect ts = True -> Occurs ts
detectSound (Unsafe   :: _)  _   = Here
detectSound (Ordinary :: ts) prf = There (detectSound ts prf)
detectSound []               prf = absurd prf

||| COMPLETENESS (no false negatives): a real occurrence forces a positive
||| detection. Together with `detectSound` this pins detection as exactly
||| "an unsafe construct occurs", with no hidden gap in either direction.
export
detectComplete : (ts : List Tok) -> Occurs ts -> detect ts = True
detectComplete (Unsafe   :: _)  Here      = Refl
detectComplete (Unsafe   :: _)  (There _) = Refl
detectComplete (Ordinary :: ts) (There o) = detectComplete ts o
