-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Comment and String Stripping Idempotence (PROOF-PROGRAMME Layer 1.0)
|||
||| Models the line-comment slice of the analyzer's comment-stripping pass,
||| `src/assail/analyzer.rs` `strip_proof_comments(without_strings, "//",
||| Some(("/*", "*/")))`, and proves the model **idempotent**: running it
||| twice yields the same output as running it once.
|||
||| What this establishes, and what it does not:
|||
||| * The theorem is about this Idris2 model, not the Rust function, and the
|||   model does not reproduce the Rust output. The model replaces comment
|||   characters with spaces and keeps every newline; the Rust pass deletes
|||   comment text and drops a trailing newline (`//x` gives three spaces
|||   here and the empty string in Rust). Block comments and string literals
|||   are not modelled. See PROOF-NEEDS.adoc for the Rust function's own
|||   status.
||| * Multi-comment semantics: every `//` comment is stripped, not only the
|||   first (the PR #111 model's error). `stripLineCommentBody` hands
|||   control back to `stripLineComments` after each preserved newline.
|||
||| Proof shape. Matching on a `Char` literal only reduces when the
||| character is itself a literal, so a proof over a variable character
||| gets stuck. Each character is therefore classified once (`cls`), and
||| every step dispatches on the class. The proofs carry the class as an
||| explicit argument together with the equation `cls c = k`, so each
||| case reduces. `stripLineComments` and `stripLineCommentBody` compute
||| the same function as the earlier pattern-matching Idris2 definitions;
||| that was checked exhaustively on every string of length at most 9 over
||| `/`, newline, `x` and space (349,525 inputs, no mismatch). That check
||| compares two Idris2 models; it is not a comparison with Rust.
module PanicAttack.ABI.Stripping

%default total

-- ═══════════════════════════════════════════════════════════════════════
-- Helpers
-- ═══════════════════════════════════════════════════════════════════════

||| The space character used to overwrite stripped regions.
public export
sp : Char
sp = ' '

||| The newline character preserved during line-comment stripping (so
||| line numbers in the stripped view match line numbers in the
||| original — critical for the analyzer's location reporting).
public export
nl : Char
nl = '\n'

||| The only distinctions the stripper makes between characters.
public export
data Cls = Slash | Newline | Other

public export
cls : Char -> Cls
cls '/'  = Slash
cls '\n' = Newline
cls _    = Other

-- ═══════════════════════════════════════════════════════════════════════
-- Stripping functions: a model of the line-comment slice of
-- src/assail/analyzer.rs strip_proof_comments. The model keeps spaces and
-- newlines where the Rust function deletes comment text and drops a
-- trailing newline.
--
-- `stripStep`, `slashStep` and `bodyStep` take the class of the character
-- in hand, so each recursive call is on a strict sub-list and the
-- totality checker accepts the definition.
-- ═══════════════════════════════════════════════════════════════════════

mutual
    ||| The main line-comment stripper. Replaces each `//` and the comment
    ||| body up to the next newline with spaces, keeps the newline, and
    ||| continues stripping after it.
    public export
    stripLineComments : List Char -> List Char
    stripLineComments [] = []
    stripLineComments (c :: rest) = stripStep (cls c) c rest

    ||| One step of `stripLineComments`, given the class of the head.
    public export
    stripStep : Cls -> Char -> List Char -> List Char
    stripStep Slash   c []       = [c]
    stripStep Slash   c (d :: r) = slashStep (cls d) c d r
    stripStep Newline c rest     = c :: stripLineComments rest
    stripStep Other   c rest     = c :: stripLineComments rest

    ||| A `/` followed by `d`: a comment opens only when `d` is `/` too.
    public export
    slashStep : Cls -> Char -> Char -> List Char -> List Char
    slashStep Slash   c d r = sp :: sp :: stripLineCommentBody r
    slashStep Newline c d r = c :: stripStep Newline d r
    slashStep Other   c d r = c :: stripStep Other d r

    ||| Walks from just after `//` to the next newline, replacing every
    ||| character with `sp`, then hands the rest back to
    ||| `stripLineComments`.
    public export
    stripLineCommentBody : List Char -> List Char
    stripLineCommentBody [] = []
    stripLineCommentBody (c :: rest) = bodyStep (cls c) rest

    ||| One step of `stripLineCommentBody`, given the class of the head.
    public export
    bodyStep : Cls -> List Char -> List Char
    bodyStep Newline rest = nl :: stripLineComments rest
    bodyStep Slash   rest = sp :: stripLineCommentBody rest
    bodyStep Other   rest = sp :: stripLineCommentBody rest

||| `stripLineComments` on a cons cell, unfolded one step.
stripCons : (c : Char) -> (x : List Char) ->
    stripLineComments (c :: x) = stripStep (cls c) c x
stripCons c x = Refl

-- ═══════════════════════════════════════════════════════════════════════
-- Idempotence — main theorem + body fixed-point lemma, mutual induction
-- ═══════════════════════════════════════════════════════════════════════

mutual
    ||| **Main theorem.** Applying the line-comment stripper twice
    ||| equals applying it once.
    public export
    stripLineCommentsIdempotent : (cs : List Char) ->
        stripLineComments (stripLineComments cs) = stripLineComments cs
    stripLineCommentsIdempotent [] = Refl
    stripLineCommentsIdempotent (c :: rest) = stepIdem (cls c) c Refl rest

    ||| Idempotence of one step, for a head `c` of class `k`.
    stepIdem : (k : Cls) -> (c : Char) -> cls c = k -> (rest : List Char) ->
        stripLineComments (stripStep k c rest) = stripStep k c rest
    stepIdem Slash c p [] =
        rewrite stripCons c [] in rewrite p in Refl
    stepIdem Slash c p (d :: r) = slashIdem (cls d) c p d Refl r
    stepIdem Newline c p rest =
        rewrite stripCons c (stripLineComments rest) in rewrite p in
        cong (c ::) (stripLineCommentsIdempotent rest)
    stepIdem Other c p rest =
        rewrite stripCons c (stripLineComments rest) in rewrite p in
        cong (c ::) (stripLineCommentsIdempotent rest)

    ||| Idempotence after a `/`, for a next character `d` of class `j`.
    ||| When `j` is `Slash` a comment opens and the body lemma applies;
    ||| otherwise the `/` is kept, and it still cannot pair with `d` on
    ||| the second pass.
    slashIdem : (j : Cls) -> (c : Char) -> cls c = Slash ->
        (d : Char) -> cls d = j -> (r : List Char) ->
        stripLineComments (slashStep j c d r) = slashStep j c d r
    slashIdem Slash c p d q r =
        cong (\xs => sp :: sp :: xs) (bodyIsFixedPoint r)
    slashIdem Newline c p d q r =
        rewrite stripCons c (d :: stripLineComments r) in rewrite p in
        rewrite q in
        cong (\xs => c :: d :: xs) (stripLineCommentsIdempotent r)
    slashIdem Other c p d q r =
        rewrite stripCons c (d :: stripLineComments r) in rewrite p in
        rewrite q in
        cong (\xs => c :: d :: xs) (stripLineCommentsIdempotent r)

    ||| **Body fixed-point lemma.** Applying the line-comment stripper
    ||| to the output of the body-stripper is a no-op: the pre-newline
    ||| region is all `sp`, so no `//` can form, and the post-newline
    ||| tail is already a fixed point by the main theorem.
    public export
    bodyIsFixedPoint : (cs : List Char) ->
        stripLineComments (stripLineCommentBody cs) = stripLineCommentBody cs
    bodyIsFixedPoint [] = Refl
    bodyIsFixedPoint (c :: rest) = bodyStepFixed (cls c) rest

    ||| The body lemma for one step, for a head of class `k`.
    bodyStepFixed : (k : Cls) -> (rest : List Char) ->
        stripLineComments (bodyStep k rest) = bodyStep k rest
    bodyStepFixed Newline rest = cong (nl ::) (stripLineCommentsIdempotent rest)
    bodyStepFixed Slash   rest = cong (sp ::) (bodyIsFixedPoint rest)
    bodyStepFixed Other   rest = cong (sp ::) (bodyIsFixedPoint rest)

-- ═══════════════════════════════════════════════════════════════════════
-- Sanity tests
-- ═══════════════════════════════════════════════════════════════════════

||| Empty input: both sides reduce to [].
private
sanityEmpty : stripLineComments (stripLineComments []) = stripLineComments []
sanityEmpty = Refl

||| Single non-comment char: preserved through both passes.
private
sanityNonCommentSingleChar :
    stripLineComments (stripLineComments ['x'])
      = stripLineComments ['x']
sanityNonCommentSingleChar = Refl

||| Bare `//`: produces `[sp, sp]` then `[sp, sp]` again.
private
sanityBareCommentMarker :
    stripLineComments (stripLineComments ['/', '/'])
      = stripLineComments ['/', '/']
sanityBareCommentMarker = Refl

||| `x//`: char preserved, then sp+sp.
private
sanityCharPlusCommentMarker :
    stripLineComments (stripLineComments ['x', '/', '/'])
      = stripLineComments ['x', '/', '/']
sanityCharPlusCommentMarker = Refl

||| `//x`: comment body strips `x` to `sp`, total `[sp, sp, sp]`. Then
||| second pass is a no-op (no further `//` can form from spaces).
private
sanityCommentWithBody :
    stripLineComments (stripLineComments ['/', '/', 'x'])
      = stripLineComments ['/', '/', 'x']
sanityCommentWithBody = Refl

||| `//x\\ny`: first pass produces `[sp, sp, sp, nl, y]`. Second pass
||| is the identity. The post-newline `y` is preserved because
||| stripLineCommentBody calls back into stripLineComments which leaves
||| non-comment chars alone.
private
sanityCommentThenCode :
    stripLineComments (stripLineComments ['/', '/', 'x', '\n', 'y'])
      = stripLineComments ['/', '/', 'x', '\n', 'y']
sanityCommentThenCode = Refl

||| TWO comments separated by a newline. PR #111's broken single-comment
||| model would have left the second `//` unstripped; this corrected
||| mutual-recursion model strips both.
private
sanityTwoComments :
    stripLineComments (stripLineComments ['/', '/', 'a', '\n', '/', '/', 'b'])
      = stripLineComments ['/', '/', 'a', '\n', '/', '/', 'b']
sanityTwoComments = Refl

-- ═══════════════════════════════════════════════════════════════════════
-- What still remains (Layer 1.0 future slices)
-- ═══════════════════════════════════════════════════════════════════════

-- Future Layer-1.0 work (recorded in PROOF-NEEDS.adoc + issue #114):
--
-- 1. **Stripping_Block.idr** — `/* … */` block-comment stripper. Same
--    mutual-recursion shape. The closing `*/` plays the role newlines
--    played here.
--
-- 2. **Stripping_Strings.idr** — `"…"` string-literal stripper with
--    `\"` escape handling. Same mutual-recursion shape.
--
-- 3. **Stripping_Composition.idr** — `strip = stripLineComments .
--    stripBlockComments . stripStrings` is itself idempotent given
--    each component is. Requires cross-component lemmas (e.g. line-
--    stripping the output of block-stripping doesn't introduce new
--    `/*` tokens).
--
-- 4. **Stripping_PositionPreservation.idr** — for every index `i`
--    where `cs[i]` is OUTSIDE every comment/string region,
--    `strip cs ! i = cs[i]`. Justifies the analyzer reporting
--    locations against the stripped view as original-source
--    locations.
--
-- Once all five land, every Layer-1.1..1.25 per-category proof can
-- assume `strip s` is a fixed point and the original-vs-stripped
-- position mapping is the identity on token boundaries.
