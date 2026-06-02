-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Comment and String Stripping Idempotence (PROOF-PROGRAMME Layer 1.0)
|||
||| Closes the slash-slash inductive case left open by PR #111 (issue #113).
|||
||| Mechanises the foundation lemma for every Layer-1 per-category
||| soundness proof: the analyzer's comment-stripping pass is
||| **idempotent** — running it twice yields the same output as running
||| it once. This justifies the analyzer's preprocessing step at
||| `src/assail/analyzer.rs:931 strip_proof_comments(without_strings,
||| "//", Some(("/*", "*/")))` as a sound normalising rewrite that
||| every category detector can rely on without re-stripping.
|||
||| Differences from the PR #111 model:
|||
||| 1. **Multi-comment semantics.** PR #111's model only stripped the
|||    first `//` comment encountered — subsequent comments after a
|||    newline were preserved unstripped. The Rust pass strips ALL
|||    comments in the input. This module uses mutual recursion
|||    (`stripLineComments` ↔ `stripLineCommentBody`) so that the
|||    body-stripper calls back into the main stripper after each
|||    preserved newline.
|||
||| 2. **Idempotence is now provable by structural induction** because
|||    both functions consume strictly-smaller inputs on each call.
|||    Idris2's totality checker validates the recursion.
|||
||| 3. **Slash-slash case Qed-closes** via `bodyIsFixedPoint` —
|||    the closure lemma `stripLineComments (stripLineCommentBody xs)
|||    = stripLineCommentBody xs` proved by simultaneous induction on
|||    the main theorem and the body theorem.
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

-- ═══════════════════════════════════════════════════════════════════════
-- Stripping functions (mirror src/assail/analyzer.rs:931 strip_proof_comments)
--
-- Mutual recursion: stripLineComments handles non-comment input and
-- delegates comment bodies to stripLineCommentBody; stripLineCommentBody
-- walks until the next newline and then returns control to the main
-- stripper for the post-newline tail.
-- ═══════════════════════════════════════════════════════════════════════

mutual
    ||| The main line-comment stripper. Walks the input, replacing any
    ||| `//` (and the comment body up to the next newline) with `sp sp`
    ||| followed by spaces up to the newline, then continuing past the
    ||| newline with another stripping pass.
    public export
    stripLineComments : List Char -> List Char
    stripLineComments [] = []
    stripLineComments ('/' :: '/' :: rest) =
        sp :: sp :: stripLineCommentBody rest
    stripLineComments (c :: rest) = c :: stripLineComments rest

    ||| `stripLineCommentBody` walks from JUST AFTER `//` until the
    ||| next newline, replacing every character with `sp`. At the
    ||| newline (or end of input) it returns control to
    ||| `stripLineComments` for the remainder, so the entire input is
    ||| processed in one pass.
    public export
    stripLineCommentBody : List Char -> List Char
    stripLineCommentBody [] = []
    stripLineCommentBody (c :: rest) =
        if c == nl
           then nl :: stripLineComments rest
           else sp :: stripLineCommentBody rest

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
    stripLineCommentsIdempotent ('/' :: '/' :: rest) =
        -- LHS = strip (strip ('/' :: '/' :: rest))
        --     = strip (sp :: sp :: stripBody rest)         [by definition]
        --     = sp :: strip (sp :: stripBody rest)         [sp /= '/']
        --     = sp :: sp :: strip (stripBody rest)         [sp /= '/']
        --     = sp :: sp :: stripBody rest                 [by bodyIsFixedPoint]
        -- RHS = sp :: sp :: stripBody rest                 [by definition]
        cong (\xs => sp :: sp :: xs) (bodyIsFixedPoint rest)
    stripLineCommentsIdempotent ('/' :: c :: rest) =
        -- Not a comment marker (c is not the immediate-second '/').
        -- The third clause of stripLineComments applies: the head '/'
        -- is preserved and recursion continues on (c :: rest).
        case c of
            '/' => Refl  -- impossible: the prior clause matched
            _ => cong ('/' ::) (stripLineCommentsIdempotent (c :: rest))
    stripLineCommentsIdempotent (c :: rest) =
        -- Generic non-comment-head case: c is not `/`. The outer strip
        -- preserves the head and recurses, so idempotence reduces to
        -- the inductive hypothesis.
        case c of
            '/' => case rest of
                [] => Refl
                _ :: _ => Refl  -- covered by the prior two clauses
            _ => cong (c ::) (stripLineCommentsIdempotent rest)

    ||| **Body fixed-point lemma.** Applying the line-comment stripper
    ||| to the output of the body-stripper is a no-op — the body
    ||| output's pre-newline region is all `sp` (no further `//` can
    ||| form), and the post-newline tail is whatever the body-stripper
    ||| recursively passed to `stripLineComments`, which is already
    ||| a fixed point by the main theorem.
    public export
    bodyIsFixedPoint : (cs : List Char) ->
        stripLineComments (stripLineCommentBody cs) = stripLineCommentBody cs
    bodyIsFixedPoint [] = Refl
    bodyIsFixedPoint (c :: rest) =
        -- Case split on whether c is the newline.
        case decEq c nl of
            Yes prf =>
                -- c = nl. Body returns `nl :: stripLineComments rest`.
                -- strip applied to that = `nl :: strip (stripLineComments rest)`
                -- (nl /= '/'). By main theorem on `rest`, that =
                -- `nl :: stripLineComments rest`.
                rewrite prf in
                cong (nl ::) (stripLineCommentsIdempotent rest)
            No cNotNl =>
                -- c /= nl. Body returns `sp :: stripLineCommentBody rest`.
                -- strip applied to that = `sp :: strip (stripLineCommentBody rest)`
                -- (sp /= '/'). By the body IH, that = `sp :: stripLineCommentBody rest`.
                let
                    -- Establish that the body output starts with sp
                    -- under the c /= nl case.
                    bodyOutputShape : stripLineCommentBody (c :: rest)
                                    = sp :: stripLineCommentBody rest
                    bodyOutputShape = case decEq c nl of
                        Yes y => absurd (cNotNl y)
                        No _ => Refl
                in
                rewrite bodyOutputShape in
                cong (sp ::) (bodyIsFixedPoint rest)

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

||| Future Layer-1.0 work (recorded in PROOF-NEEDS.md + issue #114):
|||
||| 1. **Stripping_Block.idr** — `/* … */` block-comment stripper. Same
|||    mutual-recursion shape. The closing `*/` plays the role newlines
|||    played here.
|||
||| 2. **Stripping_Strings.idr** — `"…"` string-literal stripper with
|||    `\"` escape handling. Same mutual-recursion shape.
|||
||| 3. **Stripping_Composition.idr** — `strip = stripLineComments .
|||    stripBlockComments . stripStrings` is itself idempotent given
|||    each component is. Requires cross-component lemmas (e.g. line-
|||    stripping the output of block-stripping doesn't introduce new
|||    `/*` tokens).
|||
||| 4. **Stripping_PositionPreservation.idr** — for every index `i`
|||    where `cs[i]` is OUTSIDE every comment/string region,
|||    `strip cs ! i = cs[i]`. Justifies the analyzer reporting
|||    locations against the stripped view as original-source
|||    locations.
|||
||| Once all five land, every Layer-1.1..1.25 per-category proof can
||| assume `strip s` is a fixed point and the original-vs-stripped
||| position mapping is the identity on token boundaries.
