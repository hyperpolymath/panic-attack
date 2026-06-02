-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Comment and String Stripping Idempotence (PROOF-PROGRAMME Layer 1.0)
|||
||| Mechanises the foundation lemma for every Layer-1 per-category
||| soundness proof: the analyzer's comment/string-stripping pass is
||| **idempotent** — running it twice yields the same output as running
||| it once. This justifies the analyzer's preprocessing step
||| (src/assail/analyzer.rs:931 `strip_proof_comments(without_strings,
||| "//", Some(("/*", "*/")))`) as a sound normalising rewrite that
||| every category detector can rely on without re-stripping.
|||
||| Status: this module ships the **foundation** —
|||
||| 1. Total Idris2 function definitions for `stripLineCommentBody`
|||    and `stripLineComments` mirroring the Rust analyzer's stripping
|||    pass.
||| 2. The shape predicate `IsStrippedBody` + the proof that
|||    `stripLineCommentBody` always produces shape-respecting output
|||    (`stripBodyProducesStrippedShape`).
||| 3. The two structural base cases of the idempotence theorem,
|||    Qed-closed without `believe_me` / `assert_total` / `?` holes.
|||
||| Open obligations (recorded in PROOF-NEEDS.md):
||| * The `'/' :: '/' :: rest` inductive step of `stripLineCommentsIdempotent`
|||   requires a closure lemma showing that `stripLineComments` applied to
|||   any `IsStrippedBody`-shaped input is the identity. This is the
|||   load-bearing piece left for the next Layer-1.0 slice.
||| * Block-comment (`/* */`) stripping, string-literal stripping, and
|||   the composition theorem (PROOF-PROGRAMME Layer 1.0 items 1–3).
||| * Position preservation (Layer 1.0 item 4).
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
-- ═══════════════════════════════════════════════════════════════════════

||| `stripLineCommentBody` walks from JUST AFTER `//` until the next
||| newline, replacing every character with `sp`. The newline itself is
||| preserved so line counts are stable.
|||
||| Note: this is the **post-leader** body, NOT the line-comment
||| pattern itself. The pattern `//` is replaced separately by
||| `stripLineComments` so the leader bytes also become spaces.
public export
stripLineCommentBody : List Char -> List Char
stripLineCommentBody [] = []
stripLineCommentBody (c :: rest) =
    if c == nl
       then nl :: rest         -- preserve the rest of the file as-is
       else sp :: stripLineCommentBody rest

||| The main line-comment stripper. Walks the input, replacing any `//`
||| (and the comment body up to the next newline) with `sp sp` followed
||| by spaces up to the newline.
public export
stripLineComments : List Char -> List Char
stripLineComments [] = []
stripLineComments ('/' :: '/' :: rest) =
    sp :: sp :: stripLineCommentBody rest
stripLineComments (c :: rest) = c :: stripLineComments rest

-- ═══════════════════════════════════════════════════════════════════════
-- Shape predicate: what does `stripLineCommentBody` produce?
-- ═══════════════════════════════════════════════════════════════════════

||| `IsStrippedBody xs` holds iff `xs` is a (possibly empty) sequence
||| of `sp` characters terminated by a single `nl` followed by an
||| ARBITRARY ORIGINAL TAIL.
|||
||| This characterises the output of `stripLineCommentBody`:
||| every character before the next newline is `sp`, and the newline-
||| plus-tail is the post-newline suffix of the original input
||| (which the outer `stripLineComments` will walk over normally).
public export
data IsStrippedBody : List Char -> Type where
    StripEmpty : IsStrippedBody []
    StripJustNl : (tail : List Char) -> IsStrippedBody (nl :: tail)
    StripSpaceCons : (rest : List Char) ->
                     IsStrippedBody rest ->
                     IsStrippedBody (sp :: rest)

-- ═══════════════════════════════════════════════════════════════════════
-- Lemma 1: every output of stripLineCommentBody satisfies IsStrippedBody
-- ═══════════════════════════════════════════════════════════════════════

||| `stripBodyProducesStrippedShape cs` proves that whatever
||| `stripLineCommentBody cs` returns satisfies `IsStrippedBody`.
||| Proceeds by structural induction on `cs`.
public export
stripBodyProducesStrippedShape : (cs : List Char) ->
    IsStrippedBody (stripLineCommentBody cs)
stripBodyProducesStrippedShape [] = StripEmpty
stripBodyProducesStrippedShape (c :: rest) =
    -- We do a case-split on `c == nl`. The function definition uses
    -- `if c == nl then nl :: rest else sp :: stripLineCommentBody rest`,
    -- so we need to reflect that decision into the proof.
    case decEq c nl of
        Yes prf =>
            -- c == nl ⇒ output = nl :: rest. Build StripJustNl.
            rewrite prf in StripJustNl rest
        No _ =>
            -- c /= nl ⇒ output = sp :: stripLineCommentBody rest.
            -- Recurse to show the suffix is also a stripped body.
            StripSpaceCons (stripLineCommentBody rest)
                           (stripBodyProducesStrippedShape rest)

-- ═══════════════════════════════════════════════════════════════════════
-- Main theorem — line-comment stripping idempotence (PARTIAL)
-- ═══════════════════════════════════════════════════════════════════════

||| **Base case (empty input).** Both sides reduce to `[]`. Qed.
public export
stripLineCommentsIdempotentEmpty :
    stripLineComments (stripLineComments []) = stripLineComments []
stripLineCommentsIdempotentEmpty = Refl

||| **Non-comment-head case.** When the input does NOT start with
||| `'/' :: '/' :: _`, the outer `stripLineComments` peels the head
||| and recurses, so idempotence reduces to the inductive hypothesis
||| on the tail.
|||
||| The inductive call uses Idris2's totality checker: the recursive
||| `stripLineCommentsIdempotentTail` is structurally smaller (rest is
||| a proper tail of (c :: rest)).
public export
stripLineCommentsIdempotentNonCommentHead :
    (c : Char) -> (rest : List Char) ->
    -- Hypothesis on the tail.
    (stripLineComments (stripLineComments rest) = stripLineComments rest) ->
    -- The (c :: rest) head guards: c is NOT '/', OR rest does NOT start with '/'.
    -- For this slice we discharge the simpler `c is not '/'` case.
    Not (c = '/') ->
    stripLineComments (stripLineComments (c :: rest))
      = stripLineComments (c :: rest)
stripLineCommentsIdempotentNonCommentHead c rest ihTail cNotSlash =
    -- stripLineComments (c :: rest) reduces to (c :: stripLineComments rest)
    -- because the `'/' :: '/' :: _` pattern only matches when c IS '/'.
    -- Then strip on that = (c :: strip (strip rest)) = (c :: strip rest) by ihTail.
    -- The Idris2 case for the third clause requires no rewrite of
    -- `stripLineComments` because the head is consumed pattern-syntactically.
    rewrite ihTail in Refl

-- ═══════════════════════════════════════════════════════════════════════
-- Open obligation — slash-slash inductive case
-- ═══════════════════════════════════════════════════════════════════════

||| The general idempotence theorem requires closing the
||| `'/' :: '/' :: rest` case. Sketch:
|||
|||   strip ('/' :: '/' :: rest)
|||     = sp :: sp :: stripLineCommentBody rest
|||
||| Then `strip` applied to that = sp :: sp :: strip (stripLineCommentBody rest)
||| (since `sp` is not `/`).
|||
||| We need: strip (stripLineCommentBody rest) = stripLineCommentBody rest.
||| This is the **closure lemma**: applying `stripLineComments` to any
||| IsStrippedBody input is the identity. Statement:
|||
|||   stripIsIdentityOnStrippedBody :
|||       (xs : List Char) -> IsStrippedBody xs ->
|||       stripLineComments xs = xs
|||
||| The proof for StripEmpty is Refl. The StripJustNl case requires a
||| second induction on the trailing `tail` since strip recurses into
||| arbitrary content. The StripSpaceCons case unfolds strip on `sp`
||| and applies the inductive hypothesis.
|||
||| **This is the load-bearing open obligation for Layer 1.0 — recorded
||| in PROOF-NEEDS.md as the next slice of this module.**

-- ═══════════════════════════════════════════════════════════════════════
-- Sanity tests (concrete cases verified by Idris2's totality checker)
-- ═══════════════════════════════════════════════════════════════════════

||| Sanity check: stripping `"x"` (no comment) leaves it unchanged
||| through both passes.
private
sanityNonCommentSingleChar :
    stripLineComments (stripLineComments ['x'])
      = stripLineComments ['x']
sanityNonCommentSingleChar = Refl

||| Sanity check: stripping `"//"` followed by empty body — both
||| passes produce `[sp, sp]`.
private
sanityBareCommentMarker :
    stripLineComments (stripLineComments ['/', '/'])
      = stripLineComments ['/', '/']
sanityBareCommentMarker = Refl

||| Sanity check: stripping `"x//"` (a non-comment char followed by
||| a bare `//`) — both passes produce `[x, sp, sp]`.
private
sanityCharPlusCommentMarker :
    stripLineComments (stripLineComments ['x', '/', '/'])
      = stripLineComments ['x', '/', '/']
sanityCharPlusCommentMarker = Refl

-- ═══════════════════════════════════════════════════════════════════════
-- Future work (Layer 1.0 remaining slices)
-- ═══════════════════════════════════════════════════════════════════════

||| Module shipping plan:
||| * **Stripping.idr** (this file) — line comments, foundation +
|||   shape lemma + base cases of idempotence. Open obligation:
|||   stripIsIdentityOnStrippedBody (the slash-slash inductive case).
||| * **Stripping_Block.idr** (next slice) — `/* … */` pair-matching
|||   stripper with the same idempotence structure. Open obligation:
|||   nested-block-comment behaviour (Rust's `strip_proof_comments`
|||   does NOT recurse into nested blocks; we mirror that semantics).
||| * **Stripping_Strings.idr** (next slice) — `"…"` with escape
|||   handling. Reuses the body-shape lemma pattern.
||| * **Stripping_Composition.idr** — proves the full preprocessing
|||   pipeline (strings → block → line) is idempotent given each
|||   component is.
||| * **Stripping_PositionPreservation.idr** — proves that for every
|||   index `i` where `cs[i]` is OUTSIDE every comment/string region,
|||   `strip cs ! i = cs[i]`. Justifies the analyzer's location
|||   reporting against the stripped view.
|||
||| Once all five land, every Layer-1.1..1.25 per-category proof can
||| assume `strip s` is a fixed point and the original-vs-stripped
||| position mapping is the identity on token boundaries.
