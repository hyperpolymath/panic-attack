-- SPDX-License-Identifier: MPL-2.0
-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Line-comment stripping idempotence (PROOF-PROGRAMME Layer 1.0)
|||
||| Mechanises the foundation lemma for every Layer-1 per-category
||| soundness proof: the analyzer's line-comment stripping pass is
||| **idempotent**, so running it twice gives the same output as running
||| it once. That justifies the preprocessing step at
||| `src/assail/analyzer.rs` `strip_proof_comments(without_strings, "//", …)`
||| as a normalising rewrite that every category detector can rely on
||| without re-stripping.
|||
||| The model strips ALL `//` comments: `stripLineCommentBody` hands back
||| to `stripLineComments` after each preserved newline (issue #113).
|||
||| Re-proved 2026-11-09. The previous proof (PR #111, issue #113) never
||| type-checked: its `//` case relied on reductions that do not hold for a
||| variable character, and it used `decEq` without importing it. The proof
||| below goes through two facts instead:
|||
|||   * `stripIsIdOnClean`: stripping is the identity on text with no `//`;
|||   * `stripIsClean` / `bodyIsClean`: the strippers' output has no `//`.
|||
||| Their composition is `stripLineCommentsIdempotent`. No `believe_me`,
||| `assert_total` or `postulate`; checked by Idris2 0.7.0 under
||| `%default total`.
module PanicAttack.ABI.Stripping

%default total

-- ═══════════════════════════════════════════════════════════════════════
-- Characters
-- ═══════════════════════════════════════════════════════════════════════

||| The space character used to overwrite stripped regions.
public export
sp : Char
sp = ' '

||| The newline preserved during stripping, so line numbers in the
||| stripped view match the original (the analyzer reports locations).
public export
nl : Char
nl = '\n'

||| Is this the comment-marker character `/`?
public export
isSlash : Char -> Bool
isSlash c = c == '/'

||| Is this the newline that ends a line comment?
public export
isNl : Char -> Bool
isNl c = c == nl

||| Does the list start with `/`?
public export
headIsSlash : List Char -> Bool
headIsSlash [] = False
headIsSlash (d :: _) = isSlash d

-- ═══════════════════════════════════════════════════════════════════════
-- Stripping functions (mirror strip_proof_comments for "//")
--
-- `stripLineComments` copies input until it meets `//`, which it replaces
-- with two spaces before handing the comment body to
-- `stripLineCommentBody`. That blanks every character up to the next
-- newline, keeps the newline, and hands the rest back. Each call works on
-- a strictly smaller suffix of the input.
-- ═══════════════════════════════════════════════════════════════════════

mutual
    ||| The line-comment stripper.
    public export
    stripLineComments : List Char -> List Char
    stripLineComments [] = []
    stripLineComments (c :: tl) = stripStep (isSlash c) (headIsSlash tl) c tl

    ||| One step on `c` followed by `tl`. The flags say whether `c`, and
    ||| the head of `tl`, are `/`: only both together start a comment.
    public export
    stripStep : Bool -> Bool -> Char -> List Char -> List Char
    stripStep True True _ (_ :: rest) = sp :: sp :: stripLineCommentBody rest
    stripStep _ _ c tl = c :: stripLineComments tl

    ||| The comment body, from just after `//` to the next newline.
    public export
    stripLineCommentBody : List Char -> List Char
    stripLineCommentBody [] = []
    stripLineCommentBody (c :: rest) = bodyStep (isNl c) rest

    ||| One step of the body: keep the newline and hand back, or blank.
    public export
    bodyStep : Bool -> List Char -> List Char
    bodyStep True rest = nl :: stripLineComments rest
    bodyStep False rest = sp :: stripLineCommentBody rest

-- ═══════════════════════════════════════════════════════════════════════
-- "No `//`": text the stripper leaves unchanged
-- ═══════════════════════════════════════════════════════════════════════

||| `NoDoubleSlash xs`: no `/` in `xs` is immediately followed by `/`.
public export
data NoDoubleSlash : List Char -> Type where
    NDSNil  : NoDoubleSlash []
    NDSCons : (isSlash c = True -> headIsSlash tl = False) ->
              NoDoubleSlash tl ->
              NoDoubleSlash (c :: tl)

spNeverSlash : isSlash Stripping.sp = True -> Void
spNeverSlash Refl impossible

nlNeverSlash : isSlash Stripping.nl = True -> Void
nlNeverSlash Refl impossible

-- ═══════════════════════════════════════════════════════════════════════
-- Fact 1: stripping is the identity on text with no `//`
-- ═══════════════════════════════════════════════════════════════════════

||| The step agrees with consing when no comment starts at `c`.
stepIsCons : (b1, b2 : Bool) -> (c : Char) -> (tl : List Char) ->
             (b1 = True -> b2 = False) ->
             stripLineComments tl = tl ->
             stripStep b1 b2 c tl = c :: tl
stepIsCons True True _ _ h _ = absurd (h Refl)
stepIsCons True False c tl _ ih = cong (c ::) ih
stepIsCons False _ c tl _ ih = cong (c ::) ih

public export
stripIsIdOnClean : (xs : List Char) -> NoDoubleSlash xs -> stripLineComments xs = xs
stripIsIdOnClean [] NDSNil = Refl
stripIsIdOnClean (c :: tl) (NDSCons h rest) =
    stepIsCons (isSlash c) (headIsSlash tl) c tl h (stripIsIdOnClean tl rest)

-- ═══════════════════════════════════════════════════════════════════════
-- Fact 2: the strippers' output has no `//`
-- ═══════════════════════════════════════════════════════════════════════

||| Stripping keeps a non-`/` head, so the output starts with no `/` either.
stripKeepsHead : (tl : List Char) -> headIsSlash tl = False ->
                 headIsSlash (stripLineComments tl) = False
stripKeepsHead [] _ = Refl
stripKeepsHead (d :: rest) pd = stepHead (isSlash d) (headIsSlash rest) d rest Refl pd
  where
    stepHead : (b1, b2 : Bool) -> (d : Char) -> (rest : List Char) ->
               isSlash d = b1 -> b1 = False ->
               headIsSlash (stripStep b1 b2 d rest) = False
    stepHead False _ d rest pd' _ = pd'
    stepHead True _ _ _ _ Refl impossible

mutual
    public export
    stripIsClean : (xs : List Char) -> NoDoubleSlash (stripLineComments xs)
    stripIsClean [] = NDSNil
    stripIsClean (c :: tl) =
        stepIsClean (isSlash c) (headIsSlash tl) c tl Refl Refl

    stepIsClean : (b1, b2 : Bool) -> (c : Char) -> (tl : List Char) ->
                  isSlash c = b1 -> headIsSlash tl = b2 ->
                  NoDoubleSlash (stripStep b1 b2 c tl)
    stepIsClean True True _ (_ :: rest) _ _ =
        NDSCons (\h => void (spNeverSlash h))
          (NDSCons (\h => void (spNeverSlash h)) (bodyIsClean rest))
    stepIsClean True True _ [] _ Refl impossible
    stepIsClean True False c tl _ ptl =
        NDSCons (\_ => stripKeepsHead tl ptl) (stripIsClean tl)
    stepIsClean False _ c tl pc _ =
        NDSCons (\h => absurd (trans (sym h) pc)) (stripIsClean tl)

    public export
    bodyIsClean : (xs : List Char) -> NoDoubleSlash (stripLineCommentBody xs)
    bodyIsClean [] = NDSNil
    bodyIsClean (c :: rest) = bodyStepIsClean (isNl c) rest

    bodyStepIsClean : (b : Bool) -> (rest : List Char) ->
                      NoDoubleSlash (bodyStep b rest)
    bodyStepIsClean True rest =
        NDSCons (\h => void (nlNeverSlash h)) (stripIsClean rest)
    bodyStepIsClean False rest =
        NDSCons (\h => void (spNeverSlash h)) (bodyIsClean rest)

-- ═══════════════════════════════════════════════════════════════════════
-- Idempotence
-- ═══════════════════════════════════════════════════════════════════════

||| **Main theorem.** Stripping twice equals stripping once.
public export
stripLineCommentsIdempotent : (cs : List Char) ->
    stripLineComments (stripLineComments cs) = stripLineComments cs
stripLineCommentsIdempotent cs = stripIsIdOnClean _ (stripIsClean cs)

||| **Body fixed point.** Stripping the comment body's output changes nothing.
public export
bodyIsFixedPoint : (cs : List Char) ->
    stripLineComments (stripLineCommentBody cs) = stripLineCommentBody cs
bodyIsFixedPoint cs = stripIsIdOnClean _ (bodyIsClean cs)

-- ═══════════════════════════════════════════════════════════════════════
-- Sanity tests (closed terms, checked by evaluation)
-- ═══════════════════════════════════════════════════════════════════════

private
sanityEmpty : stripLineComments (stripLineComments []) = stripLineComments []
sanityEmpty = Refl

private
sanityNonCommentSingleChar :
    stripLineComments (stripLineComments ['x']) = stripLineComments ['x']
sanityNonCommentSingleChar = Refl

private
sanityBareCommentMarker :
    stripLineComments (stripLineComments ['/', '/']) = stripLineComments ['/', '/']
sanityBareCommentMarker = Refl

private
sanityCharPlusCommentMarker :
    stripLineComments (stripLineComments ['x', '/', '/'])
      = stripLineComments ['x', '/', '/']
sanityCharPlusCommentMarker = Refl

||| `//x` strips to three spaces.
private
sanityCommentWithBody : stripLineComments ['/', '/', 'x'] = [' ', ' ', ' ']
sanityCommentWithBody = Refl

||| `//x\ny`: the newline and the code after it survive.
private
sanityCommentThenCode :
    stripLineComments ['/', '/', 'x', '\n', 'y'] = [' ', ' ', ' ', '\n', 'y']
sanityCommentThenCode = Refl

||| Two comments on different lines are both stripped (the case PR #111's
||| single-comment model got wrong).
private
sanityTwoComments :
    stripLineComments ['/', '/', 'a', '\n', '/', '/', 'b']
      = [' ', ' ', ' ', '\n', ' ', ' ', ' ']
sanityTwoComments = Refl

||| A lone `/` is code, not a comment, and is kept.
private
sanityLoneSlash : stripLineComments ['a', '/', 'b'] = ['a', '/', 'b']
sanityLoneSlash = Refl

||| `///` is a comment whose body starts with `/`.
private
sanityTripleSlash : stripLineComments ['/', '/', '/'] = [' ', ' ', ' ']
sanityTripleSlash = Refl

-- Future Layer-1.0 slices (PROOF-NEEDS, issue #114): block comments
-- (`/* … */`), string literals with escapes, the composition of the three
-- strippers, and position preservation (the stripped view has the same
-- length and newline positions as the source).
