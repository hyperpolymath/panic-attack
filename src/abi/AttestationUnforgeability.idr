-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) 2026 Jonathan D.A. Jewell (hyperpolymath) <j.d.a.jewell@open.ac.uk>

||| Attestation-chain unforgeability (PROOF-PROGRAMME §3.2).
|||
||| Mirrors `src/attestation/{intent,evidence,seal}.rs`. The seal binds the
||| three attestation phases via
|||
|||     chain_hash = H(intent_hash || evidence_hash || report_hash)
|||
||| and optionally signs that chain hash with Ed25519.
|||
||| The cryptographic facts the seal relies on are taken as explicit
||| HYPOTHESES — a `parameters` block, NOT `postulate` (panic-attack's own
||| ProofDrift detector, PA021, bans `postulate` / `believe_me` / `Admitted`).
||| This therefore proves a *conditional* theorem: GIVEN the standard
||| cryptographic assumptions, the chain is unforgeable. The assumptions are:
|||
|||   * `chainCR`         — collision resistance of the chain hash, in the
|||                         idealised injective form (distinct phase triples
|||                         hash apart). Matches the SHA-256 `chain_hash`.
|||   * `sigCorrect`      — a genuine Ed25519 signature verifies.
|||   * `sigBindsMessage` — EUF-CMA (message-binding facet): a signature made
|||                         over `d` only verifies against `d`.
|||   * `sigOnlySigner`   — EUF-CMA (signer-binding facet): a verifying
|||                         signature comes from the matching secret key.
|||
||| From these — with no further assumptions, every lemma `Qed`-closes — we
||| derive the three properties of PROOF-PROGRAMME §3.2:
|||
|||   1. `integrity`      — tampering with any phase invalidates the seal.
|||   2. `authenticity`   — a verifying seal comes from the matching key.
|||   3. `nonRepudiation` — a genuine seal is publicly verifiable.
module PanicAttack.ABI.AttestationUnforgeability

%default total

-- ═══════════════════════════════════════════════════════════════════════
-- Abstract chain + signature model, with the cryptographic assumptions as
-- module parameters (hypotheses, not postulates).
-- ═══════════════════════════════════════════════════════════════════════

parameters
  (Bytes, Digest, SecretKey, PublicKey, Sig : Type)
  (chainHash : Bytes -> Bytes -> Bytes -> Digest)
  (pubKey    : SecretKey -> PublicKey)
  (sign      : SecretKey -> Digest -> Sig)
  (verify    : PublicKey -> Digest -> Sig -> Bool)
  (chainCR         : (i, e, r, i', e', r' : Bytes) ->
                     chainHash i e r = chainHash i' e' r' ->
                     ((i, e, r) = (i', e', r')))
  (sigCorrect      : (sk : SecretKey) -> (d : Digest) ->
                     verify (pubKey sk) d (sign sk d) = True)
  (sigBindsMessage : (sk : SecretKey) -> (d, d' : Digest) ->
                     verify (pubKey sk) d' (sign sk d) = True -> d = d')
  (sigOnlySigner   : (pk : PublicKey) -> (d : Digest) -> (s : Sig) ->
                     verify pk d s = True ->
                     (sk : SecretKey ** (pk = pubKey sk, s = sign sk d)))

  ||| The seal over the three phases: sign the chain hash.
  seal : SecretKey -> Bytes -> Bytes -> Bytes -> Sig
  seal sk i e r = sign sk (chainHash i e r)

  ||| Public validity check (anyone with the public key can run it).
  valid : PublicKey -> Bytes -> Bytes -> Bytes -> Sig -> Bool
  valid pk i e r s = verify pk (chainHash i e r) s

  -- ─────────────────────────────────────────────────────────────────────
  -- 1. INTEGRITY: tampering with any phase invalidates the seal.
  -- ─────────────────────────────────────────────────────────────────────

  ||| If the phase triple is tampered (differs from the sealed one), a seal
  ||| produced over the original phases fails to verify against the tampered
  ||| ones. Proof: were it to verify, message-binding would force the chain
  ||| hashes equal and collision-resistance the triples equal — contradiction.
  integrity : (sk : SecretKey) ->
              (i, e, r, i', e', r' : Bytes) ->
              Not ((i, e, r) = (i', e', r')) ->
              verify (pubKey sk) (chainHash i' e' r') (sign sk (chainHash i e r)) = False
  integrity sk i e r i' e' r' neq
      with (verify (pubKey sk) (chainHash i' e' r') (sign sk (chainHash i e r))) proof prf
    integrity sk i e r i' e' r' neq | True =
      absurd (neq (chainCR i e r i' e' r'
                     (sigBindsMessage sk (chainHash i e r) (chainHash i' e' r') prf)))
    integrity sk i e r i' e' r' neq | False = Refl

  -- ─────────────────────────────────────────────────────────────────────
  -- 2. AUTHENTICITY: a verifying seal comes from the matching secret key.
  -- ─────────────────────────────────────────────────────────────────────

  ||| A seal that verifies under `pk` must have been produced by the holder
  ||| of the secret key whose public key is `pk`, signing exactly this
  ||| chain hash. Direct from the signer-binding facet of EUF-CMA.
  authenticity : (pk : PublicKey) -> (i, e, r : Bytes) -> (s : Sig) ->
                 verify pk (chainHash i e r) s = True ->
                 (sk : SecretKey ** (pk = pubKey sk, s = sign sk (chainHash i e r)))
  authenticity pk i e r s ok = sigOnlySigner pk (chainHash i e r) s ok

  -- ─────────────────────────────────────────────────────────────────────
  -- 3. NON-REPUDIATION: a genuine seal is publicly verifiable.
  -- ─────────────────────────────────────────────────────────────────────

  ||| A seal produced by `sk` over `(i, e, r)` always verifies under the
  ||| corresponding public key, so the signer cannot deny a seal that checks
  ||| out — verification is a deterministic public function. (= correctness.)
  nonRepudiation : (sk : SecretKey) -> (i, e, r : Bytes) ->
                   verify (pubKey sk) (chainHash i e r) (sign sk (chainHash i e r)) = True
  nonRepudiation sk i e r = sigCorrect sk (chainHash i e r)

  -- ─────────────────────────────────────────────────────────────────────
  -- Corollaries (sanity).
  -- ─────────────────────────────────────────────────────────────────────

  ||| The seal/valid wrappers agree with the underlying signature ops: a
  ||| freshly produced seal is `valid`. Ties the readable API to property 3.
  sealValid : (sk : SecretKey) -> (i, e, r : Bytes) ->
              valid (pubKey sk) i e r (seal sk i e r) = True
  sealValid sk i e r = sigCorrect sk (chainHash i e r)

  ||| Two phase triples that share a verifying seal under one key are equal
  ||| (no two distinct attestations collide under the same seal).
  sealNoCollision : (sk : SecretKey) -> (i, e, r, i', e', r' : Bytes) ->
                    verify (pubKey sk) (chainHash i e r) (sign sk (chainHash i e r)) = True ->
                    verify (pubKey sk) (chainHash i' e' r') (sign sk (chainHash i e r)) = True ->
                    ((i, e, r) = (i', e', r'))
  sealNoCollision sk i e r i' e' r' _ tampered =
    chainCR i e r i' e' r'
      (sigBindsMessage sk (chainHash i e r) (chainHash i' e' r') tampered)
