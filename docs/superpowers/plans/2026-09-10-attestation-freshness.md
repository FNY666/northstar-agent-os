# Plan: attestation freshness and replay defence

Research worktree only. No push, no merge, no cherry-pick.

## Goal

A signed proof attestation is currently replayable: its signature covers the
attestation content and nothing else, so a valid seal stays valid forever. Make
the seal depend on a single-use challenge, so a verifier can tell a fresh proof
from a replayed one without trusting a clock.

## Architecture

- `ChallengeBook` issues single-use, expiring challenges from an injected clock
  and nonce source. It is the only place that knows which challenges exist.
- `seal_attestation` binds the signature domain to the challenge id, the
  attestation digest, and the key id. Time does not enter the signature.
- `verify_sealed_attestation` requires the caller to state which challenge it
  expects. A seal made against an older challenge fails on the id, not on a
  clock comparison.

## Constraints

- The clock is host-owned and injected; this slice never reads the wall clock.
- `FreshnessError` subclasses `ProofSignatureError`, so callers that only know
  the signing error type keep working.
- Key identity and revocation are delegated to `key_lifecycle`, not re-decided
  here.

## Tasks

- [x] Task 1: single-use, expiring challenges with an injectable clock.
- [x] Task 2: seal binds challenge id + attestation digest + key id.
- [x] Task 3: verification refuses a mismatched challenge, a mismatched key, and
  an unavailable or revoked key.
- [x] Task 4: end-to-end replay refusal with `proof_signing` and `key_lifecycle`.

## Boundaries

Not proven: that the clock is honest; that the verifier stored the challenge it
issued; that a challenge reached the right party; that the first party to see a
challenge was the intended one. Freshness here is a binding property, not a
freshness measurement.
