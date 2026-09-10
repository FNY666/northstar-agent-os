# Plan: signing-key lifecycle for proof attestations

For agentic workers: this plan is executed in the independent
`research-route-journal` worktree. Required sub-skills are applied per task.

## Goal

Make a signed proof attestation answerable to the question "was this key
trusted when it signed, and who says so" — without introducing a PKI, a
certificate chain, a network call, or a stored signing secret.

## Architecture

Two layers, deliberately separated:

- `KeyHistory` — append-only, hash-chained, on disk, digest-only. It records
  `introduced` / `rotated` / `revoked` actions and never stores key material.
- `KeyRing` — in memory only. It binds material to a history that already
  declares the key, and it hands `proof_signing` a resolver.

## Tech Stack

Python 3 stdlib only: `hashlib`, `json`, `os`, `pathlib`, `dataclasses`.
No new dependency. No network. No key material on disk.

## Global Constraints

- Research worktree only: no public checkout writes, no push, no PR, no merge,
  no cherry-pick.
- The trust anchor is an externally supplied record digest. A history that does
  not begin at the pinned anchor is `untrusted-anchor`, never `trusted`.
- A verdict must be derived from a chain that verified. If the chain does not
  verify, every key in it is `unverifiable`.
- `revoke` is retrospective refusal, not retroactive invalidation. Judging a
  past signature requires a caller-supplied as-of revision, which this slice
  deliberately does not model.
- Key material never reaches the history file; only its digest does.

## Tasks

- [x] Task 1: `introduce` / `rotate` / `revoke` append hash-chained records and
  reject duplicate or unknown key ids.
- [x] Task 2: derive per-key state — `trusted`, `trusted-retired`, `revoked`,
  `unknown-key` — from the record chain.
- [x] Task 3: `verify_chain` recomputes every record digest, checks revision
  continuity, and binds the first record to the pinned anchor.
- [x] Task 4: `KeyRing.register` refuses undeclared keys and mismatched
  material; `resolver` refuses revoked, unknown, and unprovable keys.
- [x] Task 5: end-to-end with `proof_signing` — a revoked key cannot verify an
  otherwise valid attestation.

## Boundaries

What this does not prove: that the host that wrote the history is honest; that
revocation happened at a wall-clock time; that a retired key was never used
after retirement; that the material was not read out of process memory; that
two hosts agree on the same anchor.
