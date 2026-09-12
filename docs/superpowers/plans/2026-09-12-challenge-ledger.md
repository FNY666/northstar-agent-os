# Persistent Verifier-Scoped Challenge Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist one-time proof challenges, bind them to a verifier identity, and preserve replay refusal across process restarts without placing secrets in the ledger.

**Architecture:** `ChallengeLedger` stores an append-only, hash-chained JSONL event log. `issue` records a challenge with verifier audience, expiry, and optional key id; `consume` takes the same local lock, verifies the chain, checks audience/expiry/single-use state, and appends a consumed event. A separate v2 seal binds verifier identity into its HMAC domain; existing v1 sealed attestations remain untouched and remain verifiable through their existing API.

**Tech Stack:** Python 3.10+, standard library (`hashlib`, `hmac`, `json`, `fcntl`, `os`), existing `ProofAttestation`, `ProofSignatureError`, and `KeyRing` interfaces; `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only: no local-only writes, no main/integration-next/arena writes, no merge, no cherry-pick.
- Existing `attestation_freshness.py` v1 schema and signing domain remain unchanged.
- The ledger stores challenge metadata and digests only; no signing secret or raw attestation enters it.
- The verifier identity is an audience binding, not an authorization decision.
- A truncated final JSONL line is ignored; a complete malformed line makes the ledger `unverifiable`.
- `flock` provides same-host mutual exclusion only; no cross-host exactly-once claim.
- Missing/unknown/replayed/expired/audience-mismatched challenges fail closed.

---

### Task 1: Persistent challenge state and audience binding (RED first)

**Files:**
- Create: `components/northstar-agent-interop/challenge_ledger.py`
- Create: `components/northstar-agent-interop/tests/test_challenge_ledger.py`

**Interfaces:**
- `LedgerChallenge(challenge_id, verifier_id, issued_at, expires_at, key_id)`
- `ChallengeLedger(root, *, clock, ttl=300, nonce_source=None)`
- `issue(verifier_id, key_id=None) -> LedgerChallenge`
- `consume(challenge_id, verifier_id) -> LedgerChallenge`
- `verdict() -> LedgerVerdict`

- [x] Test issue/consume round-trip and verifier audience mismatch.
- [x] Test unknown, expired, repeated, and missing challenge paths.
- [x] Run the focused tests RED before implementation.

### Task 2: Restart, tamper, truncation, and concurrency semantics

**Files:**
- Modify: `components/northstar-agent-interop/challenge_ledger.py`
- Modify: `components/northstar-agent-interop/tests/test_challenge_ledger.py`

- [x] Reconstruct issued/consumed state after a new ledger instance opens the same root.
- [x] Persist consumed state so replay is refused after restart.
- [x] Ignore a truncated final line but reject a complete malformed line.
- [x] Detect record tampering, chain breaks, and missing history as `unverifiable`.
- [x] Use a same-host lock so concurrent consumption succeeds exactly once.

### Task 3: Verifier-bound v2 seals

**Files:**
- Modify: `components/northstar-agent-interop/challenge_ledger.py`
- Modify: `components/northstar-agent-interop/tests/test_challenge_ledger.py`

**Interfaces:**
- `VerifierBoundSeal.to_dict()/from_dict()`
- `seal_v2(attestation, challenge, *, key_id, secret) -> VerifierBoundSeal`
- `verify_v2(seal, attestation, *, expected_challenge_id, expected_verifier_id, key_resolver) -> ProofAttestation`

- [x] Bind challenge id, verifier id, attestation digest, and key id into the v2 signature domain.
- [x] Reject verifier substitution, challenge substitution, attestation tampering, unknown key, and malformed wire data.
- [x] Test that v1 APIs remain importable and unchanged.

### Task 4: Documentation, regression, and local commit

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-12-challenge-ledger.md`

- [x] Document persistence, audience binding, and same-host-only locking limits.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally; notify before pushing and wait for explicit acknowledgement.
