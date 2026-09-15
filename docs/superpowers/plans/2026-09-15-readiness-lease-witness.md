# Readiness Lease Registry Witness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Snapshot a readiness-lease registry observation with its exact registry sequence and head digest, so later revocation or history drift is detectable before a caller reuses the observation.

**Architecture:** `LeaseRegistryWitness` binds lease digest, observed registry state, record sequence, registry head digest, injected observation time, and a domain-separated witness digest. `make_registry_witness` verifies the registry and captures one observation. `verify_registry_witness` rechecks the current registry, compares sequence/head/state, and returns `current`, `expired`, `revoked`, `stale`, or `unverifiable`. It never authorizes execution.

**Tech Stack:** Python 3.10+, standard library, existing `EvidenceReadinessLeaseRegistry`, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Registry witness is freshness/provenance metadata, not permission to execute.
- Observation time is injected ordering metadata, not trusted wall-clock proof.
- Any registry append, revoke, tamper, missing history, or head/sequence mismatch fails closed as stale/unverifiable.
- External witness digest is required for `current`; missing pin returns `current-unpinned`.
- No prompt, action, event body, secret, or provider output enters the witness.

---

### Task 1: Registry witness schema and snapshot (RED first)

**Files:**
- Create: `components/northstar-agent-interop/readiness_lease_witness.py`
- Create: `components/northstar-agent-interop/tests/test_readiness_lease_witness.py`

**Interfaces:**
- `LeaseRegistryWitness.to_dict()/from_dict()`
- `make_registry_witness(registry, lease_digest, *, now) -> LeaseRegistryWitness`
- `verify_registry_witness(witness, registry, *, now, expected_witness_digest=None) -> RegistryWitnessVerdict`

- [x] Test active/expired/revoked/unknown snapshots and deterministic wire form.
- [x] Test sequence/head digest capture and no raw sensitive fields.
- [x] Run focused tests RED before implementation.

### Task 2: Drift and revocation detection

**Files:**
- Modify: `components/northstar-agent-interop/readiness_lease_witness.py`
- Modify: `components/northstar-agent-interop/tests/test_readiness_lease_witness.py`

- [x] Detect a registry append after snapshot as `stale`.
- [x] Detect revoke after snapshot as `stale` or `revoked`, never current.
- [x] Detect tampered/reordered/missing registry history as `unverifiable`.
- [x] Preserve `execution_authorized=False` in every verdict.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-readiness-lease-witness.md`

- [x] Document registry head/sequence binding and freshness-vs-authorization boundary.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
