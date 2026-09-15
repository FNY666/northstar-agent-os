# Replayable Witness Pins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make a pinned preflight observation survive a process restart. The previous pin slice stored only the witness *digest*, but a witness digest binds its injected observation time, so a restarted process cannot rebuild a matching witness and the pinned comparison fails on the witness component.

**Architecture:** Pin records gain an optional `registry_witness` payload (schema v2) captured from the witness the preflight was evaluated against. The payload is validated on write and on read, must agree with the record's `registry_witness_digest`, and feeds `restore_witness`, which returns a replayable `LeaseRegistryWitness`. Re-verifying that restored witness against the live registry is what detects post-observation drift across restarts. Pins still never authorize execution.

**Tech Stack:** Python 3.10+, standard library, existing preflight/witness modules, `unittest`. No network, no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- A pin remains a retained observation, never permission: every resolution and verdict keeps `execution_authorized=False`.
- The witness payload must never be trusted as current. It records what was observed at a past instant; only re-verification against the live registry gives a present-tense verdict.
- A record whose witness payload disagrees with its witness digest, or a record with an older field set, must fail closed rather than parse leniently.
- Records still carry digests, identifiers, origin, the recorded time, and the witness observation only; no action, command, prompt, event body, secret, or provider output.

---

### Task 1: Witness payload in pin records (RED first)

**Files:**
- Modify: `components/northstar-agent-interop/evidence_preflight_pins.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_preflight_pins_replay.py`
- Modify: `components/northstar-agent-os-research-journal/components/northstar-agent-interop/tests/test_evidence_preflight_pins.py`

**Interfaces:**
- `PreflightPinStore.pin_preflight(plan_id, preflight, *, now, witness=None) -> PreflightPinRecord`
- `PinResolution.registry_witness`, `PinResolution.witness_replayable`
- `restore_witness(resolution) -> LeaseRegistryWitness`

- [x] Test pin with a witness payload → resolution is replayable and restores an identical witness digest.
- [x] Test pin without a payload → resolution is not replayable and `restore_witness` refuses.
- [x] Run focused tests RED before implementation.

### Task 2: Cross-restart reuse and fail-closed parsing

**Files:**
- Modify: `components/northstar-agent-interop/evidence_preflight_pins.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_preflight_pins_replay.py`

- [x] Test a witness whose digest disagrees with the preflight is refused at pin time.
- [x] Test cross-restart reuse: pin, discard the in-memory witness, resolve, restore, and reach `preflight-ready` with the resolved pins.
- [x] Test cross-restart drift: a registry append after the pin makes the restored witness `stale`, and a revocation makes it `revoked`.
- [x] Test a tampered payload and an older field set are `pins-unverifiable`.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-replayable-witness-pins.md`

- [x] Document that a digest-only pin is not reusable across restarts for the witness component, and that a restored witness is a past observation.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
