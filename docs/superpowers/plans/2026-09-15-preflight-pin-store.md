# Preflight Pin Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax.

**Goal:** Close the documented preflight gap that an unpinned comparison is meaningless across runs, by retaining the five external digests as a durable, tamper-evident, same-host anchor that later runs can compare against — without turning a pin into permission.

**Architecture:** `PreflightPinStore` keeps a canonical hash-chained JSONL of pin records (fsync + same-host `flock`). `pin_preflight` records the digests of an `EvidenceReadinessPreflight` whose underlying decision, lease, and registry witness are all current (states `preflight-ready` or `preflight-unpinned`), labelling `first-use` versus `verified`. `resolve` returns the newest pin for a plan plus the global chain head/sequence; `verify_pin_resolution` detects drift against a remembered head. Missing history, tampering, or a truncated tail fails closed.

**Tech Stack:** Python 3.10+, standard library, existing preflight module, `unittest`. No network, no new dependency.

## Global Constraints

- Research worktree only; no local-only, main, integration-next, arena, runtime, merge, cherry-pick, or remote push changes.
- Pins are retained observations, not authorization: every resolution and verdict keeps `execution_authorized=False`.
- The first pin for a plan is trust-on-first-use and must be labelled `first-use`; only a pin taken while state was `preflight-ready` may be labelled `verified`.
- Pinning is refused for preflight artifacts whose lease or registry state is not current.
- Records carry digests, identifiers, origin, and the recorded time only; no action, command, prompt, event body, secret, or provider output.

---

### Task 1: Pin storage and resolution (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_preflight_pins.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_preflight_pins.py`

**Interfaces:**
- `PreflightPinStore(path).pin_preflight(plan_id, preflight, *, now) -> PreflightPinRecord`
- `PreflightPinStore(path).resolve(plan_id) -> PinResolution`
- `verify_pin_resolution(resolution, store, *, expected_chain_head_digest, expected_chain_sequence) -> PinVerdict`

- [x] Test pin then resolve on a fresh store instance → `pins-current` with matching digests.
- [x] Test unknown plan → `pins-unrecorded`; non-current preflight → refused.
- [x] Run focused tests RED before implementation.

### Task 2: Drift, tamper, and fail-closed semantics

**Files:**
- Modify: `components/northstar-agent-interop/evidence_preflight_pins.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_preflight_pins.py`

- [x] Test repinning after a changed decision appends a new record and makes a remembered head `pins-stale`.
- [x] Test tampered record, truncated tail, and lost history → `pins-unverifiable`.
- [x] Test end-to-end: unpinned first run is pinned as `first-use`, and a later run resolving those pins reaches `preflight-ready`.
- [x] Test every resolution/verdict keeps `execution_authorized=False` and records carry no raw content.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-preflight-pin-store.md`

- [x] Document trust-on-first-use, drift detection, and pin-versus-permission boundaries.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
