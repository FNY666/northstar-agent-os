# Evidence Resolution Agenda Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn a replayable plan evidence decision into a deterministic, non-executing agenda that says which claim needs collection, re-verification, or human conflict escalation.

**Architecture:** `EvidenceResolutionAgenda` consumes the embedded canonical `PlanEvidenceDecision` gate. It emits one item per blocked/unknown claim with a fixed disposition: `escalate-conflict`, `reacquire-evidence`, or `collect-evidence`. Items are canonically ordered by severity and claim digest; every item carries only claim digests, existing evidence state, and reason codes. The agenda is a decision-support artifact, never a command queue or authorization.

**Tech Stack:** Python 3.10+, standard library, existing plan evidence decision/readiness gate modules, `unittest`. No network and no new dependency.

## Global Constraints

- Research worktree only; no remote push, cross-session coordination, or shared-branch changes.
- No executable command, tool name, prompt, raw event, secret, provider output, or action payload enters an agenda.
- `escalate-conflict` never selects a witness winner; it requests external resolution.
- `execution_authorized` remains false for the agenda and every item.
- Agenda digest is integrity only; external agenda/decision pins are required for a fully pinned verification result.

---

### Task 1: Agenda derivation (RED first)

**Files:**
- Create: `components/northstar-agent-interop/evidence_resolution_agenda.py`
- Create: `components/northstar-agent-interop/tests/test_evidence_resolution_agenda.py`

**Interfaces:**
- `ResolutionItem(claim_digest, disposition, evidence_state, reasons)`
- `EvidenceResolutionAgenda.to_dict()/from_dict()`
- `make_resolution_agenda(decision) -> EvidenceResolutionAgenda`

- [x] Map conflict → escalate-conflict; insufficient/unverifiable → reacquire-evidence; unknown/missing → collect-evidence.
- [x] Preserve deterministic severity/claim ordering and decision provenance.
- [x] Reject ready plans, malformed decisions, and forbidden raw/executable fields.
- [x] Run focused tests RED before implementation.

### Task 2: Replay and boundary verification

**Files:**
- Modify: `components/northstar-agent-interop/evidence_resolution_agenda.py`
- Modify: `components/northstar-agent-interop/tests/test_evidence_resolution_agenda.py`

- [x] Replay an agenda from the exact decision and compare all fields.
- [x] Reject changed decision digest, item disposition, reason, evidence state, item order, or agenda digest.
- [x] Distinguish fully pinned `agenda-verified` from `agenda-verified-unpinned`.
- [x] Keep `execution_authorized=False` regardless of source decision state.

### Task 3: Documentation and local regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`
- Create: `docs/superpowers/plans/2026-09-15-evidence-resolution-agenda.md`

- [x] Document evidence completion versus execution, conflict escalation, and agenda scope limits.
- [x] Run focused tests, full Interop regression, `py_compile`, `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not notify other sessions or push.
