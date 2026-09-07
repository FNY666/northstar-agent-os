# Active Lineage Semantic Verifier Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace last-event-based lineage verification with an active-attempt semantic verifier that handles retries, replay, supersession, and conflicting branches fail-closed.

**Architecture:** Build a pure verifier over the immutable LineageGraph. It derives root-to-leaf chains, identifies superseded branches, requires legal retry ancestry, rejects multiple active terminal branches, and only returns `verified` for one consistent succeeded terminal attempt whose route/Handoff/receipt identities and digests match. It never mutates the graph or executes a backend.

**Tech Stack:** Python 3.10+, standard library, dataclasses, unittest.

## Global Constraints

- Research worktree only: `/var/minis/workspace/northstar-agent-os-research-journal`.
- No public checkout or local-only Router writes.
- No push, PR, merge, or cherry-pick.
- No real backend execution or credentials.
- `unknown` is safer than guessed success.

---

### Task 1: Active branch RED tests

**Files:**
- Modify: `components/northstar-agent-interop/tests/test_route_lineage_integration.py`
- Create: `components/northstar-agent-interop/tests/test_lineage_semantics.py`

- [ ] Add tests for a simple successful chain, a failed retry superseding its parent, replay-only evidence, two active terminal branches, a terminal event with mismatched receipt identity, and an orphan event.
- [ ] Run focused tests and observe RED because current verifier uses `events[-1]`.

### Task 2: Pure active-attempt derivation

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`

**Interfaces:**
- `active_attempts(graph, route_id) -> tuple[tuple[RouteLineageEvent, ...], ...]`
- `select_active_terminal(graph, route_id) -> RouteLineageEvent | None`

- [ ] Implement root-to-leaf traversal with bounded depth and cycle detection.
- [ ] Remove branches superseded by a valid child attempt.
- [ ] Treat replay events as evidence about an existing event, not a new execution branch.
- [ ] Return no terminal when branches conflict or evidence is incomplete.

### Task 3: Semantic verification

**Files:**
- Modify: `components/northstar-agent-interop/route_lineage.py`
- Modify: `components/northstar-agent-interop/tests/test_route_lineage_integration.py`

- [ ] Make `verify_lineage()` use active terminal selection.
- [ ] Require terminal receipt ID, route ID, target identity, provider, payload digest, decision fingerprint, deadline, and capabilities to match the trusted route/Handoff evidence.
- [ ] Return `failed` for one active failed terminal, `verified` for one active succeeded terminal, and `unknown` for missing/conflicting/ambiguous active evidence.

### Task 4: Regression and research boundary

- [ ] Run all Interop tests, compile, diff check, sensitive scan.
- [ ] Document that this verifier is evidence validation, not authorization or backend execution proof.
- [ ] Commit only on the research branch and do not send routine progress to other sessions.
