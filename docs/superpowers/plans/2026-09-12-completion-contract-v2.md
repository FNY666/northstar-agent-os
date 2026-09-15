# Completion Contract v2 Implementation Plan

> **For agentic workers:** Use TDD and execute this plan inline with verification checkpoints.

**Goal:** Build a test-only completion evaluator that rejects semantic-negation artifacts, detects unapproved workspace mutations, enforces optional milestone order, and fails closed on missing provenance.

**Architecture:** The evaluator is a standalone module and is not wired into production `TaskOutcome.ok`. It receives host-owned expectations, an independent before/after workspace snapshot, observed milestone IDs, and a provenance envelope. It returns one of `verified`, `failed`, `unknown`, or `insufficient_information`; no model claim or tool receipt is trusted.

**Files:**
- Create `components/northstar-durable-run/completion_contract_v2.py`
- Create `components/northstar-durable-run/tests/test_completion_contract_v2.py`
- Create `components/northstar-durable-run/completion_replay.py`
- Create `components/northstar-durable-run/tests/test_completion_replay.py`
- Modify `components/northstar-durable-run/README.md` only after tests pass
- Modify `.github/workflows/test.yml` only to include compile coverage

**Boundaries:**
- Work only in local-only.
- Do not modify production completion behavior in this slice.
- Use standard library only.
- Keep provenance and evaluator revision explicit.
- Detect extra file additions/changes/deletions outside the allowed mutation set.
- Treat missing required evidence as `insufficient_information`, not success.

**Execution checklist:**
- [x] Write tests first and confirm RED on the missing module.
- [x] Implement exact digest, structured semantic, mutation, milestone, and provenance checks.
- [x] Verify correct artifacts and reject semantic-negation/collateral cases.
- [x] Run complete local regression, compile, diff, and credential checks.
- [x] Commit local-only changes and refresh/verify the shared bundle.

**Result:** Test-only evaluator committed as `completion_contract_v2.py`; it is
not wired into production `TaskOutcome.ok` until a later contract-admission
review.