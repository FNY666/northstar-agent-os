# Route Evidence Audit Export Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or **superpowers:executing-plans** to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only, sanitized NDJSON audit export for the Route Ledger research line that can be independently verified without exposing prompts, secrets, opaque context, or raw backend output.

**Architecture:** Export is a pure projection from immutable RouteJournal/Lineage records. Each exported line contains schema, sequence, event/decision digest, route/receipt identity, status, failure class, target/provider, and optional bounded numeric metrics. The exporter rejects sensitive keys recursively and emits a final manifest digest over canonical exported lines. It does not authorize, replay, or execute.

**Tech Stack:** Python 3.10+, standard library, JSONL/NDJSON, hashlib, unittest.

## Global Constraints

- Research worktree only; no public or local-only writes.
- No push, PR, merge, or cherry-pick.
- No real backend execution or credentials.
- Export is evidence/observability, not authorization or success proof.
- Sensitive fields fail closed, not silently redacted.

---

### Task 1: Sanitized projection RED tests

**Files:**
- Create: `components/northstar-agent-interop/audit_export.py`
- Create: `components/northstar-agent-interop/tests/test_audit_export.py`

**Interfaces:**
- `sanitize_event(value) -> dict[str, object]`
- `export_ndjson(events, path) -> AuditManifest`
- `AuditManifest.from_dict(value)`
- `verify_export(path, manifest) -> None`

- [ ] Write RED tests for allowed fields, prompt/secret/raw-output rejection, stable canonical line ordering, and manifest digest mismatch.
- [ ] Implement strict allowlist projection; unknown/sensitive fields raise `AuditExportError`.
- [ ] Write export with fsync and mode `0600`.

### Task 2: Lineage and receipt summary

**Files:**
- Modify: `components/northstar-agent-interop/audit_export.py`
- Create: `components/northstar-agent-interop/tests/test_audit_export_integration.py`

- [ ] Add projection tests for route selection, retry lineage, terminal receipt, replay verdict, failure class, policy revision, target/provider, sequence, event digest, and bounded numeric metrics.
- [ ] Ensure export does not include raw payload, context references that reveal contents, prompts, secrets, or backend output.
- [ ] Verify export manifest after restart and after a deliberately modified line.

### Task 3: Research boundary and regression

**Files:**
- Modify: `components/northstar-agent-interop/ROUTE_JOURNAL_REVIEW.md`

- [ ] Document export limitations and evidence-vs-authorization boundary.
- [ ] Run all Interop tests plus audit tests, compile, diff check, and sensitive scan.
- [ ] Commit only to research branch; do not push or contact other sessions during routine implementation.
