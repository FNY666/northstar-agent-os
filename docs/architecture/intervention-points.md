# Intervention-Point Manifest

**Status:** reference (documents current enforcement architecture; not a change proposal)
**Reference frame:** Microsoft Agent Governance Toolkit, Agent Control Service (ACS) 8 canonical
intervention points (AGT-5 status, validated 2026-08-15).
**Scope note:** Northstar is a permission gate, not a model wrapper. The model is outside the
enforcement boundary by design — points that only make sense inside a model harness are marked
**out-of-scope**, not **gap**. An undocumented gap is worse than a declared one, so the `input`
gap is named explicitly below.

## Status key

| Status | Meaning |
|---|---|
| **exists** | Implemented and enforced in code. |
| **partial** | Implemented for a subset of the point's responsibility; remainder is a known limitation. |
| **gap** | No enforcement today; declared as roadmap or accepted risk. |
| **out-of-scope** | Deliberately not covered; follows from the gate-not-wrapper architecture. |

## Point-by-point mapping

### 1. `agent_startup` — **exists**

Fires when the agent instance initializes: credential rotation, config validation, overdue attestations.

Northstar equivalent: `run_setup.py` + `policy_file.py` + `agent_readiness.py` in
`components/northstar-agent-runtime/` — config pinning, policy load, baseline integrity checks.
Status is "exists" for the checks that are present; it is not documented elsewhere as a hook,
which is why this manifest exists.

### 2. `agent_shutdown` — **exists**

Fires when the agent instance terminates: graceful drain, evidence rollup.

Northstar equivalent: scope close — the authority ceiling is cleared and history is snapshotted
into the audit chain. No separate shutdown policy language; teardown is deterministic, not
policy-driven.

### 3. `input` — **gap**

Fires before the agent processes user input: prompt-injection scan, intent-based authorization.

Northstar has no input-side prompt-injection gate today. Injection-adjacent defenses exist at
probe level (`claimed_auth_corpus.py`, indirect-injection probes) and at the tool-result level
(composition rules, dataflow), but there is no `input`-stage gate that scans prompts before the
model sees them. This is a declared gap: a gate that cannot see the model's internals should not
pretend to secure the prompt itself. Mitigations live elsewhere: the gate enforces what the agent
*does*, not what it *reads*. (Reference: the "detection is not a security boundary" consensus —
an input scanner would be a detector, not a boundary.)

### 4. `output` — **partial**

Fires before the agent's response reaches the user: output sanitization, DLP.

Northstar covers the highest-risk output path: external sends are gated by the egress enforcer
(`components/northstar-egress-sidecar/egress_enforcer.py`), with allowlist, SSRF checks, and DNS
exfiltration suspicion detection. There is no general output-sanitization gate for text returned
to the user. Residual risk is accepted: a text answer cannot exfiltrate through a channel the
egress enforcer does not permit.

### 5. `pre_model_call` — **out-of-scope**

Fires before the LLM is invoked: token limits, content scanning, rate limits.

Out of scope by design. Northstar wraps tool execution, not model invocation. Token budgets and
model-call rate limits belong to the harness/operator layer, not the permission gate.

### 6. `post_model_call` — **out-of-scope**

Fires after the LLM responds: response validation, injection in tool-use proposals.

Out of scope by design, for the same reason as `pre_model_call`. What the model *proposes* is
handled at `pre_tool_call` (point 7), which is the actual enforcement point: a malicious
tool-use proposal that never executes a tool has no effect to govern.

### 7. `pre_tool_call` — **exists**

Fires before a tool executes: the primary authorization point — identity, policy, approval.

Northstar equivalent: `PermissionEngine.evaluate()` in
`components/northstar-agent-runtime/permissions.py`. Enforcement layers, in evaluation order:

- disallowed/allowed tool lists (canonical name matching)
- argument-level policies (`ArgumentPolicy`)
- composition rules (forbidden sequences over per-session history)
- per-scope authority ceiling (gated ascent via host callback, never persists)
- offensive-tooling deny-by-default
- Rule-of-Two escalation (3 legs → host-tier)
- approval receipts with `call_id` / arguments-digest binding
- deny-monotonicity baseline (`deny_monotonicity.py`) guarding against silent loosening

This is the primary, well-covered enforcement point. Verdicts are allow / deny / host-tier
escalate — deterministic, never model-judged.

### 8. `post_tool_call` — **partial**

Fires after a tool returns, before the agent uses the result: DLP/PII scan, result validation,
drift detection.

Northstar has the behavioral half: `post_dispatch_monitor.py` watches for error-rate spikes,
oscillation, and quota leaks and can trigger HALT; every execution is appended to the audit
chain. The content half — a deterministic scan of tool results (PII/credential patterns) before
they re-enter model context — is not implemented. Roadmap: deterministic regex only, never an
LLM judge on the same input (the "detection is not a security boundary" trap).

## Summary

| ACS point | Status | One-line justification |
|---|---|---|
| `agent_startup` | exists | run_setup + policy_file + agent_readiness |
| `agent_shutdown` | exists | scope close clears ceiling, snapshots history |
| `input` | **gap** | no input-side injection gate; gate governs actions, not prompts |
| `output` | partial | egress enforcer covers external sends; no general sanitizer |
| `pre_model_call` | out-of-scope | gate, not model wrapper |
| `post_model_call` | out-of-scope | proposals are governed at `pre_tool_call` |
| `pre_tool_call` | exists | `PermissionEngine.evaluate()` — primary enforcement point |
| `post_tool_call` | partial | behavioral monitor + audit chain; no deterministic content scan yet |

## Design rules this manifest encodes

1. **Authorization is decoupled from the model.** The agent proposes; the deterministic gate
   disposes. Even a fully jailbroken model cannot bypass `pre_tool_call`.
2. **Evaluation errors fail closed.** A point that cannot evaluate denies, never allows.
3. **Escalation without an approval resolver fails closed.** Host-tier is a question, not a hole.
4. **Telemetry and audit never carry raw secrets.** Events reference decisions and digests, not
   prompts, arguments, or results.
5. **A declared gap beats an undocumented one.** `input` and the content half of `post_tool_call`
   are named above so auditors and buyers can price the residual risk honestly.

## Related documents

- `docs/concepts/threat-model.md` — adversary model and trust boundaries
- `docs/concepts/governance.md` — governance bench and metrics (ORR, SSR, deny-monotonicity)
- `~/workspace/goals/northstar-agentos-development/hidden_files/dns-egress-threat-model-20261006.md` —
  DNS egress threat model (working note, not committed)
- `~/workspace/research_notes/intervention-points-20261006/report.md` — research backing
  (working note, not committed)
