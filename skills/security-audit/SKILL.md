---
name: security-audit
description: Security guidance and vulnerability review for Northstar AgentOS — the permission gate, approval binding, audit chain, durable gateway, MCP surface, skills, and sessions. Use for security questions, focused reviews, or a full six-phase audit of the Northstar codebase.
---

# Security Audit (Northstar)

Find vulnerabilities that violate a real trust boundary in Northstar AgentOS,
then give owners the source evidence, safe reproduction, priority, and smallest
effective fix. This is a defensive, source-first workflow. A candidate without a
concrete affected principal, resource, or security outcome is not a confirmed
finding.

**Methodology provenance.** The six-phase method, the coverage-ledger shape,
and the three verdict schemas are absorbed from
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
(MIT, Copyright 2025–2026 Cloudflare, Inc.), verified against its actual
source (`SKILL.md`, `validate-coverage-ledger.cjs`, `report-schema.json`) and
rewritten for Northstar's governance context. This is not a Cloudflare product
and carries no Cloudflare endorsement.

## Operating modes

This skill is guidance by default. Loading it does not authorize the complete
audit workflow or file creation.

- **Guidance mode**: for security questions, focused reviews, methodology,
  triage, or investigation of specific findings, use only the relevant parts.
  Do not automatically run all six phases, create an output directory, or
  write audit artifacts.
- **Full audit mode**: run the complete workflow when explicitly asked to
  audit the Northstar codebase, or when asked for a full / comprehensive /
  end-to-end security review, or when report artifacts are requested. Run all
  six phases and write the files defined below.

If the request could mean either mode, ask one focused question before
creating files or starting the complete workflow.

## Northstar trust boundaries

Every candidate must name the crossed boundary from this map. The lower-trust
principal is on the left:

| # | Boundary | Lower-trust side → higher-trust side |
|---|----------|--------------------------------------|
| B1 | agent → permission gate | agent tool call → gate decision |
| B2 | gate → host callback | gate escalation → human/owner approval |
| B3 | tool → effect | tool invocation → real-world effect (fs, net, exec) |
| B4 | MCP server → client | remote tool definition → client trust |
| B5 | skill → loader | skill script/content → host process |
| B6 | session → lease holder | session actor → lease-protected state |
| B7 | provider → retry policy | provider response → retry/amplification decision |
| B8 | plugin → host | plugin bundle → runtime |
| B9 | audit writer → verifier | event emission → chained, anchored record |

A same-principal effect (the agent harming only its own scratch state) is not
a cross-boundary result.

## Coverage vocabulary

Coverage units are keyed `surface::boundary::subsystem::attack_class`
(`::lifecycle` appended when the same tuple is audited in distinct lifecycle
modes, e.g. `run` vs `replay`).

**Subsystems** (use the canonical module name):

`permission-gate`, `approval-binding`, `consent`, `budget`, `audit-chain`,
`audit-export`, `durable-gateway`, `mcp-client`, `mcp-config`, `plugin-load`,
`skill-scripts`, `session-lease`, `provider-retry`, `os-sandbox`, `seccomp`,
`checkpoints`, `memory`, `compaction`, `cli`.

**Attack classes** (Northstar-specific):

- `approval-replay` — a stale approval authorizing a new (call, arguments) pair
- `consent-bypass` — mutating effect without the required consent/ask
- `budget-bypass` — spend exceeding the enforced budget dimension
- `permission-escalation` — a lower tier reaching a higher-tier effect
- `audit-tampering` — rewriting, dropping, or forking the chained record
- `chain-fork` — two verifiable histories from one log
- `tool-result-injection` — tool output steering the next privileged call
- `mcp-server-impersonation` — untrusted server trusted as an authority
- `skill-script-escape` — skill content escaping its sandbox/review
- `session-hijack` — one session acting as another
- `lease-bypass` — concurrent mutation past the lease
- `checkpoint-rollback` — replaying stale state as current
- `supply-chain` — unreviewed code entering the trust boundary
- `secret-exfiltration` — credentials leaving their vault/scope
- `transient-amplifier` — retry policy multiplying a transient failure
- `denial-of-service` — unbounded resource use against a shared path

## Core principles

### Require a boundary and result

For every candidate, name the lower-trust principal, accepted input or
action, intended control, crossed boundary (B1–B9), affected principal or
resource, and concrete observed or owner-observable result. Do not elevate a
missing best practice, guessed deployment behavior, generic parser crash, or
self-impact into a security finding.

### Use bounded local evidence

Static analysis establishes the source path. Sandboxed local tests resolve
behavior: run the deterministic gate, replay a fixture against
`governance_bench.py`, verify an audit chain with `audit_cli.py`, or drive a
minimal harness. Stop at a wrong verdict, an unauthorized dummy record, a
chain-verify failure, or a policy difference — the minimum boundary result.
Do not extend the check beyond it, and do not produce persistence,
post-fault, or concealment material. Never test against a live provider,
shared session, production identity, or another user's data.

### Respect source visibility

Deployment controls not present in the repository (proxy policy, provider
settings, host OS hardening) are real controls. If they are required and
absent from source, do not assume presence or absence: use
`needs_validation` with the exact missing fact and a safe owner-observed
plan.

### Separate priority from certainty

Only `confirmed` records receive severity. `needs_validation` is a specific
source-grounded boundary hypothesis that is blocked — not a low-confidence
confirmed vulnerability — and it has no severity.

Severity anchors for Northstar:

- **critical** — an unauthenticated or lower-tier actor gains arbitrary tool
  execution, full audit-log rewrite, or takeover of another session's
  approvals.
- **high** — full defeat of an explicit control with real consequences:
  approval replay onto new arguments, cross-session read/write, stored
  tool-result injection reaching a privileged call, authenticated audit
  tampering, or unauthenticated stop of a shared gateway.
- **medium** — a real boundary violation with limited blast radius, uncommon
  preconditions, or consequences confined to a narrow resource set.
- **low** — disclosure of non-secret internals, or an effect requiring
  sustained effort for minimal gain.
- **informational** — a confirmed minimal-impact observation, useful mainly
  as a prerequisite inside a larger finding.

Overall severity cannot exceed demonstrated impact. If you cannot state the
concrete damage, the severity is lower than it feels.

### Recommend the smallest effective source fix

For each confirmed finding, identify the invariant the code must enforce and
the narrowest source change that enforces it at the last trusted decision
point — usually the gate verdict function, the approval-token check, the
chain-append path, or the lease acquisition. Prefer specific
repository-relative changes and regression tests over generic hardening
advice. The audit describes fixes; it does not modify target source.

## Full audit workflow

In full audit mode, follow all six phases in order:

1. **Reconnaissance** — map the source tree, trust boundaries (B1–B9),
   subsystem entry points, local build/test paths, and the initial
   deterministic coverage ledger. Record the source ref and whether the
   worktree is dirty; do not treat unreviewed generated files as another
   revision.
2. **Coverage-led hunting waves** — assign one hunter per ledger unit (one
   `surface::boundary::subsystem::attack_class` tuple). Hunters return
   structured candidates: fingerprint, boundary, trace, evidence. No
   prose-only results — prose cannot be deduplicated or verified.
3. **Candidate validation** — consolidate fingerprints; give every candidate
   to a fresh verifier that did not hunt it. The verifier re-derives the
   trace from source and either confirms, refutes, or blocks it.
4. **Structured output** — write final `confirmed`, `needs_validation`, and
   `rejected` records to `findings.json` per `verdict-schemas.json`; write
   the coverage claim to `coverage-ledger.json` per
   `coverage-ledger.template.json` and the state invariants below.
5. **Independent record verification** — fresh eyes re-check every final
   source claim (file, line, scope). Reconcile corrections or state changes
   before reporting.
6. **Target-neutral report** — derive `REPORT.md`, `FINDINGS-DETAIL.md`, and
   `NEEDS-VALIDATION.md` from the final records, with no live-probe
   instructions.

Do not end the run before one of exactly two terminal states: (a) all Phase
6 artifacts are written and the ledger/findings validate, or (b) the run is
recorded `incomplete` with its exact reason and the gap is disclosed in the
report. Never stop mid-phase.

## Coverage-ledger state invariants

Each unit carries `coverage_id` (the canonical
`surface::boundary::subsystem::attack_class` percent-encoded join),
`canonical_refs`, `surface`, `boundary`, `subsystem`, `attack_class`,
optional `lifecycle`, `starting_paths`, `prior_status`, `attempts`, `wave`,
`status`, `agent_id`, `reviewed_paths`, `local_checks`, `result_fingerprints`,
and `unresolved`. Units are sorted lexicographically by `coverage_id`;
`coverage_id` values are unique.

- `planned` — unassigned (`agent_id: null`), no evidence, no unresolved.
- `in_progress` — assigned, no evidence yet.
- `covered` — assigned, non-empty `reviewed_paths` + `local_checks`, no
  unresolved, no fingerprints.
- `candidate` — as `covered`, plus non-empty `result_fingerprints`.
- `blocked` — assigned, evidence so far, non-empty `unresolved`.
- `deferred` / `out_of_scope` / `not_applicable` — unassigned, non-empty
  `unresolved` stating the reason. A scoped or `quick` run must present
  itself as partial coverage — never label out-of-scope units `covered`.

Each `local_checks` entry names `agent_id`, `reviewed_paths`, the
`invariant` tested, `method` (`source` or `local`), the `result`, and the
evidence artifact. Every aggregate `reviewed_paths` entry must have a check
owner.

## Run profiles

- **`quick`** — a bounded pass: coarsen units to surface × boundary × attack
  class, one hunter wave, one final coverage-critic pass. The critic's
  accepted discoveries become `deferred`, never silent coverage.
- **`standard`** — the workflow as written.
- **`deep`** — split units per subsystem and lifecycle mode, run critic
  waves to a clean pass, keep candidate validation and final record
  verification as separate fresh agents.

A budget (max agent invocations) is recorded before reconnaissance. Reserve
reconnaissance, critics, and validation before hunting; if the budget cannot
fund the minimum, run nothing and record `incomplete` with the exact reason.

## Anti-patterns

1. Checklist deviations presented as vulnerabilities.
2. Defense-in-depth advice with no reachable boundary violation.
3. Live or shared-environment testing where bounded local evidence suffices.
4. Guessing deployment behavior not present in source.
5. Treating intended same-principal authority or self-impact as a
   cross-boundary result.
6. Reporting an effect stronger than the observed effect.
7. Emitting prose-only hunter results that cannot be deduplicated.
8. Assigning severity to `needs_validation` records.
9. Writing the report before independent verification, or letting prose and
   JSON disagree.
10. Claiming one run exhausts the target.

## Output files

Full audit mode writes, outside the target tree:

- `coverage-ledger.json` — the coverage claim (see
  `coverage-ledger.template.json`)
- `findings.json` — final verdicts (see `verdict-schemas.json`)
- `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md` — derived from
  the records above
