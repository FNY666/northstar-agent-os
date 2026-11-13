# Long-horizon loop harness: Manager rebuild, fresh-context executor, auditor-verified progress

Status: implemented for B173 slice "horizon". The runtime had the *parts* of a
long-horizon loop — a blind re-runner, an independent audit-head holder,
resumable session checkpoints, a fresh-start head pin — but not the loop that
binds them. A multi-step task's "progress" was whatever the executor said. This
module adds the loop: a **Manager** that rebuilds the round state from trusted
inputs only, an **Executor** that performs one bounded step on a fresh context,
and an **Auditor** that verifies the real artifacts and is the only path by
which anything becomes trusted state.

Module: `components/northstar-agent-runtime/long_horizon.py`
Schema pin: `northstar.long-horizon.v1` — module version pin: `long-horizon.v1`

## The three roles and their boundaries

| Role | Reads | Writes | Never does |
| --- | --- | --- | --- |
| **Manager** | the original objective, the auditor-verified progress, the failure evidence | a structured `RoundState` (round index, objective, verified progress, failures, context, context digest) | read an executor's claim; write prose; decide that a step is done |
| **Executor** | the rebuilt round context | one `StepOutcome` — exactly one of `pending_audit` / `failed` / `aborted` | see the previous round's transcript or its unverified summary; declare success; choose the checks that judge it |
| **Auditor** | the files on disk, the host-declared checks | one `AuditVerdict` (pass/fail + evidence pointers) | read the executor's claim text; take checks from the executor; let a rejection become progress |

### The Manager's rebuild rule

The rebuild has exactly three inputs, and they are exactly the three inputs the
LongHorizon-Harness loop describes: the original goal, the *verified* progress,
and the failure evidence.

The rule is enforced structurally, not by convention: `ManagerBackend.rebuild`
has no parameter through which a claim could arrive, and the rebuilt context
lists only verified progress and failure evidence. The executor's summary is
therefore not "filtered out" of the rebuild — it was never an input to it.

The rebuilt state is structured (`RoundState` and its `as_dict()`), not prose.
Its `context_digest` is a SHA-256 over `(objective, verified progress, failure
evidence)` — the three trusted inputs — so two rebuilds from the same trusted
state are identical, and a rebuild from a different one is visibly different.

### The Executor's bounded step

A step is bounded three ways:

* **Bounded tool calls.** The plan may not return more commands than
  `max_tool_calls`. Exceeding it is an `aborted` step with evidence.
* **Bounded output.** The step's combined output may not exceed
  `max_output_chars`. Exceeding it is an `aborted` step with evidence.
* **Fresh context.** The step runs on the Manager's rebuilt context and nothing
  else. The context is rebuilt from scratch every round, so nothing unverified
  from a previous round rides along.

A step ends in exactly one of three ways:

| Outcome | Meaning | Effect on state |
| --- | --- | --- |
| `pending_audit` | the step ran; its artifacts await verification | handed to the Auditor |
| `failed` | the step's command failed | becomes failure evidence for the next round |
| `aborted` | a budget was exceeded | becomes failure evidence for the next round |

There is no fourth "probably succeeded". In particular a non-zero exit is a
failure, not a pending step, and an over-budget step is an abort, not a
truncated success.

### The Auditor's independence

The Auditor's `audit()` signature takes the rebuilt state, the *paths* the
host declared as artifacts, and the host-declared checks. It takes no
`step`, no `summary`, and no `claim`: there is no parameter through which the
executor's narration could reach the verdict. That is a stronger guarantee than
"we do not use it", because the claim cannot be passed in the first place.

The Auditor reads real artifacts:

* a declared artifact must exist on disk, be a regular file inside the
  workspace, and be non-empty;
* a declared check is run by the Auditor itself, in the workspace, and its
  exit status decides the check.

The verdict is pass/fail plus **evidence pointers** — which file, which command,
what was observed — and the pointers are what carry into the failure evidence
and into the verified progress.

The role backends are configurable and their identities are enforced:
`LongHorizonLoop` refuses to start when the manager, executor, and auditor
share a backend identity, and the auditor may not share the manager's or the
executor's. The checks are host-declared, so the executor cannot add the check
that judges it.

### Only verified progress is trusted state

A checkpoint is written **only** on the pass path, and it carries the
auditor's verified progress — never the executor's summary and never the plan's
summary line. The verified progress's own `summary` is the *auditor's* wording
about what it verified, so a plan cannot name its own success into the trusted
record.

Two checkpoint shapes exist:

* `VerifiedProgressStore` — an append-only NDJSON store of
  `VerifiedCheckpoint` records (objective, round, verified progress, context
  digest, verified-chain head hash).
* the **session transcript checkpoint** — the pass path also writes a real
  `checkpoints.py` checkpoint into the session store, with
  `boundary="long-horizon-verified"`, so `checkpoints.select()` finds it and a
  resume forks from it with its counters. The rebuilt context is what gets
  digested, so the digest describes the state the loop actually rebuilt.

### The bound

`max_rounds` is configurable. Reaching the bound without a passing verdict ends
the loop as `outcome_unknown` — a named outcome, never a silent pass. The
`LoopResult` carries the reason ("the loop reached its N-round bound without a
passing verdict; the outcome is unknown, not a pass") and every round's record.

## The two-round path the tests drive

The test `TwoRoundRealPathTests` drives a real multi-step path:

* Round 0's plan writes a broken `artifact.txt` and claims success in its
  summary. The Auditor's host-declared check (`grep -q fixed artifact.txt`)
  fails, so the round is rejected. No checkpoint is written, and the failure
  evidence ("the auditor rejected step lh-two-round-r0") becomes round 1's
  rebuild input.
* Round 1's plan sees the failure evidence in its rebuilt state, writes a
  fixed `artifact.txt`, and the Auditor's check passes. The verified progress
  lands, and the checkpoint is written.

Both rounds' executor summaries claim success; only the second claim survives,
because only the second one was verified against the file on disk.

## Relationship to the existing parts

| Existing part | What it did | What this module adds |
| --- | --- | --- |
| `blind_rerunner.py` (slice 5) | issues a blind bundle and compares check sets; deliberately refuses to produce a verdict ("no comparison result is a pass/fail verdict") | the Auditor reuses the *shape* of `BlindCheck` — a named, runnable command plus an assertion — but must produce a verdict, because without one nothing could ever become trusted state. `blind_rerunner` is **read only** here; it is not modified and not called |
| `audit_head_holder.py` | holds the sealed head outside the writer's store; `fresh_start_pin` carries the old head so a re-mint shows as a mismatch | the fresh-start path of the loop carries the *verified-progress* head (`verified_head_hash`) into the new chain, and `check_fresh_start_head` delegates to `audit_head_holder.check_fresh_start` rather than re-implementing it. The loop's head moves exactly when trusted state moves: a rejected step does not change it |
| `sessions.py` / `checkpoints.py` | carries resume state and counters; the state is whatever the writer produced | the loop writes checkpoints **only** from auditor-verified progress, and the session checkpoint carries the verified progress and the rebuilt context's digest |
| `shutdown_unwind.py` (unwind slice) | makes an interrupted turn visible; synthetic results never count as success | the loop's `aborted` outcome is the same idea at the round level: an over-budget step is never a success, it is failure evidence |
| `action_verifier.py` | checks a verbal claim against an observed action | the Auditor is the round-level version of that idea, with the stronger property that the claim text cannot even reach the verdict |

## Mapping to the LongHorizon-Harness loop

The source (LongHorizon-Harness, arXiv 2608.01964) describes the loop as:
the Manager rebuilds each round from the original goal, the verified progress,
and the failure evidence; the Executor works with a fresh context and takes one
bounded action; the Auditor checks the real files / UI / logs / tests rather
than believing the Executor; only an Auditor-approved result becomes trusted
state, and a failure becomes the next round's evidence; the roles may use
different models or backends.

Northstar's mapping is one-to-one:

| LongHorizon-Harness | Northstar |
| --- | --- |
| Manager rebuilds from goal + verified progress + failure evidence | `ManagerBackend.rebuild` / `RoundState` / `context_digest` |
| Executor, fresh context, one bounded action | `ExecutorBackend.run_step`, `StepPlan`, `StepOutcome`, `RoundState.context` |
| Auditor checks real artifacts, not the Executor's account | `AuditorBackend.audit`, `AuditCheck`, `EvidencePointer` |
| Only the Auditor's pass becomes trusted state | `VerifiedProgress`, `VerifiedCheckpoint`, `VerifiedProgressStore` |
| Failure becomes the next round's evidence | `FailureEvidence` carried into the next `RoundState` |
| Roles may use different backends | `RoleConfig` per role; sharing an identity is refused |

**Honest scope on the numbers.** The upstream README's reported gains
(WeaveBench 51.8 → 80.7, OSWorld 2.0 binary 2.8 → 8.3, Terminal-Bench 2.1
69.7 → 77.2 with 24% fewer tokens) are the project's own self-reported figures
on a single Qwen 3.7-Plus backbone with a Claude Code backend, without
independent replication. They are directional only. This module implements the
loop *shape*; it does not claim Northstar reproduces any of those numbers, and
it is not an evaluation harness.

## Open items

These are questions the source and the existing code do not settle. They are
recorded rather than answered by invention.

1. **Model-backed roles.** The shipped backends are deterministic: the Manager
   rebuilds a structured context, the Executor runs host-planned shell commands,
   the Auditor runs host-declared checks. The upstream loop drives a *model* in
   the Executor role. The seam for a model-backed Executor is
   `ExecutorBackend.run_step` — a subclass would need to receive the rebuilt
   context as a fresh conversation with no previous-round history. That has not
   been built here, and the role-identity rule (`RoleConfig`) is the hook it
   would have to satisfy.
2. **The completion rule.** `_is_complete` is host-supplied; the default is
   "one verified step ends the objective". A multi-step objective needs a
   host-supplied predicate over the verified progress. Upstream does not say
   how the Manager decides the goal is met.
3. **Cross-round verification cost.** The Auditor re-runs its checks from
   scratch each round. Upstream reports token savings from the loop; this
   module does not model the cost of repeated verification.
4. **Independence in fact.** The Auditor shares the process and the filesystem
   with the Executor. It is independent in *state* (fresh context, host-declared
   checks, no access to the claim), not in failure domain. A same-host operator
   can still edit an artifact after the fact; the checkpoint chain records what
   was verified, not that the world stayed that way.
5. **What "the real artifact" covers.** Upstream audits files, UI, logs and
   tests. Here the audit surface is the workspace file tree plus commands the
   host declares. A UI surface would need a different `AuditCheck` backend.
