# Inspecting an interrupted programming run

Each `northstar code` run writes its task, repository snapshot, phase/effect
journal, checks, patch, and manifest into one evidence directory. Failed runs
keep the detached worktree. Inspect that directory with:

```bash
northstar code-reconcile /path/to/code-run-evidence
```

Python callers receive the same JSON-compatible receipt:

```python
from sdk import reconcile_code_run

receipt = reconcile_code_run("/path/to/code-run-evidence")
print(receipt["classification"], receipt["unknown_side_effects"])
```

The inspector checks the run identity, transition chain, effect sequences and
timestamps, and every artifact digest recorded in the manifest. It writes a
separate `reconcile.json`; the original journal, manifest, task, patch, and
worktree are not modified. Digests detect corruption relative to the local
manifest and do not authenticate a manifest supplied by another party.

| Classification | Meaning |
|---|---|
| `terminal` | The phase outcome is sealed and matches the captured run status. |
| `interrupted_before_effects` | A versioned effect journal has no effect starts. Phase continuation remains unavailable. |
| `interrupted_after_receipted_effects` | Recorded effects returned, but the run has no complete terminal delivery. Inspect its retained worktree. |
| `manual_review_required` | At least one effect is still in flight, may have partially changed state, or has a failed legacy receipt. A write-path preflight refusal is recorded separately as `denied` because it occurs before mutation. |
| `insufficient_effect_evidence` | The evidence predates the versioned effect journal. Absence of records cannot prove absence of effects. |
| `incomplete_terminal_evidence` | A phase outcome exists, but sealing or final capture did not finish. |
| `invalid_evidence` | Identity, schema, transitions, timestamps, or referenced digests are inconsistent. |

The command returns exit code 0 for the first three classifications, 2 when
review is required or evidence is incomplete/invalid, and 64 when the directory
cannot be read. Code 0 means inspection succeeded; it does not execute recovery.
Every receipt reports `automatic_tool_replay: false` and
`phase_resume_supported: false`.

A mutating tool writes an atomic `in_flight` record immediately before entering
its authorized handler. A normal return closes that record as `completed`; a
write-path preflight refusal closes it as `denied`; an unexpected exception
records `unknown`, because the handler may have modified state before failing.
Parent and delegated child tools share the same phase gate and
effect journal. Host verification commands use the same start/completion
protocol under the `HostCheck` tool name. Arguments and command output are not
copied into the effect journal.

At delivery, `patch-replay.json` proves that the model's patch applies to the
starting commit, `patch-audit.json` checks delivery boundaries, and
`delivery-seal.json` proves host verification did not change that patch. A
verification command that returns zero while changing delivered files still
ends as `error_postconditions_failed`.

To resume manually, inspect unresolved files and any affected external system
first. Carry the original permission and budget constraints into a fresh run.
Automatic phase restoration and inherited-budget continuation for `code` remain
future work; the generic session checkpoint API does not provide those code-run
guarantees.
