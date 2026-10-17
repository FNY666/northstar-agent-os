# Programming-run evidence hard gates

`scripts/check-code-run-evidence.py` is an **offline, read-only, host-side**
validator for a completed `northstar code` evidence directory. It is a stricter
completion gate than `northstar code-reconcile`: reconciliation classifies an
interrupted run and writes `reconcile.json`; this tool writes **nothing** to the
evidence directory, worktree, repository, or any external system.

```bash
python3 scripts/check-code-run-evidence.py /path/to/code-run-evidence
python3 scripts/check-code-run-evidence.py --json /path/to/code-run-evidence
python3 scripts/check-code-run-evidence.py --require-verified --json /path/to/code-run-evidence
```

The script uses only the Python standard library and deliberately does **not**
import the runtime's provider, tool, sandbox, or Git execution graph.

## Result and exit semantics

`--json` emits one object with three independent layers and a `hard_gates`
array. Every gate includes its actual boolean determination and reasons.

| Layer | What a pass means |
|---|---|
| `evidence_integrity` | The local artifacts are regular bounded files; JSON has no duplicate keys or non-finite numbers; schemas, types, safe names, and manifest digests agree. |
| `trajectory` | The phase chain has legal ordered transitions and a single terminal state; effects have consistent IDs, sequence/status/timestamps and stay in their executing/verifying intervals; and each `HostCheck` matches an independently recorded declared-check receipt. |
| `verified_completion` | A **`success`** terminal has actual successful declared check receipts and a consistent replay, audit, and delivery seal chain for the exact final patch. |

`verified_success: true` is returned only when all three layers pass and all
host-declared checks have successful receipts. In particular, the validator
does not accept `manifest.verification_ok`, `summary.ok`, a final assistant
text, or a patch hash as proof by itself. It means **only** that this local,
declared-host-check chain passed. It never represents hidden benchmark
acceptance: repeated local host successes must not be extrapolated to hidden
evaluation outcomes.

Default exit behavior is intended for evidence inspection:

| Condition | Exit |
|---|---:|
| Verified success | 0 |
| Complete `success_unverified` | 0 |
| Valid plan-only terminal | 0 |
| Valid terminal failure (for example a failed host check) | 0 |
| Invalid/incomplete evidence or a `success` claim lacking the hard proof | 2 |
| Any result other than verified success with `--require-verified` | 2 |

Thus a host check that genuinely failed can still be represented as a valid
terminal evidence set, but it can never be reported as a verified success.
`success_unverified` can be a complete captured run, but is never a verified
success; use `--require-verified` in a policy that requires verification. A
legal plan-only terminal is likewise inspectable by default, but can never be a
verified delivered change and fails `--require-verified`.

## Contract checked

For delivery-capable successes, the checker binds these artifacts by canonical
single-file names and manifest SHA-256 values:

- `manifest.json`, `phases.json`, `task.json`, and `repository-snapshot.json`;
- `verification.json` and the task's exact host-declared command list;
- `changes.patch`, `patch-replay.json`, `patch-audit.json`, and
  `delivery-seal.json`.

It rejects symlinks, special files, references containing traversal or path
separators, files above contract limits, malformed JSON, duplicate JSON keys,
non-finite numeric literals, and schema/type mismatches. Artifact bytes are
read only through a no-follow file descriptor, verified by `fstat`, and capped
during the actual read (not only by a pre-read `lstat` size). JSON validation is
bounded to 128 nesting levels and 100,000 nodes, so malformed/deep input fails
closed rather than raising `RecursionError`. It also checks that:

1. the manifest, phase journal, snapshot, replay receipt, and seal agree on
   run identity/start commit where the v1 contract records them;
2. transition and effect sequences are ordered, timestamps do not run
   backwards, there is only one terminal state, and no effect begins or
   completes after it (equal-millisecond boundaries are valid);
3. normal effects begin and complete in the executing interval; `HostCheck`
   effects are in the verifying interval, are completed, and match
   the independent receipt index and host-declared command;
4. replay/audit/seal all bind the byte-identical final patch; and
5. the seal says host verification did not alter that audited patch.

A `success` terminal cannot contain `in_flight`, `unknown`, or `failed`
effects. A `denied` effect remains valid evidence of an explicit governance
decision. A `success` whose replay/audit/seal completion chain fails is
**invalid or incomplete evidence**, not a `valid_non_success_terminal`.

Some non-success terminals can legitimately lack delivery receipts because the
runtime stopped before the completion boundary. The tool preserves that
information as non-verified rather than inventing a delivery claim. Plan-only
runs likewise cannot establish a delivered, verified code change.

## Important limits

> SHA-256 comparisons provide **local consistency with the supplied
> manifest**. They are not signatures and do not authenticate an evidence
> producer or an adversarial host.

The current artifact contract contains insufficient host-attestation data to
verify real network isolation, so `limitations.network_isolation` is always
reported as **`unknown`**. The process-sandbox fixture used by the unit tests
is explicitly test-only and is not OS isolation.

This checker does not execute a patch, commands, Git, tools, or a model. It
therefore does not measure real-model success rate and does **not** decide
release eligibility.

## Tests

```bash
python3 -m unittest -v tests/test_code_evidence_gates.py
```

The suite creates genuine offline scripted `northstar code` CLI fixtures with
`--sandbox process --seccomp off --capdrop off --landlock off`. This is a
**fixture-only** process backend, not OS isolation. It then copies and tampers
with their evidence. Coverage includes verified, failed, unverified, and
plan-only terminals; digest and terminal mismatches; effect lifecycle and
timestamp violations; HostCheck/receipt binding; success receipts; seal
mismatch; symlinks and oversize input; duplicate/non-finite, deeply nested,
and over-node-cap JSON; container-valued contract fields; and
`--require-verified`.
