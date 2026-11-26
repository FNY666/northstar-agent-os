# SWE-bench Verified 50

A frozen slice of [SWE-bench Verified](https://www.swebench.com/), used to
measure the model on the industry benchmark rather than only on the
in-house task pack.

## What is frozen

`verified-50.json` holds 50 instances across 12 repositories.  Each entry
records:

| Field | Meaning |
|---|---|
| `instance_id` | the upstream instance name |
| `repo` | the repository the instance belongs to |
| `base_commit` | the commit the bug is present at |
| `fail_to_pass` | the tests the patch has to make pass |
| `pass_to_pass` | the tests the patch must not break |
| `problem_statement_sha256` | fingerprint of the issue report |
| `environment_image` | the container the evaluation runs in |
| `environment_digest` | the digest of that container image |

`verified-50.digests.json` holds the image digests on their own, so a
changed digest is visible in a diff.

The sample is regenerated with `scripts/freeze_swe_bench_sample.py`.

## How a run works

Solving and evaluating are two separate steps.

1. `scripts/solve_swe_bench.py` lets a real model attempt an instance.  The
   repository is exported from the instance's own environment image, so the
   checkout the model edits is the checkout the evaluation will run
   against.  The model works through the normal `northstar code` path, and
   the patch it delivers is read from the run's evidence bundle.
2. `scripts/run_swe_bench_batch.py` drives both of them over the whole
   sample, one instance at a time.  It keeps the receipts, removes each
   environment image once it has been used, and can be started again after
   an interruption: an instance whose evaluation receipt already exists is
   skipped and the patch file is never truncated.
3. `scripts/run_swe_bench_eval.py` hands the patch to the upstream
   `swebench.harness` and records its verdict.  The verdict is the
   upstream one; this repository does not reimplement the grading.

A receipt from the solver records the provider, the model, the endpoint,
the sampling temperature, the sandbox profile, the budget and the sample
fingerprint, so a later run can show it measured the same thing.

## Reading a result

The outcomes are the upstream states:

| Outcome | Meaning |
|---|---|
| `RESOLVED_FULL` | every failing test passes and nothing else broke |
| `RESOLVED_PARTIAL` | the failing tests pass, but some other test broke |
| `RESOLVED_NO` | the patch did not fix the issue |
| `evaluation_timeout` | the evaluation ran out of time; not a verdict |
| `no_patch_delivered` | the model delivered no patch |
| `ERROR` | the evaluation itself broke |

`RESOLVED_PARTIAL` and `RESOLVED_NO` are both failures of the model, but
they are different failures, and the receipt keeps them apart.

## Cost and time

The evaluation runs the upstream test suite inside the instance's
container.  On an aarch64 host the amd64 images run under emulation, which
makes a single instance take from half an hour to more than an hour.  A
full 50-instance run is therefore a multi-hour job, not a quick check.
