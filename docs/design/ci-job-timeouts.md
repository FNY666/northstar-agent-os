# CI job timeouts

## The rule

> **Every CI job in `.github/workflows/test.yml` declares a `timeout-minutes`.**

A GitHub Actions job that declares no `timeout-minutes` inherits the
platform default of **360 minutes**. A step that hangs — a `pip install`
that stalls on a dead index, a test suite that blocks on a socket, a
`node --test` that never returns — therefore burns six hours of CI
before GitHub cancels the job and reports anything. On a runner fleet
that is six hours of paid capacity spent on a job that will fail anyway.

## What the workflow looked like

Measured on this branch, before the fix:

| job | steps | declared timeout | effective timeout |
|---|---|---|---|
| `egress-sidecar` | 4 | `5` | 5 min |
| `test` | 23 | **none** | **360 min** |
| `agent-runtime` | 11 | **none** | **360 min** |
| `documentation` | 7 | `15` | 15 min |

Two of the four jobs were unbounded, and they are the two largest: the
`test` job runs every sidecar and contract component's compile, unit
and packaging steps, and the `agent-runtime` job runs the runtime's
21,352-test pytest suite plus the 13-guard invariant verification.

The repository already had the convention and the precedent —
`egress-sidecar` declares `timeout-minutes: 5` and
`tests/test_egress_ci.py` pins that value — but nothing covered the
workflow as a whole. The precedent was the only thing that stopped
the pattern from spreading.

## How the limits were chosen

Each limit is set well **above** the job's measured workload on this
host, so a slower GitHub runner cannot produce a false failure, and
well **below** 360 minutes, so a hang is bounded. The measured
workloads:

| job | measured workload | limit | headroom |
|---|---|---|---|
| `egress-sidecar` | 4.5 s | 5 min | unchanged |
| `test` | ~3 min | **30 min** | 10× |
| `agent-runtime` | ~13 min | **45 min** | 3.4× |
| `documentation` | 64.4 s + 6.1 s | 15 min | unchanged |

The `agent-runtime` job's 13 minutes is the sum of two measured runs:

* the runtime's pytest suite: 31,435 passed / 27 failed / 14 skipped /
  1,020 subtests in **404.48 s** (6m44s);
* `tools/verify_invariants.py`: **5m06s** across 13 guards, each of
  which already carries its own inner `timeout=300`.

So 45 minutes is roughly 3.4× the measured wall clock, leaving room for
a runner materially slower than this host.

The workflow contains **no failure-masking patterns** — no
`continue-on-error`, no `|| true`, no `--skip`, no `--exit-zero` — so
the limits cannot hide a failure; they can only end a job that has
already stopped making progress.

## The guard

`tests/ci_job_timeouts.py` holds the detector; `tests/test_ci_job_timeouts.py`
holds the guard and the detector's own tests.

The detector lives in a module rather than in the test file because the
mutant probe mutates a *module* and reruns the slice's tests, and a
test file is excluded from the probe by name. A guard whose logic lives
entirely inside a test file cannot be mutation-probed at all — the
probe skips it.

### Reading the workflow

The detector does **not** parse YAML, and that is a deliberate choice:
the repository's tests carry no YAML dependency. Instead it reads the
`jobs:` mapping with an indentation-aware reader, because three
properties of this workflow make the naive readings wrong:

1. **`on:` is not `jobs:`.** The workflow's trigger block carries `push:`
   and `pull_request:` indented exactly like job names. A reader that
   scans the whole file for two-space-indented keys reads two triggers
   as jobs. The detector therefore scopes itself to the region under
   the top-level `jobs:` key.

2. **A job's own keys are one level below its header, not a fixed
   column.** The detector finds each job's header at the shallowest
   indentation of the `jobs:` region and reads the job's own keys at
   the next level down.

3. **A step-level `timeout-minutes` is not a job-level one.** GitHub
   allows `timeout-minutes` on a step, and a step's keys are two levels
   below its job's. A reader that looked for the key anywhere in the
   job's text would let a step-level value bound a job whose other
   steps are unbounded. The detector only accepts a value at the job's
   own child indentation.

Two independent checks back this up:

* the crafted-workflow tests, which pin each of those three properties
  against a hand-built workflow; and
* a cross-check against **PyYAML** — an independent implementation of
  the same question — which asserts that the detector's timeouts and
  step counts equal the parser's for the real workflow. The test
  skips when PyYAML is absent, so no new dependency is introduced.

### The crafted-input tests

The repository-level checks read the real workflow, which — once the
fix lands — declares a timeout everywhere. On their own they could not
tell a working detector from one that never fires. The eight crafted
tests therefore pin:

* a job without a timeout is named;
* a timeout belongs to its own job, and is not attributed to another;
* a job without a timeout inherits the 360-minute default;
* a zero or a negative timeout is reported as nonsensical;
* a step-level timeout does not count as a job timeout;
* the step count is read correctly;
* a workflow with no jobs yields no missing timeouts.

## What did not change

* No job's steps, commands, or ordering.
* No component's source.
* No version change, no tag, no release, no push, no merge.
