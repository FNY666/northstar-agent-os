# Read-only code review in CI

A copy-paste recipe for running a **governed, read-only** agent review of a pull
request. The agent can look, but `Write`/`Edit` are denied at the permission
gate (`--read-only`), the run is capped by turn and dollar ceilings, and every
tool call lands in an append-only session transcript that you keep as an audit
artifact.

Nothing here is wired into this repository's own CI: it is a template for
*consumers* of the runtime, because enabling it on a real PR flow requires your
`ANTHROPIC_API_KEY` (as a GitHub secret) and a review policy decision.

## Local run

```sh
cd examples/ci-readonly-review
export ANTHROPIC_API_KEY=...
REVIEW_WORKSPACE=/path/to/the/repo sh run_review.sh
```

Offline smoke (no key, deterministic, exercises the same flags; the scripted
provider replies with a canned `VERDICT: approve` block):

```sh
REVIEW_WORKSPACE=. REVIEW_PROVIDER=scripted \
  REVIEW_PROMPT_FILE="$PWD/prompt.md" sh run_review.sh
```

## GitHub Actions

Add `.github/workflows/readonly-review.yml` to the repository you want
reviewed:

```yaml
name: Read-only agent review

on:
  pull_request:

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # so the agent can read the actual diff
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install the runtime
        run: pip install ./components/northstar-agent-runtime
      - name: Run the governed read-only review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          sh ./examples/ci-readonly-review/run_review.sh \
            > review-events.jsonl
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agent-review-transcript
          path: |
            review-events.jsonl
            .northstar-reviews/*.jsonl
```

## What the exit code tells CI

`run_review.sh` inherits the runtime's exit-code contract, so the job fails on
the same conditions a reviewer should fail on:

| exit | meaning in this recipe |
| --- | --- |
| 0 | review completed (read the verdict from the JSONL result event) |
| 1 | execution error mid-review — fail the job |
| 4 | budget ceiling hit — the review cost more than `REVIEW_MAX_USD`; fail |
| 5 | a tool call was denied (`--halt-on-denial`) — a policy surprise; fail |

Gate on the verdict by parsing the last JSON line (`"type": "result"`) of
`review-events.jsonl`, or keep it advisory and ship the transcript as an
artifact. Start advisory: the point of the recipe is the audit trail, not
automatic merge blocking.

## Why these flags

- `--read-only` subtracts `Write` and `Edit` from the tool set at the gate — the
  agent physically cannot change the checked-out tree.
- `--max-budget-usd` and `--max-turns` bound cost and loop length independently.
- `--halt-on-denial` converts a denied call into a visible failure instead of a
  silent skip.
- `--session-dir` writes the append-only JSONL transcript outside the reviewed
  workspace, so the job's own audit trail never dirties the tree it reviews.
