# CLAUDE.md — Northstar AgentOS

Project memory for Claude Code sessions working on this repo. Read this first,
every session. Facts here outrank anything in a one-off brief; if a brief
contradicts this file, follow this file and flag the conflict.

## What this is

Northstar AgentOS — a next-gen agent runtime. Goal: an agent that runs far
(long-horizon autonomous tasks), stays inside its authorization, is fully
verifiable/auditable, and keeps learning. Absorption priority, in order:
**programming > red-team attack > blue-team defense**; multimodal last.

## Environment (140)

- Work happens on 140 (`muse-newapi@140.245.125.82`) via `~/bin/cc.sh`
  (Claude-Group token via relay `https://relay.nework.uk`). Never export, echo,
  or paste any API key / token yourself — always go through the wrapper.
  `cc-ds.sh` = DeepSeek-Group, `cc-gpt.sh` = ChatGPT-Group; use them only when
  the task explicitly says so.
- SSH from the VM needs `-o UserKnownHostsFile=/home/hatch/.ssh/known_hosts`
  (exec runs as root but HOME is /home/hatch; ssh resolves `~` via passwd).
- The repo's git remote is GitHub `FNY666/northstar-agent-os`, deploy key
  "Muse VM northstar push" (read/write, repo-scoped).

## Iron rules — never break these

- **No version changes**: never edit `_version.py` / version strings, never
  bump a formal version.
- **No tags, no Releases, no publishing.**
- **Never push `main` yourself, never force-push.** Delivery is a git bundle
  (`git bundle create <name>.bundle <branch>`), handed to the parent for
  review; the parent pushes. Committing on your batch branch is fine.
- **Never delete branches** (`git branch -D` / `--delete` are blocked).
- **Baseline first, re-verify after**: run the relevant tests / bench before
  changing anything, then run them again after. A batch without a re-check is
  not done.
- **Code first, not docs**: read the actual code, not just documentation.
  Prove the existing end-to-end path works before adding modules.
- **Token efficiency**: if you don't know something, search the web / read the
  code first. Don't guess and burn tokens on trial-and-error loops.
- **Don't add new modules to stack features**; prove the current path first.

## How a batch works (see also `/northstar-batch`)

1. Branch from `main`: `batch-<n>-<short-topic>`.
2. Baseline: `make test` (or the component suite) + `make bench` where relevant.
   Record the numbers.
3. Implement the brief, smallest diff that does the job. Keep commits
   focused, one logical change each, message in the repo's existing style
   (`<area>: <what>`, e.g. `fix: drop duplicated return in _canary_evidence`).
4. Re-run the affected tests + bench; record before/after. If a live-leg
   bench failure appears, diagnose the root cause and write it up
   (`bench-live-leg-diagnosis.md` style) — don't just re-run hoping it passes.
5. Deliver: `git bundle create` with full history; report commits, files,
   test results, and anything left open. Don't push.

## Verification (see also `/northstar-verify`)

Verify in a fresh clone/worktree, never in the working tree that produced the
work. Re-run the tests yourself; check the diff commit by commit; confirm no
version/tag/release changes; confirm the bundle verifies and its HEAD matches
the reported commit.

## Commands

- `make test` — component test suites. `make bench` — governance bench.
- `make help` — all targets.
- Interop suite lives under `components/northstar-agent-interop`.
- Remote canary: `examples/remote-canary/` + `scripts/` (see
  `bench-live-leg-diagnosis.md` for the known Landlock loader issue:
  Landlock path restrictions break nested Python loaders; `landlock='off'`
  passes — do not "fix" by disabling Landlock without a decision).

## Repo map

- `components/northstar-agent-runtime/` — the runtime (largest component).
- `components/northstar-agent-interop/` — interop suite + scoring.
- `components/northstar-{host,run-contract,run-evidence,durable-run,egress-sidecar,codex-sidecar}/`
  — host, contracts, evidence, sidecars.
- `benchmarks/`, `tests/`, `examples/`, `docs/`, `research/`, `scripts/`.
- `skills/` at repo root is Northstar's own skill system — not Claude Code
  skills (those live in `.claude/skills/`).

## Model choice

Default model is Sonnet (set in user settings) — good enough for most batch
work and much cheaper than Opus. For genuinely hard tasks (novel architecture,
subtle debugging), run with `--model opus` or `/model opus` in-session.
Cheaper models (DeepSeek/Gemini via `cc-ds.sh` / `cc-gpt.sh`) are for
probing/verification only unless the brief says otherwise.
