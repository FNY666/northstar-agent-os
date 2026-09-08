"""Scaffold a new governed Northstar project (``northstar-agent-runtime new``).

Generates a minimal, self-consistent workspace that bakes in the governance
defaults, so a new repository starts *safe and auditable* and loosens
deliberately instead of the other way round:

- ``AGENTS.md`` — project instructions auto-injected into every run;
- ``.northstar/config.toml`` — repository policy (``northstar.policy.v1`` +
  a date-based revision) whose default agent is the read-only reviewer;
- ``.northstar/agents/reviewer.md`` — a read-only, plan-mode reviewer agent;
- ``.northstar/hooks/README.md`` — how hooks apply (registered in code; a
  workspace file is never silently given code execution);
- ``.github/workflows/northstar-review.yml`` — governed CI review recipe
  (template: install source and API key left as TODOs);
- ``README.md`` — what was created and the three commands to try it.

Everything generated is validated by the runtime's own loaders: the config
file parses under ``policy_file.load_policy_file``, the agent file registers
under ``agent_files``, and the workspace passes ``doctor``.
"""
from __future__ import annotations

import time
from pathlib import Path

CONFIG_NAME = ".northstar/config.toml"
AGENT_NAME = ".northstar/agents/reviewer.md"
SKILLS_README = ".northstar/skills/README.md"
HOOKS_README = ".northstar/hooks/README.md"
WORKFLOW_NAME = ".github/workflows/northstar-review.yml"
PROJECT_README = "README.md"
AGENTS_MD = "AGENTS.md"


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def _revision() -> str:
    return f"{_today()}.0"


def scaffold_project(directory: str | Path, *, force: bool = False) -> list[Path]:
    """Create a governed project under ``directory``; returns created paths.

    Refuses (``ValueError``) when the directory already exists and is
    non-empty unless ``force`` is set. With ``force``, template files are
    (re)written and everything else is left untouched.
    """
    target = Path(directory)
    if target.exists() and not target.is_dir():
        raise ValueError(f"{target}: exists and is not a directory")
    if target.exists() and any(target.iterdir()) and not force:
        raise ValueError(
            f"{target}: directory is not empty; pass --force to write the template "
            "files into it (existing files are overwritten, nothing else is touched)"
        )

    name = target.name or "northstar-project"
    files = {
        CONFIG_NAME: _config_toml(),
        AGENT_NAME: _reviewer_agent(),
        HOOKS_README: _hooks_readme(),
        SKILLS_README: _skills_readme(),
        WORKFLOW_NAME: _ci_workflow(),
        AGENTS_MD: _agents_md(name),
        PROJECT_README: _project_readme(name),
    }
    created: list[Path] = []
    for relative, content in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(path)
    return created


def _config_toml() -> str:
    return f"""\
# .northstar/config.toml — repository policy for every governed run in this workspace.
# Every key is optional; values may only tighten (see the runtime README and
# docs/concepts/governance.md). `allow_tools`/`bypassPermissions` are never
# accepted here: loosening is an operator's per-run CLI decision.
schema_version = "northstar.policy.v1"   # canonical policy schema (fail-closed on future versions)
revision = "{_revision()}"               # audit correlation key for this revision

project_context = "AGENTS.md"            # project instructions auto-injected from the repo root

# Governance defaults for this project: every run executes as the read-only
# reviewer unless you pick another agent (--agent) or remove this key.
agent = "reviewer"

# Tighten further per project, for example:
# read_only = true                # refuse Write/Edit for every run
# deny_tools = ["Write", "Edit"]  # additive floor; --allow-tool cannot resurrect these
# max_turns = 10                  # may only lower the built-in ceiling of 25
# max_tool_calls = 50             # may only lower 50
# max_budget_usd = 0.25           # any positive cap (built-in default: unlimited)
# halt_on_denial = true           # end with error_permission_denied on a refusal
#
# Postconditions - claims about the workspace that THIS PROCESS checks after the run,
# so "the agent said it finished" is not the evidence. A repo may add checks here; it
# can never remove or weaken one passed on the command line.
# [[verify]]
# kind = "unchanged"             # exists | absent | changed | unchanged | contains
# path = "uv.lock"
# [[verify]]
# kind = "contains"
# path = "docs/runbook.md"
# text = "rollback"
"""


def _reviewer_agent() -> str:
    return """\
---
name: reviewer
description: Read-only reviewer for this repository. Inspects code and tests and reports findings without ever changing files. The governance default agent for new runs.
tools: [Read, Grep, LS, DescribeTools]
permission_mode: plan
read_only: true
max_turns: 10
---
You are the read-only reviewer for this repository.

- Inspect the code, the diff or the current state with Read/Grep/LS and answer
  precisely; never propose edits as actions, report them as text.
- Verify claims against the actual files (tests, commands in AGENTS.md) before
  asserting anything.
- When you find a problem, name the file and line and explain why it matters;
  end with a short verdict paragraph.
"""


def _skills_readme() -> str:
    return """\
# Agent Skills in this workspace

A skill is a folder here containing `SKILL.md`:

```
.northstar/skills/
  release-notes/
    SKILL.md
```

```markdown
---
name: release-notes
description: How this project writes release notes. Use when drafting a changelog entry.
---

The body is the instruction the model reads *on demand*, with the ordinary
sandboxed Read tool. Keep it under ~500 lines and put detail in linked files.
```

Rules that are not negotiable here:

- **Frontmatter is `name`, `description`, `model` only.** The `description` is the
  trigger text injected into every session's prompt, so it is short by design and
  capped by the runtime.
- **A skill is text, never an execution or permission channel.** It cannot register
  a tool, cannot grant itself one, and cannot write policy: `.northstar` is
  write-protected for the agent, so a run cannot mark its own skills reviewed or
  loosen its own gate.
- **Nothing outside the workspace is followed**, including a symlinked skill folder.
- `skills check --workspace .` reviews the set (instruction override, concealment,
  credential reads, `curl … | bash`, policy self-edit, invisible unicode, context
  bloat) and `--write-lock` pins the reviewed digests in `.northstar/skills.lock`.
  `run --require-skill-lock` then refuses to start if a skill changed since review.
- Third-party bundles usually install to `.claude/skills/` or `.agents/skills/`;
  `skills check --root <checkout>` reads those trees too, so you can review before
  adopting.

"""


def _hooks_readme() -> str:
    return """\
# Hooks in this project

Hooks (SessionStart, PreToolUse, PostToolUse, PostToolUseFailure, SessionEnd,
...) are the runtime's observation/veto surface. There are two ways to wire one,
and the difference is a trust decision, not a style preference.

## 1. In embedding code (default, always available)

Register them on a `HookRegistry` and hand that to `AgentRuntime(hooks=...)`:

    from hooks import HookInput, HookResult, HookRegistry
    from loop import AgentRuntime, RuntimeConfig
    from providers.scripted import ScriptedProvider

    def guard(ctx: HookInput) -> HookResult:
        path = (ctx.tool_input or {}).get("path", "")
        if ctx.tool_name == "Write" and "secrets/" in str(path):
            return HookResult.deny("secrets/ is protected in this project")
        return HookResult()

    hooks = HookRegistry()
    hooks.register("PreToolUse", guard)

    runtime = AgentRuntime(
        provider=ScriptedProvider([{"text": "ok"}]),
        config=RuntimeConfig(workspace=".", max_turns=2),
        hooks=hooks,
    )
    for event in runtime.run("hi"):
        print(type(event).__name__)

## 2. Declared by this repository (off unless a human enables it)

`.northstar/config.toml` may name a hook per lifecycle event, so reviewing the
policy in a pull request is the whole change:

    [[hooks]]
    event = "PreToolUse"
    script = ".northstar/hooks/gate.py"   # workspace-relative; never a shell line
    interpreter = "python3"               # optional allowlist, no path separators
    tool = "Write"                        # optional: fire for one tool only
    timeout_ms = 2000

The script receives the event JSON on stdin and may print one verdict JSON on
stdout (`{"decision": "deny", "reason": "..."}`). Exit code 2 denies, using stderr
as the reason; a timeout, a crash, or an unparseable verdict is also a denial - a
hook that cannot answer is never a green light.

**Nothing in section 2 runs unless you pass `--enable-workspace-hooks`.**
Cloning a repository must not mean executing it, which is why the surface is
narrow on purpose: veto-capable events only (`PreToolUse`, `UserPromptSubmit`,
`SessionStart`, `PreCompact`, `SubagentStart`); no `command` key and no shell
anywhere in the schema; the script must live inside this workspace (symlinks are
resolved before the check, never followed); output is capped; and the child sees
only `PATH` and `LANG`, so no model credential crosses into hook code.

`Write` and `Edit` cannot touch this directory at all: `.northstar` is write-
protected, so a run can neither plant a hook nor rewrite the policy that gates it.

Scripts that must run regardless of any flag belong behind your own supervisor
(CI, host automation) - not in `.northstar/hooks/`. A repository file may only
ever tighten what a run may do, and an ungated executor would not.
"""


def _ci_workflow() -> str:
    return """\
# Governed read-only agent review for this project (CI recipe template).
#
# TODO before enabling:
#   1. install source: nothing is published yet — point the pip step at your
#      release wheel asset or a local path (keep the TODO until then);
#   2. add the ANTHROPIC_API_KEY repository secret;
#   3. tune the prompt and ceilings to your review policy.
# Mirrors examples/ci-readonly-review in the northstar-agent-os repository.
name: northstar review

on:
  pull_request:

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install the runtime
        run: |
          # TODO: point at your wheel asset / index once published.
          pip install ./components/northstar-agent-runtime
      - name: Review the Agent Skills supply chain
        # Fails when a SKILL.md instructs the model to override its instructions,
        # read a credential store, pipe a remote script to a shell, or edit the
        # agent's own policy; also fails when a skill changed since it was pinned
        # with `skills check --write-lock` (commit that lockfile).
        run: |
          northstar-agent-runtime skills check --workspace . || {
            echo "::error::unreviewed or unsafe Agent Skills - run 'skills check' locally and read the findings"
            exit 1
          }
      - name: Run the reviewer (read-only, ceiling-capped, audited)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          northstar-agent-runtime run --workspace . --agent reviewer \
            --prompt "Review this change for correctness and security. Do not change files." \
            --halt-on-denial --session-dir .northstar/sessions
      - name: List the audit trail
        if: always()
        run: |
          northstar-agent-runtime sessions list --session-dir .northstar/sessions \
            || echo "no sessions yet"
"""


def _agents_md(name: str) -> str:
    return f"""\
# {name} — project instructions

## Commands

- Tests: (fill in — the reviewer verifies claims against real output)
- Lint / format: (fill in)

## Conventions

- Keep changes small and reviewable; explain the why in the description.
- Never commit secrets; keep policy changes in `.northstar/config.toml`
  reviewable and revisioned.
- This repository is governed by `.northstar/config.toml` (schema
  `northstar.policy.v1`): runs here default to the read-only `reviewer` agent.

## Boundaries

- Do not modify files under `.northstar/` without a policy discussion.
"""


def _project_readme(name: str) -> str:
    return f"""\
# {name}

A governed Northstar workspace, scaffolded by `northstar-agent-runtime new`.

## What the template created

| Path | Purpose |
| --- | --- |
| `AGENTS.md` | project instructions auto-injected into every run |
| `.northstar/config.toml` | repository policy (`northstar.policy.v1`, revision `{_revision()}`); default agent is the read-only reviewer |
| `.northstar/agents/reviewer.md` | read-only, plan-mode reviewer agent |
| `.northstar/hooks/README.md` | how hooks apply (embedding code, or declared + flagged) |
| `.northstar/skills/README.md` | where skills live, and how a skill gets trusted (review, then pin) |
| `.github/workflows/northstar-review.yml` | governed CI review recipe (template — see TODOs inside) |

## Try it

```sh
northstar-agent-runtime doctor --workspace .            # environment self-check
northstar-agent-runtime run --workspace . --prompt "What does this project do?" --dry-run
northstar-agent-runtime run --workspace . --agent reviewer \\
  --prompt "Review the current state and report findings." --session-dir .northstar/sessions
```

Runs default to the read-only `reviewer` agent because `.northstar/config.toml`
sets `agent = "reviewer"`. Loosen deliberately: `--agent explorer` for a
read/write exploration run, or remove the key to run the main loop.

## Adding a skill

Drop `.northstar/skills/<name>/SKILL.md` (frontmatter `name` + `description`; only
those two lines go into the prompt, the model reads the body on demand). A skill is
instructions, so it gets reviewed like a dependency before it is trusted:

```sh
northstar-agent-runtime skills check --workspace .              # findings only
northstar-agent-runtime skills check --workspace . --write-lock # pin what you read
northstar-agent-runtime run --workspace . --require-skill-lock … # refuse drift
```

Commit `.northstar/skills.lock`. A model cannot forge it: writes under `.northstar`
are refused by the tool layer, so the record stays outside the reach of the run that
is gated by it. Vet a third-party bundle before adopting it with
`skills check --root /path/to/checkout`, which reads `.claude/skills` and
`.agents/skills` too.

## Verification, not vibes

`[[verify]]` (see `.northstar/config.toml`) declares workspace postconditions the
runtime checks itself after the run — `exists`, `absent`, `changed`, `unchanged`,
`contains`. A failed check ends the run with `error_postconditions_failed` (exit 6).
The conditions are deliberately *not* shown to the model: a check the model can see
becomes a string it can write.

Every run is auditable: `northstar-agent-runtime sessions list --session-dir
.northstar/sessions` and `sessions export <id> --session-dir …` give you the
canonical NDJSON audit feed.
"""
