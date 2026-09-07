# Northstar Agent Runtime

A governed agent loop: reasoning, policy, budgets, and auditability in one
process — with **execution delegated** to the
[Northstar Codex Sidecar](../northstar-codex-sidecar/README.md) over its private
Unix socket.

The runtime never spawns a model CLI and never holds Codex credentials. It owns
the *decision* half of a turn (what may be called, for how long, at what cost,
with what recorded); the sidecar owns the *doing* half (spawning `codex`, the
sandbox, process cleanup).

```
prompt ──► AgentRuntime ──► provider (Anthropic Messages API, or scripted)
                 │
                 ├─ hooks (10 lifecycle events, veto-capable)
                 ├─ permission gate (disallowed → allowed → mode + host callback)
                 ├─ ceilings (turns / tool calls / USD)
                 ├─ tools (Read, Grep, LS, Write, Edit, DescribeTools, Task)
                 │        └── CodexReadOnly ──Unix socket──► northstar-codex-sidecar ──► codex --sandbox read-only
                 ├─ subagents (own context, tool subset, ceilings, provider)
                 ├─ compaction (safe boundaries only)
                 ├─ sessions (append-only JSONL, fsync per write)
                 └─ tracing (run → turn[n] → generation | tool:Name | subagent:Type)
                 │
                 ▼
            exactly one ResultMessage
```

## Install (pip)

The component installs as a console script with lazy SDK imports, so the
offline provider works with no extras at all:

```sh
pip install .                       # offline scripted provider, doctor, dry-run
pip install '.[anthropic]'          # + live Anthropic provider
pip install '.[tracing]'            # + OpenTelemetry span export
# or, once published:
pip install 'northstar-agent-runtime[full]'
```

Then run from any directory:

```sh
northstar-agent-runtime --version
northstar-agent-runtime doctor --workspace .
northstar-agent-runtime run --workspace . --provider anthropic --prompt "summarise README" --dry-run
```

The installed names mirror the in-tree layout (`python -m cli run ...` works
identically from a checkout). The version has one source of truth (`_version.py`)
and the test suite asserts it equals the `pyproject.toml` version, so an
installed wheel and a source checkout can never disagree.

## Quick start (offline, no API key)

The scripted provider is the reference provider, so the component is fully
exercised with no credentials and no network:

```sh
cd components/northstar-agent-runtime
pip install -r requirements.txt -r requirements-tracing.txt   # anthropic + OpenTelemetry
python3 -m cli run \
  --workspace . \
  --prompt "read README.md and say how long it is" \
  --script /tmp/demo.json \
  --json
```

with `/tmp/demo.json` holding two scripted turns:

```json
[
  {"tool": {"name": "Read", "input": {"path": "README.md"}}},
  {"text": "The README is 41 lines."}
]
```

Against a live model, replace the provider and keep every other flag:

```sh
export ANTHROPIC_API_KEY=...   # the runtime reads it only through the SDK
python3 -m cli run --provider anthropic --model claude-sonnet-4-5 \
  --workspace . --prompt "summarise CHANGELOG.md" \
  --max-turns 12 --max-budget-usd 0.25 --permission-mode default \
  --session-dir /tmp/northstar-sessions --trace
```

`python3 -m cli --version` prints the component version (one source of truth,
`_version.py`). Two side-effect-free commands help before spending a token:

```sh
python3 -m cli doctor --workspace .        # self-check: python, SDKs, workspace,
                                           # session dir, sidecar socket
python3 -m cli run --workspace . --provider anthropic \
  --prompt "summarise CHANGELOG.md" --dry-run   # what the run would do, no request
```

`doctor` exits 0 only when every check passes (missing optional SDKs are
warnings, not failures); `--dry-run` prints the resolved tools, allow/deny
lists, ceilings, and pricing, then exits without constructing the provider.

Transcripts are append-only JSONL, but they are meant to be read back:

```sh
python3 -m cli sessions list --session-dir /tmp/northstar-sessions
python3 -m cli sessions show --session-dir /tmp/northstar-sessions <session-id>
python3 -m cli sessions show --session-dir /tmp/northstar-sessions <session-id> --json
```

`list` summarizes every transcript; `show` renders one as a timeline (records,
turns, result subtype, cost); `--json` exports the raw records. The viewer is
read-only: it never creates the directory, never writes a file, and reports a
damaged record instead of "repairing" an audit trail.

To delegate execution to Codex, point the runtime at the sidecar socket. That is
the only switch; without it `CodexReadOnly` is not registered at all:

```sh
python3 -m cli run --sidecar-socket /var/run/northstar-codex/sidecar.sock \
  --probe-sidecar            # one health-check prompt, then exit
```

## Events, not exceptions

A run yields the event vocabulary the surrounding host already knows:
`SystemMessage` (`init`, `compact_boundary`, `informational`), `AssistantMessage`,
`UserMessage`, and exactly one `ResultMessage` per run. Every foreseeable
condition arrives as an event, never as a raised exception:

| `ResultMessage.subtype`     | meaning                                             |
| --------------------------- | --------------------------------------------------- |
| `success`                   | the model stopped asking for tools                  |
| `error_max_turns`           | `max_turns` reached                                 |
| `error_max_tool_calls`      | `max_tool_calls` reached                            |
| `error_max_budget_usd`      | `max_budget_usd` reached                            |
| `error_permission_denied`   | a denial ended the run (`halt_on_denial`)           |
| `error_during_execution`    | provider failure, malformed tool input, internal bug |

The three ceilings are independent, each with its own subtype, so an operator can
tell "it ran out of money" from "it ran in circles". `RunReport` (from
`run_collect`) carries the same information structurally: `denials`, `tool_calls`,
`subagents`, `compactions`, `hook_fires`, `errors`, `trace`.

## Hooks

Ten events, uniform handler signature, and a deny that cannot be argued with:

`PreToolUse` (veto or rewrite the input) · `PostToolUse` · `PostToolUseFailure` ·
`UserPromptSubmit` (inject context or refuse the whole run) · `Stop` (may refuse
to stop, feeding its reason back as a new user turn) · `SubagentStart` ·
`SubagentStop` · `PreCompact` · `SessionStart` · `SessionEnd`.

- Handlers all take `(payload: HookInput)` and may return `None`, a dict, or a
  `HookResult`; anything else is a registration error, not a surprise at 3 a.m.
- **Deny is terminal.** Later hooks are skipped and listed in
  `outcome.skipped`; a subsequent allow cannot resurrect the call.
- `deny` on a non-veto event is recorded in `outcome.ignored` rather than silently
  dropped, so a mis-wired hook shows up in the report.
- A hook that raises on a veto-capable event **fails closed** (the call is
  refused). On an observation-only event it is logged and the run continues.
- `PreToolUse` runs *before* the permission gate so a hook can rewrite arguments
  that policy then inspects — a rewrite can narrow what is allowed, never bypass
  the gate.

## Permissions

Three layers, evaluated in this order:

1. `disallowed_tools` — always wins, and a name here is removed from the registry
   offered to the model.
2. `allowed_tools` — auto-approves without consulting anything else.
3. `permission_mode` plus the optional `can_use_tool` host callback.

Modes: `default`, `acceptEdits`, `plan`, `bypassPermissions`. In `default`, a
mutating tool with no host approval callback is **denied, not executed** — the
fail-safe direction is always "no". A denial is not an exception: the model
receives an `is_error` `tool_result` naming the rule that refused it, and the run
records a `Denial` with `tool`, `source`, and `reason`.

## Cost

`max_budget_usd` is checked before every generation against real per-million-token
prices, including prompt-cache discounts (`cache_read` 0.1×, `cache_write` 1.25×).
An unknown model id falls back to conservative pricing and flips
`pricing_estimated=True` on the result, so an estimate is never mistaken for an
invoice. A subagent's cost rolls up into its parent's meter: delegation cannot be
used to multiply a budget.

## Subagents

`Task` spawns a child run with its own transcript, tool subset, ceilings, and
optionally its own provider — which is how a cheap model reads the files while an
expensive one decides. Delegation is permission-gated **per tool the subagent
declared**, never by the literal name `Task`: blanket-denying `Task` as "mutating"
would mean subagents never get created at all, and the error message would blame
the wrong thing. Nested delegation is off by default; `max_subagent_depth` is the
backstop even when it is enabled.

Four built-ins ship in `agents.py`: `general`, `explorer`, `planner`, and
`evaluator`. The evaluator is read-only, `plan`-mode, and **default-FAIL**: an
answer with no explicit `VERDICT: PASS|FAIL` line, or a `PASS` that cannot name
what it checked, or a `PASS` leaving a criterion unverified, is reported as `FAIL`.
A passing verdict is an assertion the runtime can audit, not a vibe.

## Sessions, compaction, tracing

- **Sessions**: append-only JSONL, one `fsync` per write, `0600` under a `0700`
  directory. A torn last line is skipped and counted, not treated as corruption —
  a crash mid-write must not make the audit trail unreadable. A session id is
  generated even when nothing is persisted.
- **Compaction** may only cut at a boundary with no pending tool call. Cutting
  mid-exchange orphans a `tool_use` from its `tool_result`, and the API answers
  that with a 400 the model cannot recover from. After compaction the runtime
  asserts (in tests) that no request carries a dangling block and that roles still
  alternate.
- **Tracing** records `run → turn[n] → generation | tool:Name | subagent:Type`
  with cost attributes. It never records prompt text or tool output bodies — only
  `tool.is_error`. Attributes are written *before* `span.end()`, because
  OpenTelemetry discards a late `set_attribute` silently and the trace would just
  be missing its cost.

## Tool sandbox

Every tool path is resolved through `ToolSandbox.resolve`: lexical normalisation,
then `realpath` of the nearest existing ancestor, then a containment check against
the workspace root, then (for writes) protection of paths like `.git`. Symlinks are
followed *before* the check, and a path that does not exist yet is checked through
its existing parents, so `link/../../etc/passwd` cannot smuggle a write out.

Caps exist because a tool that can read 4 GB can also read 4 GB into a prompt:
`Read` 256 KB, `Grep` 200 matches, `LS` 500 entries, and a shared per-result
character cap. Each cap says so in its own output, and the report keeps the true
size (`result_chars`), so truncation is visible instead of inferred.

## Layout

| Module              | Responsibility                                                      |
| ------------------- | ------------------------------------------------------------------- |
| `loop.py`           | the turn loop, ceilings, event stream, `RunReport`                   |
| `hooks.py`          | 10 lifecycle events, veto semantics, fail-closed errors              |
| `permissions.py`    | the three-layer gate and the delegation gate                         |
| `budget.py`         | price table, cost computation, budget meter                          |
| `tools/`            | package: registry, sandbox, caps, built-in tools, `CodexReadOnly` spec (`__init__.py`), plus the guard-verification harness (`verify_invariants.py`) |
| `compaction.py`     | safe-boundary detection and summarisation                            |
| `sessions.py`       | append-only JSONL transcripts and recovery                            |
| `agents.py`         | agent definitions, registry, verdict parsing                         |
| `tracing.py`        | span tree, redaction, optional OpenTelemetry export                  |
| `sidecar_client.py` | Unix-socket client for the sidecar component                         |
| `providers/`        | `base` (events + contract), `anthropic`, `scripted`                  |
| `cli.py`            | one governed run from a shell, with distinct exit codes              |
| `doctor.py`         | `cli doctor` environment self-checks (no requests, no file writes)   |
| `session_view.py`   | `cli sessions list/show` - the read-back half of the transcripts     |
| `_version.py`       | single source of truth for the component version                     |

## Exit codes

`0` success · `1` error_during_execution · `2` error_max_turns ·
`3` error_max_tool_calls · `4` error_max_budget_usd · `5` error_permission_denied ·
`64` usage or configuration error (nothing was run). Result errors and refusals
are printed to stderr; `--json` emits one object per event.

`--deny-tool` subtracts from the computed allow list rather than leaving a name in
both lists, because a name in both lists is an operator mistake the engine would
otherwise report as a policy conflict.

## Tests

```sh
cd components/northstar-agent-runtime
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

413 tests, fully offline and deterministic: the scripted provider is the only
model, and `test_integration_sidecar.py` runs the real sidecar `serve()` over a
real Unix socket with a 100,000-Chinese-character prompt.

To confirm the tests actually cover the guards they claim, revert each one in a
throwaway copy and check that its test goes red:

```sh
python3 tools/verify_invariants.py
```

It mutates nothing in the working tree, and it re-runs the untouched copy as a
baseline at the end. Five invariants are checked this way: safe-boundary
compaction, workspace containment, the budget ceiling, hook deny terminality, and
recording span usage before `end()`. `is_safe_cut` is the one place where a second
guard (`orphaned_tool_results`) also blocks the same cut, so that mutation is
caught by the unit-level compaction tests rather than the loop-level one.

## Limitations and scope

- **The live Anthropic API is unverified here.** No credentials exist in the
  development sandbox, so request building and response normalisation are tested
  against an injected fake client, not against the network.
- **MCP is not implemented.** Tools are in-process; there is no MCP client and no
  server bridge.
- **Process-group `TERM`→`KILL` cleanup is not verified on real Linux here.** That
  behaviour belongs to the sidecar; the runtime only bounds its own socket read.
- Session transcripts are a local audit trail, not a compliance store: there is no
  signing, no retention policy, and no tamper evidence.
- Cost accounting is arithmetic on provider-reported usage. It cannot see retries
  the SDK swallowed, and it never predicts a price for a model the table lacks
  without saying so.
- `permission_mode` and the hooks are in-process. They constrain this runtime, not
  a hostile process on the same machine.
