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

## Concepts, guides and API reference

- Concepts: [governance and the permission gate](../../docs/concepts/governance.md) ·
  [audit trail: sessions and durable history](../../docs/concepts/audit-trail.md)
- Guides: [governed-run cookbook](../../docs/guides/governed-run-cookbook.md) ·
  [packaging and CI](../../docs/guides/packaging-and-ci.md)
- API reference: [generated from docstrings](../../docs/api/northstar-agent-runtime.md)

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

## Creating a governed project (`new`)

```sh
northstar-agent-runtime new my-project
```

Scaffolds a minimal repository that starts **safe by default** and loosens
deliberately: `.northstar/config.toml` (schema `northstar.policy.v1` + a
date-based revision) whose default agent is a read-only, plan-mode reviewer
(`.northstar/agents/reviewer.md`); `AGENTS.md` project instructions;
`.northstar/hooks/README.md` (hooks are registered in code, never auto-run
from files); and a `.github/workflows/northstar-review.yml` CI recipe
template. Everything generated parses under the runtime's own validators —
`doctor --workspace my-project` is green immediately. Try it:

```sh
northstar-agent-runtime new my-project
northstar-agent-runtime doctor --workspace my-project
northstar-agent-runtime run --workspace my-project --prompt "Summarise this project" --dry-run
```

## Embedding in Python (sdk)

The same governed loop is importable — no subprocess, no CLI string, no API
key needed for the offline provider:

```python
import sdk

report = sdk.run(sdk.RunOptions(
    prompt="Summarise notes.txt", workspace="examples/demo/workspace"))
print(report.subtype, report.exit_code, report.session_id, report.total_cost_usd)
```

- `sdk.run(options)` → `RunReport` (subtype, `exit_code`, session id, turns,
  cost, denials, `events` — the same JSON-ready dicts `--json` emits).
- `sdk.stream_run(options)` yields each event dict as it happens; the last is
  the `result`.
- `RunOptions` carries the governance knobs (`permission_mode`,
  `allowed_tools`/`disallowed_tools`, `read_only`, ceilings, `halt_on_denial`,
  `session_dir`, subagent depth) plus provider/model/session resume.
- Policy files, AGENTS.md/context files, skills and MCP servers stay on the
  CLI by design — the SDK is the stable embedding contract
  ([example](../../examples/sdk/README.md), full API in the
  [reference page](../../docs/api/northstar-agent-runtime.md)).

## MCP servers (experimental)

A minimal Model Context Protocol **stdio client** connects external tool
servers without adding a dependency or a policy bypass:

```sh
python3 -m cli run --workspace . --prompt "summarise the files" \
  --mcp-server "filesystem=python3 /opt/mcp/filesystem_server.py" \
  --allow-tool mcp__filesystem__list_directory
```

- Each server is a child process speaking JSON-RPC 2.0 over stdio; the
  handshake (`initialize` → `notifications/initialized` → `tools/list`) runs
  under a per-request deadline (`--mcp-timeout-ms`, default 15 s) and a server
  that stops answering is TERM→KILLed as a process group.
- Every remote tool appears as `mcp__<server>__<tool>` and is **mutating by
  default**: under the runtime's `default` permission mode it is denied until an
  operator names it with `--allow-tool` (or a policy file denies it, which
  stays terminal). MCP is a tool *transport*; permission decisions remain in
  the three-layer gate and every call still fires the hooks.
- Output is bounded client-side (per-line and per-call caps); image/resource
  content blocks are replaced with a placeholder rather than rendered.
- `run --dry-run` and `doctor` list the configured servers without spawning
  them. Combining `--mcp-server` with `--agent` is a configuration error: an
  agent-definition run fixes its tool subset by definition, and silently adding
  MCP tools would widen declared policy.
- Limits: no sampling/roots/prompts, no reconnection, and only one protocol
  dialect (`2024-11-05`) is negotiated.

## Repository policy and project context

A workspace can ship two files that every run inside it honors, and both can
only ever *tighten* what a run may do:

- **`.northstar/config.toml`** — the run's policy defaults. A repository that
  ships one is declaring policy for every run in it, so an unreadable file, an
  unknown key, or a value that would loosen a guardrail is a configuration
  error (exit 64): policy is never silently ignored.

```toml
# .northstar/config.toml — every key is optional; values may only tighten.
schema_version = "northstar.policy.v1"   # canonical policy schema; an unsupported
                                         # (future) version is a fail-closed error
revision = "2026-09-07.r1"       # optional audit correlation key for this file revision
permission_mode = "plan"        # "default" or "plan" only; acceptEdits/bypassPermissions
                                # are an operator's per-run CLI decision
read_only = true                # denies Write/Edit for every run
deny_tools = ["Write", "Grep"]  # additive floor; even --allow-tool cannot resurrect one
max_turns = 10                  # may only lower the built-in ceiling of 25
max_tool_calls = 50             # may only lower 50
max_budget_usd = 0.25           # any positive cap (built-in default: unlimited)
halt_on_denial = true           # end with error_permission_denied on a refusal
[[verify]]                      # checked after the run, by this process, not by the model
kind = "unchanged"
path = "uv.lock"
agent = "explorer"              # run as a built-in agent by default (CLI --agent wins)
compaction_threshold_tokens = 30000   # 0 disables compaction
project_context = "AGENTS.md"   # file name inside the workspace, or false to disable
```

  `allow_tools` is not accepted in a policy file: auto-approval is an operator
  decision made per run (`--allow-tool`). When both the file and the CLI set a
  ceiling, the lower value wins; file denials add to CLI denials and the
  permission gate's first layer keeps them terminal. `--no-policy-file` skips
  the file entirely for one run.

- **`AGENTS.md`** (or the `project_context` file configured above, or an
  explicit `--context-file`) — developer-authored project instructions. When
  present it is appended to the system prompt behind a clear delimiter, so the
  model sees repository conventions without the operator repeating them. It is
  resolved strictly inside the workspace root: a symlink pointing out of the
  workspace is refused, never followed, and files larger than 64,000 characters
  are truncated with a marker. `--no-project-context` disables discovery.

- **`.northstar/agents/*.md`** — repository-defined subagents. Frontmatter
  (`name`, `description`, `tools`, optional `read_only`, `permission_mode`
  limited to `default`/`plan`, ceilings no higher than the built-in limits,
  `model`, `allow_delegation`, `require_verdict`) plus the markdown body as the
  agent's prompt:

```markdown
---
name: summariser
description: Summarises files and directories concisely.
tools: [Read, Grep, LS]
read_only: true
max_turns: 4
---
Summarise what the workspace contains: key files, purposes, and conventions.
```

  The compiled agent joins the registry exactly like a built-in: usable with
  `--agent summariser`, delegatable through `Task` under the existing
  delegation gate, listed by `cli agents --workspace .`. Names may not shadow
  a built-in agent; `read_only` only ever narrows the tool set;
  `--no-workspace-agents` disables discovery for one run.

- **`.northstar/skills/*/SKILL.md`** — Agent Skills, consumed read-only with
  progressive disclosure: only each skill's `name` and `description` are placed
  in the system prompt (a few tokens), and the model reads the full file with
  the ordinary sandboxed `Read` tool when a task matches. A skill file is
  text - it is never an execution or permission channel - and everything is
  resolved strictly inside the workspace root (symlinks out are refused).
  `--no-skills` disables the listing.

`doctor` and `run --dry-run` both report which files apply, so a run never
surprises: `policy_file=`, `project_context=`, `workspace_agents=`, and
`skills=` lines show the effective inputs before anything is sent.

## Attribution and the Run Contract bridge

`--run-id` sets one correlation key for the whole run: it appears in the `init`
event - which the session transcript and the `sessions export` audit feed both
carry - and as the sidecar `request_id`, so a runtime transcript and a sidecar log
line can be joined without guessing at timestamps. The policy file's `revision`
travels with it, and `--dry-run` prints both plus the effective `protected_prefixes`.

`contract_bridge` is the single definition of the runtime-to-sidecar boundary: the
three wire fields come from the same place the run contract narrows a verified run
to, and `tests/test_contract_bridge.py` pins runtime, contract adapter, and sidecar
validator to that one set. When a host injects a Run Binding
(`NORTHSTAR_RUN_BINDING`, `NORTHSTAR_HOST_KEY`, `NORTHSTAR_RUN_REQUEST`) the client
re-derives its own request through the contract and **refuses the call** if the two
disagree or the binding cannot be verified - with no SDK optional-dependency cost
when they are absent, because the runtime stays importable on a bare interpreter.

The sidecar still authenticates callers through Unix permissions only: it holds no
host key, so it cannot verify a binding on the wire. Closing that last gap means
changing the sidecar's request allowlist (the very thing that makes it refuse
capabilities), which is a protocol decision for maintainers, not a silent edit.

## Providers and models

Three providers, one governed loop. The model is swappable; the gate is not.

| `--provider`  | what it is                                                     |
| ------------- | -------------------------------------------------------------- |
| `scripted`    | replays a JSON script of turns - the offline default every test runs on |
| `anthropic`   | the Messages API (`anthropic` SDK, lazy import, non-streaming) |
| `openai`      | the Chat Completions wire: OpenAI, Azure, vLLM, SGLang, Ollama, LM Studio, LiteLLM, OpenRouter and any gateway that speaks it |

`--provider openai` translates both directions on every call: the transcript's
`tool_use` blocks become `tool_calls` with JSON-encoded `arguments`, `tool_result`
blocks become `role: "tool"` messages carrying `tool_call_id`, `finish_reason`
becomes the runtime's own stop vocabulary, and `prompt_tokens_details.cached_tokens`
lands on `cache_read_input_tokens` so the cost view stays comparable across
backends. Four decisions worth knowing:

- **`thinking` blocks are dropped from the request, never from the transcript.**
  Pasting a chain of thought into `content` would feed it back as user text.
- **Non-JSON `arguments` fail the turn** (`ProviderError`, reported as an event).
  Coercing them to `{}` would execute a truncated call as a real write.
- **`--model` is validated against `--provider` before any request**: a `claude-*`
  id on the chat wire (or a `gpt-*` id on the Messages API) is a guaranteed 400, so
  it exits `64` without reading a credential or spending a turn.
- **Price is never invented.** An unknown model id falls through to the
  conservative tier and the result says `pricing_estimated: true`; a budget cap acts
  on that number, so over-estimating is the safe direction.

The key comes from the environment only (`OPENAI_API_KEY`, `OPENAI_BASE_URL`) - a
flag would put a credential in the process list and in CI logs. A `base_url` with no
key still works, because local servers ignore it while the SDK demands one.

## Postconditions: verifying the work, not the claim

A run ending `success` has always meant only *the model stopped asking for tools*.
`--verify KIND:PATH[:TEXT]` (and `[[verify]]` in `.northstar/config.toml`) declares
a claim about the workspace that **this process** checks after the run:

| kind        | holds when                                                   |
| ----------- | ------------------------------------------------------------ |
| `exists`    | the path is a regular file at the end of the run             |
| `absent`    | the path is gone at the end of the run                       |
| `changed`   | its bytes differ from the pre-run snapshot (a new file counts)|
| `unchanged` | its bytes are identical to the pre-run snapshot              |
| `contains`  | the text appears at least `count` times (default 1)          |

```console
$ northstar-agent-runtime run --verify exists:report.md --verify unchanged:uv.lock
· postconditions: 1 of 2 check(s) failed
[error_postconditions_failed] turns=1 tool_calls=0 cost=$0.000000     # exit 6
```

The rules that make this governance rather than a linter:

- **The conditions are never injected into the prompt.** A model told that
  `report.md` must contain "all tests pass" will write exactly that and nothing
  else. They live in the config and the audit stream; the model is not consulted.
- **`unchanged` is the enforceable one for a review run**, because it constrains
  what the run may *not* do - and the tool layer, not the model, decides that.
- **`contains` is a convenience, not proof.** The structural kinds
  (`exists`/`absent`/`changed`/`unchanged`) are what a report should be signed off
  on; for "the tests actually pass", declare a `Stop` command hook that runs the
  test script - it can veto finishing, and it is a vetted script, not a shell.
- **Digests are taken before the first event**, so neither a hook nor a tool can
  redefine "before". A symlink or a path that resolves outside the workspace is
  refused at configuration time (exit 64): evidence from outside the boundary is
  not evidence about this run.
- **A repository may add a check and can never remove one**: `[[verify]]` and
  `--verify` merge additively, and evaluation only reads.

The verdict is its own audit record (`type: "postconditions"`, 12th `RECORD_TYPES`
entry, rendered by `examples/session-panel`), so an archive proves what was checked
and what held - independently of anything the assistant said.

## Events, not exceptions

A run yields the event vocabulary the surrounding host already knows:
`SystemMessage` (`init`, `compact_boundary`, `informational`, `postconditions`), `AssistantMessage`,
`UserMessage`, and exactly one `ResultMessage` per run. Every foreseeable
condition arrives as an event, never as a raised exception:

| `ResultMessage.subtype`     | meaning                                             |
| --------------------------- | --------------------------------------------------- |
| `success`                   | the model stopped asking for tools                  |
| `error_max_turns`           | `max_turns` reached                                 |
| `error_max_tool_calls`      | `max_tool_calls` reached                            |
| `error_max_budget_usd`      | `max_budget_usd` reached                            |
| `error_permission_denied`   | a denial ended the run (`halt_on_denial`)           |
| `error_postconditions_failed` | the model stopped, but a declared workspace check did not hold |
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

### Hooks a repository may declare

The same events can be wired from `.northstar/config.toml` instead of Python, so a
policy review in a pull request is the whole change:

```toml
[[hooks]]
event = "PreToolUse"
script = ".northstar/hooks/gate.py"   # workspace-relative; never a shell line
interpreter = "python3"                # optional; allowlist, no path separators
tool = "Write"                         # optional matcher: fire for one tool only
timeout_ms = 2000
```

The hook receives the event JSON on stdin and may print one verdict JSON on stdout
(`{"decision": "deny", "reason": "..."}`, coerced by the same rules as a Python
handler). Exit code 2 denies with stderr as the reason.

What makes this safe enough to enable, and what it deliberately is not:

- **Off by default.** `--enable-workspace-hooks` is required; `doctor` and
  `--dry-run` both report declared-but-ignored hooks. Cloning a repository must
  not mean executing it.
- **Veto-capable events only** (`PreToolUse`, `UserPromptSubmit`, `SessionStart`,
  `PreCompact`, `SubagentStart`). A repository file may add a veto, never a power:
  declaring `PostToolUse` is a configuration error, not an ignore.
- **No shell, no arguments, no environment.** There is no `command` key to inject
  into; `;`, `|`, `&&` and `$( )` cannot be expressed. The child gets `PATH`/`LANG`
  only, so model credentials never cross into hook code.
- **Bounded and reaped.** Output caps, a 100 ms–10 s timeout, and TERM-then-KILL of
  the whole process group. A hang or a crash is a denial on a veto event.

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
  generated even when nothing is persisted. `sessions export <session-id>` (with
  `--session-dir`) replays one transcript to stdout as the canonical NDJSON
  audit feed `audit.ndjson/1` — denials, failed tool results and `error_*`
  results carry `"level":"error"`; see
  [audit trail concept](../../docs/concepts/audit-trail.md).
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
the workspace root, then (for writes) protection of `.git` and `.northstar`.
Symlinks are followed *before* the check, and a path that does not exist yet is
checked through its existing parents, so `link/../../etc/passwd` cannot smuggle a
write out.

**The agent cannot rewrite its own governance.** `.northstar` holds the policy
file, the repository subagent definitions, and the skill packages that reach the
system prompt, so it is write-refused for `Write`/`Edit` by default. A policy file
may only ever tighten, so a rewrite could not install `bypassPermissions` - what it
*could* do is drop existing tightenings for every later run, plant a poisoned skill
or agent file, or corrupt the file so the workspace refuses to start. All three are
refused here rather than detected later. `--allow-policy-writes` opens the tree for
one run when a human means it, and the effective set is recorded in the `init`
event (`protected_prefixes`), so the audit transcript shows which rule applied.

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
| `providers/`        | `base` (events + contract), `anthropic`, `openai_compat`, `scripted` |
| `command_hooks.py`  | repository-declared command hooks: vetted scripts, veto events only, never a shell string |
| `contract_bridge.py`| request-id derivation and the run-document cross-check on the sidecar boundary |
| `postconditions.py` | independent end-of-run workspace checks (`exists`/`absent`/`changed`/`unchanged`/`contains`) |
| `cli.py`            | one governed run from a shell, with distinct exit codes              |
| `doctor.py`         | `cli doctor` environment self-checks (no requests, no file writes)   |
| `session_view.py`   | `cli sessions list/show` - the read-back half of the transcripts     |
| `policy_file.py`    | `.northstar/config.toml` parsing + tighten-only validation; AGENTS.md project-context discovery and prompt composition |
| `agent_files.py`    | `.northstar/agents/*.md` -> governed `AgentDefinition` compilation   |
| `skills.py`         | `.northstar/skills/*/SKILL.md` discovery + progressive-disclosure listing |
| `frontmatter.py`    | strict minimal frontmatter reader shared by agents and skills        |
| `mcp_client.py`     | minimal MCP stdio client: handshake, tool listing, bounded calls, process-group cleanup |
| `audit_export.py`   | transcript replay as the canonical NDJSON audit feed (`audit.ndjson/1`)      |
| `events.py`         | public event vocabulary: `event_to_dict` shapes + result `EXIT_CODES` |
| `sdk.py`            | Python API: `RunOptions` / `run` / `stream_run` / `RunReport`       |
| `scaffold.py`       | `new` project generator: governance-default template files   |
| `_version.py`       | single source of truth for the component version                     |

## Exit codes

`0` success · `1` error_during_execution · `2` error_max_turns ·
`3` error_max_tool_calls · `4` error_max_budget_usd · `5` error_permission_denied ·
`6` error_postconditions_failed · `64` usage or configuration error (nothing was run). Result errors and refusals
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
- **MCP is a minimal stdio client.** Only tool discovery and calls are
  implemented (protocol `2024-11-05`), verified against an offline fixture
  server; no sampling/roots/prompts, no reconnect, and no vendor server has
  been exercised here.
- **Process-group `TERM`→`KILL` cleanup is not verified on real Linux here.** That
  behaviour belongs to the sidecar; the runtime only bounds its own socket read.
- Session transcripts are a local audit trail, not a compliance store: there is no
  signing, no retention policy, and no tamper evidence.
- Cost accounting is arithmetic on provider-reported usage. It cannot see retries
  the SDK swallowed, and it never predicts a price for a model the table lacks
  without saying so.
- `permission_mode` and the hooks are in-process. They constrain this runtime, not
  a hostile process on the same machine.
