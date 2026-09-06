# Northstar Agent Runtime

A governed agent loop modelled on the Claude Agent SDK's capability surface. The runtime does **reasoning and policy**; execution that needs the Codex CLI is delegated over a Unix socket to [`northstar-codex-sidecar`](../northstar-codex-sidecar/README.md) (the `CodexReadOnly` tool, registered only when a socket path is configured). The runtime never spawns a model CLI and holds no model credentials.

## Files

- `loop.py` — the agent loop, tool dispatch, subagent spawning, and the event types (`SystemMessage`, `AssistantMessage`, `UserMessage`, `ResultMessage`).
- `hooks.py` — the ten governance hooks; the first deny is terminal.
- `permissions.py` — three-tier gate: `disallowed_tools` → `allowed_tools` → `permission_mode` + optional `can_use_tool`.
- `budget.py` — real per-million-token pricing with prompt-cache read discount (0.1x) and write premium (1.25x); unknown models fall back to conservative pricing flagged `pricing_estimated`.
- `tools.py` — sandboxed built-in tools. One handler signature everywhere: `handler(payload, ctx)`. Paths are resolved (symlinks followed) **before** the containment check. Caps: read 256 KiB, grep 200 matches, list 500 entries.
- `compaction.py` — compaction only at safe boundaries (no orphaned `tool_use` without its `tool_result`).
- `sessions.py` — append-only JSONL, `fsync` per write, truncated last line skipped on load.
- `agents.py` — subagent definitions, including `evaluator_agent()` (read-only, default-FAIL acceptance semantics).
- `tracing.py` — OpenTelemetry spans: `run → turn[n] → generation | tool:Name | subagent:Type`. No prompt or tool-output text is recorded; only `tool.is_error` and cost/usage attributes, always set before the span ends.
- `sidecar_client.py` — zero-dependency Unix-socket client for the sidecar.
- `cli.py` — command-line entry; offline via `--script`.
- `providers/base.py`, `providers/anthropic.py`, `providers/scripted.py` — provider abstraction, Anthropic adapter (lazy SDK import), deterministic offline provider.

## Semantics

- **Events.** A run emits `SystemMessage(subtype=init)` first and **exactly one** `ResultMessage` last. Subtypes: `success`, `error_max_turns`, `error_max_tool_calls`, `error_max_budget_usd`, `error_during_execution`, `error_permission_denied`. Foreseeable failures are events, not exceptions.
- **Hooks.** `PreToolUse` (deny or rewrite input), `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit` (inject context or deny the whole run), `Stop` (deny = refuse the end; the reason is fed back as a new user turn), `SubagentStart`, `SubagentStop`, `PreCompact`, `SessionStart`, `SessionEnd`. A deny is terminal: later hooks are not called and cannot overturn it; a hook that raises is treated as a deny.
- **Permissions.** `default` mode denies mutating tools unless the host supplies a `can_use_tool` callback — failing safe is refusing, never executing. `acceptEdits` auto-approves edits only. `plan` denies mutating tools outright. `bypassPermissions` passes everything except `disallowed_tools`, which always win. `Task` is never judged by its own name: the subagent's *declared* tool set is gated one tool at a time, and denials name the offending tool.
- **Limits.** `max_turns`, `max_tool_calls`, `max_budget_usd` are independent, each with its own ResultMessage subtype. When a generation exhausts the budget, that generation's pending tool calls are **not** executed.
- **Subagents.** Independent context, tool subset, own turn/budget limits, optional different provider/model. Nesting is off by default; `max_subagent_depth` is the backstop.
- **Sessions.** A `session_id` is generated even when no session store is configured, so logs always correlate.

## Quick start

```sh
cd components/northstar-agent-runtime
pip install -r requirements.txt -r requirements-tracing.txt
python -m unittest discover -s tests -p 'test_*.py' -v
```

Offline run with the CLI (no API key):

```sh
python cli.py --prompt "hello" --workspace /tmp/agent-ws \
  --script <(echo '[{"text":"hi"}]')
```

## Known limitations

- The real Anthropic API is **not** verified here: the sandbox has no API key, so `providers/anthropic.py` is tested only for request construction and response normalisation against fakes.
- MCP is **not** implemented.
- The sidecar's process-group TERM→KILL cleanup is inherited from the sidecar component and was not re-verified on native Linux by this component's tests.
