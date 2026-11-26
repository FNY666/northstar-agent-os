# Northstar ACP Adapter (`northstar acp`)

`northstar acp` exposes the governed Northstar runtime as a standard **Agent Client Protocol (ACP v1)** coding agent over newline-delimited JSON-RPC 2.0 on `stdin`/`stdout`.

It is intentionally a **thin protocol adapter** over `sdk.stream_run()`, not a second agent loop. Every turn from an ACP-compatible editor (such as Zed, JetBrains IDEs, or Android Studio) crosses the exact same Northstar permission gate, ceilings, workspace path containment, append-only hash-chained session store, and optional digest-first evidence sink.

## Quick start

Validate configuration without starting the stdio loop:

```sh
bin/northstar acp --dry-run \
  --workspace /path/to/repo \
  --permission-mode default \
  --max-turns 15 \
  --max-budget-usd 1.00 \
  --run-evidence-dir /tmp/northstar-acp-evidence
```

Start an offline deterministic ACP stdio server (no API key required):

```sh
bin/northstar acp \
  --workspace /path/to/repo \
  --provider scripted \
  --scripted-text "Hello from governed Northstar." \
  --permission-mode default
```

Start with an Anthropic or OpenAI-compatible provider, interactive editor approvals, and CaMeL untrusted-data taint isolation (credentials stay in the host environment; `authMethods` is always `[]`):

```sh
northstar acp \
  --workspace /path/to/repo \
  --provider anthropic \
  --permission-mode default \
  --interactive-permissions \
  --dataflow-policy camel \
  --max-turns 20 \
  --max-budget-usd 2.00 \
  --run-evidence-dir ~/.local/state/northstar/acp-evidence
```

### Example Zed `settings.json` entry

```json
{
  "agent_servers": {
    "Northstar": {
      "command": "northstar",
      "args": [
        "acp",
        "--workspace", "/abs/path/to/repo",
        "--provider", "anthropic",
        "--permission-mode", "default",
        "--interactive-permissions",
        "--dataflow-policy", "camel",
        "--max-turns", "20",
        "--max-budget-usd", "2.00"
      ]
    }
  }
}
```

## Supported ACP v1 methods and notifications

| Direction | Method | Behavior |
|---|---|---|
| Client → Agent | `initialize` | Negotiates integer `protocolVersion: 1`; advertises `loadSession: true`, `promptCapabilities.embeddedContext: true`, `image: false`, `audio: false`, `mcpCapabilities: {http: false, sse: false}`, `authMethods: []`. |
| Client → Agent | `session/new` | Validates absolute existing `cwd` (confined to `--workspace` when set), refuses non-empty `mcpServers`, returns `sessionId` and tighten-only `modes`. |
| Client → Agent | `session/load` | Verifies the persisted session's cryptographic hash chain (`require_integrity=True`), replays historical `user_message_chunk` / `agent_message_chunk` notifications, and resumes on the next prompt. |
| Client → Agent | `session/set_mode` | Allows tightening within `acceptEdits -> default -> plan`; refuses widening or `bypassPermissions`. Emits `current_mode_update`. |
| Client → Agent | `session/prompt` | Streams `agent_message_chunk`, `tool_call`, `tool_call_update`, `plan` (when `SubmitPlan` runs), and `usage_update`, then resolves with ACP `stopReason` (`end_turn`, `max_turn_requests`, `max_tokens`, `refusal`, `cancelled`) plus `_meta.northstar`. |
| Client → Agent | `session/cancel` | Notification that interrupts an in-flight `session/prompt` worker thread (and cancels any pending `session/request_permission` waiter fail-closed) so the pending request resolves with `stopReason: "cancelled"`. |
| Agent → Client | `session/request_permission` | Opt-in (`--interactive-permissions`): routes per-call host approvals (mutating tools in `default` mode and CaMeL/dataflow escalations) to the editor with `allow_once` / `reject_once` and `_meta.northstar.argumentsDigest`. Hard denials (`plan`, `--read-only`, `--deny-tool`, path escapes) never ask; timeout or client disconnect fails closed. |

## Governance invariants enforced at the ACP boundary

1. **Single governance kernel**: every turn executes through `sdk.stream_run(RunOptions(...))` — default-deny `Shell`, protected `.git`/`.northstar` prefixes, workspace path containment, turn/tool/USD ceilings, and sandbox policy remain host-owned.
2. **Policy may only tighten**: `bypassPermissions` is never exposed over ACP. Clients cannot escalate beyond `--permission-mode` and cannot re-widen a session once narrowed via `session/set_mode`.
3. **Per-call approval binding (no blanket caching)**: when `--interactive-permissions` is enabled, `session/request_permission` binds approval to a single `(call_id, argumentsDigest)` pair via Northstar's `can_use_tool` gate and offers only `allow_once` / `reject_once`. Every subsequent mutating or tainted call asks fresh.
4. **CaMeL cross-tool & cross-subagent dataflow taint (`--dataflow-policy camel | camel-strict`)**:
   - `camel` (`DataflowPolicy.camel_default()`): keeps the default confidentiality + audience rules and adds integrity taint on external untrusted sources (`Fetch`, `mcp__*`, `mcp/*`). Once tainted, privileged sinks (`Shell`, `RunCheck`, `Edit`, `Write`, `ApplyPatch`, `Fetch`, `Task`, `mcp__*`) escalate to `session/request_permission` (or fail closed without `--interactive-permissions`).
   - `camel-strict` (`DataflowPolicy.camel_strict()`): additionally treats workspace content reads/searches (`Read`, `Grep`, `SearchCode`, `GitInspect`, `RepoMap`) as untrusted inputs for untrusted repositories while leaving control-plane planning (`SubmitPlan`) clean.
   - Taint propagates bidirectionally across `Task` subagents (parent → child and child → parent) and conservatively marks resumed sessions as tainted so taint cannot be washed across delegation or resume.
5. **Isolated Git-worktree coding mode (`--code-worktree`, `--keep-worktree`)**:
   - When `--code-worktree` is enabled, `session/new` fails closed (`-32602`) on non-Git directories, prepares a detached `IsolatedCodeWorkspace`, and seals a non-executing `admission.json` (`northstar.repository-admission.v1`) receipt before any model turn runs.
   - Every turn runs inside the detached worktree so the editor's live checkout stays untouched. After each turn, `audit_delivery_patch()` checks for BenchJack startup hooks (`sitecustomize.py`), `.mcp.json` poisoning, `.git`/`.northstar` writes, and secret leaks, writes `changes.patch`, and demotes `stopReason` to `"refusal"` if the audit fails.
   - On server exit, worktrees are automatically cleaned up unless `--keep-worktree` is passed.
6. **Client-supplied `mcpServers` refused fail-closed**: non-empty `mcpServers` in `session/new` or `session/load` return JSON-RPC `-32602`. MCP servers remain host-operator policy.
7. **Tamper-evident session continuity & digest-first evidence**: `session/load` verifies the session JSONL hash chain (`SessionStore.transcript(..., require_integrity=True)`). Passing `--run-evidence-dir <dir>` writes a sealed `northstar.runtime-evidence-manifest.v1` bundle (`manifest.json`, `ledger.jsonl`, `audit.ndjson`) per turn under `<dir>/<sessionId>/turn-NNNN`.
8. **Bounded wire parsing**: inbound JSON-RPC lines are capped at `1 MB`, container nesting depth at `128`, and embedded text resources at `64 KB` with explicit untrusted-data framing.

## Explicit non-goals of this prototype

- Does **not** delegate filesystem writes or shell execution back to client-side `fs/*` or `terminal/*` callbacks (Northstar's own governed tools and sandbox remain the sole execution authority).
- Does **not** accept image/audio content blocks or binary resource blobs (`promptCapabilities.image = false`, `audio = false`).
- Does **not** replace `northstar code` for batch host-owned `--check` verification gates and delivery-seal replay.

## Ready-to-use editor templates & offline smoke test

Copyable Zed (`agent_servers`) and Neovim (`codecompanion.nvim` / generic stdio)
configurations plus a zero-API-key offline smoke script live in
[`examples/acp/README.md`](../../examples/acp/README.md):

```sh
python3 examples/acp/smoke_offline.py
```
