# Northstar Agent OS — initial public component

This repository establishes the Northstar Agent OS name and publishes five independently maintained components: Northstar Codex Sidecar, the Northstar Run Contract, the Northstar Agent Runtime, host-side candidates, and backend-neutral Agent Interop foundations.

## Agent Runtime (unreleased)

- **Governed agent loop with the Claude Agent SDK capability surface:** `SystemMessage` / `AssistantMessage` / `UserMessage` events and exactly one `ResultMessage` per run, whose subtype distinguishes `success` from `error_max_turns`, `error_max_tool_calls`, `error_max_budget_usd`, `error_permission_denied`, and `error_during_execution`. Every foreseeable condition is an event; a foreseeable failure never reaches the caller as an exception.
- **Reasoning here, execution there:** the runtime holds no Codex credentials and never spawns a model CLI. The `CodexReadOnly` tool is registered only when a sidecar socket path is supplied, and one request travels over one private Unix-socket connection to `components/northstar-codex-sidecar`.
- **Ten lifecycle hooks** with a uniform handler signature: `PreToolUse` (veto or rewrite input), `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit`, `Stop` (may refuse to stop and feed its reason back), `SubagentStart`, `SubagentStop`, `PreCompact`, `SessionStart`, `SessionEnd`. A deny is terminal — later hooks cannot overturn it — and a hook that raises on a veto-capable event fails closed.
- **Three permission layers in a fixed order:** `disallowed_tools` always wins, then `allowed_tools`, then `permission_mode` plus the optional host `can_use_tool` callback. Under `default`, a mutating tool with no approval callback is denied rather than executed.
- **Three independent ceilings** (`max_turns`, `max_tool_calls`, `max_budget_usd`), priced from real per-million-token rates including cache-read 0.1× and cache-write 1.25×; an unknown model falls back to conservative pricing and marks `pricing_estimated`.
- **Subagents** with their own context, declared tool subset, ceilings, and optionally a different provider. Delegation is gated per tool the subagent declared, never by the literal name `Task`; nested delegation is off by default with `max_subagent_depth` as a backstop. The built-in `evaluator_agent()` is read-only and default-FAIL.
- **Append-only JSONL sessions** with an `fsync` per write, `0600` files under a `0700` directory, and a truncated final line skipped rather than treated as corruption. A session id is generated even when nothing is persisted.
- **Compaction that only cuts at a safe boundary** with no pending tool call, so a summary can never orphan a `tool_use` from its `tool_result` and produce an API 400 the model cannot recover from.
- **Span tracing** as `run → turn[n] → generation | tool:Name | subagent:Type` with cost attributes, recording usage before the span ends (OpenTelemetry discards a late attribute write silently) and never recording prompt text or tool output bodies.
- **Sandboxed tools** with symlink-resolution-before-containment-check, plus caps of 256 KB per `Read`, 200 matches per `Grep`, and 500 entries per `LS`, each announced in the tool result itself.
- **383 offline tests**, including an integration test that starts the real sidecar `serve()` on a temporary Unix socket and pushes a 100,000-Chinese-character prompt through a full agent loop. Each core invariant has been verified to fail when its guard is individually reverted.
- **Known gaps:** the live Anthropic API is unverified in this repository's sandbox (only an injected fake client is exercised), MCP is not implemented, and process-group `TERM`→`KILL` cleanup is not verified on real Linux here. See `components/northstar-agent-runtime/README.md`.

## Run Contract foundation

- **Versioned Run Request:** strict schema, bounded IDs and prompt, timeout limits, task-kind allowlist, and requested-capability syntax.
- **Versioned Run Receipt:** explicit statuses and postcondition verdicts (`verified`, `failed`, `unknown`).
- **Authenticated Run Binding:** expiring HMAC-SHA256 binding for `run_id`, `actor_id`, and `workspace_id`; host-key possession is kept separate from authorization.
- **Strict Sidecar adapter:** only `request_id`, `prompt`, and `timeout_ms` cross the legacy Sidecar boundary; unknown fields and unverified bindings are rejected.

The contract is a local foundation, not a production authorization or workspace broker. Native Linux deployment, caller identity, per-run workspace creation, and policy grants remain separate host-level responsibilities.

## Fixes since the initial component

- **`CODEX_HOME` is no longer double-nested under systemd.** The unit set `CODEX_HOME=/var/lib/northstar-codex/codex-home` while the sidecar appended a second `/codex-home`, so Codex looked for credentials in a directory the host never populated. `CODEX_HOME` is now passed to the child verbatim, and the workspace default is decoupled from it so run inputs and credentials never share a directory. Tests assert the unit's `Environment=` lines against `service.service_config()`.
- **A maximum-length prompt is no longer rejected by framing.** The socket reader capped input at 200,000 bytes while the validator capped the prompt at 100,000 characters, so a 100,000-character CJK prompt (300,054 bytes raw, 600,182 bytes as `\uXXXX` escapes) came back as `invalid or oversized request`. The wire cap is now derived from the prompt cap and covers both serialisations.
- **`serve()` enforces the socket path contract.** `service.validate_socket_path` was previously asserted only in tests; the listener now refuses to bind any path it rejects, and does so before creating a socket file.
- **`install.sh` produces a startable service.** It now requires root, creates the `northstar-codex` system account and the `/var/lib/northstar-codex` state directories, normalises `PATH` so the sbin account tools are found, warns when `codex` is absent, and is idempotent. Both lifecycle scripts are now mode `0755` so the documented `sudo ./install.sh` works from a fresh clone.

## Host-side local candidates

- **Host authorization and workspace candidate:** `components/northstar-host/`
  adds explicit actor-to-capability default-deny policy grants and
  host-derived opaque `0700` workspace allocation. It re-verifies the Run
  Binding and grant at allocation time and never executes commands.
- **Durable Run vertical slice:** `components/northstar-durable-run/` adds a
  local candidate for canonical task/run/step/event identity, append-only
  replayable history, checkpoints, leases, per-call action gates, independent
  postcondition verification, minimal trace metrics, and a deterministic
  10-fixture task-level evaluation harness. Its local suite proves component
  and fixture behavior only; it is not a production scheduler, sandbox, or
  deployment.

These candidates are local-only and have not been deployed to 103, 104, a
dormitory host, or production OpenBot. They are not a complete workspace
broker, sandbox, identity system, or production safety proof. Native Linux
concurrency, filesystem race, lifecycle, and deployment validation remain
outstanding.

- **Agent interoperability candidate:** `components/northstar-agent-interop/`
  adds a backend-neutral signed attestation, narrowed handoff grant, context
  envelope, typed adapter receipt boundary, and a local-only
  `orchestrator → Claude Code → Codex → Hermes` canary. The canary uses fake
  executors only and does not connect real vendor backends.
- **CLI process adapter candidate:** the interop component includes a bounded,
  no-shell process adapter and disabled-by-default specifications for Codex,
  Claude Code, and Cursor. No vendor CLI is installed or authenticated here.

## Scope of this release

- restricted Unix-socket transport;
- bounded request validation;
- read-only, ephemeral Codex execution;
- structured errors and redaction;
- process-group timeout cleanup;
- systemd hardening template;
- deterministic Python tests.

## Explicit non-goals

This is not yet a complete multi-agent operating system, hosted service, or
endorsement of the upstream OpenBot project. Runtime identity binding, per-run
workspace authorization, durable execution integration, native Linux E2E, and
production deployment integration remain host-level responsibilities or future
work.

See [README.md](README.md) for installation and security boundaries.
