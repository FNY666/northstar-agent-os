# Northstar Agent OS — initial public component

This repository establishes the Northstar Agent OS name and publishes three independently maintained foundations: Northstar Codex Sidecar, the Northstar Run Contract, and the Northstar Agent Runtime.

## Agent Runtime foundation

A governed agent loop modelled on the Claude Agent SDK's capability surface, in `components/northstar-agent-runtime/`. The runtime does reasoning and policy; Codex execution stays in the Sidecar (the `CodexReadOnly` tool, registered only when a socket path is configured). The runtime never spawns a model CLI and holds no model credentials.

- **Typed event stream:** `SystemMessage` (init / compact_boundary / informational), `AssistantMessage`, `UserMessage`, and exactly one `ResultMessage` per run, with subtypes `success`, `error_max_turns`, `error_max_tool_calls`, `error_max_budget_usd`, `error_during_execution`, `error_permission_denied`. Foreseeable failures are events, not exceptions.
- **Ten governance hooks:** `PreToolUse` (deny or rewrite input), `PostToolUse`, `PostToolUseFailure`, `UserPromptSubmit` (inject context or deny the whole run), `Stop` (refuse the end; the reason is fed back as a new user turn), `SubagentStart`, `SubagentStop`, `PreCompact`, `SessionStart`, `SessionEnd`. The first deny is terminal; a hook that raises is treated as a deny.
- **Three-tier permissions:** `disallowed_tools` (always wins) → `allowed_tools` (auto-approve) → `permission_mode` (`default` / `acceptEdits` / `plan` / `bypassPermissions`) plus an optional `can_use_tool` callback. In `default` mode, mutating tools are denied unless the host supplies approval — failing safe is refusing, never executing. `Task` is gated per declared subagent tool, never by its own name, so denials name the real offending tool.
- **Independent limits with real pricing:** `max_turns` / `max_tool_calls` / `max_budget_usd` each end the run with their own subtype. Costs use published per-million-token prices with prompt-cache read discount (0.1x) and write premium (1.25x); unknown models fall back to conservative pricing flagged `pricing_estimated`. A generation that exhausts the budget does not execute its pending tool calls.
- **Bounded subagents:** independent context, tool subset, own turn/budget limits, optional different provider. Nesting is off by default; `max_subagent_depth` is a structural backstop that applies in every permission mode. `evaluator_agent()` is read-only with default-FAIL acceptance semantics.
- **Durable sessions:** append-only JSONL with `fsync` per write; a truncated last line is skipped, not an error; a `session_id` is generated even without a store so logs always correlate.
- **Safe-boundary compaction:** cuts only where no `tool_use` would be orphaned without its `tool_result`.
- **Privacy-respecting tracing:** OpenTelemetry span tree `run → turn[n] → generation | tool:Name | subagent:Type`; usage/cost attributes are set before each span ends; no prompt text or tool output text is recorded (only `tool.is_error`).
- **Sandboxed tools:** one uniform `handler(payload, ctx)` signature; paths are resolved (symlinks followed) before the workspace containment check; output caps of 256 KiB (read), 200 matches (grep), 500 entries (list).

The test suite is fully offline and deterministic (scripted provider, no API key) and includes integration tests that start a real Sidecar `serve()` over a real Unix socket, including a 100,000-Chinese-character prompt at the documented maximum. Each core invariant (safe boundary detection, workspace containment, budget enforcement, hook deny terminality, span usage timing) has a dedicated test, verified to fail when the invariant is broken.

**Known limitations:** the real Anthropic API is not verified (no API key in the test environment; the Anthropic provider is tested for request construction and response normalisation against fakes); MCP is not implemented; the sidecar's process-group TERM→KILL cleanup is not re-verified on native Linux by this component.

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

## Scope of this release

- restricted Unix-socket transport;
- bounded request validation;
- read-only, ephemeral Codex execution;
- structured errors and redaction;
- process-group timeout cleanup;
- systemd hardening template;
- deterministic Python tests.

## Explicit non-goals

This is not yet a complete multi-agent operating system, hosted service, or endorsement of the upstream OpenBot project. Runtime identity binding, per-run workspace authorization, native Linux E2E, and production deployment integration remain host-level responsibilities.

See [README.md](README.md) for installation and security boundaries.
