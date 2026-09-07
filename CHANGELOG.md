# Northstar Agent OS — initial public component

## Unreleased (fourth batch) — minimal MCP stdio client

- **MCP stdio client** (`northstar-agent-runtime`, experimental). `--mcp-server
  NAME=COMMAND...` (repeatable) connects one Model Context Protocol server as a
  child process speaking JSON-RPC 2.0 over stdio; `--mcp-timeout-ms` bounds each
  request. The handshake (`initialize` → `notifications/initialized` →
  `tools/list`) runs under the deadline, and a server that stops answering is
  TERM→KILLed as a process group (client-side line/call caps bound output).
- **Governed by default:** every remote tool registers as
  `mcp__<server>__<tool>` with `kind="other"`/mutating-by-default, so under the
  `default` permission mode it is denied until `--allow-tool` names it; policy
  files may deny `mcp__*` names ahead of connection (forward-looking, like
  `CodexReadOnly`); all calls still cross the gate and fire hooks. MCP is a
  tool transport, never a policy bypass.
- **Fail-closed CLI:** an unreachable server, a bad `NAME=`, a server that
  exceeds the tool/schema caps, or `--mcp-server` combined with `--agent` (an
  agent run's tool subset is fixed) are configuration errors (exit 64).
  `--dry-run` and `doctor` list configured servers without spawning them.
- Verified offline against `tests/fixtures/mcp_echo_server.py` (pure stdlib),
  including timeout, error-result, and process-group cleanup paths. Runtime
  tests 470 → 488.

## Unreleased (third batch) — repository agents and skills

- **Repository-defined subagents (`.northstar/agents/*.md`)**. A markdown file
  with strict frontmatter (`name`, `description`, `tools`, optional `read_only`,
  `permission_mode` limited to `default`/`plan`, ceilings no higher than the
  runtime's built-in limits, `model`, `allow_delegation`, `require_verdict`)
  and a prompt body compiles into the same `AgentDefinition` a built-in agent
  uses: runnable with `--agent`, delegatable through `Task` under the existing
  delegation gate, listed by `cli agents --workspace`. Names may not shadow a
  built-in agent or another file; `read_only` only narrows the tool set;
  unknown keys, unknown tools, loosening modes/ceilings, unparseable
  frontmatter, and symlinks escaping the workspace are configuration errors
  (exit 64) — never silently ignored. `--no-workspace-agents` skips discovery.
- **Agent Skills, read-only (`.northstar/skills/*/SKILL.md`)**. Progressive
  disclosure: only each skill's `name` and `description` enter the system
  prompt; the model reads the full file with the ordinary sandboxed `Read`
  tool when a task matches. Skill files are knowledge, not an execution or
  permission channel; everything resolves strictly inside the workspace root.
  `--no-skills` disables the listing.
- **Strict frontmatter reader** (`frontmatter.py`): a dependency-free subset of
  YAML frontmatter shared by both file types, with duplicate/malformed/unknown
  content failing closed.
- **Visibility:** `doctor` and `run --dry-run` report `workspace_agents=` and
  `skills=` lines; the demo workspace now ships one repository agent and one
  skill. Tests: runtime suite grows to 470 offline tests (24 new across
  frontmatter, skills, agent files, and CLI integration).

## Unreleased (second batch) — repository policy and project context

- **`.northstar/config.toml` workspace policy file** (`northstar-agent-runtime`).
  A repository that ships one pins the run's defaults; it may only ever
  *tighten*: `permission_mode` limited to `default`/`plan`, `allow_tools`
  rejected (approvals stay per-run CLI decisions), ceilings may only lower the
  built-in values, denials and `read_only` are an additive floor that even
  `--allow-tool` cannot resurrect, and file denials stay terminal in the
  permission gate's first layer. Unknown keys, unreadable TOML, unknown tool
  or agent names, and loosening values are configuration errors (exit 64) —
  policy is never silently ignored. When both the file and the CLI set a
  ceiling, the lower wins; `halt_on_denial` is true if either says so;
  `--no-policy-file` skips the file for one run.
- **Project context (`AGENTS.md`)**. A `AGENTS.md` in the workspace root (or the
  file named by the policy's `project_context`, or an explicit `--context-file`)
  is appended to the system prompt behind a clear delimiter. Discovery resolves
  strictly inside the workspace root — a symlink pointing out is refused, never
  followed — and oversized files are truncated with a marker.
  `--no-project-context` disables discovery.
- **Visibility:** `cli doctor` and `run --dry-run` report the effective
  `policy_file=` and `project_context=` inputs before anything is sent; a
  policy error fails a dry run exactly as it fails a real run.
- **Demo:** `examples/demo/workspace/` now carries an `AGENTS.md` showing the
  convention. Tests: 446 offline runtime tests green; the tighten-only limits
  are asserted to stay in sync with the loop's built-in defaults.

## Unreleased — DX foundations: installable packages, CLI self-checks, session read-back

Phase 0–1 of the DX roadmap (see `docs/dx-benchmark-2026.zh-CN.md` for the full
analysis and remaining phases). Everything below is additive; no runtime
semantics changed.

- **All six components are pip-installable.** Each `components/*/pyproject.toml`
  declares `version = "0.1.0.dev0"`, real dependencies, and flat-module layouts
  that match the existing in-tree names. The agent runtime additionally ships a
  `northstar-agent-runtime` console script with lazy SDK imports (`[anthropic]`,
  `[tracing]`, `[full]` extras; no hard dependency).
- **The `tools.py` / `tools/` name collision is gone.** The module moved into
  `tools/__init__.py`, so `import tools` and `import tools.verify_invariants`
  both resolve; the guard-verification harness now mutates
  `tools/__init__.py` and runs in CI.
- **Dependencies are declared, not spliced.** `northstar-host` depends on
  `northstar-run-contract`; `northstar-durable-run` and `northstar-agent-interop`
  depend on both. All `PYTHONPATH=` prefixes are gone from CI and the Makefile
  (the test modules bootstrap sibling paths themselves); CI installs by
  dependency chain and runs a packaging smoke per component; `make install`
  builds one virtualenv with every component.
- **New CLI surface (`python3 -m cli`):** `--version` (single source
  `_version.py`), `doctor` (side-effect-free environment self-check; fails on
  broken checks, warns on missing optional SDKs), `run --dry-run` (prints the
  resolved tools/allow-deny/ceilings/pricing and exits without constructing the
  provider or sending a request), and `sessions list|show [--json]` (read-only
  read-back of the append-only audit transcripts). `--probe-sidecar` with the
  live provider now explains how to install the missing SDK instead of
  tracebacking.
- **One-line offline demo:** `make demo` (or `sh examples/demo/run_offline.sh`)
  runs a full governed loop with a tool call, policy, ceilings, and an audit
  transcript — no API key, no network, no SDK.
- **CI-only read-only review recipe:** `examples/ci-readonly-review/` — governed
  PR review with `--read-only`, turn and dollar ceilings, `--halt-on-denial`,
  and a session transcript kept outside the reviewed workspace; includes a
  GitHub Actions template and the exit-code contract.
- **Releasing guide** added to `CONTRIBUTING.md` (dependency-graph release
  order, immutable tags, semantic majors for contract components).
- Tests: 621 offline tests green across the repository (agent runtime 413,
  including 4 skipped where the SDK is absent); the five-guard invariant
  harness turns each reverted guard red and keeps the untouched copy green.


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
