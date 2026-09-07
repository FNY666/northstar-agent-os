# Northstar Agent OS

**Open, reliable, and governed runtime components for autonomous AI coworkers.**

> 中文名：北辰智能体系统

[English](README.md) · [简体中文](docs/README.zh-CN.md) · [繁體中文](docs/README.zh-TW.md) · [日本語](docs/README.ja.md) · [Español](docs/README.es.md) · [한국어](docs/README.ko.md) · [Français](docs/README.fr.md) · [Deutsch](docs/README.de.md) · [Português (Brasil)](docs/README.pt-BR.md) · [Italiano](docs/README.it.md) · [Türkçe](docs/README.tr.md) · [Tiếng Việt](docs/README.vi.md)

**In one sentence:** Northstar is an independently maintained project for assembling governed AI coworkers from explicit routing, local tool boundaries, auditability, and recoverable execution components. **What exists today is the Northstar Codex Sidecar—a restricted local worker adapter—not a finished autonomous-agent operating system.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when this file changes.

## What it is

Northstar is a component-oriented runtime project for developers who want AI coworkers to operate with visible boundaries instead of an unconstrained prompt-and-tools loop. It focuses on small, testable building blocks: a caller-visible contract, constrained execution, structured outcomes, and operational recovery.

The project is built incrementally. A component can be useful on its own, but a component passing its tests does not prove that a complete agent platform is safe or production-ready.

## What is shipped today

This repository currently publishes six complementary components:

- `components/northstar-codex-sidecar/` — a local Unix-socket service that validates requests, runs Codex in read-only mode, bounds input and output behavior, redacts errors, cleans up timed-out process groups, and returns structured statuses.
- `components/northstar-run-contract/` — a versioned Run Request/Receipt contract, expiring HMAC Run Binding, and strict adapter boundary for passing a verified run to the Sidecar.
- `components/northstar-agent-runtime/` — a governed agent loop with events, ten lifecycle hooks, a three-layer permission gate, turn/tool-call/USD ceilings, subagents, append-only sessions, path-level workspace-change receipts, bounded content-addressed checkpoints with inspect/diff/rewind/fork, safe-boundary compaction, and span tracing. It holds no model credentials for Codex and never spawns a model CLI: Codex execution is delegated to the sidecar over its Unix socket, so reasoning and policy stay in the runtime while execution and sandboxing stay in the sidecar.
- `components/northstar-host/` — a standard-library local candidate for explicit host policy grants and opaque private workspaces; it re-verifies binding and authorization and does not execute commands.
- `components/northstar-durable-run/` — a local vertical-slice prototype for canonical Run/Step/Event contracts, append-only history, checkpoints, leases, pause/resume/retry/cancel lifecycle controls, a local inspection/control CLI, per-call action authorization, independent verification, minimal trace metrics, and a deterministic fixture evaluation harness. It is not a production scheduler or sandbox.
- `components/northstar-agent-interop/` — a backend-neutral local candidate for signed Agent attestations, narrowed handoff grants, opaque context envelopes, and typed adapter receipts. It does not yet connect real Codex, Claude Code, Hermes, Cursor, or OpenBot backends.

The Run Contract separates structural validation, host-key authentication, authorization, execution, and postcondition verification. The host and durable-run candidates demonstrate these boundaries locally; neither claims production identity, isolation, or deployment readiness.

The agent runtime is deliberately split from execution in the same way: a `Read`/`Grep`/`LS`/`Write`/`Edit` tool set is confined to a workspace root, and the optional `CodexReadOnly` tool exists only when a sidecar socket path is supplied. Denials, exhausted ceilings, provider failures, and hook vetos are all reported as events in the run's stream, and every run ends with exactly one `ResultMessage` whose subtype says why. Repository context (`AGENTS.md`), policy-as-code, file-defined subagents, portable `SKILL.md` packages, and a minimal governed MCP stdio client are available in the runtime; skills are validated and read-only, and no extension can bypass the gate.

The repository also includes its deterministic tests, a systemd hardening template, a conservative installer, and a rollback script.

## How the sidecar works

The sidecar accepts one JSON request per Unix-socket connection:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

It returns one bounded JSON response:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Important properties:

- Unix socket only; no TCP listener is provided.
- The listener refuses to bind unless the socket path satisfies `service.validate_socket_path`.
- Strict request allowlist: `request_id`, `prompt`, and `timeout_ms`.
- Prompt and timeout bounds. The 100,000-character prompt limit is a character limit, and the wire cap is derived from it, so a maximum-length prompt survives framing whether the client sends raw UTF-8 or `\uXXXX` escapes.
- Codex runs with `--sandbox read-only` and `--ephemeral`.
- Separate process group with TERM-to-KILL cleanup on timeout.
- Per-connection read deadline and bounded worker pool.
- Structured error classes and secret redaction.
- Dedicated service user and systemd hardening template.
- Codex is disabled until the host administrator explicitly installs and enables the service.

## Quick start

**One-line offline demo (no API key, no network, no model SDK):**

```sh
make demo        # or: sh examples/demo/run_offline.sh
```

It runs one full governed agent loop (tool call, permission gate, ceilings,
event stream) against the scripted provider and writes an audit transcript to
`/tmp/northstar-demo-sessions/`.

The agent runtime CLI also self-checks and previews a run before it spends a
token — both commands are side-effect free:

```sh
cd components/northstar-agent-runtime
python3 -m cli --version
python3 -m cli doctor --workspace .       # environment self-check
python3 -m cli run --workspace . --provider anthropic --prompt "summarise README" --dry-run
```

`make test` runs every component's suite and the repository documentation tests
(881 tests at the current snapshot, 877 pass; four optional OpenTelemetry checks
are skipped when that extra is not installed).

### Sidecar installation

Requirements:

- Linux with Python 3.10 or newer.
- A separately installed `codex` executable available to the service user.
- systemd for the supplied service unit.
- `useradd`/`groupadd` (or `adduser`/`addgroup`) for `install.sh` to create the service account.

`install.sh` creates the dedicated unprivileged service account and the state directories; you do not need to prepare them by hand.

`CODEX_HOME` is Codex's own config/auth directory and is passed to the child process verbatim. The sidecar never appends to it, so the value in the unit file is exactly the directory Codex reads. The run workspace is deliberately separate from `CODEX_HOME`; credentials and run inputs do not share a directory. Set `CODEX_BIN` explicitly when the host uses a non-standard installation path.

Run the local verification from the component directory:

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

The agent runtime verifies the same way, offline and with no API key (its scripted provider is the only model; one test file starts a real sidecar listener on a temporary Unix socket):

```sh
cd components/northstar-agent-runtime
pip install -r requirements.txt -r requirements-tracing.txt
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The process-group cleanup behavior should also be validated on the target native Linux distribution. Signal and PID reaping behavior in mobile Linux environments may not be representative.

To review and install the deliberately conservative service lifecycle:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

`install.sh` creates the `northstar-codex` system account, `/var/lib/northstar-codex` with its `codex-home` and `workspace` subdirectories, installs the code and unit, and runs `systemctl daemon-reload`. It is idempotent and warns if `codex` is not on `PATH`. It does not enable or start the service.

`rollback.sh --confirm` removes the installed code and unit but deliberately preserves the service account and `/var/lib/northstar-codex`, because those hold Codex login state and run inputs.

The default Codex executable is resolved from `PATH`. Review the scripts, service account, paths, and permissions before enabling anything. Do not expose the Unix socket through a TCP proxy; it is intended to be called by a local, authenticated runtime under a dedicated Unix group.

## Who it is for

Northstar is for developers and operators building local or self-hosted AI coworker runtimes who need a narrow execution component that can be tested, audited, disabled, and rolled back. It is not a hosted AI product, a drop-in security guarantee, or a replacement for a full identity, policy, workspace, and observability architecture.

## What it is not

- It is not yet a complete multi-agent operating system.
- It is not a hosted service or a promise of production readiness.
- It is not a general shell execution API.
- It does not by itself authorize callers, isolate every run, or propagate parent cancellation.
- It does not include Codex credentials or provide a Codex account.
- The agent runtime's MCP support is deliberately a minimal stdio client (tool discovery/calls only; no sampling, roots, prompts, reconnect, or vendor server validation). Its live Anthropic calls are unverified in this repository's sandbox (no credentials): request building and response normalisation are covered against an injected fake client.

## Relationship to OpenBot

Northstar is an independent, OpenBot-compatible project. It is not affiliated with or endorsed by CopilotKit, OpenBot, or their maintainers. The sidecar is designed to integrate with OpenBot-style runtimes without claiming to be part of the upstream OpenBot repository.

Compatibility describes an integration target, not ownership, endorsement, or security equivalence.

## Security boundary

The sidecar authenticates callers through Unix permissions only. The local
`northstar-host` candidate adds a separately testable host-side policy grant
and opaque `0700` workspace allocation, but it is not a sandbox or production
identity system. A production integration must additionally provide:

- caller identity and authorization policy storage/rotation/revocation;
- workspace lifecycle, cleanup, lease, and native filesystem race handling;
- cancellation propagation from the parent runtime;
- structured observability without sensitive prompt logging;
- health checks and rollback procedures;
- native Linux concurrency and process-tree verification;
- a review of Codex's own account, network, and tool configuration.

The host candidate has not been deployed to 103, 104, a dormitory host, or
production OpenBot. It does not execute commands or connect the workspace to
the Sidecar by itself.

Do not expose the Unix socket through a TCP proxy. Never commit API keys, OAuth tokens, Codex login state, private keys, production `.env` files, or user transcripts.

## Project status

This is the first public Northstar component. The broader Northstar Agent OS runtime is intentionally being built incrementally. Runtime identity binding, per-run workspace authorization, cancellation propagation, native Linux end-to-end verification, and production deployment integration remain host-level responsibilities or future work. Do not treat this repository as a finished autonomous-agent platform.

Process-group cleanup should be validated on the target native Linux distribution. Signal and PID reaping behavior in mobile Linux environments may not be representative.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the evidence, testing, security, compatibility, and rollback expectations. Security reports belong in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
