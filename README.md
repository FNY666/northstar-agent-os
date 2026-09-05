# Northstar Agent OS

**Open, reliable, and governed runtime components for autonomous AI coworkers.**

> 中文名：北辰智能体系统

Northstar Agent OS is an independent project for building AI coworkers with explicit model routing, local tool boundaries, auditability, and recoverable execution. The first published component is **Northstar Codex Sidecar**, a restricted Unix-socket adapter for running Codex as a supervised worker.

## Relationship to OpenBot

Northstar is an independent, OpenBot-compatible project. It is not affiliated with or endorsed by CopilotKit. The sidecar is designed to integrate with OpenBot-style runtimes without claiming to be part of the upstream OpenBot repository.

## Repository status

This repository currently contains the first Northstar component:

- `components/northstar-codex-sidecar/` — a local Unix-socket service that validates requests, runs Codex in read-only mode, bounds input and output behavior, redacts errors, and returns structured statuses.

The broader Northstar Agent OS runtime is intentionally being built incrementally. Do not treat this repository as a finished autonomous-agent platform yet.

## Northstar Codex Sidecar

The sidecar accepts one JSON request per connection:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

It returns a bounded JSON response such as:

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

## Requirements

- Linux with Python 3.10 or newer.
- A separately installed `codex` executable available to the service user.
- systemd for the supplied service unit.
- `useradd`/`groupadd` (or `adduser`/`addgroup`) for `install.sh` to create the service account.

`install.sh` creates the dedicated unprivileged service account and the state directories; you do not need to prepare them by hand.

`CODEX_HOME` is Codex's own config/auth directory and is passed to the child process verbatim. The sidecar never appends to it, so the value in the unit file is exactly the directory Codex reads. Set `CODEX_BIN` explicitly when the host uses a non-standard installation path.

## Local tests

Run from the component directory:

```sh
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The process-group cleanup behavior should also be validated on the target native Linux distribution. Signal and PID reaping behavior in mobile Linux environments may not be representative.

## Installation

The installation script is deliberately conservative: it accepts only its canonical prefix and must run as root. Review the files and adapt the service account and host paths before enabling it:

```sh
cd components/northstar-codex-sidecar
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

`install.sh` creates the `northstar-codex` system account, `/var/lib/northstar-codex` with its `codex-home` and `workspace` subdirectories, installs the code and unit, and runs `systemctl daemon-reload`. It is idempotent and warns if `codex` is not on `PATH`. It does not enable or start the service.

`rollback.sh --confirm` removes the installed code and unit but deliberately preserves the service account and `/var/lib/northstar-codex`, because those hold Codex login state and run inputs.

Do not expose the Unix socket through a TCP proxy. The socket is intended to be called by a local, authenticated runtime under a dedicated Unix group.

## Security boundary

This component is not a complete security model for an agent platform. A production integration must additionally provide:

- caller authorization and identity binding;
- workspace isolation per run or actor;
- cancellation propagation from the parent runtime;
- structured observability without sensitive prompt logging;
- health checks and rollback procedures;
- native Linux concurrency and process-tree verification;
- a review of Codex's own account, network, and tool configuration.

Never commit API keys, OAuth tokens, Codex login state, private keys, production `.env` files, or user transcripts.

## License

MIT. See [LICENSE](LICENSE).
