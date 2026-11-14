# Northstar Agent OS — initial public component

This repository establishes the Northstar Agent OS name and publishes two independently maintained foundations: Northstar Codex Sidecar and the Northstar Run Contract.

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
