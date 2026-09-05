# Northstar Codex Sidecar

A restricted local adapter for running Codex as a supervised worker in an OpenBot-compatible runtime.

## Protocol

One JSON object is accepted per Unix-socket connection:

```json
{"request_id":"r1","prompt":"Reply with OK","timeout_ms":10000}
```

The response is one JSON object followed by a newline. The request surface is intentionally limited to three fields. Shell commands, arbitrary environment data, and tool declarations are not accepted from the caller.

## Files

- `sidecar.py` — request validation, Codex process execution, event parsing, timeout cleanup, and error redaction.
- `transport.py` — bounded JSON transport helpers.
- `sidecar_socket.py` — private Unix-socket listener and bounded worker pool.
- `service.py` — static service safety contract.
- `northstar-codex-sidecar.service` — systemd hardening template.
- `install.sh` / `rollback.sh` — deliberately constrained service lifecycle scripts.
- `tests/` — deterministic unit and local fake-Codex tests.

## Integration warning

The sidecar authenticates callers through Unix permissions only. The parent runtime must provide identity binding, per-run workspace authorization, cancellation propagation, and production observability. Do not expose the socket over TCP.

See the repository [README](../../README.md) for the full security boundary.
