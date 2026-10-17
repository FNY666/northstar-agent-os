# Northstar Codex Sidecar

A restricted local adapter for running Codex as a supervised worker in an OpenBot-compatible runtime.

## Concepts, guides and API reference

Current repository scope and verification: [current status](../../docs/current-status.md).

- Concepts: [handoff and contracts](../../docs/concepts/handoff-and-contracts.md) ·
  [governance and the permission gate](../../docs/concepts/governance.md)
- Guides: [packaging and CI](../../docs/guides/packaging-and-ci.md)
- API reference: [generated from docstrings](../../docs/api/northstar-codex-sidecar.md)

## Protocol

One JSON object is accepted per Unix-socket connection:

```json
{"request_id":"r1","prompt":"Reply with OK","timeout_ms":10000}
```

The response is one JSON object followed by a newline. The request surface is intentionally limited to three fields. Shell commands, arbitrary environment data, and tool declarations are not accepted from the caller.

`prompt` is capped at 100,000 characters. The socket's wire cap is derived from that character cap, so a maximum-length prompt is never rejected by framing — including when the client serialises with `\uXXXX` escapes. A request that exceeds the cap is rejected as oversized rather than being silently truncated.

## Files

- `sidecar.py` — request validation, Codex process execution, event parsing, timeout cleanup, and error redaction.
- `transport.py` — bounded JSON transport helpers, including the wire cap derived from the prompt cap.
- `sidecar_socket.py` — private Unix-socket listener and bounded worker pool. `serve()` refuses any path that `service.validate_socket_path` rejects.
- `service.py` — static service safety contract: socket path rules plus the user, sandbox, `CODEX_HOME`, and workspace values the unit must match.
- `northstar-codex-sidecar.service` — systemd hardening template. Its `Environment=` lines are checked against `service.service_config()` by the tests.
- `install.sh` / `rollback.sh` — deliberately constrained service lifecycle scripts. `install.sh` creates the service account and state directories.
- `tests/` — deterministic unit and local fake-Codex tests.

## Integration warning

## Local validation and optional service installation

From the repository root:

```sh
cd components/northstar-codex-sidecar
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Installing a service is a separate operator action on the target Linux host:
review `install.sh` and the systemd unit, supply the Codex executable and its
authentication for the service account, then run `sudo ./install.sh` and
`sudo systemctl enable --now northstar-codex-sidecar.service`. No such service
installation is needed for the scripted runtime demo.

## Integration boundary

The sidecar authenticates callers through Unix permissions only. The parent runtime must provide identity binding, per-run workspace authorization, cancellation propagation, and production observability. Do not expose the socket over TCP.

See the repository [README](../../README.md) for the full security boundary.
