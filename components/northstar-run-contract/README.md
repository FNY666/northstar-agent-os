# Northstar Run Contract

This component defines the versioned structural boundary between an Agent OS orchestrator and a controlled worker such as the Codex Sidecar.

## Concepts, guides and API reference

- Concepts: [governance and the permission gate](../../docs/concepts/governance.md) ·
  [handoff and contracts](../../docs/concepts/handoff-and-contracts.md)
- Guides: [packaging and CI](../../docs/guides/packaging-and-ci.md)
- API reference: [generated from docstrings](../../docs/api/northstar-run-contract.md)

## Install (pip)

The contract is pure standard library, so it installs with no dependencies and
stays importable in the most constrained verification environments:

```sh
pip install .          # from a checkout
# or, once published:
pip install northstar-run-contract
```

The three modules are installed under their in-tree names and the version
(`0.1.0.dev0`, unreleased) is declared in `pyproject.toml`:

```python
import contract, binding, adapter
```

## Trust boundary

`validate_run_request()` checks shape, size, identifiers, task kind, timeout, and requested capability syntax. It does **not** authenticate the caller and it does **not** grant any requested capability. `actor_id` and `workspace_id` are declarations until a host-provided authenticated binding is verified.

The contract deliberately keeps these concerns separate:

1. **Validation** — is the request structurally safe to parse?
2. **Authentication** — does the caller possess a host-issued binding?
3. **Authorization** — may this actor use this workspace and capability set?
4. **Execution** — does the worker perform the bounded task?
5. **Postcondition verification** — did the claimed outcome actually hold?

## Run request

A request uses `schema_version: "northstar.run.v1"` and contains a bounded `run_id`, declared `actor_id`, declared `workspace_id`, one supported `task_kind`, a prompt, a bounded timeout, requested capability names, and an optional parent run ID.

Requested capabilities are not permissions. A later authenticated policy layer must reduce them to an explicit grant set before execution.

## Run receipt

Receipts use `schema_version: "northstar.receipt.v1"`. Every receipt contains a status and a list of explicit postcondition verdicts: `verified`, `failed`, or `unknown`. Unknown must not be presented as success.

Only `timeout` and `transport_unavailable` are fallback-eligible. `cancelled`, `protocol_error`, `business_error`, and `internal_error` must remain visible to the orchestrator and must not be silently retried as another worker.

The signed binding layer is intentionally separate from structural validation. `sign_binding()` creates an expiring HMAC-SHA256 token from `schema_version`, `run_id`, `actor_id`, `workspace_id`, and `expires_at`. `verify_binding()` proves possession of the host-held secret and detects tampering or expiry; it does not prove user intent and it does not grant capabilities. The host must still authorize the actor, workspace, and requested capabilities before execution.

## Current scope

This is a pure standard-library contract component. It does not create workspaces, run commands, store secrets, or claim production isolation. The Sidecar adapter is a separate layer.

Besides the run request/receipt, the component owns the canonical **audit
feed** envelope (`audit.py`, `audit.ndjson/1`): the versioned NDJSON record
shape that runtime transcripts, durable-run events and host authorization
grants all export into (see the
[audit trail concept](../../docs/concepts/audit-trail.md)).
