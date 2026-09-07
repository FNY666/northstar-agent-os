# Handoff and contracts: crossing a trust boundary

Northstar is not one process: a host orchestrates, a runtime reasons, a
sidecar executes delegated work, and future engines plug in through an
interop boundary. Every crossing is a **trust boundary**, and each one is
covered by a versioned contract. This page maps the boundaries and points at
the definitions.

## The run contract (orchestrator <-> worker)

`northstar-run-contract` defines the versioned structural boundary between an
Agent OS orchestrator and a controlled worker (today: the Codex sidecar). It
carries:

- the **run request**: prompt, workspace, mode, ceilings — everything that
  fixes what the worker may do;
- the **run receipt**: the worker's commitment, aligned to the request;
- schema **versioning** (`SCHEMA_VERSION`) so a mismatch between components is
  a loud failure instead of a silent misread.

The contract is pure standard library by design: it must stay importable in
the most constrained verification environments. The runtime's signed
`ActionReceipt` projects into the contract's `northstar.receipt.v1` shape without
adding fields to that legacy boundary; consumers that need tamper verification
retain the runtime receipt alongside the projection.

## Host authorization handshake (host <-> verified run)

`northstar-host` brokers the boundary in the other direction: a
default-deny `authorization` layer decides whether a proposed run may proceed,
and an opaque `workspace` allocation hands the verified run a private directory
whose contents the host controls. The boundary order is fixed — authorization
checks run before any workspace is revealed — and workspaces are opaque: the
run sees only what the host decided to mount. `issue_approval_lease()` can
narrow a verified grant to one runtime session/workspace/capability set with an
expiry and finite use count; it is not a persistent lease manager or a bypass
around the signed host grant.

## Sidecar delegation (runtime <-> Codex)

The runtime executes *reasoning* in-process but delegates *work* to the
`northstar-codex-sidecar` over a private Unix socket: one JSON request
(`request_id`, `prompt`, `timeout_ms`) per connection, one response, no
network surface. The delegation tool (`CodexReadOnly`) is a normal tool: it
crosses the same permission gate as anything else, and the sidecar itself has
no write capability to expose.

## Interop boundary (this engine <-> other engines)

`northstar-agent-interop` is a backend-neutral boundary for combining engines
(coding agents, browser/workflow agents, future OpenBot-compatible adapters).
`handoff.py` owns the state-transfer protocol, `process_adapter` +
`process_backend` provide the local process transport, and `canary.py` is the
health probe. It calls no vendor product and impersonates none: interop means
speaking the repository's own contract at the seam.

## Reading on

- Contracts: [northstar-run-contract README](../../components/northstar-run-contract/README.md),
  API reference [docs/api/northstar-run-contract.md](../api/northstar-run-contract.md).
- Host: [Boundary order](../../components/northstar-host/README.md#boundary-order)
  and [docs/api/northstar-host.md](../api/northstar-host.md).
- Sidecar: [Protocol](../../components/northstar-codex-sidecar/README.md#protocol)
  and [docs/api/northstar-codex-sidecar.md](../api/northstar-codex-sidecar.md).
- Interop: [What is standardized](../../components/northstar-agent-interop/README.md#what-is-standardized)
  and [docs/api/northstar-agent-interop.md](../api/northstar-agent-interop.md).
