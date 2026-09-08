# Remote / hosted worker: protocol and evaluation notes (P3-3)

Northstar deliberately does **not** build a cloud. This document is the
decision record for wrapping the existing execution model into a remote
worker, together with the protocol a hosted worker would speak. It is a
*map*, not a deployment claim: the T20 SSH lifecycle helper and T21/T22/T23 local
control/replay channel are implemented and loopback-tested, but no remote
worker is deployed or exercised.

## Scope: what "remote worker" means here

The repository already separates **decision** (`northstar-agent-runtime`:
reasoning, policy, budgets, audit) from **doing** (sidecar: spawns the model
CLI in a sandbox, bounded process). "Remote/hosted worker" means running the
*doing* half somewhere else — a container on another host, a CI runner, or a
hosted OpenBot-compatible runtime — under the same governance, not as a
second class of agent.

## What already exists (and what it gives us)

- `northstar-run-contract` — the versioned run request/receipt boundary
  between an orchestrator and a controlled worker (`northstar.run.v1`); the
  schema version is the loud-failure seam for component drift.
- `northstar-host` — default-deny authorization + opaque workspace
  allocation, re-verifying the run binding before anything runs; every grant
  is signed, short-lived and carries the policy revision.
- `northstar-durable-run` — append-only event history, leases, per-call
  action gates and independent postcondition verification: the machinery a
  hosted worker needs to survive crashes and report *verifiably*. T21/T22/T23 add a
  loopback-only authenticated, cursor-paged, crash-marker-aware control/replay transport, but not a
  fleet scheduler or serialized step execution.
- `northstar-agent-interop` — `process_adapter`/`process_backend` give a
  backend-neutral **process boundary** for version-pinned Codex / Claude Code
  / Cursor CLIs (disabled by default; no vendor integration), the canary proves
  a host-authorized multi-backend handoff chain with fake executors, and T20's
  `ssh_forward.py` provides the local-only Profile A socket lifecycle helper.
- `audit.ndjson/1` — the canonical audit feed that runtime transcripts,
  durable events and host grants all export into.

## The remote-worker protocol (map)

A hosted worker is a **transport variant of the sidecar**, not a new
governance surface:

```
orchestrator (decision half)
   │  run request (northstar.run.v1) — prompt, workspace ref, mode, ceilings
   ▼
host (authorization)                  transport: TLS + mTLS / HMAC channel
   │  signed short-lived grant (policy_revision, expiry, capabilities)
   ▼
remote worker (doing half)
   │  - host-verified binding before anything runs
   │  - opaque private workspace (host-resolved)
   │  - bounded, version-pinned execution (process boundary)
   │  - per-call action gate + postcondition verification (durable-run)
   ▼
event store / audit feed             receipt (run receipt v1, structured)
```

Properties the transport must keep, carried over from the local path:

1. **Same request/receipt contract** — the worker understands
   `northstar.run.v1`, never a bespoke chat API.
2. **Host holds the keys** — the grant is signed by the host, short-lived,
   capability-scoped and revision-stamped; the worker cannot mint its own.
3. **Opaque workspace** — the host allocates and reveals; the worker never
   sees the host's own files.
4. **Bounded and version-pinned** — absolute executable, fixed argv template,
   no shell, no env credential leaks (the process-boundary rules).
5. **Auditable** — every event lands in the store/feed; receipts are
   structured and idempotency-keyed for replay.
6. **Verifiable** — the orchestrator can check the receipt against the
   event history instead of trusting the worker's report.

### Evaluated transport options

| Option | Fit | Effort | Notes |
| --- | --- | --- | --- |
| Reuse the sidecar socket over SSH | highest for a single private worker | low | Existing protocol + Unix socket via SSH tunnel; no new protocol |
| Container + the durable-run runner as a sidecar | highest for managed fleets | medium | Add a network transport around the runner; needs identity/secret rotation |
| OpenBot ecosystem (`interop` already targets it) | strategic | medium | Aligns with the A2A-style interop boundary; requires ecosystem availability |
| Build a new HTTP service | lowest (duplicates existing layers) | high | Not chosen: reinvents contracts/host/durable layers |

## Evaluation result (see the accompanying assessment)

The scorecard (36 criteria across contracts, host, durable-run, interop,
audit, ops; `remote_worker.py --score`, run in CI) lands at **94/100
ready-for-remote, 0/100 shipped**: the governance and contract layers are
fully present (100% in all five kernel areas). T5 (2026-09-07) closed two of
the four original ops gaps with authoritative artifacts — the credential
issuance + rotation [story](northstar-remote-identity.md) and the
[operator guide](../guides/remote-worker-operations.md) for deployment and
monitoring (ops 4/6 = 67%). What remains is genuinely implementation-shaped:

- **complete network transport readiness** for a hosted worker — T20 supplies
  the local `ssh_forward.py` lifecycle helper and T21/T22/T23 supply a loopback
  control/replay slice, while Profile A real-host validation and all Profile B
  execution transport code remain open;
- **a real (non-fake) end-to-end canary *run*** on a real host — the
  operator [recipe](../../examples/remote-canary/README.md) exists and its
  probe is CI-tested against the real socket server, but by design no CI run
  has ever touched a real worker.

The next increment is a real-host Profile A canary and operator sign-off,
followed by a separately scoped Profile B transport if fleet execution is
actually needed. If OpenBot/remote-worker availability matures, an
interop-backed hosted adapter remains an alternative. No cloud is built by this
repository either way.
