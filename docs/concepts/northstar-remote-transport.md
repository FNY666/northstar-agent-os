# Remote transport for a hosted worker (T5 specification)

> **Status: specification only.** No transport code ships in this repository
> and nothing on this page has ever run against a real host. It is the T5
> answer to the P3-3 ops gap *"network transport for a hosted worker"* — the
> design an implementer (or the T5b increment) builds from. Readiness
> measured by `remote_worker.py` stays unchanged by this page: a spec is not
> a transport.

A hosted worker is a **transport variant of the sidecar**, not a new
governance surface (see [`northstar-remote-worker.md`](northstar-remote-worker.md)).
This page therefore does not design a protocol. It designs the *channel*:
two profiles, reusing the framing, contracts, grants and process-boundary
rules that already exist in this tree, and a precise list of what must still
be written and exercised before the word "transport" is earned.

## 1. What is reused unchanged (the vocabulary)

| Piece | Real artifact in this tree | Used as |
| --- | --- | --- |
| JSON-lines framing | `sidecar_socket.py::read_json_line`, `handle_line`, `serve`; `SOCKET_PATH`, `CONNECTION_READ_TIMEOUT`, `MAX_WORKERS`, `socket_mode` | the wire format — one JSON object per line, request in, response out |
| Run contract | `contract.py::make_receipt`; `RECEIPT_SCHEMA_VERSION`, `MAX_TIMEOUT_MS`, `MIN_TIMEOUT_MS`, fallback statuses `transport_unavailable`/`timeout` | what a run may ask, what a run must answer |
| Host authorization | `authorization.py::authorize_run`, `sign_authorization`, `verify_authorization`; `AUTHORIZATION_SCHEMA_VERSION`; fields `actor_id`, `run_id`, `workspace_id`, `policy_revision`, `expires_at` | who may ask, against which policy revision, until when |
| Hop binding | `binding.py::sign_binding`, `verify_binding` (with caller-supplied `now`); binding fields incl. `expires_at` | a short-lived, keyed, capability-scoped envelope for one hop |
| Handoff grants | `interop_contract.py::GRANT_SCHEMA_VERSION`; `handoff.py::authorize_handoff`, `verify_handoff_grant` | narrowed per-step delegation between agents/backends |
| Process boundary | `process_adapter.py` (no shell, version-pinned command, env allowlist `_FIXED_ENV`, private workspace, grant verified before launch, bounded stdout/stdin) | how the worker launches any agent — the same rules a remote worker must keep |
| Sidecar lifecycle | `components/northstar-codex-sidecar`: `sidecar.py::run_one`, `_terminate_process_tree`; `northstar-codex-sidecar.service`, `install.sh`, `rollback.sh` | what actually runs on the worker machine today, managed |
| Durable-run machinery | `runner.py::DurableRunner`, `LeaseManager`; `event_store.py::EventStore`; `verifier.py::verify_run_completion`, `make_final_receipt`; `trace_metrics.py` span/metrics boundary | the fleet profile's execution core and its state/verification story |

The properties those pieces guarantee locally (bounded, version-pinned,
auditable, verifiable, opaque workspace, host-held keys) are the properties
the channel must *preserve*, never re-derive.

## 2. Profile A — one private worker over SSH (lowest cost, chosen)

The P3-3 evaluation's short-term option: **reuse the sidecar socket over
SSH**. Design, concretely:

```
orchestrator host                          worker machine
┌─────────────────────┐      ssh -N -L     ┌──────────────────────────┐
│ runtime (unchanged) │  /tmp/ns.sock →    │ sidecar.sock (0o660,     │
│  reads/writes one   │  /var/run/north-   │  root:codex) served by   │
│  Unix socket, JSON-  │  star-codex/       │  northstar-codex-sidecar │
│  lines, as today     │  sidecar.sock      │  .service (systemd)      │
└─────────────────────┘                     └──────────────────────────┘
```

- The worker runs the **existing systemd unit** (`northstar-codex-sidecar.service`,
  installed by `install.sh`) — no remote command execution at all. SSH only
  forwards the socket, so the "no shell" rule is kept at the boundary itself.
- The orchestrator starts `ssh -N -L <local-sock>:<worker-sock> <user>@<worker>`
  with `ExitOnForwardFailure=yes`, `ServerAliveInterval`/`ServerAliveCountMax`
  tuned below `CONNECTION_READ_TIMEOUT` so a dead SSH channel surfaces as a
  failed read inside the application timeout, not as a hung worker.
- Local socket path lives in a `0700` directory owned by the runtime user
  (same convention as session stores), so no other local user can reach the
  forwarded socket.
- Host key verification is mandatory (`known_hosts`, no `StrictHostKeyChecking=no`,
  key-only auth, agent-forwarding off). The SSH identity is the *account*
  boundary; run authorization still rides in-band as today's binding/grant
  tokens (see [`northstar-remote-identity.md`](northstar-remote-identity.md)).
- The runtime application needs **zero changes**: the byte pipe is
  transparent, timeouts are the existing `CONNECTION_READ_TIMEOUT` and
  contract `MAX_TIMEOUT_MS`; only the socket path is now a forwarded path.

Open decisions (must be pinned by the implementer, not by this page):
SSH vs WireGuard for multi-hop sites; keepalive budget per deployment;
socket path per runtime user; Windows workers are out of scope.

## 3. Profile B — container fleets (managed workers, sketch)

The P3-3 evaluation's medium-term option: a container that runs the
**durable-run runner as the execution sidecar** of a managed worker. This
profile deliberately reuses the durable layer instead of inventing a new one:

- state: `EventStore` (append-only events, `CHECKPOINT_SCHEMA_VERSION`,
  digests) on a worker volume; leases via `LeaseManager` for exclusive step
  ownership and crash takeover;
- execution: `DurableRunner` steps through the plan; every action passes the
  `action_gateway`; postconditions are checked by the independent
  `verifier.py::verify_run_completion`; a run ends with
  `make_final_receipt` — the same receipt shape the contract layer defines;
- metrics: `trace_metrics.py` gives structured spans/metrics (span kinds,
  `verifier_verdict`, `cost_micros`) that a fleet can ship before the worker
  is even network-capable;
- the missing network transport around the runner, and the
  identity/secret-rotation for fleets, are the genuinely unimplemented parts
  (Profile A's forward-only socket does not need them; a fleet needs mTLS or
  an equivalent — see the identity page's open decisions).

Nothing of Profile B runs in this repository today. It is a sketch so the
next increment knows exactly which mechanisms exist and which one gap —
transport code — it must write.

## 4. Failure taxonomy (reuse the contract's, don't invent one)

| Failure | Surface | Mapping |
| --- | --- | --- |
| Channel dead (ssh exit, network) | runtime read fails within timeout | receipt fallback status `transport_unavailable` (`contract.py` fallback set) |
| Channel slow/stalled | read exceeds `CONNECTION_READ_TIMEOUT` after SSH keepalive fired | receipt status `timeout` |
| Grant/binding expired mid-flight | `verify_binding`/`verify_authorization` with caller `now` | refused before launch; operator reruns with a fresh grant |
| Worker process tree hangs | `sidecar.py::_terminate_process_tree` / adapter termination | bounded kill, then `transport_unavailable` |
| Receipt lost after success | idempotency-keyed replay from the event history | orchestrator re-derives, never double-executes |

Receipts and audit records are produced on the worker and streamed over the
same JSON-lines channel; a lost response is answered by replaying the event
store, not by re-running the work — that property comes from the durable
layer and is preserved by the channel, which must stay **at-most-once on
execution, at-least-once on evidence**.

## 5. What "done" would mean (T5b checklist)

- [ ] Profile A channel helper: spawn/monitor the SSH forward, verify socket
      readiness, surface ssh exits as `transport_unavailable`; local-only
      tests over a loopback pair.
- [ ] Profile B: a network transport around `DurableRunner` (framing reused),
      with identity from the rotation story below.
- [ ] A real (non-fake) end-to-end canary run against a real SSH worker —
      the recipe exists (`examples/remote-canary`) but has not run in CI.
- [ ] `remote_worker.py` ops probe flips from MISSING only when the above
      code exists *and* a canary has passed on a real host.

Related: [identity/rotation story](northstar-remote-identity.md),
[the remote-worker evaluation](northstar-remote-worker.md),
[operations guide](../guides/remote-worker-operations.md),
[canary recipe](../../examples/remote-canary/README.md).
