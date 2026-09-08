# Remote-worker operations (T5 operator guide)

How to stand up, watch and take down a **hosted worker** built from this
repository's pieces — written for the operator who actually runs the thing,
on a real machine. This guide is the T5 answer to the ops gap
*"deployment/monitoring guide for a hosted worker"*.

> **Status: an operator guide, not a product.** None of this has been
> exercised by this repository's CI, which has no Docker, no SSH targets and
> no real workers. Every step below carries the check the operator must do
> the first time. Design context: [transport
> spec](../concepts/northstar-remote-transport.md) (profiles A/B) and
> [identity/rotation story](../concepts/northstar-remote-identity.md).

## 0. What you are deploying

A hosted worker is a **transport variant of the sidecar**: the same governed
execution model, with the socket moved across a machine boundary. The worker
machine runs the existing sidecar service; the orchestrator machine talks to
it over an SSH-forwarded Unix socket. Nothing new is installed on the worker
beyond what the sidecar component already ships
(`components/northstar-codex-sidecar`: the systemd unit, `install.sh`,
`rollback.sh`).

## 1. Recipe A — one private worker

### 1.1 Worker side (once)

1. Install the sidecar component on the worker (`install.sh` in
   `components/northstar-codex-sidecar`) and start/enable the unit. The unit
   runs as its own user/group, creates the private runtime directory and
   publishes the socket at the canonical path with group rw.
2. Verify: the socket exists, owned by the sidecar user, mode `0660`:
   `ls -l /var/run/northstar-codex/sidecar.sock` (run the service's own
   validation first if it exposes one).
3. No inbound ports beyond SSH (22) are needed; the worker never dials out
   to the orchestrator.

### 1.2 Orchestrator side (per session or as a managed forward)

1. Create a private state directory for the runtime user (`0700`, same
   convention as session stores) and forward the socket:
   `ssh -N -L <dir>/sidecar.sock:/var/run/northstar-codex/sidecar.sock user@worker`
   with `ExitOnForwardFailure=yes`, `ServerAliveInterval`/`ServerAliveCountMax`
   tuned below the sidecar's `CONNECTION_READ_TIMEOUT` (10 s), key-only auth,
   no agent forwarding, strict host keys.
   - The local socket **must** be named `sidecar.sock` — the runtime's
     socket validation requires the canonical filename.
2. For a programmatic local lifecycle, use the T20 helper after creating the
   private directory. It performs no remote shell execution and does not mint
   authorization:

   ```python
   from ssh_forward import SSHForward, SSHForwardConfig

   config = SSHForwardConfig(
       destination="user@worker",
       local_socket="/tmp/northstar-private/sidecar.sock",
       remote_socket="/var/run/northstar-codex/sidecar.sock",
       known_hosts="/home/operator/.ssh/known_hosts",
   )
   with SSHForward(config):
       # point the unchanged runtime/sidecar client at config.local_socket
       ...
   ```

   The helper is local-only and loopback-tested; it has not been run against a
   real worker by this repository.
3. Verify the channel with the deterministic probe (no model, no key):
   `NS_WORKER=user@worker sh examples/remote-canary/run_remote_canary.sh`.
4. Run governed work as usual, pointing the runtime at the local socket.

### 1.3 Rotation (from the identity story)

1. Generate a fresh enrollment secret (≥ 32 random bytes) at the host.
2. Re-provision the worker's copy during a **dual-key grace window** (host
   verifies with both secrets for one window).
3. The window ends when the slowest worker has rotated; then destroy the old
   secret. Expiry (`expires_at` on every token) is the backstop; bumping the
   policy `revision` is the emergency kill switch.
4. Drill this once per worker before relying on it — rotation is the one
   procedure where a missed worker shows up as an outage.

## 2. Recipe B — container fleets (sketch, explicitly not built)

The fleet profile (transport spec, Profile B) reuses the durable-run layer:
`EventStore` on a worker volume, `LeaseManager` for step ownership and crash
takeover, `DurableRunner` for execution, the independent verifier for
postconditions. What does not exist yet: the network transport around the
runner, and the fleet identity story (mTLS or equivalent — see the identity
page's open decisions). Do not treat this section as runnable; treat it as
the shape the T5b implementation must keep.

## 3. Monitoring

Three signals exist today; know which one answers which question:

| Signal | Produced by | Answers | Where to look |
| --- | --- | --- | --- |
| Session transcript + audit feed | runtime `sessions export` → `audit.ndjson/1`; host `authorization_grant` records; durable `event_to_audit` | what was decided, by whom, against which policy revision | `docs/concepts/audit-trail.md`; ship the NDJSON stream (fluent-bit/rsyslog, file → TCP/TLS), tag by `component`, index on `ts`, route on `schema_version` |
| OTEL spans | runtime `tracing.py` (span tree with usage/cost) | why a run took its shape | local stack in `examples/observability` (Jaeger/Grafana); collector topology is an open T5 item |
| Durable-run metrics | `trace_metrics.py` (span kinds, `verifier_verdict`, `cost_micros`) | step health in the fleet profile | today: structured logs/metrics boundary; OTEL wiring is open |

Alert thresholds worth starting with (all derivable from the feed, none
wired yet):

- `denial` rate spike → policy change or prompt loop;
- `verifier_verdict = failed` / receipt `status` other than ok → investigate
  before rerunning (idempotency, not double-execution);
- binding expiry skew (rejections whose `expires_at` is recent) → clock or
  rotation problem;
- receipt fallback statuses `transport_unavailable` / `timeout` → channel
  health (this is what the canary's probe phase watches).

## 4. Runbook

| Incident | Response |
| --- | --- |
| Worker unreachable | canary phase 0 fails first; check SSH + unit on the worker; the orchestrator's reads fail within the existing timeouts and the run surfaces as `transport_unavailable` — nothing hangs |
| Forward died silently | `ServerAlive*` turns it into a failed read inside the app timeout; restart the forward and re-run the probe |
| Run stuck / worker crashed mid-run | in Profile A: rerun — the run contract's receipt + idempotency key decides replay; in Profile B: `LeaseManager` expiry lets another worker take the step over |
| Receipt mismatch | run the independent verifier (`verify_run_completion`) against the event history; trust the history, not the worker's report |
| Suspected credential leak | rotate immediately + bump policy `revision`; `authorization_grant` audit records show what the leaked key could have authorized |
| Disk filling (event store / sessions) | these are append-only by design; archive via the audit export, then truncate with the store's own tooling (never by hand-editing the feed) |

## 5. First-run validation checklist (operator signs off)

- [ ] Canary passes: reachability, forward, deterministic probe
      (`examples/remote-canary`).
- [ ] A real run over the channel succeeds (`NS_REAL=1` phase) with codex
      credentials on the worker.
- [ ] Rotation drill done once (issue → dual-key window → revoke old).
- [ ] Audit feed reaches the SIEM/sink and correlates on `session_id` /
      `run_id` / `actor_id`.
- [ ] Clock discipline confirmed (all verifiers share the caller's `now`).
- [ ] Rollback known: `rollback.sh` on the worker; orchestrator changes are
      just socket path + SSH config, so rollback is trivial by design.

## 6. Honesty footer

This guide is unexercised end to end: no CI run, no real deployment. Its
value is that every mechanism it names is either an existing tested boundary
or the local-only T20 `ssh_forward.py` lifecycle helper (contracts, host grants,
sidecar framing, durable machinery, audit feed); complete transport readiness,
Profile B and a real-host canary remain open in the T5b checklist.

Related: [transport spec](../concepts/northstar-remote-transport.md),
[identity story](../concepts/northstar-remote-identity.md),
[the remote-worker evaluation](../concepts/northstar-remote-worker.md),
[audit trail](../concepts/audit-trail.md), [canary
example](../../examples/remote-canary/README.md).
