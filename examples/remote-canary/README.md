# Remote-worker channel canary (T5)

The operator-run "real (non-fake) end-to-end canary" recipe from the T5
transport specification — phase one of it. `run_remote_canary.sh` connects
to a **real host** over SSH, forwards the worker's sidecar socket, and proves
the channel end to end:

1. **Reachability** — key-only SSH to the worker works.
2. **Forward** — `ssh -N -L` brings the remote
   `/var/run/northstar-codex/sidecar.sock` to a local `sidecar.sock`
   (the canonical filename the runtime's socket validation requires).
3. **Deterministic probe** — `probe_socket.py` does one JSON-lines round
   trip with a *shaped-but-invalid* request: the real server
   (`sidecar_socket.serve` → `sidecar.run_one`) rejects it **before any
   process is spawned**, so this phase needs **no model, no API key and no
   codex binary** on the worker. It proves: socket reachable, framing
   intact, `request_id` echoed, bounded response. Deterministic and safe to
   run any time.
4. **(optional, `NS_REAL=1`)** — one valid tiny request that really launches
   codex on the worker. Needs codex + credentials there; `ok` passes,
   `codex_error`/`timeout` are reported as inconclusive (exit 2), never as a
   channel failure.

## Run it (on the orchestrator host)

```sh
NS_WORKER=user@worker-host sh examples/remote-canary/run_remote_canary.sh
# optional real-run phase:
NS_WORKER=user@worker-host NS_REAL=1 sh examples/remote-canary/run_remote_canary.sh
```

Exit codes: **0** pass · **1** failure · **2** inconclusive (real phase).

## Failure hints

| Symptom | Check |
| --- | --- |
| phase 0 fails | SSH keys and `known_hosts`; the worker accepts your account |
| phase 1 fails (`ExitOnForwardFailure`) | remote socket exists: `systemctl status northstar-codex-sidecar` on the worker |
| phase 2 times out | socket never appeared locally — same check; also `rm -rf ~/.local/state/northstar/canary` and retry |
| probe FAIL | something between the sockets changed framing — file a bug with the probe output |

## Honesty notes

- **This repository's CI never runs this example** — it requires a real host
  and an SSH connection, by design. The pieces that *can* run locally do:
  `probe_socket.py` is exercised in CI against the real
  `sidecar_socket.serve` on a loopback socket, and the script is
  syntax-checked.
- The canary proves the **channel**. Run governance, credential rotation and
  the durable-run path are exercised by the local suites and by the P3-3
  scorecard; a full governed-run-over-remote-channel canary is the T5b item
  that stays open until the transport code itself exists
  (see the [transport spec](../../docs/concepts/northstar-remote-transport.md)).

Context: [transport specification](../../docs/concepts/northstar-remote-transport.md),
[identity/rotation story](../../docs/concepts/northstar-remote-identity.md),
[operations guide](../../docs/guides/remote-worker-operations.md).
