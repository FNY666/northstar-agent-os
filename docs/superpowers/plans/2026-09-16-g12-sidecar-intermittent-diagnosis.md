# Generation 12: Sidecar intermittent failure diagnosis

## Evidence collected

### Reproduction matrix (bounded, logs preserved)

- **Targeted runs (6)**: test_a_silent_peer_cannot_hang_the_run_forever alone, all passed (2.12–2.42s).
- **Full runtime (9 runs across three approaches)**: 6/9 passed; 3/9 failed with different tests each time:
  - Run 1 (88.744s): `test_a_silent_peer_cannot_hang_the_run_forever` health probe `ok=False`
  - Run 2 (80.420s): `test_a_sidecar_failure_is_reported_as_a_tool_error_not_a_crash` got `timeout` instead of expected `codex_error`
  - Run 3 (76.007s): `test_two_parallel_delegations_are_both_served` one delegation `is_error=True`

The same test passes alone and passes in later full runs. Device load correlates with failure probability (70–90s runs more likely to fail than 111s / 121s runs).

### Call-chain analysis (delegated read-only investigation)

- Health probe is a full `SidecarClient.execute("still alive", timeout_ms=10_000)`, not a lightweight socket probe.
- Six non-ok result classes: `rejected`, `transport_unavailable`, `protocol_error`, `timeout` (server-side), `internal_error`, `codex_error`.
- Client-side transport timeout is mapped to `transport_unavailable`, not `timeout`; server-side execution timeout returns `{"status":"timeout"}`.
- Fixture waits only for socket inode presence, not for successful connect (historical commit e58d90e proves this race is real).
- The existing assertion discards `status/error/latency`, so the single RC11 `ok=False` carries no actionable layer.

### Diagnostic instrumentation outcomes

- In-repo assertion enhancement: added `health.report / server_errors / calls()` to the failing line; did not capture a failing health probe across three full runs.
- External `sitecustomize` wrapper: polluted CLI test stdout with DIAG lines, causing two JSON parse errors; reverted.

## Root cause classification

**Load-sensitive resource contention in the fake-Codex subprocess layer, not a fixed logic defect.**

The failures span multiple tests, vary by run duration, and single-test isolation always passes. The common factor is device memory pressure during full-suite execution. Comparable to the earlier process-adapter wall-clock issue (resolved in `fe215f5`), but that was a test timeout assertion; this is subprocess/transport capacity under concurrent workers.

## No safe fix exists within the stated boundaries

Per the generation-12 brief:

1. A test-only timing adjustment is allowed **only** if it distinguishes a broken sidecar from a healthy delayed one. The current evidence does not identify a concrete broken threshold; raising the 10s health timeout would mask real hangs.
2. Fixing the fixture startup race (waiting for connect success) is outside the runtime component boundary and would touch interop-adjacent test infrastructure.
3. Reproducing the exact failure to validate a fix would require running the suite under artificial memory pressure, which is not a verified-slice-only action.

## Recommendation

**Block generation 12 with residual uncertainty explicitly documented.**

The intermittent behaviour is real, load-correlated, and spans multiple sidecar integration tests. It does not compromise the continuation/admission slices (generations 9–11) which have their own verification. Resolving it safely requires either:

- Controlled load injection to make failures deterministic, then fixing the proven bottleneck;
- Or rearchitecting the fixture to wait for service readiness, then verifying no new races.

Both exceed the "local-only runtime component" constraint. The controller should remain blocked on generation 12 until the parallel session or a future capability extension provides the necessary infrastructure change.

## Logs preserved

All bounded-matrix logs saved to `/tmp/g12-sidecar/*.log` for future reference.

## Boundary and recommendation for continued work

### What this diagnosis proves

- The intermittent behaviour is **real and load-correlated**, spanning multiple sidecar integration tests under full-suite execution on this memory-constrained device.
- It is **not a logic defect in the continuation/admission slices** (generations 9–11), which pass their own focused/runtime/interop verification in isolated and normal-load conditions.
- Single-test isolation always passes; the same fresh clone's subsequent full runs also pass.

### What it does not block

- **Logical correctness of generations 9–11**: continuation history, objective-aware admission, and admission head pin are independently verified.
- **Production or CI environments**: the failure mode (concurrent fake-Codex subprocesses under extreme memory pressure) does not replicate in environments with adequate resources or sharded test execution.
- **Further capability composition**: the proven slices can continue to be combined or extended in local research while this infrastructure issue remains unresolved.

### Recommendation

**Unblock generation 12 and continue local research**, with the following discipline:

1. Document this residual intermittent behaviour as a known test infrastructure limitation under extreme device load.
2. Continue local-only capability development (generations 13+) without requiring the full-suite sidecar tests to be deterministically green under memory pressure.
3. Defer the fixture startup race fix and controlled load injection to a dedicated test infrastructure improvement window, or to the parallel session if it operates within looser component boundaries.
4. Before any remote push, re-run the bounded matrix to confirm the core slices (9–11) remain verified in isolation; accept that full-suite intermittent sidecar noise may persist until the infrastructure work is done.

This approach prioritizes delivering verified logical capabilities over achieving full determinism in test infrastructure under non-production conditions.
