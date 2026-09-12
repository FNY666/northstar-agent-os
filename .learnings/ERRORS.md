# Errors

Command failures and integration errors.

---

## 2026-09-11 — fragile archive assertion

- **Symptom:** the evidence archive repair command exited on an assertion.
- **Root cause:** the command asserted an exact `report.json` line count (337), an incidental formatting detail unrelated to archive correctness.
- **Resolution:** inspect the directory tree and validate semantic invariants instead: six task-scoped evidence files, each non-empty, and report summary 3/3.
- **Prevention:** assertions should check stable semantic properties, not incidental serialization length.

## 2026-09-12 — existing Interop concurrent subprocess flakiness

- **Symptom:** full `northstar-agent-interop` discovery intermittently failed in `test_concurrent_same_edge_append_is_written_once`; three full reruns failed in different existing process/route concurrency tests, while the focused causal-store case and other complete reruns passed.
- **Evidence:** failures varied between causal-store append, route-process integration, process-adapter timeout, and route-ledger append; the focused causal-store test passed in 1/1 and a later full rerun in the independent prior commit passed 136/136.
- **Decision:** do not modify unrelated Interop code during the agent recovery slice; preserve first-failure logs and report Interop as unstable rather than claiming a full green suite.
- **Prevention:** run the Interop suite with absolute `PYTHONPATH`, retain first-failure output, and separate focused recovery from full-suite stability claims.
