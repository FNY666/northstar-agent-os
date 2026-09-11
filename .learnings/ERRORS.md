# Errors

Command failures and integration errors.

---

## 2026-09-11 — fragile archive assertion

- **Symptom:** the evidence archive repair command exited on an assertion.
- **Root cause:** the command asserted an exact `report.json` line count (337), an incidental formatting detail unrelated to archive correctness.
- **Resolution:** inspect the directory tree and validate semantic invariants instead: six task-scoped evidence files, each non-empty, and report summary 3/3.
- **Prevention:** assertions should check stable semantic properties, not incidental serialization length.
