# Task fixture

`asyncMapLimit(values, limit, fn)` bounds active calls, preserves result order, and rejects with the first failure. `limit` is a positive integer. Stop scheduling new work after detecting a failure.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
