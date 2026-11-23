# Task fixture

`deepMerge(base, patch)` merges JSON-like own properties recursively, replaces arrays, and returns independent values. Reject `__proto__,constructor,prototype` at every depth in either input before writing output. Cycles are invalid.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
