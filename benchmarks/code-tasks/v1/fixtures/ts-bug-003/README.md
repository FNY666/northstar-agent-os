# Task fixture

`buildQuery(params)` returns a query string without `?`. Array values repeat the key, `undefined` and empty arrays are omitted, and all text must round-trip through `URLSearchParams`. Preserve input structures.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
