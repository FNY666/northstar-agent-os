# Task fixture

Keep `request(fetcher)` success results and existing error messages. Export `ClientError` with `kind='http'|'network'|'unknown'`. Error objects from fetchers are network failures; non-Error causes are unknown and must be retained.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
