# Task fixture

`redact(value, paths, replacement='***')` returns a deep independent JSON-like value. Dotted paths match object fields; array elements inherit their array's path (`users.token` matches each user). Preserve non-target fields and input objects.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
