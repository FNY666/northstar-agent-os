# Task fixture

`parseNdjson(chunks)` is an async generator accepting text chunks. Records may span chunks, blanks count toward physical line numbers, and a final non-newline record is valid. Validate/yield before consuming later chunks.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
