# Task fixture

`decodeChunks(chunks)` returns one UTF-8 string from arbitrary byte chunks. Preserve code points split across chunks and reject malformed/truncated UTF-8 with `TypeError`.

Run public checks with `node --test tests/contract.test.ts` on Node 24.
