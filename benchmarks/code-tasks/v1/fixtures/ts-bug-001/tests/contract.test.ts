import assert from "node:assert/strict";
import test from "node:test";
import {decodeChunks} from "../decoder.ts";

test("split_codepoint", async () => {
  const bytes = new TextEncoder().encode("a🙂z");
  assert.equal(decodeChunks([bytes.slice(0, 3), bytes.slice(3)]), "a🙂z");
});

test("ascii", async () => {
  assert.equal(decodeChunks([Uint8Array.of(65), Uint8Array.of(66)]), "AB");
});
