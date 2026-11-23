import assert from "node:assert/strict";
import test from "node:test";
import {decodeChunks} from "../decoder.ts";

test("every_byte", async () => {
  const bytes = new TextEncoder().encode("你好🙂");
  assert.equal(decodeChunks([...bytes].map(byte => Uint8Array.of(byte))), "你好🙂");
});

test("invalid_final", async () => {
  assert.throws(() => decodeChunks([Uint8Array.of(0xe2, 0x82)]), TypeError);
});

test("empty", async () => {
  assert.equal(decodeChunks([]), "");
  assert.equal(decodeChunks([new Uint8Array()]), "");
});
