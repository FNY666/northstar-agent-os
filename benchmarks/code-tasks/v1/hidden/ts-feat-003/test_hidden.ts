import assert from "node:assert/strict";
import test from "node:test";
import {parseNdjson} from "../ndjson.ts";
async function* chunks(values: string[]) { yield* values; }
async function collect(values: string[]) { const result = []; for await (const row of parseNdjson(chunks(values))) result.push(row); return result; }

test("line_number", async () => {
  await assert.rejects(collect(['\n{"a":1}\n', 'bad\n']), /line 3/);
});

test("no_final_newline", async () => {
  assert.deepEqual(await collect(['{"v":"🙂', '"}']), [{v: "🙂"}]);
});

test("lazy_validation", async () => {
  async function* source() { yield "bad\n"; throw new Error("read past invalid line"); }
  await assert.rejects(async () => { for await (const row of parseNdjson(source())) void row; }, /line 1/);
});
