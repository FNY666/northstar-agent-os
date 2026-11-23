import assert from "node:assert/strict";
import test from "node:test";
import {parseNdjson} from "../ndjson.ts";
async function* chunks(values: string[]) { yield* values; }
async function collect(values: string[]) { const result = []; for await (const row of parseNdjson(chunks(values))) result.push(row); return result; }

test("split_records", async () => {
  assert.deepEqual(await collect(['{"a":', '1}\n{"b":2}', '\n']), [{a: 1}, {b: 2}]);
});

test("blanks", async () => {
  assert.deepEqual(await collect(['\n \n{"ok":true}\n']), [{ok: true}]);
});
