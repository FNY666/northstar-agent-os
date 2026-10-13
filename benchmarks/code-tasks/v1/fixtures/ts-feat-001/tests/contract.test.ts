import assert from "node:assert/strict";
import test from "node:test";
import {asyncMapLimit} from "../async_map.ts";

test("bounded_concurrency", async () => {
  let active = 0, peak = 0;
  const result = await asyncMapLimit([1, 2, 3, 4], 2, async value => {
    active++; peak = Math.max(peak, active);
    await Promise.resolve(); active--;
    return value * 2;
  });
  assert.ok(peak <= 2, "concurrency limit exceeded");
  assert.deepEqual(result, [2, 4, 6, 8]);
});

test("invalid_limit", async () => {
  await assert.rejects(asyncMapLimit([1], 0, async x => x), RangeError);
});
