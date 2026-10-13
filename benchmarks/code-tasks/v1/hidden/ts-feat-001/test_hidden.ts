import assert from "node:assert/strict";
import test from "node:test";
import {asyncMapLimit} from "../async_map.ts";

test("stable_order", async () => {
  const output = await asyncMapLimit([3, 1, 2], 2, async (value, index) => {
    for (let i = 0; i < value; i++) await Promise.resolve();
    return index;
  });
  assert.deepEqual(output, [0, 1, 2]);
});

test("first_failure", async () => {
  const failure = new Error("first");
  const started: number[] = [];
  await assert.rejects(asyncMapLimit([0, 1, 2, 3, 4], 2, async value => {
    started.push(value);
    if (value === 0) throw failure;
    await Promise.resolve(); return value;
  }), error => error === failure);
  assert.ok(started.length <= 2, "started new work after failure");
});

test("empty_and_fractional", async () => {
  assert.deepEqual(await asyncMapLimit([], 1, async x => x), []);
  await assert.rejects(asyncMapLimit([], 1.5, async x => x), RangeError);
});
