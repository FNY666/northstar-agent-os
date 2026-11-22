import assert from "node:assert/strict";
import test from "node:test";
import {deepMerge} from "../merge.ts";

test("unsafe_key", async () => {
  const patch = JSON.parse('{"__proto__":{"polluted":"yes"}}');
  assert.throws(() => deepMerge({}, patch), TypeError);
  assert.equal(({} as any).polluted, undefined);
});

test("ordinary", async () => {
  assert.deepEqual(deepMerge({a: {x: 1}}, {a: {y: 2}}), {a: {x: 1, y: 2}});
});
