import assert from "node:assert/strict";
import test from "node:test";
import {deepMerge} from "../merge.ts";

test("nested_forbidden", async () => {
  for (const key of ["constructor", "prototype", "__proto__"]) {
    const value = JSON.parse('{"safe":[{"' + key + '":{"bad":1}}]}');
    assert.throws(() => deepMerge({}, value), TypeError);
    assert.throws(() => deepMerge(value, {}), TypeError);
  }
});

test("immutable", async () => {
  const base = {a: {x: [1]}};
  const patch = {b: [2]};
  const result = deepMerge(base, patch) as any;
  result.a.x.push(3); result.b.push(4);
  assert.deepEqual(base, {a: {x: [1]}}); assert.deepEqual(patch, {b: [2]});
});

test("null_and_array_replacement", async () => {
  assert.deepEqual(deepMerge({a: {x: 1}, b: [1]}, {a: null, b: [2]}), {a: null, b: [2]});
});
