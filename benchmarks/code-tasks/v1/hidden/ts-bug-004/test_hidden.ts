import assert from "node:assert/strict";
import test from "node:test";
import {sortByPriority} from "../ordering.ts";

test("immutable", async () => {
  const input = Object.freeze([{id: "a", priority: 1}, {id: "b", priority: 3}]);
  assert.deepEqual(sortByPriority(input).map(item => item.id), ["b", "a"]);
  assert.deepEqual(input.map(item => item.id), ["a", "b"]);
});

test("many_ties", async () => {
  const input = Array.from({length: 40}, (_, i) => ({id: String(i), priority: i % 3}));
  const result = sortByPriority(input);
  for (const priority of [2, 1, 0]) {
    assert.deepEqual(result.filter(item => item.priority === priority).map(item => item.id), input.filter(item => item.priority === priority).map(item => item.id));
  }
});
