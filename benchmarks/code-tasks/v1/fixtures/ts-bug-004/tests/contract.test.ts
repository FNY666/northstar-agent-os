import assert from "node:assert/strict";
import test from "node:test";
import {sortByPriority} from "../ordering.ts";

test("stable_ties", async () => {
  const input = [{id: "a", priority: 2}, {id: "b", priority: 2}, {id: "c", priority: 1}];
  assert.deepEqual(sortByPriority(input).map(item => item.id), ["a", "b", "c"]);
});

test("descending", async () => {
  assert.deepEqual(sortByPriority([{id: "low", priority: -1}, {id: "high", priority: 5}]).map(item => item.id), ["high", "low"]);
});
