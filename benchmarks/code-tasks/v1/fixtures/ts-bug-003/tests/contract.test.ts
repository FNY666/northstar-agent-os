import assert from "node:assert/strict";
import test from "node:test";
import {buildQuery} from "../query.ts";

test("repeated_values", async () => {
  const parsed = new URLSearchParams(buildQuery({tag: ["a", "b"]}));
  assert.deepEqual(parsed.getAll("tag"), ["a", "b"]);
});

test("encoding", async () => {
  const parsed = new URLSearchParams(buildQuery({q: "a & b"}));
  assert.equal(parsed.get("q"), "a & b");
});
