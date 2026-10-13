import assert from "node:assert/strict";
import test from "node:test";
import {buildQuery} from "../query.ts";

test("reserved_and_unicode", async () => {
  const parsed = new URLSearchParams(buildQuery({"x=y": ["中文", "+#?"]}));
  assert.deepEqual([...parsed], [["x=y", "中文"], ["x=y", "+#?"]]);
});

test("immutability", async () => {
  const tags = Object.freeze(["", "same", "same"]);
  const input = Object.freeze({tag: tags, omitted: undefined});
  assert.deepEqual(new URLSearchParams(buildQuery(input)).getAll("tag"), ["", "same", "same"]);
  assert.deepEqual(tags, ["", "same", "same"]);
});

test("omitted", async () => {
  assert.equal(buildQuery({none: undefined, empty: []}), "");
});
