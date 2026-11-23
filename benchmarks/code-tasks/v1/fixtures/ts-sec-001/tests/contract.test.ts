import assert from "node:assert/strict";
import test from "node:test";
import {isAllowedUrl} from "../allowlist.ts";

test("suffix_bypass", async () => {
  assert.equal(isAllowedUrl("https://api.example.test.evil.test/x", ["https://api.example.test"]), false);
});

test("allowed", async () => {
  assert.equal(isAllowedUrl("https://api.example.test/x?q=1", ["https://api.example.test"]), true);
});
