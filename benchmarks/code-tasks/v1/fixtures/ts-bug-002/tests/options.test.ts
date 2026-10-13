import assert from "node:assert/strict";
import test from "node:test";

import {resolveOptions} from "../options.ts";

test("an explicit zero timeout is preserved", () => {
  assert.equal(resolveOptions({timeoutMs: 0}).timeoutMs, 0);
});

test("an omitted timeout gets the default", () => {
  assert.equal(resolveOptions({}).timeoutMs, 5_000);
});
