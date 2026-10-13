import assert from "node:assert/strict";
import test from "node:test";

import {resolveOptions} from "../options.ts";

test("negative timeouts are rejected", () => {
  assert.throws(() => resolveOptions({timeoutMs: -1}), RangeError);
});

test("the default input object remains optional", () => {
  assert.deepEqual(resolveOptions(), {timeoutMs: 5_000});
});
