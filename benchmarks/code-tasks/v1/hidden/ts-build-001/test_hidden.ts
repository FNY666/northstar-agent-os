import assert from "node:assert/strict";
import test from "node:test";


test("private_internals", async () => {
  await assert.rejects(import("northstar-fixture-ts-build-001/internal"), {code: "ERR_PACKAGE_PATH_NOT_EXPORTED"});
});

test("documented_surface", async () => {
  const root = await import("northstar-fixture-ts-build-001");
  const utils = await import("northstar-fixture-ts-build-001/utils");
  assert.deepEqual(Object.keys(root), ["greet"]);
  assert.deepEqual(Object.keys(utils), ["double"]);
});
