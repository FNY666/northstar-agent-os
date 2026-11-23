import assert from "node:assert/strict";
import test from "node:test";


test("root_import", async () => {
  const api = await import("northstar-fixture-ts-build-001");
  assert.equal(api.greet("Ada"), "Hello, Ada!");
});

test("subpath_import", async () => {
  const api = await import("northstar-fixture-ts-build-001/utils");
  assert.equal(api.double(3), 6);
});
