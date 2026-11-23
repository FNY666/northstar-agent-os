import assert from "node:assert/strict";
import test from "node:test";
import {redact} from "../redaction.ts";

test("nested", async () => {
  const input = {user: {name: "Ada", token: "secret"}};
  assert.deepEqual(redact(input, ["user.token"]), {user: {name: "Ada", token: "***"}});
});

test("unchanged_source", async () => {
  const input = {token: "secret"};
  redact(input, ["token"]);
  assert.equal(input.token, "secret");
});
