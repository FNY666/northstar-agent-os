import assert from "node:assert/strict";
import test from "node:test";
import {redact} from "../redaction.ts";

test("arrays", async () => {
  assert.deepEqual(redact({users: [{token: "a"}, {token: "b"}]}, ["users.token"]), {users: [{token: "***"}, {token: "***"}]});
});

test("root_array_and_null", async () => {
  assert.deepEqual(redact([{token: "a"}, null], ["token"]), [{token: "***"}, null]);
});

test("independent_output", async () => {
  const input = {user: {names: ["Ada"]}};
  const output = redact(input, []);
  output.user.names.push("Bob");
  assert.deepEqual(input.user.names, ["Ada"]);
});
