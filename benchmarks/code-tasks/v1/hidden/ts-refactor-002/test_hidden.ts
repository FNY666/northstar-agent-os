import assert from "node:assert/strict";
import test from "node:test";
import {request} from "../errors.ts";
import * as errors from "../errors.ts";

test("exported error class", async () => {
  assert.equal(typeof errors.ClientError, "function");
  await assert.rejects(request(async () => ({status: 400, body: "no"})), error => {
    assert.ok(error instanceof errors.ClientError);
    assert.equal(error.kind, "http");
    return true;
  });
});

test("network_cause", async () => {
  const cause = new TypeError("offline");
  await assert.rejects(request(async () => { throw cause; }), error => {
    assert.equal(error.message, "request failed: offline"); assert.equal(error.kind, "network"); assert.equal(error.cause, cause); return true;
  });
});

test("unknown_cause", async () => {
  const cause = {reason: "unknown"};
  await assert.rejects(request(async () => { throw cause; }), error => {
    assert.equal(error.kind, "unknown"); assert.equal(error.cause, cause); assert.equal(error.message, "request failed: [object Object]"); return true;
  });
});
