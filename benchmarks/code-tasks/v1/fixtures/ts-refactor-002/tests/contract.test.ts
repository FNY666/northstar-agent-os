import assert from "node:assert/strict";
import test from "node:test";
import {request} from "../errors.ts";

test("http_kind", async () => {
  await assert.rejects(request(async () => ({status: 503, body: "no"})), error => {
    assert.equal(error.message, "HTTP 503"); assert.equal(error.kind, "http"); return true;
  });
});

test("success", async () => {
  assert.equal(await request(async () => ({status: 200, body: "ok"})), "ok");
});
