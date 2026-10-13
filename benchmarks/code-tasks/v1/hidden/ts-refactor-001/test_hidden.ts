import assert from "node:assert/strict";
import test from "node:test";
import {Client} from "../client.ts";
import * as clientModule from "../client.ts";
globalThis.fetch = async () => { throw new Error("fixture forbids ambient network"); };

test("default transport class is public", async () => {
  assert.equal(typeof clientModule.FetchTransport, "function");
  assert.equal(typeof new clientModule.FetchTransport().request, "function");
});

test("default_compatible", async () => {
  const original = globalThis.fetch;
  try {
    let requested = "";
    globalThis.fetch = async input => { requested = String(input); return new Response("ok", {status: 200}); };
    assert.deepEqual(await new Client("https://api.example.test").get("x"), {status: 200, body: "ok"});
    assert.equal(requested, "https://api.example.test/x");
  } finally { globalThis.fetch = original; }
});

test("transport_error", async () => {
  const failure = new Error("transport failed");
  const client = new Client("https://api.example.test", {request: async () => { throw failure; }});
  await assert.rejects(client.get("x"), error => error === failure);
});
