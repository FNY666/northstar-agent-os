import assert from "node:assert/strict";
import test from "node:test";
import {Client} from "../client.ts";
globalThis.fetch = async () => { throw new Error("fixture forbids ambient network"); };

test("injected_transport", async () => {
  const urls: string[] = [];
  const client = new Client("https://api.example.test", {request: async url => { urls.push(url); return {status: 201, body: "created"}; }});
  assert.deepEqual(await client.get("items"), {status: 201, body: "created"});
  assert.deepEqual(urls, ["https://api.example.test/items"]);
});
