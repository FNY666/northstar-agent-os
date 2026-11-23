import assert from "node:assert/strict";
import test from "node:test";
import {isAllowedUrl} from "../allowlist.ts";

test("userinfo", async () => {
  assert.equal(isAllowedUrl("https://api.example.test@evil.test/x", ["https://api.example.test"]), false);
  assert.equal(isAllowedUrl("https://user:pass@api.example.test/x", ["https://api.example.test"]), false);
});

test("port_policy", async () => {
  assert.equal(isAllowedUrl("https://api.example.test:8443/x", ["https://api.example.test"]), false);
  assert.equal(isAllowedUrl("https://api.example.test:443/x", ["https://api.example.test"]), true);
});

test("normalized_and_malformed", async () => {
  assert.equal(isAllowedUrl("HTTPS://API.EXAMPLE.TEST/x", ["https://api.example.test"]), true);
  assert.equal(isAllowedUrl("http://api.example.test/x", ["https://api.example.test"]), false);
  assert.equal(isAllowedUrl("not a url", ["https://api.example.test"]), false);
});
