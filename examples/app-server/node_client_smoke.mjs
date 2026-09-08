#!/usr/bin/env node
/** Run the Node consumer against a host-started local app-server. */
import { AppServerClient } from "./node_client.mjs";

const [socketPath, secretHex] = process.argv.slice(2);
if (!socketPath || !secretHex) {
  console.error("usage: node node_client_smoke.mjs /absolute/app.sock SECRET_HEX");
  process.exit(64);
}

try {
  const client = new AppServerClient(socketPath, { secret: Buffer.from(secretHex, "hex") });
  const description = await client.describe({
    requestId: "node-example-describe",
    actorId: "node-example",
  });
  if (!description.capabilities.operations.includes("run.wait")) {
    throw new Error("host did not advertise run.wait");
  }
  const started = await client.start({
    requestId: "node-example-start",
    actorId: "node-example",
    prompt: "reply with a short offline result",
  });
  const waited = await client.wait({
    requestId: "node-example-wait",
    actorId: "node-example",
    runId: started.run_id,
    timeoutMs: 2_000,
  });
  const events = await client.events({
    requestId: "node-example-events",
    actorId: "node-example",
    runId: started.run_id,
  });
  console.log(JSON.stringify({ status: waited.status, eventCount: events.events.length }));
} catch (error) {
  console.error(`${error.code ?? "client_error"}: ${error.message}`);
  process.exit(1);
}
