# Local app-server example

This is an offline, deterministic example of the experimental T25 local
background-run surface. It starts a private Unix-domain JSON-lines server,
submits one host-configured scripted run, reads bounded events, and replays the
same `run.start` request id. It uses `server.wait_ready()` so startup errors are
reported explicitly instead of being hidden behind a socket polling race.

```sh
python3 examples/app-server/run_offline.py
```

`node_client.mjs` is a dependency-free Node consumer for the same protocol. A
host can start the Python server and then run its smoke client with the socket
path and channel secret:

```sh
node examples/app-server/node_client_smoke.mjs /absolute/app.sock SECRET_HEX
```

The Node client verifies response HMACs and uses bounded `run.wait`; it is an
experimental source example, not an npm package or publication.

No API key, model SDK, network listener or remote worker is used. The example
shows the important ownership boundary:

- the host constructs `RunManager` and injects `runtime_factory`;
- the host chooses the provider, workspace, policy and session configuration;
- the client can submit only a bounded prompt and use `run.start`, `run.status`,
  `run.events`, bounded `run.wait` and `run.cancel`;
- requests and responses are HMAC-authenticated, and the repeated start is an
  idempotent replay rather than a second run.

The manager registry is in memory. A real host should configure the runtime's
append-only session store when it needs a durable transcript. This example is
not a scheduler, a crash-recovery service, a public listener, an mTLS transport
or hosted execution.
