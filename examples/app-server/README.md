# Local app-server example

This is an offline, deterministic example of the experimental T25 local
background-run surface. It starts a private Unix-domain JSON-lines server,
submits one host-configured scripted run, reads bounded events, and replays the
same `run.start` request id.

```sh
python3 examples/app-server/run_offline.py
```

No API key, model SDK, network listener or remote worker is used. The example
shows the important ownership boundary:

- the host constructs `RunManager` and injects `runtime_factory`;
- the host chooses the provider, workspace, policy and session configuration;
- the client can submit only a bounded prompt and use `run.start`, `run.status`,
  `run.events` and `run.cancel`;
- requests and responses are HMAC-authenticated, and the repeated start is an
  idempotent replay rather than a second run.

The manager registry is in memory. A real host should configure the runtime's
append-only session store when it needs a durable transcript. This example is
not a scheduler, a crash-recovery service, a public listener, an mTLS transport
or hosted execution.
