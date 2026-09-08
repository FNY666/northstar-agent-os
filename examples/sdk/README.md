# Embedding Northstar in your own Python: the `sdk` example

A minimal, runnable demonstration of the **Python API** (`sdk.py` in
`northstar-agent-runtime`) — drive one governed agent loop from your own
program, without a subprocess and without an API key.

```sh
python3 examples/sdk/run_sdk_demo.py
```

or, from an installed runtime:

```sh
pip install ./components/northstar-agent-runtime
python3 examples/sdk/run_sdk_demo.py
```

What one run gives back (printed by the demo):

```text
subtype       success
exit_code     0        # 0 = success (see events.EXIT_CODES)
session_id    ns-2026…
num_turns     4
tool_calls    2
denials       1
  refused: Write (… refused by the permission gate …)
```

The demo's second scripted action tries to **Write into the workspace without
permission** — under the default permission mode the gate refuses it, the
denial lands in `report.permission_denials`, and the run continues. That is
the embedding contract in one screen: the same governance applies no matter
whether you drive the runtime from a terminal or from code.

## The API in three lines

```python
import sdk

report = sdk.run(sdk.RunOptions(prompt="Summarise notes.txt", workspace="."))
print(report.subtype, report.exit_code, report.session_id)
```

- `sdk.run(options)` → `RunReport` (subtype, exit code, session id, turns,
  cost, denials, full event list).
- `sdk.stream_run(options)` → yields each event as a plain JSON-ready dict as
  it happens; the last one is the `result`. With `stream=True` the assistant text
  also arrives as `stream_delta` dicts *before* the matching `assistant` event -
  presentation only, and the runtime refuses a provider whose chunks disagree
  with the turn it finally returns.
- `options` covers the governance knobs: `permission_mode`, `allowed_tools` /
  `disallowed_tools`, `read_only`, turn/tool/budget ceilings,
  `halt_on_denial`, `session_dir` (append-only transcript), subagent depth,
  `stream` (incremental text), `lock_session` / `session_lease_seconds` (the
  claim on that transcript — see below), and the provider (`"scripted"` by
  default — deterministic and offline).

Setting `session_dir` also claims the session file, so two embedders aimed at one
session id cannot interleave into it. A run that loses the claim ends
`error_session_busy` (the same exit `7` the CLI returns) having written nothing; pass
`lock_session=False` where `flock` is unavailable and the run will say so rather than
pretend the transcript was protected. Subagents need no claim of their own: they share
their parent's transcript file, and the parent's claim covers them until the parent's
last record is on disk.

Deep repository features (policy files, AGENTS.md/context files, skills, MCP
servers) stay on the CLI by design; the SDK is the stable embedding contract.
Full reference: `docs/api/northstar-agent-runtime.md` (`sdk` and `events`
modules), and the [governance concept](../../docs/concepts/governance.md).
