# `@northstar/agent-runtime` — the TypeScript face

A governed agent loop, called from Node:

```ts
import { run } from "@northstar/agent-runtime";

const report = await run({
  prompt: "summarise what changed in this workspace",
  workspace: "/srv/repos/app",
  provider: "anthropic",
  model: "claude-sonnet-4-5",
  permissionMode: "acceptEdits",
  maxTurns: 8,
  maxBudgetUsd: 0.5,
  sessionDir: "/srv/repos/app/.northstar/sessions",
});

console.log(report.subtype, report.totalCostUsd, report.permissionDenials.length);
```

There is no daemon, no second protocol, and no second implementation. A run is
`python3 -m cli run --json …` (or the installed `northstar-agent-runtime`) as a child process, and
this package is the typed argv builder plus the NDJSON reader around it. The permission gate, the
ceilings, the transcript, the redaction rules and the exit codes are the runtime's, so a TypeScript
caller cannot accidentally get a *different* agent than the shell gets — which is the whole
argument for this shape, and the whole cost of it (see "What this cannot do").

## Requirements

- **Node ≥ 22.6.** The `src/*.ts` files are the shipped artefact: node's native type stripping runs
  them directly, so there is no build step, no `tsc`, and no `npm install` — `dependencies` and
  `devDependencies` are both empty, on purpose.
- **Python ≥ 3.10 with this component importable.** The default runner is `python3 -m cli` executed
  from the component directory, which is why the package works from a checkout with nothing
  installed. Point `binary` at an installed `northstar-agent-runtime` if you have one.
- Nothing else. No network access is needed to run the test suite; the scripted provider is the
  only model the tests talk to.

`package.json` says `"private": true`. That is a decision, not an oversight: this repository does
not publish packages — see *Publishing* below.

## Running a run

| call                                                | what you get                                              |
| --------------------------------------------------- | --------------------------------------------------------- |
| `run(options, runner?)`                             | one `RunReport` after the child exits                     |
| `streamRun(options, runner?, trace?)`               | each event as it arrives; the last one is always `result` |
| `preview(options, runner?)`                         | the CLI's own `--dry-run` text, before a request or write  |

`RunReport` carries `subtype`, `sessionId`, `numTurns`, `durationMs`, `totalCostUsd`, `totalUsage`,
`pricingEstimated`, `errors`, `permissionDenials`, `toolCalls`, `exitCode`, `processExitCode`,
`isError`, `events`, `result`, `stderr`.

Two rules are what make this embeddable in a service:

1. **A finished run never throws.** A run that exhausted its turns, spent its budget, or was denied
   a tool returns a report whose `subtype` and `exitCode` say so. Throwing would invite callers to
   treat a policy decision as an SDK bug and retry it.
2. **An unusable stream throws.** No `result` event at all, a line that is not JSON, or exit 64
   raises `RunFailedError` / `UsageError`. Those are complaints about the *call*, and exit 64 in
   particular means nothing ran, so retrying the same command cannot help.

`streamRun` yields `RunEvent`s typed in `src/events.ts`. An event whose `type` this package does not
know still parses and passes through with every field intact: a newer runtime must not break an
older caller. Known events are normalised, so the fields the types declare as present really are.

```ts
for await (const event of streamRun(options)) {
  if (event.type === "assistant") for (const block of event.content) console.log(block.type);
}
```

`trace` is an optional box (`RunTrace`) that fills in `exitCode`, `stderr` and `aborted` as the
child exits — an async generator has nowhere else to put "the process exited 5", and inventing a
pseudo-event for it would put a non-contract line in a contract stream.

## Options, and the flags they compile to

`RunOptions` is a closed set: every key maps to exactly one `northstar-agent-runtime run` flag, and
an unknown key is a `ConfigurationError` rather than something silently dropped. `retry`, `mcp` and
`sidecar` are grouped namespaces whose keys map to their own flags. `--json` is appended by
`toArgv` and is not caller-settable.

The traps a reader of the type alone would not guess, all of them inherited from the runtime:

- **`maxToolCalls: 0` means no tool call is allowed.** Not unlimited. The loop checks
  `max_tool_calls is not None`, and `--dry-run` prints `max_tool_calls=0 (no tool call allowed)`
  against an omitted ceiling printing `unlimited` — the two are different policies, and `null` (or
  omission) is how you ask for the operator's own number instead.
- **A ceiling cannot be raised from here, only tightened.** `retry.maxAttempts` and friends may ask
  for fewer attempts than the workspace's `[retry]` table allows; `baseDelayMs`, `maxDelayMs`,
  `jitter`, `respectRetryAfter` and `onContextOverflow` are *policy-file* keys and are refused by
  name, with a message saying so. The schedule is the operator's; the run may only shorten it.
- **`compactionThresholdTokens: 0` disables compaction**, unlike every other zero: `maxBudgetUsd: 0`
  or `maxTurns: 0` is a mistake and is refused before a process exists.
- **`mcp.elicitAnswers` requires `mcp.elicit: true`.** Answering a server's input request is opt-in;
  supplying answers is not consent.
- **`mcp.config` reads a workspace file; `mcp.allowExec` starts what it names.** Two flags, two
  decisions, so that a repository can declare a server without being able to launch one. `mcp.env`
  is the matching release list for `${VAR}` and for the environment a server child inherits.
- **`mcp.servers` cannot combine with `agent`**, and `--mcp-config` takes a path (or `off`/`auto`),
  never an inline object: a run may use the servers the workspace declares or name its own, and an
  inline declaration would let a caller smuggle a server definition past review.
- **`resumeRecord` needs `resumeFrom`**, and `contextFile` excludes `noProjectContext`.
- **`retry: { enabled: false }` is the only spelling of `--no-retry`**; `true` means "leave the
  policy alone", not "retry everything".
- **No option carries a credential.** `baseUrl` exists; an API key does not. The runtime reads
  `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` from the environment, and a test asserts that no flag name
  here looks like a secret, so a config object stays safe to log.

## Exit codes

`EXIT_CODES` mirrors `events.EXIT_CODES`: `0` success, `1` error during execution, `2` max turns,
`3` max tool calls, `4` max budget, `5` permission denied, `6` postconditions failed, `7` session
busy (another live process holds the transcript — wait and retry), plus `USAGE_ERROR = 64` for a
command that was refused before anything ran. `report.exitCode` is the code the subtype implies —
what a wrapper should act on — and `report.processExitCode` is what the child actually returned.
They should agree; when they do not, the report is telling you the CLI is misbehaving.

## Testing

```sh
cd components/northstar-agent-runtime/sdk-ts
node --test "test/*.test.ts"        # 57 tests, no install, no network
make -C ../../.. ts-test            # the same, guarded: skipped, not failed, where node is old
```

`test/parity.test.ts` asks the runtime itself — the exit-code table from `events.py`, the closed
value sets from `permissions.py`/`postconditions.py`/`provider_retry.py` and from
`run --help`'s own choice lists, the `result` payload's key set from a real `--json` run — so the
mirror fails when the contract moves. `../../../tests/test_typescript_sdk.py` runs the same
comparisons from Python, so drift still fails a build image that has no node in it; it is the part
of the gate that cannot be skipped.

## What this cannot do

- **No streaming input.** The CLI takes a prompt at argv, so a caller cannot answer a mid-run
  question. `mcp.elicitAnswers` is a pre-declared answer table, not a conversation.
- **No callbacks across the process boundary.** Hooks, permission prompts and subagent progress are
  in-process Python concepts; here they surface as events in the stream, not as handlers.
- **One process per run.** Startup is milliseconds, not microseconds: fine for a service call, not
  for a per-token loop.
- **`--stream` deltas arrive as events, not as a typed partial-text API** — the runtime emits
  `stream_delta` lines, and this package hands them over without re-timing them.
- **The mirror is a subset.** `--continue`, `--session`, `--halt-on-*` extras the face has not
  mapped are refused, not passed through: `extraArgs`-style escape hatches would put the drift gate
  out of reach of the very options that need checking.

## Publishing

Not from this repository, and not yet. The version stays `0.1.0.dev0`, `private: true` stays in
`package.json`, and no tag is cut: publishing is the boundary the project has decided not to cross,
so the TypeScript face ships as source plus tests, and consumers vendor it (or install the whole
checkout) until that decision changes. The Python twin, `../sdk.py`, is importable today from the
same checkout for exactly the same reason.
