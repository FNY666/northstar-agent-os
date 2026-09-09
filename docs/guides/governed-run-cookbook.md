# Guide: running a governed run (cookbook)

End-to-end walk of one governed run with the offline tools, then with a live
provider. All switches shown here are validated by the runtime's own tests and
demo; exit codes follow the table in the runtime README.

## 1. Bring up the components

From the repository root:

```sh
make test          # all six components + repository documentation checks
make demo          # offline demo smoke (see step 2)
```

To install into a virtualenv (`components/*` are local path-installable):

```sh
make install       # creates ./.venv with all six components
./.venv/bin/northstar doctor --workspace .
```

## 2. First run: the offline demo

```sh
make demo
# or: cd examples/demo && sh run_offline.sh
```

One full governed loop via the **product path** (`bin/northstar agent`): Read call
+ scripted model turn through the same code path a live run uses — permission
gate, ceilings, event stream, append-only transcript and per-turn checkpoint under
`examples/demo/workspace/.northstar/sessions/`. Exit code 0.

## 3. Dry-run before anything real

```sh
bin/northstar agent --workspace . --prompt "summarise the repo" \
  --scripted-text ok --dry-run
# kernel path (every default explicit): python3 -m cli run …
```

Prints the plan — provider, pricing, tools, skills, MCP servers, sessions —
and exits 0 **without sending a request or spawning a child process**.
`--dry-run` is the cheapest way to validate a configuration.

## 4. Tighten, then run

```sh
python3 -m cli run --workspace . --prompt "read README and note the license" \
  --read-only                       # Write/Edit structurally removed
python3 -m cli run --workspace . --prompt "..." --permission-mode plan
```

With a live model, `--provider anthropic` and `ANTHROPIC_API_KEY` switch from
the scripted provider. Any denial under `--halt-on-denial` ends the run with
`error_permission_denied` (exit 5) and prints every refused tool to stderr.

## 5. Add context and tools

- **Policy file**: `.northstar/config.toml` in the workspace — every key
  optional, values may only tighten; `deny_tools`, ceilings, `project_context`.
- **Project instructions**: `AGENTS.md` (auto-injected) or
  `--context-file PATH` (must live inside the workspace).
- **Skills**: `.northstar/skills/<name>/SKILL.md` — read-only packages listed
  in the system prompt.
- **Subagents**: `.northstar/agents/*.md` (workspace) or `--agent <definition>`
  — fixed tool subset and ceilings; combine with `--max-subagent-depth`.
- **MCP servers** (experimental): `--mcp-server "name=python3 /path/server.py"`
  + `--allow-tool mcp__name__tool`; never combine with `--agent`.
- **Delegated execution**: `--sidecar-socket /var/run/northstar-codex/sidecar.sock`.

## 6. Audit what happened

```sh
python3 -m cli sessions list
python3 -m cli sessions view <session-id>     # read-only
```

Transcripts are append-only JSONL; the final summary line prints
`turns=… tool_calls=… cost=$… session=…` and is the one stable line scripts
should parse (`--quiet` keeps it).

## 7. Make "it says it finished" not the evidence

```sh
python3 -m cli run --workspace . --prompt "write the runbook" \
  --verify exists:docs/runbook.md --verify unchanged:uv.lock
```

Postconditions are checked by the runtime after the run, against a snapshot taken
before the first event. A failed check ends the run with
`error_postconditions_failed` (exit 6) and writes a `postconditions` record into the
transcript. Declare the durable set in `.northstar/config.toml` so CI inherits it:

```toml
[[verify]]
kind = "unchanged"          # exists | absent | changed | unchanged | contains
path = "uv.lock"
```

Two things to keep in mind: the conditions are **not** shown to the model (a model
that knows the check optimises the check), and `contains` is convenience — the
structural kinds are what a sign-off should rest on. For "the tests actually pass",
pair it with a `Stop` command hook that runs the suite and vetoes finishing.

## 8. Review Agent Skills, then pin what you reviewed

```sh
python3 -m cli skills check --workspace .            # findings; exit 1 on errors
python3 -m cli skills check --workspace . --write-lock   # pin digests in .northstar/skills.lock
python3 -m cli run --workspace . --require-skill-lock …  # refuse to start on drift
python3 -m cli skills check --root ../downloaded-bundle  # vet a third-party bundle first
```

`skill_audit` is deterministic and offline: instruction override, concealment,
policy self-edit, `curl … | bash`, credential paths, metadata endpoints, invisible
unicode, and context bloat. Commit `skills.lock`; `doctor` warns when it disagrees
with the tree. A run cannot rewrite it — `.northstar` is write-protected for the
agent, so the review record stays outside the reach of what it gates.

## 9. Resume and fork at a turn boundary

```sh
python3 -m cli run --workspace . --session-dir S --checkpoint-turns 1 …
python3 -m cli run --workspace . --session-dir S --resume-from <parent-session-id> …
```

A checkpoint records the transcript length, its digest, and the consumed
turns/tool calls/cost. `--resume-from` **forks**: a new file, the parent untouched,
and the new run starting *at* the parent's counters — so resuming cannot hand out a
fresh `max_budget_usd` or restart `max_turns`. `--resume-record N` picks an earlier
boundary (rewind), and a digest mismatch refuses the run instead of attributing
numbers to the wrong history.

## 10. Connect an MCP server, and let it ask only what you pre-approved

```sh
# 1. See the stance before anything spawns (no child process, no probe):
python3 -m cli run --workspace . --prompt "hi" --scripted-text x \
  --mcp-server "fs=python3 /opt/mcp/fs_server.py" --dry-run
#    mcp_servers=fs=… (protocol=auto, elicit=off→input_required is declined,
#                     roots=off, sensitive_input=off, rounds=3)

# 2. Allow one remote tool, as with any mutating tool:
python3 -m cli run --workspace . --prompt "…" \
  --mcp-server "fs=python3 /opt/mcp/fs_server.py" --allow-tool mcp__fs__list_directory

# 3. If that server uses input_required, answer it from a pre-approved set:
python3 -m cli run … --mcp-elicit --mcp-elicit-answers '{"approved": true}'
```

What the client guarantees, and what to check in a log:

- **Which generation it settled on**, printed once per server on stderr with the
  reason (`server/discover answered: …` or `… answered with a non-modern error
  (-32601 …): legacy server`). `--mcp-protocol` pins it when you already know; a
  `-32022` refusal adopts the version the server named instead of falling back,
  because only a 2026-07-28 server can produce that code.
- **`elicit=off` is the safe default and it is enforced in the protocol**, not in
  a handler: without an approver the `elicitation` capability is never advertised,
  so a conforming server cannot ask at all. Turning it on does not open a prompt —
  `--mcp-elicit-answers` is a *closed set*, and a server that starts asking for a
  field outside it gets a refusal, which is exactly the behaviour you want after a
  dependency update.
- **Refusals are visible to the model and to you.** A declined round returns a tool
  error naming each request and why it was refused, and the session transcript keeps
  the `[governance] …` note. Values are never recorded, only field names.
- Keep `roots` off unless a server truly needs the tree, and keep
  `sensitive_input` off full stop — a credential belongs in a secret store, not in
  a text box that a remote process designs.

For an embedding that needs the decisions in its own audit pipeline, build the
client directly and pass both hooks:

```python
from mcp_client import McpStdioClient, mcp_tool_specs
from mcp_elicitation import make_answers_elicitor

client = McpStdioClient(
    "fs",
    ["python3", "/opt/mcp/fs_server.py"],
    elicitor=make_answers_elicitor({"approved": True}),
    audit=lambda record: my_audit.append(record),   # {"kind": "mcp-elicitation", …}
    workspace_root=".",
)
client.connect()
for spec in mcp_tool_specs(client):
    registry.register(spec, replace_existing=False)
print(client.negotiation, client.elicitation_log)
```

## 11. Watch it live without trusting the live view

```sh
python3 -m cli run --workspace . --prompt "…" --stream          # text as it arrives
python3 -m cli run --workspace . --prompt "…" --stream --json   # {"type":"stream_delta",…}
python3 -m cli sessions show <id>                                # the transcript, unchanged shape
```

`--stream` is presentation only, and the runtime enforces that rather than assuming
it: a provider's chunks must concatenate to the turn's recorded text, or the turn fails
as `error_during_execution` with **no assistant record written**. So a stream can be
shorter than the record (the client caps a turn at 200 000 characters / 4 000 events
and says so in an `informational` event) but never different, and an interrupted run
leaves the half-spoken text out of the transcript entirely.

Two consequences worth knowing when you build on top of it:

- deltas are **not** transcript records, so `sessions show`, checkpoint digests and
  `--resume-from` behave exactly as they do without streaming — there is nothing to
  replay;
- tool arguments and reasoning content are never streamed, so a live view is not a
  complete view of a turn. If your UI needs "what the model actually said", read the
  `assistant` event; if it needs liveness, read the deltas and treat the record as the
  verdict.

For CI, keep `--stream` off: the value is a human watching. `--quiet --stream` prints
the result line only, and `--json --stream` is the shape to use if you do want the
deltas in a log - each is one more NDJSON line, and the final line is still the single
`result`.

## 12. Two shells, one session: the lease, and what durable-run shares with it

```sh
# shell A                                                       # shell B
python3 -m cli run --session-dir S --resume <id> \              python3 -m cli run --session-dir S --resume <id> \
  --prompt "refactor the parser"                                  --prompt "and now the tests"
                                                                  echo $?        # 7
```

`RECORD_TYPES` is append-only and fsynced, which means two runs pointed at one session id
produce a file neither of them can explain: valid-looking lines in an order that matches
no single conversation. The runtime claims the session for the duration of a run, and the
second claimant is refused **before it writes anything** — no hook fires, no record lands,
and the failure has its own name (`error_session_busy`, exit 7) so a wrapper can tell
"wait and retry" from "the command was wrong" (64) and from "the run failed" (1).

What the claim is *not*, and why:

- **not a timeout.** `--session-lease-seconds N` (default 900) is a liveness promise the
  run renews at every turn boundary and every checkpoint, so a slow tool call never loses
  its session. A holder whose promise has lapsed is still refused, because that reading
  means "it forgot to renew", not "it is gone". There is no `--steal-lease` flag: a wedged
  holder is exactly the case where a second writer must be refused. End the holder, or
  fork instead (`--resume-from` writes a new file and never touches the parent).
- **not a record type.** The transcript's `session_start` says `{locked, ttl_seconds,
  kernel_lock_available}` — what this file was written *under* — and nothing else: no owner
  id, no path. Those identify a process, and a record that varies between two identical
  runs is a record a checkpoint digest cannot certify.
- **not a lease you can read as a fact.** `sessions list` and `sessions show` print the
  holder's claim labelled `(unverified: the lock was not probed)`. A viewer that took the
  lock to answer a question could make an unrelated run refuse to start, so it doesn't.
- **not inherited by subagents.** A delegated turn shares its parent's transcript file, and
  `flock` is per open file description, so a child that claimed again would be refused by
  its own parent. The parent's claim covers the child, and releases after the parent's last
  record.

`--no-session-lease` exists for the one case where it is honest: a host with no `flock`,
where the runtime would otherwise refuse to start. It is not accepted together with
`--session-lease-seconds`, because that pairing is a caller who believes they are protected.

If you also run `northstar-durable-run`, a checkpoint needs no translation by hand:
`durable_bridge.checkpoint_event()` turns the runtime's `checkpoint` record into a dict that
satisfies durable's closed `EventContract` schema, and `checkpoint_document()` into a
`northstar.checkpoint.v1` document digested under durable's own canonical rule — so one
boundary can be indexed in one event stream keyed by the same `run_id`. Two limits are part
of that design rather than caveats in it: the transcript format stays the runtime's (a
checkpoint digest certifies bytes, so unifying them would rewrite what every existing
checkpoint attests to), and a durable event never authorises a resume on its own —
`checkpoint_from_event()` re-runs the digest over the transcript through the same
`prepare_resume` gate a runtime checkpoint passes. Same gate, whoever wrote the boundary.

## 13. Ship an extension as a bundle, and let the lock carry the review

A plugin here is how you hand someone four things at once — a skill, an agent file, a
lifecycle hook, and an MCP server — without handing them a way around the gate. The format
is `plugin.toml` next to those files; the install is a visible copy under
`.northstar/plugins/`; the review is one line in `.northstar/plugins.lock`.

```toml
# release-bundle/plugin.toml  -  names must match the directory, or install refuses
schema_version = "northstar.plugin.v1"
name = "release-bundle"
version = "1.2.0"
publisher = "release-team"
description = "Changelog skill, a release critic, and a veto on editing policy."

[compatibility]
platforms = ["posix", "linux", "darwin"]   # enforced at install: refused, not half-applied
requires_flock = true                      # the session lease needs it, and so do we

[components]
skills = ["skills"]
agents = ["agents"]

[[components.hooks]]
event = "PreToolUse"
script = "hooks/block-force.py"             # a file in the bundle; there is no command key
interpreter = "python3"                      # an allowlist entry, never a path
timeout_ms = 1500

[policy]
max_turns = 12                               # tighten-only, against the workspace's own file
deny_tools = ["Edit", "Write"]
```

```console
$ northstar-agent-runtime plugin install ../bundles/release-bundle --workspace .
installed release-bundle 1.2.0 at ./.northstar/plugins/release-bundle
  content digest sha256:1820482d0d4a75eea4cd7242697cb82048b6214f7e1b86f316d794f50c8be283
  pinned in plugins.lock; review the diff before committing it
$ northstar-agent-runtime plugin compat --workspace .
PLUGIN               linux     darwin    windows     portable
release-bundle       ok        ok        NO          no

  release-bundle on windows: claims darwin, linux, posix, which does not cover this windows host; requires flock, which this platform does not provide (the session lease would be refused)
```

Then the run tells you what it took, in the same lines it tells you everything else it took:

```console
$ northstar-agent-runtime run --workspace . --prompt "release 1.2" --dry-run --enable-workspace-hooks
disallowed_tools=Edit,Write
max_turns=12 max_tool_calls=50 max_budget_usd=unlimited
retry=2 additional attempt(s) on rate_limited, overloaded, network, timeout, server_error; base 250 ms x2 up to 20000 ms, full jitter, deadline 60000 ms (worst case 750 ms/turn)
workspace_agents=release-critic
skills=1 package(s): no-force-push
plugins=1 bundle(s): release-bundle@1.2.0 (1820482d0d4a)
hooks=1 command hook(s): PreToolUse<-block-force.py
```

Nothing in those six lines came from a new mechanism: the ceiling is the policy file's
min-merge, `workspace_agents` is `register_workspace_agents` refusing a shadow, `skills` is
`discover_skills` refusing a name collision, and `hooks` is `command_hooks.parse_hooks`
confining the script to the workspace — which is also why `--enable-workspace-hooks` is
still what runs them, bundle or not.

What to expect from the refusals, because they are the feature:

- **A changed file stops the run.** Edit `.northstar/plugins/<name>/` by hand after
  installing and `plugin verify` prints `drift`, `run` exits 64, and nothing loads. Re-pin
  with `plugin verify --write-lock` once you have read what changed — the report then names
  the bundles whose pin moved, since pinning *is* the review and should not look like a
  green light.
- **A name collision is an error, not an override.** A bundle's skill or agent that shadows
  one from the repository (or from another bundle) is refused, because which instructions
  the model sees must not depend on discovery order.
- **A loosening ceiling is refused at install**, and a `[policy]` that denies a tool this
  runtime does not have is refused at load: a denial that matches nothing is a false sense of
  one. `deny_tools = ["WebFetch"]` in a workspace with no such tool is not caution, it is
  noise, and noise in a governance file is how real lines stop being read.
- **Secrets do not travel.** A bundle's MCP server may name a command and args; `env` is
  refused at load with a pointer to the workspace's own `.mcp.json` (§15), which the operator imports
  with `--mcp-config` — where `env` comes from their own environment rather than from the bundle. And a bundle has no
  `allow_tools`: auto-approval is something a human types at a command line.
- **The bundle's skill text is read before it is copied.** `plugin install` runs the same
  versioned rules `skills check` uses over each `SKILL.md` in the bundle and refuses on any
  finding at or above `--fail-on`; `plugin verify` re-runs them, so a rules update shows up
  against a pinned bundle instead of only against a fresh install.
- **Export is a port of the portable half.** `plugin export claude-code` renders the skills,
  the agent files and the hook there, in that host's shape — and still refuses to write,
  because `[policy]` has no equivalent anywhere else. `cursor` additionally cannot carry the
  agents or the hooks. Both messages name the missing pieces; `--allow-drop` is what writes a
  knowingly downgraded port. Keep the governed half in Northstar rather than exporting it away.

There is no marketplace, no index and no dependency resolver, and that is a decision
rather than a missing feature: everything a bundle can do is already a file in your
repository, which means the diff is the install, the review is the lock, and `git revert` is
the uninstall.

## 14. Bound what a flaky provider may cost you

The failure that actually reaches an operator is rarely the model refusing: it is a 429, a
529, a connection reset at 03:00. What that costs a governed run used to be decided by the SDK
client's `max_retries`, which the runtime neither saw nor reported. It is decided here now, and
it is visible before the run in the same dry-run you read for the ceilings.

```toml
# .northstar/config.toml
[retry]
max_attempts = 4
base_delay_ms = 500
max_delay_ms = 5000
deadline_ms = 30_000
jitter = "full"
on_context_overflow = "compact_once"
```

Then rehearse it offline, with no key and no network - a scripted turn may raise a classified
fault, so the retry path runs on the same provider as the demo:

```console
$ northstar-agent-runtime run --workspace . --script plan.json --prompt "draft the release notes"
· attempt 1/4 failed: rate_limited (too many requests) - retrying in 20 ms (waited 20 ms so far)
· attempt 2/4 failed: overloaded (overloaded_error) - retrying in 10 ms (waited 30 ms so far)
Release notes drafted: 3 fixes, 1 feature.

[success] turns=1 tool_calls=0 cost=$0.000000 session=ns-20260908T160541Z-148f55aa
```

Four things to know before you widen it:

- **The flags can only shorten the wait.** `--retry-max-attempts 9` against a workspace that
  said 4 gets you 4. `--no-retry` is what a CI job wants: the first fault, reported at once,
  with jitter off so nothing hides behind a sleep.
- **Four faults are not retryable and saying so is the point.** Auth and bad-request faults do
  not become true on the second try; an unclassified fault is not evidence of transience; and
  a stream that broke after characters reached your terminal is never re-issued, because a
  transcript that repeats a sentence is worse than one that stops.
- **A retry is not a turn.** It does not consume `max_turns` (the model never answered), and it
  leaves no transcript record - the digest your reviewer pinned should not move because the
  transport hiccupped. It is an event, a span attribute, and, when it fails, part of the
  explanation: `(after 4 request(s), 35 ms of policy waiting)`.
- **`on_context_overflow = "compact_once"` degrades the request, once.** A 413 gets the
  transcript compacted through the ordinary `PreCompact` hook path - so a hook may veto it - and
  the re-issued request costs no retry budget. There is no `fallback_model` on purpose: another
  model answering is a policy change, not a transport detail.

## 15. Import the MCP servers a repository already declares

Most projects already carry an MCP config file: Claude Code reads `.mcp.json`,
Cursor `.cursor/mcp.json`, VS Code `.vscode/mcp.json` (under `servers`), Gemini
`.gemini/settings.json`. Until this batch the only way in here was to retype that
list as `--mcp-server` flags — and three of our own docs pointed at a workspace
`[mcp.servers]` table that has never existed. The file can be read now, with our
gates rather than theirs:

```sh
# 1. Look first. Read-only: nothing spawned, nothing contacted, nothing written.
python3 -m cli mcp list --workspace .
#    == MCP declarations ==
#      file: .mcp.json
#      demo: python3 server.py
#          env=DEMO_TOKEN cwd=. sandboxed=false (.mcp.json)
#      ! .mcp.json: remote: refused (url/headers); this runtime speaks MCP over stdio only
#      (declarations are inert until a run passes both --mcp-config and --mcp-allow-exec; approval lists are never honoured)

# 2. Then decide. `auto` searches the four known locations, a PATH reads exactly one.
python3 -m cli run --workspace . --prompt "summarise the files" \
  --mcp-config auto --dry-run
python3 -m cli run --workspace . --prompt "list the files" \
  --mcp-config .mcp.json --mcp-allow-exec --allow-tool mcp__demo__list_directory
```

What the importer refuses to do, in its three severities:

- **start something nobody asked for.** `--mcp-config` defaults to `off`, so a
  declaration in a checkout is inert; the dry-run line records what was imported
  (`config 1 server(s) from .mcp.json: demo`).
  And *reading is not starting*: without `--mcp-allow-exec` every declared server in the
  file is named on stderr, deferred, and recorded as `mcp.deferred` in the run's own
  `system:init`. A server you typed yourself with `--mcp-server` needs neither flag - the
  line is drawn at who wrote the text, not at the file format.
- **read a credential it was never given.** A server child starts with `PATH`, `LANG`,
  `LC_ALL` plus that server's own `env` map - the parent's environment is not handed over -
  and `${VAR}` in the file resolves only for a name released with `--mcp-env NAME`.
  Anything else is a configuration error that prints the flag to add. `mcp list` no longer
  resolves references at all, because reviewing a file should not put a secret in a CI log.
- **name a shape nobody can review.** A `command` that is a shell (`sh`, `bash`, `cmd`,
  `powershell`) or an interpreter followed by `-c`/`-e`/`eval` is refused - after `${VAR}`
  expansion, so a declaration that *resolves* to `sh` is refused as one, and past wrappers
  (`env`, `nohup`, `timeout`), so a prefix is not an escape. `python3 server.py`,
  `python3 -m package`, `npx -y pkg`, `uvx pkg` and `docker run -i img` stay legal.
- **skip a refusal quietly, or treat ours as theirs.** A server this runtime cannot
  start (`url`, `headers`, `type: "http" | "sse"`) is named on stderr and skipped —
  that is our missing transport, not somebody's typo, and the rest of the file still
  runs. Anything whose *meaning* would have to be guessed is exit 64 with nothing
  started: malformed JSON, `mcpServers` and `servers` both in one file, a key this
  importer does not read, a `command` written as an array, an unresolved `${VAR}`,
  a `cwd` that resolves outside the workspace, more than 16 servers.
- **honour an approval written in a repository.** A non-empty `autoApprove` or
  `alwaysAllow` is fatal: delete the key and pass `--allow-tool`, which is where an
  operator's consent lives. An empty list is a no-op, and `disabled: true` is a note
  rather than an alarm — that one is the file working as intended.
- **rename or deduplicate for you.** `"GitHub"` is refused with instructions, because
  a tool name nobody read is a tool name nobody reviewed; one name claimed by two
  files refuses both, as does a name that also arrives via `--mcp-server` — neither
  source may shadow the other's environment.
- **hide a secret, or invent one.** `${VAR}` and `${VAR:-fallback}` expand against
  *your* environment, and a missing variable is an error instead of an empty API key
  failing with an authentication message three layers from the typo. Reports name the
  variables, never the values; declared variables are *added* to the child's
  environment, not a filter over it — trimming what a process may see belongs to the
  host OS, and pretending a config file does it would be a promise we cannot keep.

`--json` on the listing is the CI-shaped form of the same check: it exits 1 when any
declaration was refused, so adding a server that no reviewer read - or one that asks
to approve itself - fails the build instead of appearing in somebody's tool list:

```sh
python3 -m cli mcp list --workspace . --json
```

A plugin bundle is deliberately different: it may name a server but not that server's
environment (a side channel for a plugin's secrets would be a new permission path
wearing a plugin's clothes), and such a bundle is refused at load with a pointer to
this section. The workspace file, by contrast, is the operator's own checkout: the
values it references are theirs, and the digest of a run records which variables were
named.

## 16. Check a fork point before you pay for a resume

`--checkpoint-turns N` makes a run record resumable boundaries, and `--resume-from`/
`--resume-record` continue from one. Both halves were write-and-honour: nothing could tell you
whether a boundary was still *usable*, which matters because a checkpoint's whole value is its
prefix digest - the thing that makes a resumed run inherit counters instead of laundering them.

```sh
# Which boundaries exist, and does the file still agree with each one?
python3 -m cli sessions checkpoints --session-dir .northstar/sessions
#    ns-2026...-a1b2: 2 checkpoint(s)
#      #4    turn 1     3 msgs  1 call(s)  $0.000000  digest 73e9f5e4bbc9  [verified]
#          a run resumed here inherits $0.000000 spent and may still use $1.000000
#      #6    turn 2     4 msgs  1 call(s)  $0.000250  digest f54ce97a2cce  [verified]
#    (a verified boundary is one whose transcript prefix still digests to what was recorded)

# What would a run resumed from #4 actually start with?
python3 -m cli sessions replay --session-dir .northstar/sessions <session-id> --from-checkpoint 4
```

`checkpoints` exits 1 when any boundary is not `verified`, which is the form a CI job wants: a
transcript that was truncated, hand-edited, or left half-written by a crash stops being a
suspicions-and-grep exercise and becomes a red check, without a provider key, without taking the
session lease, and without spending a run to find out. The four verdicts are `verified`,
`digest-mismatch`, `prefix-short` and `malformed`, and a recognised checkpoint that is missing
`turns` is reported rather than defaulted to zero - restoring partial counters is precisely the
budget leak checkpoints were invented to close.

The recomputation is the writer's own canonical form over the reader's own record filter, so
**"verified here" and "accepted by `run --resume-from`" are the same code path**, not two
implementations that happen to agree. When a session ran under `--max-budget-usd`, each boundary
is priced from the ceiling its own `session_start` recorded: `a run resumed here inherits $0.25
and may still use $0.75`, or - when the boundary already spent the ceiling - that a resume would
be refused.

`replay` is the other half of the question, "what did this run do":

- frames are `start`, `prompt`, `turn`, `checkpoint`, `compaction`, `result` and `note`, and a
  turn frame carries the assistant's prose, its tool calls, its tool-error and denial counts and
  its token usage, so the listing is diff-able rather than scrollable;
- `--json` emits the same report for a machine (`counts`, `frames`, `checkpoints`, `lineage`,
  `sealed`, `verified`), and `--from-checkpoint` cuts the replay at the boundary so you see the
  inherited prefix and nothing after it;
- a child's replay names its parent (`forked from session X record #4 (inherits 2 turn(s), ...)`),
  read from the child's own `session_start` - a fork that cannot name its parent is a fork nobody
  can audit;
- `sealed=NO` in the summary means the transcript never wrote its `session_end`: useful on its own
  after a `kill -9`, and the reason the listing counts torn trailing lines instead of hiding them.

What this is not: it never re-executes a tool and never re-decides a permission (the transcript is
the record of what was permitted, not a script to re-run); and it is not a signature. Anyone who
can rewrite the file can recompute a digest for the file they wrote - the check catches the
accident and the casual edit, and says nothing about a determined forger.

## 17. Embed the governed run from TypeScript

If your caller is a Node service, `components/northstar-agent-runtime/sdk-ts` is the face to use.
It is not a second runtime: every run is the CLI as a child process, so you inherit the permission
gate, the ceilings, the transcript and the exit codes instead of re-implementing them.

```ts
import { run, streamRun } from "@northstar/agent-runtime";

const report = await run({
  prompt: "Review the diff and list anything that writes outside src/",
  workspace: repo,
  provider: "anthropic",
  model: "claude-sonnet-4-5",
  permissionMode: "plan",
  maxTurns: 6,
  maxBudgetUsd: 0.4,
  sessionDir: `${repo}/.northstar/sessions`,
  redactToolOutput: true,
});
if (report.exitCode === 5) for (const d of report.permissionDenials) console.log(d.tool, d.source, d.reason);
```

Requirements and rules worth knowing before you wire it into a service:

- node ≥ 22.6 and nothing else: the `.ts` files are the artefact (native type stripping), so there
  is no build step, no lockfile and no registry contact;
- a completed run returns a report — `exitCode` is what the subtype promises a wrapper and
  `processExitCode` is what the child actually did, and both are reported so a disagreement is
  visible instead of smoothed over;
- `RunOptions` is a closed set: an unknown key is a `ConfigurationError` raised before a process
  exists, and the flags it refuses include anything that looks like a credential (keys come from the
  environment, as they do for the CLI);
- abort is a first-class option: pass `signal` (or `timeoutMs`) and the run gets SIGTERM — the same
  signal a Ctrl-C sends, which is the one the runtime knows how to seal a transcript on — with a
  short grace period before the process group is killed;
- the suite is drift-gated against the Python side, in both languages:
  `make -C ../../.. ts-test` where node exists, `tests/test_typescript_sdk.py` where it does not.

`make demo` stays Python-only; the TypeScript face is verified by its own tests, not by a runner.

## 18. Freeze the governance tree, and let the run notice if it moved

`.northstar/config.toml` and `.git/` are `protected_prefixes`: Write/Edit refuse
them, the deny list is merge-only, and a run can neither widen its own tool list nor
delete an audit record. That promise is enforced in the *file tools* — and a run with
`--allow-tool Shell` can write the same bytes with `printf`, because the OS sandbox
binds the workspace as one writable mount.

Two layers close that, and both are on by default:

- **bwrap backend**: the governance tree is re-bound read-only *after* the workspace
  (`--ro-bind-try`), with the documented carve-outs re-bound writable after that
  (`.northstar/memory`, `.northstar/tmp`). A protected directory that does not exist
  yet is created empty first — "not protected at startup" and "did not exist at
  startup" were the same hole in CVE-2026-25725. The Shell tool reports what was
  enforced in its result data (`governance_binds`), derived from the run's own limits
  so a tool payload cannot widen or narrow the list.
- **process backend** (no user namespaces — CI containers, most laptops): detection
  instead of prevention. The runtime hashes the governance tree at `system:init`,
  re-checks it after every `Shell`/`Bash` result, and on any change appends a
  `governance_drift` record and ends the run with `error_governance_drift` (**exit
  8**). It runs after `postconditions`, so a run that wrote the required file *and*
  its own policy reports the drift, not the success.

```sh
python3 -m cli run --workspace . --prompt "..."            # drift check on
python3 -m cli run --workspace . --prompt "..." --no-drift-check   # says so in init
python3 -m cli bench --workspace . --json                  # 14 cases, one per invariant
```

Detection is the weaker guarantee, so it is stated rather than implied: `--dry-run`
prints `shell: … drift detection on/off`, `northstar doctor` reports the governance
tree state, and `system:init` carries the digest it froze (or `{"enabled": false}`).
A `--allow-tool Shell` run with `--no-drift-check` is a documented trade with no
enforcement layer behind it, which is exactly the case `northstar bench` must go red
on.

## Consumer CI recipe

`examples/ci-readonly-review/` is a copy-paste template for running a
read-only, ceiling-capped review of a pull request in **your** CI — it is not
wired into this repository's own workflows (that would need your API key).
See also [packaging-and-ci](packaging-and-ci.md) for how this repository's
own CI is structured.
