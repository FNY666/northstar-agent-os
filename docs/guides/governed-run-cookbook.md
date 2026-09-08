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
./.venv/bin/northstar-agent-runtime doctor --workspace .
```

## 2. First run: the offline demo

```sh
cd examples/demo && sh run_offline.sh
```

One full governed loop (Read call + scripted model turn) through the **same
code path** a live run uses — permission gate, ceilings, event stream,
append-only transcript in `/tmp/northstar-demo-sessions/`. Exit code 0.

## 3. Dry-run before anything real

```sh
python3 -m cli run --workspace . --prompt "summarise the repo" \
  --scripted-text ok --dry-run
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

## Consumer CI recipe

`examples/ci-readonly-review/` is a copy-paste template for running a
read-only, ceiling-capped review of a pull request in **your** CI — it is not
wired into this repository's own workflows (that would need your API key).
See also [packaging-and-ci](packaging-and-ci.md) for how this repository's
own CI is structured.
