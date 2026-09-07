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
- **Skills**: `.northstar/skills/<name>/SKILL.md` or portable
  `.agents/skills/<name>/SKILL.md` — standards-validated, read-only packages
  listed in the system prompt. Run the same validation used by a real run:

  ```sh
  northstar-agent-runtime skills check --workspace .
  northstar-agent-runtime skills list --workspace . --json
  ```

  `allowed-tools` is descriptive metadata only; it never auto-approves a
  Northstar call. Use `--skills-dir PATH` for an explicit in-workspace root.
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

## Consumer CI recipe

`examples/ci-readonly-review/` is a copy-paste template for running a
read-only, ceiling-capped review of a pull request in **your** CI — it is not
wired into this repository's own workflows (that would need your API key).
See also [packaging-and-ci](packaging-and-ci.md) for how this repository's
own CI is structured.
