# Northstar demo — one governed agent turn, offline, no API key

```sh
cd examples/demo
sh run_offline.sh
# or from the repo root:
make demo
```

That single command:

1. uses the product entry `bin/northstar agent` (session + per-turn checkpoints on by default);
2. runs one full governed agent loop (`Read` tool call + a scripted model turn)
   through the **same code path** a live run uses — permission gate, ceilings,
   event stream, append-only session transcript;
3. prints the run as JSONL events and points at the audit transcript under
   `workspace/.northstar/sessions/` (and fails if a checkpoint record is missing).

Everything is deterministic: the scripted provider supplies the model turn, so
the demo needs no `ANTHROPIC_API_KEY`, no network, and no `anthropic` package.
The exit code is `0` on success and meaningful otherwise (see
`components/northstar-agent-runtime/cli.py` for the mapping).

The workspace also ships repository extension files that every run honors:
an `AGENTS.md` (project instructions appended to the system prompt), a
repository subagent under `.northstar/agents/` (`--agent summariser`), and a
skill package under `.northstar/skills/` whose name and description are listed
in the prompt. `doctor` and `--dry-run` show which files apply:

```sh
# from repo root
bin/northstar doctor --workspace examples/demo/workspace

bin/northstar agent --workspace examples/demo/workspace --prompt "hi" \
  --provider anthropic --dry-run
# look at the policy_file= / project_context= / session lines
```

Try the other views while you are here:

```sh
# the read-only twin of the demo, live-model ready when ANTHROPIC_API_KEY is set
bin/northstar agent --workspace examples/demo/workspace --prompt "summarise notes.txt" \
  --read-only

# workspace policy lives in .northstar/config.toml; see
# components/northstar-agent-runtime/README.md for the schema
# product spine: docs/next-gen-agent-os.zh-CN.md
```

The `script.json`, `notes.txt`, and `AGENTS.md` here double as a compact
example of the scripted-provider format, a minimal audited workspace layout,
and the project-context convention.
