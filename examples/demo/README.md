# Northstar demo — one governed run, offline, no API key

```sh
cd examples/demo
sh run_offline.sh
```

That single command:

1. builds a workspace whose only file is `notes.txt`;
2. runs one full governed agent loop (`Read` tool call + a scripted model turn)
   through the **same code path** a live run uses — permission gate, ceilings,
   event stream, append-only session transcript;
3. prints the run as JSONL events and points at the audit transcript it wrote
   to `/tmp/northstar-demo-sessions/`.

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
# does this host have what a run needs? (no request, no file writes)
python3 -m cli doctor --workspace workspace

# what a live run would do — no request is sent
python3 -m cli run --workspace workspace --prompt "hi" \
  --provider anthropic --dry-run
# look at the policy_file= / project_context= lines
```

Try the other views while you are here:

```sh
# the read-only twin of the demo, live-model ready when ANTHROPIC_API_KEY is set
python3 -m cli run --workspace workspace --prompt "summarise notes.txt" \
  --read-only

# workspace policy lives in .northstar/config.toml; see
# components/northstar-agent-runtime/README.md for the schema
```

The `script.json`, `notes.txt`, and `AGENTS.md` here double as a compact
example of the scripted-provider format, a minimal audited workspace layout,
and the project-context convention.
