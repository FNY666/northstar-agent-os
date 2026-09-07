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

Try the other views while you are here:

```sh
# what a live run would do — no request is sent
python3 -m cli run --workspace workspace --prompt "hi" \
  --provider anthropic --dry-run

# does this host have what a run needs? (also no request, no file writes)
python3 -m cli doctor --workspace workspace

# the read-only twin of the demo, live-model ready when ANTHROPIC_API_KEY is set
python3 -m cli run --workspace workspace --prompt "summarise notes.txt" \
  --read-only
```

The `script.json` and `notes.txt` here double as a compact example of the
scripted-provider format and of a minimal audited workspace layout.
