# Offline session panel (P3-4)

A **single self-contained HTML file** that renders a governed run's record of
itself: session transcripts and audit exports as an annotated timeline with
statistics and a local fingerprint.

Open `session-panel.html` in a browser (double-click is enough — `file://`,
no server) and **drop a file** onto the page:

- a **session transcript** — one `*.jsonl` file per session, as written by
  `--session-dir DIR` on `python3 -m cli run …` (see the
  [demo](../../examples/demo/README.md) or `run_offline.sh` for a full run);
- an **audit export** — `python3 -m cli sessions export <session-id>
  --session-dir DIR > audit.ndjson`, the canonical `audit.ndjson/1` feed
  (records carry `schema_version` and are rendered in audit mode).

The viewer shows: record counts by type, sessions seen, total cost and
denials, an errors/denials-only filter, a read-only replay slice by inclusive
transcript index range, chain metadata (a cue to use the runtime verifier, not
a browser-side cryptographic claim), the full timeline with expandable raw JSON
per record,
and a local fingerprint (FNV-1a 64 over the file text — a convenience
integrity marker, not a cryptographic hash).

## Guarantees

- **No network**: one file, all CSS/JS inline, no fonts, no CDN, no fetch.
  Open the developer-tools network tab while loading a session: nothing.
- **No backend**: parsing and rendering happen in the page via `FileReader`;
  your transcripts never leave the browser.
- Handles torn trailing lines (a crash can leave one) — they are counted as
  unparseable lines, never fatal.
- The replay controls only filter the already loaded records in the browser;
  they never re-run a tool, model call or workspace action. For cryptographic
  chain verification, use `python3 -m cli sessions verify <session-id>
  --session-dir DIR` with the HMAC secret environment variable when applicable.

## Try it

```sh
# from the runtime component directory — one offline governed run
python3 -m cli run --workspace ../../examples/demo/workspace \
  --prompt "Read notes.txt and summarise what it says in one sentence." \
  --script ../../examples/demo/script.json --session-dir /tmp/ns-sessions --json

# then open examples/session-panel/session-panel.html and drop
# /tmp/ns-sessions/ns-*.jsonl onto it
```

`sample-session.jsonl` in this directory is a real transcript from that
recipe (a run that also attempted a `Write`, so it shows a permission
**denial**, the failed `tool_result` and the `result` record's
`permission_denials`). Only one thing was edited for portability: the
absolute `workspace` path inside the `session_start` record is shown as
`<repo>/examples/demo/workspace`.

## Honesty notes

- The panel renders whatever fields it finds and falls back to raw JSON for
  anything it does not recognise — it is a viewer, not a validator
  (validation lives in the runtime/audit readers).
- It is a local developer tool; nothing here is part of any component and no
  repository test executes the page's JavaScript in a browser (a CI test
  only checks the script parses, when a Node runtime is available).

Full context: the live-trace plane that complements these offline records is
in `examples/observability`; the concept page is
[`docs/concepts/observability.md`](../../docs/concepts/observability.md) and
the Chinese assessment record is
[`docs/dx-observability.zh-CN.md`](../../docs/dx-observability.zh-CN.md).
