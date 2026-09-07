# Observability: reading a governed run back

A governed run records itself twice. The **live plane** mirrors the run's
span tree into OpenTelemetry while the process is alive; the **offline
plane** persists the session transcript and can export it as the canonical
NDJSON audit feed. The write side of both planes is documented in
[`audit-trail.md`](audit-trail.md); this page is about the read side — the
two ways to look at a run afterwards, and the honest boundary between what
ships and what the operator supplies.

```
                    live plane                              offline plane
                 (while running)                            (afterwards)
  span tree  --ambient tracer-->  OTEL (Jaeger/Grafana)     sessions *.jsonl
  (tracing.py)  [provider: YOURS]  examples/observability    (one file/session)
                                                          ---sessions export-->
  run --trace prints the tree anywhere                        audit.ndjson/1 feed
                                                          session-panel.html
                                                          (drop the file, offline)
```

## 1. The live plane: spans into OpenTelemetry

Every run grows one span tree per run — `run → turn[n] →
generation | tool:<name> | subagent:<name>` — with usage and cost recorded
while each span is still open (OpenTelemetry drops a late `set_attribute`
silently, so `tracing.py` snapshots attributes at `end()` and refuses writes
afterwards; a regression would show up as a refused key, never as missing
data). Content is never recorded: attribute keys naming prompts, transcripts
or tool I/O are refused, and string values are capped at 200 characters,
because traces are expected to travel further than the run workspace.

Real span attributes (all asserted by the runtime's own tests):

| Span | Created for | Representative attributes |
| --- | --- | --- |
| `run` | one governed run | `session.id`, `agent.name`, `agent.depth`, `model`, `provider`, `permission.mode`, `limits.max_turns`, `tools.count`, `workspace.root` |
| `turn[n]` | one model turn | `turn.index`, `turn.depth`, `agent.name` |
| `generation` | one model call | `provider.name`, `model`, `turn.index`, then `usage.input_tokens`, `usage.output_tokens`, `usage.cache_read_input_tokens`, `usage.cache_creation_input_tokens`, `cost.usd` |
| `tool:<name>` | one tool execution | `tool.name`, `tool.kind`, `tool.is_delegation`, `tool.input_keys`, `permission.source`, `turn.index`, `hook.rewrote_input` |
| `tool:<name>` (denied) | a governed refusal | `tool.denied`, `tool.is_error`, `permission.source`, `turn.index` |
| `subagent:<name>` | one delegated run | `subagent.name`, `subagent.depth`, `subagent.permission_mode`, `subagent.tools`, `subagent.provider` |

**The seam, stated plainly:** the runtime mirrors every span into the
process's *ambient* OpenTelemetry tracer and never configures a provider or
exporter — a bare `python3 -m cli run` exports nowhere no matter what is
installed, and `--trace` only prints the tree. Spans reach a backend when
the embedding process installs an SDK + exporter and calls
`trace.set_tracer_provider(...)`. That is deliberate: exporter code is a
host-side choice and keeping it out keeps the runtime dependency-free.

`examples/observability/` turns the seam into a local recipe: a two-service
docker compose (Jaeger all-in-one as the OTLP/HTTP receiver + Grafana with a
provisioned core Jaeger data source) and `otel_bootstrap.py`, a template
that attaches a `TracerProvider` with a `BatchSpanProcessor` and then hands
the arguments over to `cli.main`. Traces go straight from the process to
Jaeger (`:4318`) — no collector, because a collector is deployment
infrastructure and deployment/monitoring is an open work item, not a
local-dev default.

## 2. The offline plane: transcripts, export, panel

The session transcript (`sessions.py`) is one append-only `*.jsonl` file per
session under the `--session-dir` directory — `session_start`, `user_prompt`,
`assistant`, `tool_result`, `hook`, `denial`, `compact_boundary`,
`informational`, `subagent`, `result`, `session_end` — written before the run
reports success, so a crash still leaves the decision trail. The CLI reads it
back read-only:

- `python3 -m cli sessions list --session-dir DIR` — sessions present;
- `python3 -m cli sessions show <id> --session-dir DIR` — human timeline;
- `python3 -m cli sessions export <id> --session-dir DIR > audit.ndjson` —
  the canonical `audit.ndjson/1` feed (envelope in
  `northstar-run-contract/audit.py`), for SIEM-style pipelines.

`examples/session-panel/session-panel.html` is the human-scale viewer for
both formats: one self-contained HTML file (all CSS/JS inline, zero network
references) that renders any `*.jsonl`/`.ndjson` you drop onto it — by-type
counts, sessions, total cost, denials, an errors/denials-only filter, the
annotated timeline with expandable raw JSON per record, and a local
fingerprint (FNV-1a 64, honestly labelled non-cryptographic). It is a
viewer, not a validator: records it does not recognise are shown as raw JSON
rather than rejected.

## 3. Which plane when

| Question | Open |
| --- | --- |
| Why did the run take this shape *while it ran*? (cost, turns, redactions) | Jaeger/Grafana over `examples/observability` |
| What exactly did a finished session decide, in order, as a human? | `sessions show` or the session panel |
| What happened across machines/sessions, in a schema-versioned machine feed? | `sessions export` → `audit.ndjson/1` |
| Give me the durable record with no tooling at all | the `*.jsonl` transcript itself |

## 4. Scope and honesty

Nothing in this page changes runtime behaviour: `--trace` keeps printing the
tree, transcripts keep their shape, and the exporters, compose stack and
panel are templates beside the product. The repository's CI never runs
Docker and never executes the page's JavaScript in a browser; the checks in
`tests/test_observability_examples.py` pin structure and intent instead
(the example is on the index, the compose stays minimal, the bootstrap keeps
the ambient seam, the panel stays network-free, its script parses when a
Node runtime is present). Deployment and fleet monitoring of the OTEL path
remains an open work item (see `docs/dx-benchmark-2026.zh-CN.md`, ops
section), as do the remote-worker ops gaps it was filed under.
