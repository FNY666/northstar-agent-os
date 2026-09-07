# Local observability stack (P3-4)

Watch a governed run's OpenTelemetry spans in **Jaeger** and **Grafana**,
fully on your machine.

The model turns stay offline — the example drives the same
`--provider scripted` demo run used by `examples/demo`, so the only new
moving parts are the export path and the trace backend. Everything here is a
**template to copy**, not part of the product: the repository ships no
OpenTelemetry exporter configuration in the runtime by design.

## Why this file exists (the seam, honestly stated)

The runtime mirrors every span into the process's **ambient** OpenTelemetry
tracer (`tracing.py::_default_otel_tracer` → `trace.get_tracer(...)`); it
never installs a provider or exporter itself, so a bare
`python3 -m cli run` exports nowhere no matter what is installed. Spans reach
a backend only when the embedding process installs an SDK + exporter and
calls `trace.set_tracer_provider(...)`.

`otel_bootstrap.py` is that seam for the CLI: it builds a
`TracerProvider` with an OTLP-over-HTTP `BatchSpanProcessor`, then hands the
rest of `sys.argv` to `cli.main`. Copy it into your own embedding if you want
the same behaviour in-process.

## What the stack is

| Service | Image | Role |
| --- | --- | --- |
| jaeger | `jaegertracing/all-in-one` | OTLP receiver + trace storage + UI (`:16686`) |
| grafana | `grafana/grafana` | dashboards over the Jaeger core data source (provisioned, `:3000`) |

Traces go **directly** from the runtime process to Jaeger's OTLP/HTTP
endpoint (`:4318`) — no collector in between. Jaeger all-in-one keeps traces
**in memory**, so `docker compose down` loses history. That is correct for a
local dev loop and deliberately not a production deployment (deployment and
monitoring remain an open work item — see `docs/dx-benchmark-2026.zh-CN.md`,
ops section).

## Run it

```sh
# 1. start the stack (Docker required; not exercised by this repository's CI)
docker compose -f examples/observability/docker-compose.yml up -d

# 2. one-time: runtime (with the tracing extra) + an OTLP exporter package
pip install './components/northstar-agent-runtime[tracing]'
pip install opentelemetry-exporter-otlp-proto-http

# 3. run the governed demo with the bootstrap (from the repository root)
python3 examples/observability/otel_bootstrap.py run \
  --workspace examples/demo/workspace \
  --prompt "Read notes.txt and summarise it in one sentence." \
  --script examples/demo/script.json \
  --session-dir /tmp/northstar-obs-sessions \
  --trace --json
```

Then:

- **Jaeger** → <http://localhost:16686> → Search → service
  `northstar-agent-runtime` → open the run: the span tree is
  `run → turn[n] → generation | tool:Read | ...` with usage/cost attributes
  (`usage.input_tokens`, `cost.usd`, …).
- **Grafana** → <http://localhost:3000> (admin / admin) → Explore →
  data source **Jaeger** (provisioned) → same service.
- Stop with `docker compose -f examples/observability/docker-compose.yml down`.

The endpoint is overridable with `OTEL_EXPORTER_OTLP_ENDPOINT` (default
`http://localhost:4318/v1/traces`).

## Honesty notes

- Image tags are pinned at write time but this repository's CI never runs
  Docker — verify the current tags on Docker Hub before first use.
- `opentelemetry-exporter-otlp-proto-http` is *not* in the component's
  `tracing` extra (which ships only the API + SDK); the exporter is a
  host-side choice, which is why step 2 installs it separately.
- Nothing in this directory changes runtime behaviour: without the bootstrap
  process, `--trace` still prints the span tree and exports nothing.

Full context: the record plane that complements these live traces is
documented in
[`docs/concepts/audit-trail.md`](../../docs/concepts/audit-trail.md); the
P3-4 roadmap row lives in
[`docs/dx-benchmark-2026.zh-CN.md`](../../docs/dx-benchmark-2026.zh-CN.md).
