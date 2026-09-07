"""Attach a real OpenTelemetry provider to the governed CLI (P3-4 template).

The runtime never configures an exporter: by design it mirrors every span
into the process's *ambient* OpenTelemetry tracer (``tracing.py``), so spans
reach a backend only when the embedding process installs an SDK + exporter
and calls ``trace.set_tracer_provider``. This script is that seam for the
CLI - a template to copy into your own embedding, not part of the product.

Local use (from the repository root, with the stack from
``examples/observability/docker-compose.yml`` up)::

    python3 examples/observability/otel_bootstrap.py run \\
        --workspace examples/demo/workspace \\
        --prompt "Read notes.txt and summarise it in one sentence." \\
        --script examples/demo/script.json \\
        --session-dir /tmp/northstar-obs-sessions --trace --json

The endpoint defaults to the local Jaeger OTLP/HTTP receiver and can be
overridden with ``OTEL_EXPORTER_OTLP_ENDPOINT``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces")
# Checkout layout: allow running straight from the repository (installed
# wheels fall back to site-packages when this directory does not exist).
RUNTIME_DIR = Path(__file__).resolve().parents[2] / "components" / "northstar-agent-runtime"


def main(argv: list[str]) -> int:
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as error:
        print(
            f"[otel_bootstrap] missing OpenTelemetry package '{error.name}' - see "
            "examples/observability/README.md step 2 "
            "(pip install '.../northstar-agent-runtime[tracing]' + opentelemetry-exporter-otlp-proto-http)",
            file=sys.stderr,
        )
        return 3

    if RUNTIME_DIR.is_dir() and str(RUNTIME_DIR) not in sys.path:
        sys.path.insert(0, str(RUNTIME_DIR))

    provider = TracerProvider(
        resource=Resource.create({SERVICE_NAME: "northstar-agent-runtime"})
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=ENDPOINT)))
    trace.set_tracer_provider(provider)

    from cli import main as cli_main  # noqa: PLC0415 - import after the seam is up

    print(f"[otel_bootstrap] exporting spans to {ENDPOINT}", file=sys.stderr)
    return cli_main(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
