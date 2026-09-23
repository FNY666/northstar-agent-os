# S18 sources

Access date: 2026-09-22.

1. OpenTelemetry Logs Data Model — https://opentelemetry.io/docs/specs/otel/logs/data-model/ — verified: log record model and correlation fields; cannot prove delivery or retention.
2. OpenTelemetry Metrics Data Model — https://opentelemetry.io/docs/specs/otel/metrics/data-model/ — verified: metric data model; cannot prove that a corresponding log/trace exists.
3. OpenTelemetry Trace API — https://opentelemetry.io/docs/specs/otel/trace/api/ — verified: trace/span context and lifecycle concepts; cannot prove complete sampling/export.
4. OpenTelemetry Collector resiliency — https://opentelemetry.io/docs/collector/resiliency/ — verified: queues/retries/WAL-related resiliency concepts; cannot prove target business commit.
5. OTLP specification — https://opentelemetry.io/docs/specs/otlp/ — verified: transport and response semantics; cannot prove backend query completeness.

Evidence window: documents retrieved publicly on 2026-09-22; conclusions are limited to the stated specifications and documented behavior.
