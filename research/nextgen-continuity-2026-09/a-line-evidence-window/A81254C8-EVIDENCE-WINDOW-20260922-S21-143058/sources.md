# Sources — S21

Access date for all: 2026-09-22. All are official first-party documentation.

1. OpenTelemetry OTLP specification — https://opentelemetry.io/docs/specs/otlp/
   - **verified:** protocol response/error and partial-success semantics are transport/protocol evidence, not an external business postcondition.
   - **window:** OTLP request/response and export outcome semantics.
   - **cannot prove:** destination application or durable business commit.

2. OpenTelemetry Collector resiliency — https://opentelemetry.io/docs/collector/resiliency/
   - **verified:** queues/retries/WAL improve resilience but have configured capacity and failure boundaries.
   - **window:** collector queue, retry and persistent-queue behavior.
   - **cannot prove:** no loss under all failures or exactly-once external effect.

3. OpenTelemetry Logs data model — https://opentelemetry.io/docs/specs/otel/logs/data-model/
   - **verified:** log records have identity/time/context fields but the model is not a universal completeness proof.
   - **window:** LogRecord identity and timestamps.
   - **cannot prove:** every generated record was exported or retained.
