# Sources

Accessed 2026-09-22. Official first-party sources only.

1. OpenTelemetry OTLP Specification: https://opentelemetry.io/docs/specs/otlp/
   - Evidence window: full/partial success, retryable/non-retryable failure, dropped data, acknowledgement timeout.
   - Cannot prove: destination persistence or external business commit.

2. OpenTelemetry Collector Resiliency: https://opentelemetry.io/docs/collector/resiliency/
   - Evidence window: sending queues, retry backoff/deadlines, queue overflow, crash without persistence, WAL and monitoring metrics.
   - Cannot prove: any deployment's zero-loss behavior from configuration guidance alone.

3. OpenTelemetry Metrics Data Model: https://opentelemetry.io/docs/specs/otel/metrics/data-model/
   - Evidence window: temporality, resets, gaps, missing timestamps, aggregation semantics.
   - Cannot prove: a metric stream is a complete event log.

4. Kubernetes Auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
   - Evidence window: audit webhook/log buffering, retry, overflow drops, `apiserver_audit_event_total`, and `apiserver_audit_error_total`.
   - Cannot prove: production capture completeness without its configuration and metrics.

5. GitHub REST API — Artifacts: https://docs.github.com/en/rest/actions/artifacts
   - Evidence window: artifact expiry and digest fields; retention is separate from run/log evidence.
   - Cannot prove: artifact presence proves workflow or external effect.

6. OpenTelemetry Logs Data Model: https://opentelemetry.io/docs/specs/otel/logs/data-model/
   - Evidence window: event/observed timestamps and log record identity fields.
   - Cannot prove: an exported log is a complete multi-signal record.

## Evidence labels

`verified` means directly stated by the source; `inferred` means the schema, precedence, or vectors are a derived design; `unknown` means deployment-specific completeness, configuration, or external-effect status is not established.
