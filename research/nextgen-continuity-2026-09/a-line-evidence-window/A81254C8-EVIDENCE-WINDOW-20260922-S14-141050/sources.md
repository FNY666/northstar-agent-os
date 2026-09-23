# Sources

Accessed 2026-09-22 UTC.

1. OpenTelemetry Logs data model: https://opentelemetry.io/docs/specs/otel/logs/data-model/ — log identity/timestamp fields; does not establish global business-event uniqueness.
2. OpenTelemetry Trace API: https://opentelemetry.io/docs/specs/otel/trace/api/ — span/trace identity and context; does not prove external effect.
3. OpenTelemetry Metrics data model: https://opentelemetry.io/docs/specs/otel/metrics/data-model/ — metric identity/temporality context; not an event ledger.
4. Kubernetes Event v1 API: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/ — Event metadata, UID, series/count; does not prove complete observation.
5. GitHub workflow-runs REST API: https://docs.github.com/en/rest/actions/workflow-runs — run IDs/statuses; run status is separate from jobs, logs, artifacts and external effects.

Evidence levels: verified = directly documented schema/semantics; inferred = acceptance rule synthesized from the sources; unknown = deployment property not proven by public schemas.
