# Sources

Accessed 2026-09-22 UTC.

1. OpenTelemetry Collector resiliency — https://opentelemetry.io/docs/collector/resiliency/ — queues/retry/persistent storage are configured mechanisms; no universal completeness guarantee.
2. OpenTelemetry Collector configuration — https://opentelemetry.io/docs/collector/configuration/ — component configuration boundary; does not prove runtime health.
3. OTLP specification — https://opentelemetry.io/docs/specs/otlp/ — transport and partial response semantics; response is not business commit.
4. GitHub workflow run logs — https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/using-workflow-run-logs — logs are a separate resource and can have availability/retention boundaries.
5. GitHub artifacts REST API — https://docs.github.com/en/rest/actions/artifacts — artifacts are separately enumerated/downloaded resources; run state is not artifact completeness.

Evidence labels: verified = directly documented; inferred = cross-system acceptance rule; unknown = deployment state not established by public docs.
