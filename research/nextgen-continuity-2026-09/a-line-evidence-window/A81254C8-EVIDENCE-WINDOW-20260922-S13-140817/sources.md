# Sources

Accessed 2026-09-22 UTC. Official first-party sources only.

1. OpenTelemetry Logs data model — https://opentelemetry.io/docs/specs/otel/logs/data-model/
   - Window: Timestamp versus ObservedTimestamp and log-record fields.
   - Boundary: timestamp semantics do not establish complete collection.

2. OpenTelemetry common specification — https://opentelemetry.io/docs/specs/otel/common/
   - Window: time representation and common semantic conventions.
   - Boundary: representation is not clock synchronization proof.

3. OpenTelemetry Metrics data model — https://opentelemetry.io/docs/specs/otel/metrics/data-model/
   - Window: temporality, resets and metric data-point semantics.
   - Boundary: metric streams are not event ledgers.

4. W3C Trace Context — https://www.w3.org/TR/trace-context/
   - Window: propagation identifiers and interoperability.
   - Boundary: correlation does not prove ordering or effect completion.

5. AWS CloudWatch metric publishing — https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-metric-publishing.html
   - Window: accepted metric timestamp constraints.
   - Boundary: service acceptance does not prove source completeness.

Evidence labels: `verified` is directly documented; `inferred` is the cross-system acceptance rule; `unknown` is a deployment property not established by these sources.
