# Sources

Accessed 2026-09-22. Official first-party sources only.

1. W3C Trace Context: https://www.w3.org/TR/trace-context/
   - Evidence window: `traceparent` carries trace ID, parent ID, and flags; propagation support is not guaranteed across all intermediaries/providers.
   - Cannot prove: complete downstream propagation or event existence from a trace ID.

2. W3C Baggage: https://www.w3.org/TR/baggage/
   - Evidence window: baggage is propagated application metadata; members may be dropped to satisfy size limits; values require untrusted-data treatment.
   - Cannot prove: authorization, integrity, or event continuity.

3. OpenTelemetry Trace API: https://opentelemetry.io/docs/specs/otel/trace/api/
   - Evidence window: SpanContext trace/span IDs, sampling flags, recording state, and span event ordering semantics.
   - Cannot prove: sampled data is complete or external side effects committed.

4. OpenTelemetry Logs Data Model: https://opentelemetry.io/docs/specs/otel/logs/data-model/
   - Evidence window: Timestamp, ObservedTimestamp, optional TraceId/SpanId/TraceFlags.
   - Cannot prove: optional trace linkage means an event did not occur.

5. AWS CloudTrail Log File Validation: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
   - Evidence window: signed digest references delivered log files and supports post-delivery validation.
   - Cannot prove: capture completeness or business effect.

## Evidence labels

`verified` = directly stated by the cited official specification/documentation. `inferred` = proposed schema or verdict mapping derived from those statements. `unknown` = deployment-specific completeness, propagation, sampling, or external-effect property not established by these public sources.
