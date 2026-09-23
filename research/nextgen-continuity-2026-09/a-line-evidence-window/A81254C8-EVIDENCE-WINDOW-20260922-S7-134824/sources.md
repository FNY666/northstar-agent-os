# Sources

Accessed 2026-09-22. All sources are official first-party documentation.

1. OpenTelemetry, **Logs Data Model**: https://opentelemetry.io/docs/specs/otel/logs/data-model/
   - Evidence window: `Timestamp` = event time; `ObservedTimestamp` = observation time; timestamps may be unknown.
   - Supports: separating event and observation time.
   - Cannot prove: complete ingestion, export success, backend persistence, or no-event.

2. OpenTelemetry, **OTLP Specification**: https://opentelemetry.io/docs/specs/otlp/
   - Evidence window: client sends a sequence of requests and expects responses; partial success and retryable/non-retryable failure semantics; non-retryable rejected data must be dropped.
   - Supports: transport receipt and explicit rejected/drop classification at the protocol boundary.
   - Cannot prove: final destination persistence or end-to-end continuity across intermediaries.

3. OpenTelemetry, **Collector Resiliency**: https://opentelemetry.io/docs/collector/resiliency/
   - Evidence window: in-memory sending queues, queue-full drops, retry timeout drops, persistent WAL behavior, disk-space/unavailability limits.
   - Supports: exporter-failure, dropped, and delayed state distinctions.
   - Cannot prove: a particular deployment's configuration or losslessness.

4. AWS, **Working with CloudTrail event history**: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
   - Evidence window: searchable/downloadable/immutable event history for the past 90 days; regional and management-event scope.
   - Supports: retention-expired and query-scope gates.
   - Cannot prove: absence outside the window/scope, all data events, or business effects.

5. AWS, **Validating CloudTrail log file integrity**: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
   - Evidence window: hourly signed digest references delivered log files and permits post-delivery integrity validation.
   - Supports: integrity evidence and tamper/deletion detection after delivery.
   - Cannot prove: complete event capture or external effect.

6. Kubernetes, **Auditing**: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
   - Evidence window: chronological records of user, application, and control-plane activity; audit policy/backend and truncation/batching are relevant.
   - Supports: source identity/activity and query/coverage modeling.
   - Cannot prove: an unconfigured backend captured every action or that an observed record caused a business commit.

7. Temporal, **Events and Event History**: https://docs.temporal.io/workflow-execution/event
   - Evidence window: Workflow Execution consists of a sequence of Events created by the Temporal Service.
   - Supports: platform-history event identity/ordering as one evidence source.
   - Cannot prove: arbitrary external side-effect commitment or complete external-system continuity.

8. GitHub, **Workflow syntax / retention-days**: https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idretention-days
   - Evidence window: workflow/job retention configuration is scoped to GitHub Actions artifacts/logs.
   - Supports: modeling retention as a queryability/coverage field.
   - Cannot prove: retained logs cover every execution or prove external deployment effect.

## Evidence grading

- `verified`: the source directly states the documented boundary above.
- `inferred`: mapping those boundaries into the proposed cross-system schema and state machine.
- `unknown`: any deployment-specific completeness, configuration, timing, external effect, or end-to-end losslessness claim.
