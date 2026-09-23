# Sources

Accessed 2026-09-22 UTC. Official first-party sources only.

1. OpenTelemetry Collector resiliency — https://opentelemetry.io/docs/collector/resiliency/
   - Window: sending queues, retry deadline/backoff, WAL, queue overflow and crash-loss scenarios.
   - Verified boundary: exporter/buffer behavior; not proof of deployment-wide completeness.

2. OpenTelemetry Collector configuration — https://opentelemetry.io/docs/collector/configuration/
   - Window: receiver/processor/exporter pipeline composition and validation.
   - Boundary: configuration semantics, not runtime proof.

3. Kubernetes auditing — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
   - Window: chronological records, audit policy, webhook retry/backoff, batching, overflow drops.
   - Boundary: configured-policy/backend coverage only; not universal activity completeness.

4. AWS CloudTrail log-file validation — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
   - Window: digest hashes, chained signatures, delivered-file validation.
   - Boundary: validates delivered files, not source coverage or business effects.

5. GitHub Actions workflow runs REST API — https://docs.github.com/en/rest/actions/workflow-runs
   - Window: pagination and maximum page size for run queries.
   - Boundary: API query mechanics, not complete history unless every page is proven.

6. GitHub Actions artifacts REST API — https://docs.github.com/en/rest/actions/artifacts
   - Window: `expires_at` and digest metadata.
   - Boundary: retained artifact availability/integrity, not workflow effect completeness.

7. OpenTelemetry Metrics data model — https://opentelemetry.io/docs/specs/otel/metrics/data-model/
   - Window: metric stream semantics and temporality.
   - Boundary: metrics are not event-log completeness evidence.

## Evidence labels

`verified` = directly documented; `inferred` = cross-system schema/verdict policy; `unknown` = deployment property not established by public documentation.
