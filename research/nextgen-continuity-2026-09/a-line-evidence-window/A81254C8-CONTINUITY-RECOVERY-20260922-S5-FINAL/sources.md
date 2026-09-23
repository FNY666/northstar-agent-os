# S5 Sources — official first-party URLs

Access date for all sources: 2026-09-22.

1. OpenTelemetry Collector resiliency — https://opentelemetry.io/docs/collector/resiliency/
   Evidence: queueing, retries, WAL persistence, loss conditions, queue/failure metrics. Status: verified documentation; no deployment evidence.
2. AWS CloudTrail validation introduction — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
   Evidence: log hashes, signed digest chain, integrity validation. Status: verified documentation.
3. AWS CloudTrail validation CLI — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html
   Evidence: validate-logs, file-level results, unvalidated ranges, original S3 location requirement. Status: verified documentation.
4. AWS CloudTrail digest structure — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html
   Evidence: digest chaining, redelivery/out-of-order caveat, final digest. Status: verified documentation.
5. GitHub Actions workflow-runs REST — https://docs.github.com/en/rest/actions/workflow-runs
   Evidence: pagination, run relationships, logs endpoint, search limits. Status: verified documentation.
6. GitHub Actions workflow-jobs REST — https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run
   Evidence: jobs are separately enumerated. Status: verified documentation.
7. GitHub Actions artifacts REST — https://docs.github.com/en/rest/actions/artifacts
   Evidence: pagination, expiration fields, digest, unavailable/expired download behavior. Status: verified documentation.
8. GitHub REST pagination — https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
   Evidence: page traversal contract. Status: verified documentation.
9. Kubernetes API concepts — https://kubernetes.io/docs/reference/using-api/api-concepts/
   Evidence: limit/continue, resourceVersion, watch, 410 recovery, bookmarks. Status: verified documentation.
10. Kubernetes Event v1 API — https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/
    Evidence: Event scope and best-effort/limited-retention boundary. Status: verified documentation.
11. Temporal Event — https://docs.temporal.io/workflow-execution/event
    Evidence: Event History, replay, durable recovery and limits. Status: verified documentation.
12. Temporal Workflow Execution — https://docs.temporal.io/workflow-execution
    Evidence: replay and execution recovery semantics. Status: verified documentation.
13. Temporal Visibility — https://docs.temporal.io/visibility
    Evidence: asynchronous/stale Visibility, approximate count, Describe as authoritative per execution. Status: verified documentation.
14. Claude Agent SDK observability — https://code.claude.com/docs/en/agent-sdk/observability
    Evidence: OTel signals, batching, flush/loss window, silent exporter errors, session correlation. Status: verified accessible official documentation.

No source above proves production continuity, lossless delivery, exactly-once external effect, or complete historical coverage for a particular deployment. Missing records remain UNKNOWN unless the complete generation, query, exporter, retention, and latency boundaries are independently established.
