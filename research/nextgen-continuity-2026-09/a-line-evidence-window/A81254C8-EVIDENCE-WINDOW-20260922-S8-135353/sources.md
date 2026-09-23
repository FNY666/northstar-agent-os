# Sources

Accessed 2026-09-22. Official first-party sources only.

1. Kubernetes API Concepts: https://kubernetes.io/docs/reference/using-api/api-concepts/
   - Evidence window: paginated list continuation tokens, expiry, HTTP 410, resourceVersion availability and timeout/retry behavior.
   - Verified boundary: a cursor/resource-version failure prevents a complete query.
   - Cannot prove: a particular cluster's query was complete without run evidence.

2. Kubernetes Auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
   - Evidence window: audit backend configuration, batching, bounded buffers; page states that overflow can drop events.
   - Verified boundary: explicit buffer overflow is loss evidence.
   - Cannot prove: a deployment's drop count or full audit coverage absent its metrics/backend evidence.

3. GitHub REST API — Artifacts: https://docs.github.com/en/rest/actions/artifacts
   - Evidence window: artifact object includes `expired`, `expires_at`, and `digest` fields; download can return 410 Gone.
   - Verified boundary: artifact expiry is a retention/queryability fact; digest is an integrity fact.
   - Cannot prove: all workflow runs, jobs, logs, or external effects are represented.

4. GitHub REST API — Workflow Runs: https://docs.github.com/en/rest/actions/workflow-runs
   - Evidence window: workflow-run query is a bounded API resource and must be reconciled with jobs/logs/artifacts.
   - Verified boundary: run existence is distinct from artifact/log availability.
   - Cannot prove: a run record proves external deployment success.

5. AWS CloudTrail Event History: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html
   - Evidence window: searchable/downloadable/immutable past 90 days of management events in an AWS Region.
   - Verified boundary: age/region/event-class limits create coverage gates.
   - Cannot prove: absence outside that scope.

6. AWS CloudTrail LookupEvents API: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
   - Evidence window: lookup is scoped to events in a Region and recent history.
   - Verified boundary: regional lookup cannot establish global absence.
   - Cannot prove: complete multi-region or non-management-event coverage.

7. Temporal Events and Event History: https://docs.temporal.io/workflow-execution/event
   - Evidence window: Workflow Execution is a sequence of events created by the Temporal Service; history limits/continue-as-new are documented.
   - Verified boundary: platform history is separate from visibility/search and external effects.
   - Cannot prove: visibility-empty means history-empty or side effect absent.

8. Temporal Visibility: https://docs.temporal.io/visibility
   - Evidence window: Visibility is the search/list plane for workflow executions.
   - Verified boundary: visibility is a separate query plane.
   - Cannot prove: complete event-history coverage or external postconditions.

## Status key

`verified` = directly stated by the cited official page. `inferred` = schema/state-machine mapping derived from those boundaries. `unknown` = deployment-specific completeness, configuration, timing, or external-effect claim not established by public documentation alone.
