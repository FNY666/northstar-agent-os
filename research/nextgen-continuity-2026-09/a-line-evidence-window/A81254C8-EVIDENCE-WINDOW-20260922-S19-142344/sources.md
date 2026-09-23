# S19 sources

访问日期：2026-09-22。

1. AWS CloudTrail View events: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html — verified: lookup is scoped query/history view; query result boundaries do not establish universal event completeness.
2. GitHub REST workflow runs: https://docs.github.com/en/rest/actions/workflow-runs — verified: runs are paginated API resources; pagination and filters are part of the evidence window.
3. Kubernetes API concepts: https://kubernetes.io/docs/reference/using-api/api-concepts/ — verified: list/watch uses resourceVersion; 410/Gone means the requested resource version is no longer available and recovery requires a new list.
4. Temporal Visibility: https://docs.temporal.io/visibility — verified: Visibility is a query surface distinct from workflow event history.

Evidence window: official pages fetched/read on 2026-09-22; claims above are limited to documented API semantics. No production endpoint or credential was used.
