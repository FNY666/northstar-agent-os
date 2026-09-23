# Slice 3 — Durable reconciliation and manual-review gate

访问日期：2026-09-22。仅官方/一手公开资料；独立 `/tmp` 隔离目录。未访问真实服务、凭据或任何受保护目标。

## Core result

A platform’s own status/history is an observation, not automatically an external postcondition. Reconciliation must distinguish: (1) platform receipt/history, (2) target authoritative state, (3) business invariant. If the target query is eventually consistent, unavailable, deleted, or ambiguous, keep `UNKNOWN_NEEDS_RECONCILE`; do not convert an absent log or a failed platform call into `NOT_COMMITTED`.

## Temporal Visibility and authoritative state

URL: https://docs.temporal.io/visibility  
Accessed: 2026-09-22  
Evidence: Temporal documents Visibility as eventually consistent, with variable delay and no fixed/guaranteed delay; it is for finding/filtering/counting executions, not for reading the current state of one execution. The official page directs users to `DescribeWorkflowExecution` for authoritative, up-to-date state of a specific execution.  
Status: verified.  
Window: workflow event/state changes → visibility ingestion/indexing → query visibility (variable) → retention/configured availability → specific-execution Describe/read-back.  
Can prove: search/index visibility semantics and why a query result can lag.  
Cannot prove: external target state or business postcondition; a visibility query alone is not authoritative current state.

URL: https://docs.temporal.io/workflow-execution/workflowid-runid  
Accessed: 2026-09-22  
Evidence: Official Workflow Id/Run Id documentation defines execution identity and reuse policies, including distinctions among completed, failed, timed out, terminated and cancelled executions.  
Status: verified for identity/status vocabulary; inferred for reconciliation use.  
Can prove: how to bind a read-back to a particular Workflow execution/run.  
Cannot prove: a same-named external resource belongs to that run without operation_id/target binding.

## AWS Step Functions DescribeExecution and history

URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeExecution.html  
Accessed: 2026-09-22  
Evidence: `DescribeExecution` returns execution metadata including status/output where available, but AWS explicitly says the operation is eventually consistent and results are best effort and may not reflect very recent updates. Express executions are not supported by this API.  
Status: verified.  
Window: execution state changes → Describe visibility (eventual/best effort) → output/status read-back; external target state remains separate.  
Can prove: Step Functions’ own recorded execution status/output subject to its consistency caveat.  
Cannot prove: external side effect or current external resource state.

URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_GetExecutionHistory.html  
Accessed: 2026-09-22  
Evidence: official API exposes execution history for supported executions with pagination/limits. History is platform evidence and must not be treated as a target-side receipt.  
Status: verified for API boundary; inferred for external-effect limitation.  
Can prove: returned platform event history within API scope.  
Cannot prove: complete external request/response sequence if the target or network was outside Step Functions.

## AWS CloudTrail event validation

URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html  
Accessed: 2026-09-22  
Evidence: CloudTrail log file validation uses digest files/signatures to determine whether delivered log files were modified or deleted after delivery, when validation is enabled and performed.  
Status: verified.  
Window: event occurs → trail delivers log file → digest records file relationship → verifier checks integrity; coverage/configuration and business result are separate.  
Can prove: integrity of delivered files under the validation procedure.  
Cannot prove: events that were never configured/recorded, complete data-plane coverage, or business commit.

## GitHub Actions API and artifact retention

URL: https://docs.github.com/en/rest/actions/workflow-runs  
Accessed: 2026-09-22  
Evidence: official REST API exposes workflow-run status/conclusion and run/attempt log/artifact operations. These are GitHub control-plane observations.  
Status: verified for API fields and operations; inferred for reconciliation boundary.  
Can prove: GitHub’s recorded run status/conclusion and available run-scoped objects.  
Cannot prove: remote deployment/API/database postcondition; a successful workflow step is not an independent target read-back.

URL: https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts  
Accessed: 2026-09-22  
Evidence: workflow artifacts can store build/test data and have configurable retention.  
Status: verified.  
Can prove: retained artifact exists in GitHub within configured lifecycle.  
Cannot prove: artifact content is complete, immutable evidence of an external effect, or that the target consumed it.

## Kubernetes Event and Job evidence

URL: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/  
Accessed: 2026-09-22  
Evidence: Kubernetes officially describes Events as limited-retention, informative, best-effort, supplemental data; consumers should not rely on continued existence or exact timing as a stable trigger proof.  
Status: verified.  
Window: cluster observation → Event creation/update → API visibility → limited retention/cleanup → possible absence.  
Can prove: supplemental cluster observation while retained.  
Cannot prove: absence of an event means absence of a failure/effect; Event is not a durable business receipt.

URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/  
Accessed: 2026-09-22  
Evidence: Job status conditions and Pod tracking provide controller-level completion/failure information.  
Status: verified.  
Can prove: Kubernetes Job controller state.  
Cannot prove: external target commit or full business invariant.

## Stripe webhook delivery as reconciliation example

URL: https://docs.stripe.com/webhooks  
Accessed: 2026-09-22  
Evidence: Stripe documents automatic webhook retries for live mode for up to three days with exponential backoff, plus manual resend. Webhook delivery is a transport/event delivery mechanism; the receiver must use event identity and query authoritative payment state as needed.  
Status: verified for documented delivery retries; reconciliation conclusion is inferred.  
Window: provider event → delivery attempt → receiver ack or failure → automatic/manual retry window → receiver deduplication and authoritative object read-back.  
Can prove: provider delivery-attempt/retry behavior.  
Cannot prove: receiver processed exactly once, or downstream business invariant without its own commit/read-back.

## Manual-review gate

1. **Automatic verified-effect gate:** only when target read-back matches `operation_id`, target fingerprint, normalized-args hash, and expected postcondition.
2. **Automatic not-committed gate:** only with an authoritative target response that explicitly establishes nonexistence/noncommit and is within the target’s consistency/retention boundary; a missing log is insufficient.
3. **UNKNOWN/manual gate:** timeout, disconnect, ambiguous provider response, stale/eventually-consistent query, deleted/expired evidence, or conflicting read-backs. Freeze blind retries; reconcile with the target, idempotency key, durable receipt, or operator review.
4. **Compensation gate:** compensation is another external effect. Mark it separately (`COMPENSATION_ATTEMPTED` → `COMPENSATION_VERIFIED` only after read-back); never infer original rollback from a successful compensating call alone.

## Boundary

No production validation or shared target was touched. No claim of production pass.
