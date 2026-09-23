# Slice 2 — UNKNOWN after cancellation/timeout/disconnect; idempotent retry and compensation

访问日期：2026-09-22。仅使用公开官方/一手资料。此为独立 `/tmp` 目录，不接触真实服务、凭据、shared/P0、事故目录、D10/L12/D14、canonical、140、tri-line 或 systemd。

## Decision rule

`timeout/cancel/disconnect/worker crash/partial log` is not a negative proof of absence. Unless an authoritative target read-back, durable operation record, server-side idempotency key/unique constraint, or independent reconciliation resolves the operation, keep `UNKNOWN_NEEDS_RECONCILE`. A retry is safe only when the target-side protocol makes the operation idempotent or the operator intentionally performs compensation after determining the first attempt’s state.

## Temporal — Activity idempotency and worker crash

**URL:** https://docs.temporal.io/activity-definition  
**Accessed:** 2026-09-22  
**Evidence:** Temporal explicitly describes the worker-crash window: an Activity may complete successfully, then the worker can crash before notifying Temporal; Event History then does not reflect completion and the Activity is retried. The docs require idempotent Activities or service-enforced idempotency keys, and note an Activity can execute more than once.  
**Status:** verified for the documented Temporal semantics.  
**Window:** operation starts → worker executes external effect → worker sends completion to Temporal (or crashes) → Temporal history records completion or schedules retry → history is queryable according to deployment retention. The exact external effect commit/read-back interval is outside Temporal’s Event History.  
**Can prove:** why duplicate execution is possible; why unique server-side idempotency keys are needed.  
**Cannot prove:** that an external effect occurred once, that a retry is harmless, or that the business postcondition holds.

## Temporal — cancellation versus termination

**URL:** https://docs.temporal.io/encyclopedia/workflow/cancellation-and-termination  
**Accessed:** 2026-09-22  
**Evidence:** Cancellation lets Workflow code observe the request and run cleanup/compensation; Termination closes immediately, Workflow code does not see it, cleanup does not run, and partial writes/held resources may remain.  
**Status:** verified.  
**Window:** cancel/terminate request → Workflow receives cancellation (only for cancellation) → cleanup/compensation may run → closing event is recorded; termination can close before cleanup.  
**Can prove:** control-plane distinction and cleanup opportunity.  
**Cannot prove:** that compensation completed, reversed every external effect, or restored the business invariant; those require target read-back/postcondition checks.

## Temporal — failure detection and timeout

**URL:** https://docs.temporal.io/encyclopedia/detecting-activity-failures  
**Accessed:** 2026-09-22  
**Evidence:** Temporal states the server relies on Start-To-Close Timeout to force Activity retries when a Worker loses communication or crashes; Heartbeat Timeout is relevant for long-running Activities.  
**Status:** verified for Temporal detection/retry behavior.  
**Window:** Activity is accepted/executes → communication or heartbeat becomes unavailable → timeout window elapses → server marks the attempt timed out and schedules retry; an external operation may have committed before the timeout.  
**Can prove:** liveness/failure detection and retry scheduling.  
**Cannot prove:** old worker stopped, external effect absent, or retry is safe.

## Temporal — retry policy

**URL:** https://docs.temporal.io/encyclopedia/retry-policies  
**Accessed:** 2026-09-22  
**Evidence:** Retry policy exposes initial interval, backoff, maximum attempts and non-retryable errors; it is a scheduling/error policy, not an external transaction protocol.  
**Status:** verified for policy controls; inferred for the boundary conclusion.  
**Can prove:** configured retry decision/timing after an observed Activity failure.  
**Cannot prove:** exactly-once external execution, compensation success, or final business state.

## AWS Step Functions — retry/catch

**URL:** https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html  
**Accessed:** 2026-09-22  
**Evidence:** Step Functions provides Retry and Catch state-machine controls; retry applies according to error matching and configured limits, Catch provides fallback state transitions.  
**Status:** verified for orchestration semantics.  
**Window:** task starts → task returns error/timeout → Retry/Catch transition is applied → later task/fallback executes; an external side effect can precede the error response.  
**Can prove:** state-machine response to surfaced errors.  
**Cannot prove:** task was never executed, external write was rolled back, or Catch is a business compensation.

## AWS Step Functions — task timeout

**URL:** https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-task-state.html  
**Accessed:** 2026-09-22  
**Evidence:** `TimeoutSeconds` bounds a task/activity; the count begins at a start event and timeout produces `States.Timeout`.  
**Status:** verified.  
**Window:** start event → timeout deadline → timeout event/state transition. The external service may have accepted or committed work before the timeout is observed.  
**Can prove:** control-plane timeout state.  
**Cannot prove:** external non-commit.

## AWS Step Functions — redrive

**URL:** https://docs.aws.amazon.com/step-functions/latest/dg/redrive-executions.html  
**Accessed:** 2026-09-22  
**Evidence:** Redrive re-executes eligible failed/timed-out portions under Step Functions rules; this is not a universal deduplication guarantee for external targets.  
**Status:** verified for redrive existence; external-effect conclusion is inferred.  
**Can prove:** platform-level redrive action and its execution-history context.  
**Cannot prove:** the prior attempt had no side effect or that rerun is idempotent.

## GitHub Actions — reruns

**URL:** https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/re-running-workflows-and-jobs  
**Accessed:** 2026-09-22  
**Evidence:** GitHub documents rerunning workflows/jobs and a rerun time window; rerunning creates another attempt of execution.  
**Status:** verified for GitHub control-plane behavior.  
**Window:** run starts → runner/network interruption or failed step → rerun request within platform window → new attempt executes.  
**Can prove:** a new workflow/job attempt was requested/executed in GitHub.  
**Cannot prove:** prior external deployment/API call did not commit; deployment retries need target idempotency/read-back.

## Kubernetes — Job retries and deadlines

**URL:** https://kubernetes.io/docs/concepts/workloads/controllers/job/  
**Accessed:** 2026-09-22  
**Evidence:** `backoffLimit` governs failed Pod retry behavior; `activeDeadlineSeconds` terminates running Pods and marks the Job Failed with `DeadlineExceeded`; deadline takes precedence over backoff in the documented case.  
**Status:** verified.  
**Window:** Job/Pod starts → Pod fails or deadline elapses → controller creates replacement or terminates Pods → Job condition becomes Failed/Complete.  
**Can prove:** Kubernetes control-plane scheduling/termination state.  
**Cannot prove:** process stopped everywhere at the instant, external write absent, or business compensation completed.

## Stripe — idempotency as target-side example

**URL:** https://docs.stripe.com/api/idempotent_requests  
**Accessed:** 2026-09-22  
**Evidence:** Stripe documents that an idempotency key lets a client safely repeat a request after a connection error; the server saves the first result for a key, compares parameters, and may prune keys after at least 24 hours. Reusing a pruned key can create a new request.  
**Status:** verified for Stripe’s API contract, not a general claim about all targets.  
**Window:** request with key → server begins endpoint execution and stores result → response lost/connection error → retry with same key → stored result or new request if key was pruned.  
**Can prove:** why idempotency must be enforced by the target and why key lifetime/parameter binding matter.  
**Cannot prove:** universal exactly-once semantics, compensation, or correctness of a different service.

## Cross-source adjudication

| Situation | Allowed status before target read-back | Reason |
|---|---|---|
| timeout after external request was sent | UNKNOWN_NEEDS_RECONCILE | response loss does not distinguish absent/committed |
| cancellation requested, cancellation handler completed | PLATFORM_CANCELLED / COMPENSATION_REPORTED | still need postcondition/read-back |
| force termination | UNKNOWN_NEEDS_RECONCILE | official Temporal docs explicitly say cleanup/compensation does not run |
| retry policy exhausted | PLATFORM_FAILED | not proof of no external effect |
| retry/redrive/rerun completed | PLATFORM_RETRIED | not proof the first effect was absent or duplicate-free |
| target idempotency key accepted and authoritative result read back | VERIFIED_EFFECT, bounded to target contract | target-side evidence closes ambiguity within key lifetime/parameter scope |

## Unknowns retained

- No official source here proves a generic external exactly-once effect across workers, queues, APIs, payment systems, or deployments.
- No platform completion/failure flag substitutes for target-side read-back, a durable target receipt, or business postcondition validation.
- Compensation is an attempted forward operation unless independently verified; it is not an automatic rollback of arbitrary external side effects.
- Production status is not assessed and is not claimed.
