# Sources

Accessed 2026-09-22 UTC.

1. Temporal Event History — https://docs.temporal.io/workflow-execution/event — durable workflow event records; not third-party state proof.
2. Temporal Workflow Failure — https://docs.temporal.io/workflow-execution/workflow-failure — failure/termination semantics and boundary between workflow and external effects.
3. Temporal Retry Policies — https://docs.temporal.io/encyclopedia/retry-policies — retries and repeated Activity execution considerations.
4. AWS Step Functions redrive executions — https://docs.aws.amazon.com/step-functions/latest/dg/redrive-executions.html — redrive execution behavior; not external target proof.
5. Stripe idempotent requests — https://docs.stripe.com/api/idempotent_requests — key/result/parameter lifecycle semantics; not universal exactly-once.

Evidence labels: verified = direct vendor semantics; inferred = state-machine acceptance synthesis; unknown = deployment/runtime result not established.
