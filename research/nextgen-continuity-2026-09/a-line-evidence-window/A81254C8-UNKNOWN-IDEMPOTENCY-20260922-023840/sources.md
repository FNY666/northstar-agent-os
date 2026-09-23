# 来源清单（访问日期：2026-09-22）

1. Temporal Documentation — Activities: https://docs.temporal.io/activities — verified: idempotency recommendation, Retry Policy, heartbeat detail checkpointing. Boundary: no universal external exactly-once.
2. Temporal Documentation — Workflow Execution: https://docs.temporal.io/workflow-execution — verified: durable history/replay and platform statuses. Boundary: replay is not external read-back.
3. Temporal Documentation — Go cancellation: https://docs.temporal.io/develop/go/workflows/cancellation — verified: cancellation request, heartbeat propagation, cleanup, Complete/Canceled choice, reset. Boundary: reset is not rollback.
4. Temporal Documentation — Go error handling: https://docs.temporal.io/develop/go/best-practices/error-handling — verified: error taxonomy and timeout subtypes. Boundary: app decides business retry safety.
5. GitHub Docs — Cancel workflow run: https://docs.github.com/en/actions/how-tos/manage-workflow-runs/cancel-a-workflow-run — verified: queued/in-progress run cancellation. Boundary: no external effect guarantee.
6. GitHub Docs — Workflow syntax: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax — verified: timeout-minutes and continue-on-error controls. Boundary: no idempotent business semantics.
7. GitHub Docs — Concurrency: https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency — verified: concurrency group and cancel-in-progress. Boundary: canceled run is not proof of rollback.
8. Anthropic Documentation — Claude Code CLI reference: https://docs.anthropic.com/en/docs/claude-code/cli-reference — verified: resume/continue/background/timeout controls. Boundary: no cited exactly-once/reconcile contract.
9. SWE-bench official repository: https://github.com/SWE-bench/SWE-bench — verified: benchmark and Docker evaluation scope. Boundary: not production evidence.
10. Stripe API Reference — Idempotent requests: https://docs.stripe.com/api/idempotent_requests — verified: same-key result replay, parameter binding, pruning, pre-execution exceptions. Boundary: Stripe-specific.
11. AWS DynamoDB Documentation — Condition expressions: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html — verified: predicate-gated put/update/delete. Boundary: condition failure is not reconciliation.

## 访问与证据规则

每条来源均为公开一手官方材料，访问日期统一为 2026-09-22。材料区分 verified（页面直接陈述）、inferred（由文档范围推导的工程边界）和 unknown（公开材料未承诺）。没有把平台回执当外部效果，也没有把 SWE-bench benchmark 当 production。
