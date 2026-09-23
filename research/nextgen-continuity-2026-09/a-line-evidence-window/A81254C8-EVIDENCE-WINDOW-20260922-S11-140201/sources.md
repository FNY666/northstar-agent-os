# Sources

Accessed 2026-09-22. Official first-party sources only.

1. Stripe Idempotent Requests: https://docs.stripe.com/api/idempotent_requests
   - Evidence window: idempotency key retry semantics and parameter consistency.
   - Cannot prove: a target other than Stripe honors the key or that an unknown request was not committed.

2. Stripe Webhooks: https://docs.stripe.com/webhooks
   - Evidence window: retry/redelivery, event IDs for duplicates, non-authoritative creation-time order, fast acknowledgement guidance.
   - Cannot prove: business processing completion from delivery receipt.

3. Temporal Activity Definition: https://docs.temporal.io/activity-definition
   - Evidence window: Activity may execute multiple times or partially complete during retries; idempotency guidance.
   - Cannot prove: external target uniqueness without target-side controls/read-back.

4. Temporal Retry Policies: https://docs.temporal.io/encyclopedia/retry-policies
   - Evidence window: retry policy and timeout mechanics; Activity vs workflow retry distinctions.
   - Cannot prove: retry outcome equals external commit.

5. AWS Step Functions Error Handling: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
   - Evidence window: Retry/Catch, timeout/error names and redrive retry behavior.
   - Cannot prove: external effect status after task error or retry.

6. AWS Step Functions Execution History: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-view-execution-history.html
   - Evidence window: platform execution history and workflow-type semantics.
   - Cannot prove: target-side postcondition.

## Evidence labels

`verified` = directly documented; `inferred` = derived evidence-window schema/verdict policy; `unknown` = target/deployment property not proven by public documentation.
