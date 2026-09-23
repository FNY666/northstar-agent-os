# Agent runtime lease / heartbeat / fencing research

- **Research date / access date:** 2026-09-22 (all URLs below are public first-party documentation; no account, credential, live service, shared target, or private data was accessed).
- **Scope:** semantics of liveness signals, expiry, duplicate/stale execution, fencing/conditional writes, recovery handoff, cancellation/timeout, platform-vs-external state, and evidence/operations.
- **Conclusion in one sentence:** A lease or heartbeat is evidence about a holder’s recent contact/progress; expiry is not proof that the old process stopped. Safety requires the *destination of every consequential write* to reject stale authority (generation/token/version/conditional predicate), plus idempotency and audit evidence.

## Decision matrix

| Platform/object | Officially established | What it does **not** establish | Fencing implication |
|---|---|---|---|
| Kubernetes Lease | Lease objects coordinate shared resources; kubelet updates `spec.renewTime`; control plane uses that timestamp to determine Node availability. Leases also support leader election. | No statement that expiry kills or interrupts a process, revokes network access, or rolls back an external write. | `metadata.resourceVersion` gives optimistic lost-update detection when the API object itself is conditionally updated. It is not automatically a fencing token for an arbitrary database/device/API. |
| Kubernetes Job/Pod | Job retries/replaces Pods according to policy; deadlines and backoff can make a Job terminal. During Job termination, grace periods affect timing; docs explicitly warn replacement Job and old Job Pods can run simultaneously in one replacement pattern. | Job success/failure and Pod deletion/termination do not prove an arbitrary old process has ceased, nor do they serialize external side effects. | Put a generation/attempt in the work item and enforce a conditional write at the external target; treat Job status as platform observation, not external-effect proof. |
| Temporal Activity | Worker heartbeat says Activity is making progress and Worker has not crashed; missed Heartbeat Timeout fails the Activity and retry policy may schedule another attempt. Cancellation is delivered when the Activity heartbeats. | Temporal does not say timeout kills a stuck Worker or undoes side effects. A retry can overlap a delayed old attempt unless the Activity/target is designed for it. | Heartbeat details are checkpoint/progress data, not a documented fencing token. External writes need their own compare-and-set/idempotency/lease-fence mechanism. |
| AWS Step Functions Activity/callback | `SendTaskHeartbeat` resets the heartbeat clock; taskToken identifies the assigned task. Overall Task Timeout remains the maximum regardless of heartbeats. Standard workflows are exactly-once at workflow-execution level; Activity workers are external. | Heartbeat/task timeout does not document process termination or external rollback. Callback acceptance is platform state, not proof that an external side effect occurred once. | taskToken authenticates a callback to that task, but docs do not define it as a monotonic fencing token for arbitrary resources. Use target-side conditional state and idempotency. |

## Findings and failure model

### 1. Lease expiry is suspicion/eligibility, not process death
Kubernetes describes a lease as a coordination mechanism and says the control plane uses the kubelet Lease `renewTime` timestamp to determine Node availability. This is a control-plane observation. It is not a kill signal. The same docs say components use Leases to select/elect a leader, and that a controller can define its own Lease. They do not promise that a holder that misses renewal has stopped executing.

Therefore after a partition or pause, the old worker may still be CPU-running, may regain network, and may issue a delayed write. A new worker may concurrently be elected/restarted. The unsafe assumption is: `expired == stopped`. The safe assumption is: `expired == no longer trusted by the coordinator`; the target must independently enforce that trust decision.

Temporal is even more explicit in operational effect: heartbeat is a ping informing the Service that the Activity is making progress and the Worker has not crashed. A missed heartbeat timeout fails the Activity and can cause retry, but no official text promises termination of the OS process or cancellation of an in-flight external call. AWS says heartbeat resets its heartbeat clock, while the Task Timeout remains the maximum no matter how many heartbeats arrive. Neither is a process revocation primitive.

### 2. Heartbeat is liveness/progress, not a write fence
Temporal heartbeats can carry application-layer progress and the next retry can access the last recorded details. The docs warn the progress is available only if the Worker delivered it before crashing; SDK throttling can delay delivery. Thus checkpoint state is useful for recovery but is neither proof of side-effect completion nor authority to overwrite a newer attempt.

Step Functions `SendTaskHeartbeat` uses a taskToken generated when a task is assigned. It resets the heartbeat clock and creates no execution-history event by itself. A timeout creates a platform history entry, but that history still describes the orchestration state. It does not attest that an external target accepted/rejected a side effect. Keep separate records: assignment, heartbeat receipt, target commit receipt, and reconciliation outcome.

### 3. Fencing requires the resource to reject stale writers
Kubernetes API semantics supply a useful primitive: `metadata.resourceVersion` lets the API server detect lost updates; if the supplied version is stale, the API server returns HTTP 409 Conflict. This is a conditional update on the Kubernetes object, not a universal fencing mechanism.

A robust external target pattern is:
1. Coordinator allocates a monotonically increasing attempt/generation (or a unique epoch) for a logical work item.
2. Worker includes that fence in every mutation, not merely in heartbeat messages.
3. Target atomically accepts only `fence >= current` (or exactly the expected predecessor), and records the fence with the side effect. Older fences receive a durable stale/rejected result.
4. Target-side compare-and-set/version check and idempotency key cover retries and duplicated requests.
5. Worker checks authority immediately before commit and handles rejection as a normal lost-race outcome; this check alone is insufficient unless the target enforces it atomically.

For Kubernetes-owned coordination, update the Lease/object with the version/resourceVersion observed and handle 409 by abandoning leadership. For a database/device/third-party API, Kubernetes resourceVersion does nothing unless that target participates in the same conditional protocol.

### 4. Restart, retry, and concurrency are distinct
A restarted Pod/Worker can be a new attempt while an old attempt remains alive or merely delayed. Kubernetes Job controller behavior is policy-driven: it counts completions/failures, applies backoff/deadlines, and terminates Pods after success/failure criteria. The official Job page warns that creating a replacement Job as soon as a terminal-in-progress condition appears can result in old and replacement Pods running at the same time. This is direct evidence that controller status is not an external serialization guarantee.

Temporal schedules another Activity attempt when a timeout/failure and Retry Policy allow it. Its docs recommend breaking work into Activities for recovery, timeouts, and idempotence. Design every Activity as potentially duplicated or overlapping, particularly across network partitions and delayed responses.

Step Functions documents execution semantics by workflow type: Standard is exactly-once workflow execution; asynchronous Express is at-least-once; synchronous Express is at-most-once. It also says starting multiple Express workflows with the same name results in concurrent executions and can lose internal workflow state if state-machine logic is not idempotent. “Exactly-once workflow execution” is not “exactly-once external side effect”; the latter still depends on the integration/target protocol.

### 5. Recovery handoff and cancellation need explicit evidence
A handoff should be a state transition, not a guess based on wall-clock expiry:
- record old attempt’s last accepted heartbeat/progress and coordinator observation;
- mark the attempt superseded with a new fence/generation;
- dispatch the new attempt carrying the new fence and an idempotency key;
- have the target reject old fence writes atomically;
- retain old/new attempt IDs, versions, rejection responses, and timestamps;
- reconcile ambiguous outcomes (request timed out after target may have committed) by querying target status, never by blindly replaying.

Cancellation is cooperative in the cited systems. Temporal says Activities receive cancellation when they heartbeat; an Activity that does not heartbeat cannot receive it. AWS callback/activity heartbeat timeout likewise changes orchestration state, not the external process. Kubernetes graceful termination honors a grace period, but deadline/replacement/status should not be treated as proof that every descendant or side effect is gone. If a target supports cancellation, use a target-side cancel generation and verify the target’s terminal state.

### 6. Platform receipt vs external target state
Use four separate claims:
- **Platform receipt:** coordinator accepted heartbeat/claim/callback/status update.
- **Execution observation:** coordinator marked timeout/failure/success.
- **Target commit:** external resource atomically committed the requested mutation under the correct fence.
- **Reconciliation:** an independently read target state matches the intended operation.

Only the third/fourth establish external-effect state. A platform success event cannot prove a downstream API/device/database committed unless the platform integration explicitly provides that guarantee; the cited documentation does not make that general promise. Likewise, a timeout cannot prove no external effect happened.

### 7. Manual intervention and evidence preservation
For a suspected split-brain or ambiguous timeout, freeze further writes for the logical key if possible, preserve append-only coordinator history, task/attempt IDs, heartbeat payloads (excluding secrets), resource versions/fences, API status codes, target request IDs, and monotonic/UTC timestamps. Do not delete the old record before reconciliation. A human may revoke/disable the external capability, quarantine the old worker, or mark the item “unknown—needs reconciliation,” but manual action must itself be recorded with actor, reason, before/after state, and evidence links. Never claim “no effect” from absent heartbeat alone.

## Implementation checklist

- [ ] Define a logical work-item key and a monotonic fence/epoch independent of process ID.
- [ ] Make every consequential target mutation conditional on that fence/version, atomically with the mutation.
- [ ] Store idempotency key, attempt ID, fence, target response/request ID, and result; retain rejected-stale attempts.
- [ ] Set heartbeat timeout materially below the recovery SLO, accounting for SDK throttling, pauses, and network latency; do not set a timeout as a substitute for fencing.
- [ ] Treat expiry/timeout/cancel as “new work may be eligible,” never “old work is definitely dead.”
- [ ] Make retries safe under overlap; test pause-after-claim, partition-after-commit, delayed response, restart, and recovery race.
- [ ] Separate workflow/platform receipts from target commit and reconciliation evidence in status schemas and dashboards.
- [ ] Require an operator runbook for ambiguous outcomes and preserve evidence before cleanup.

## Limits of this report
No benchmark, production system, private account, credential, real service, or shared target was used. The cited docs establish each platform’s documented semantics only; statements about stale processes, split-brain, and target-side fencing are safety deductions from those semantics and are labeled **inferred** in `sources.md`, not claims that the platforms automatically provide those guarantees.
