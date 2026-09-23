# Sources and claim boundaries

**Access date for every source:** 2026-09-22. **Source policy:** public, first-party vendor/project documentation only. `verified` means the linked page directly states the proposition; `inferred` means a constrained safety conclusion drawn from verified semantics; `unknown` means the page does not establish the stronger proposition.

## Kubernetes

1. Kubernetes Authors, **Leases**. URL: https://kubernetes.io/docs/concepts/architecture/leases/  
   Status: **verified** for: Lease objects coordinate shared resources; Lease API is used for kubelet heartbeats and leader election; kubelet heartbeat updates `spec.renewTime`; control plane uses that timestamp to determine Node availability; custom workloads can define Leases; a feature-gated controller-manager lock release can shorten leader transition; expired API-server identity Leases are garbage-collected after one hour.  
   Cannot prove: expiry kills the holder, revokes its network/credentials, interrupts code, prevents delayed writes, serializes arbitrary external resources, or fences a database/device/API.  
   Safety inference: **inferred**—a Lease is coordination/liveness state, so target-side fencing is required for external effects.

2. Kubernetes Authors, **Lease API reference (coordination.k8s.io/v1)**. URL: https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/lease-v1/  
   Status: **verified** for: Lease schema and fields including `holderIdentity`, `leaseDurationSeconds`, `acquireTime`, `renewTime`, and `leaseTransitions`.  
   Cannot prove: these fields automatically create a monotonic fencing token for arbitrary targets or stop a stale process.  
   Safety inference: **inferred**—an application may use transition/generation data in a protocol, but must enforce it at the resource being protected.

3. Kubernetes Authors, **API Concepts**. URL: https://kubernetes.io/docs/reference/using-api/api-concepts/  
   Status: **verified** for: an object’s `metadata.resourceVersion` lets the API server detect lost updates; a stale version causes HTTP `409 Conflict`; clients must handle conflicts/retries.  
   Cannot prove: `resourceVersion` is accepted by non-Kubernetes targets, fences an arbitrary old worker, or protects a side effect outside the API server.  
   Safety inference: **inferred**—this is conditional optimistic concurrency for Kubernetes object writes and can be used as fencing only within that API’s write path.

4. Kubernetes Authors, **Jobs**. URL: https://kubernetes.io/docs/concepts/workloads/controllers/job/  
   Status: **verified** for: Job controller behavior around completions, parallelism, backoff, `activeDeadlineSeconds`, Pod failure policy, terminal conditions, graceful termination, and replacement. The page explicitly warns that a replacement Job can result in old and replacement Pods running at the same time in the cited early-replacement pattern.  
   Cannot prove: Job completion/failure or Pod deletion proves every old process/descendant stopped, or that external writes are exactly once/serialized.  
   Safety inference: **inferred**—Jobs must be treated as potentially overlapping attempts; use idempotency and target-side fencing.

5. Kubernetes Authors, **Pod Lifecycle**. URL: https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/  
   Status: **verified** for: container restart policies, Pod termination flow, graceful termination and node/kubelet failure behavior described by the page.  
   Cannot prove: a status transition or grace-period expiry proves an external effect was absent or undone.  
   Safety inference: **inferred**—termination state is platform observation, not external commit/reconciliation evidence.

## Temporal

6. Temporal Technologies, **Detecting Activity failures**. URL: https://docs.temporal.io/encyclopedia/detecting-activity-failures  
   Status: **verified** for: Activity heartbeat is a ping from executing Worker to Temporal Service; it indicates progress and that Worker has not crashed; Heartbeat Timeout is the maximum interval between heartbeats; if reached, Activity Task fails and retry policy may cause another attempt; heartbeats may carry progress; next attempt can access the last recorded details; cancellation is delivered when Activities heartbeat; non-heartbeating Activities cannot receive cancellation; heartbeat throttling/delivery caveats exist; Heartbeat Timeout can be disabled with `0s` and is capped by Start-To-Close Timeout.  
   Cannot prove: timeout kills/revokes the old process, cancels an in-flight external call, rolls back a side effect, prevents overlapping retry, or fences an arbitrary target.  
   Safety inference: **inferred**—heartbeat is liveness/progress and retry trigger, not a target-side fencing token.

7. Temporal Technologies, **Activities**. URL: https://docs.temporal.io/activities  
   Status: **verified** for: Activities are normal functions executed by Workers; Temporal dispatches Activity Tasks and collects results; docs recommend splitting work into Activities for failure recovery, short timeouts, and idempotence; failed Activity attempts are automatically retried under Retry Policy; heartbeat detail can checkpoint progress for a next attempt.  
   Cannot prove: retries are non-overlapping, side effects are exactly once, or a prior Worker is dead after retry.  
   Safety inference: **inferred**—Activity implementations and external targets must tolerate duplicate/overlapping attempts.

8. Temporal Technologies, **Workers**. URL: https://docs.temporal.io/workers  
   Status: **verified** for: Temporal Workers are coupled to Task Queues and Worker Processes.  
   Cannot prove: task queue membership/worker polling is a fencing protocol for an external target.  
   Safety inference: **inferred**—polling/assignment is not enough to protect an external side effect.

## AWS Step Functions

9. AWS, **SendTaskHeartbeat API Reference**. URL: https://docs.aws.amazon.com/step-functions/latest/apireference/API_SendTaskHeartbeat.html  
   Status: **verified** for: activity workers and callback/job-run Task states use `SendTaskHeartbeat`; it reports progress for a `taskToken`; it resets heartbeat clock; the heartbeat threshold is `HeartbeatSeconds`; the call itself does not create an execution-history event; task timeout remains maximum regardless of heartbeats; task tokens are generated when tasks are assigned.  
   Cannot prove: heartbeat/token kills a worker, fences arbitrary external writes, guarantees callback-side effect commit, or undoes an already-completed side effect.  
   Safety inference: **inferred**—taskToken is an orchestration callback capability, not documented as a monotonic resource fence.

10. AWS, **Activities**. URL: https://docs.aws.amazon.com/step-functions/latest/dg/activities.html  
    Status: **verified** for: Activities are workers outside Step Functions; tasks can use activity workers/callback patterns; the page documents execution and callback concepts.  
    Cannot prove: external workers are terminated after timeout or that target side effects are exactly once.  
    Safety inference: **inferred**—external worker and target need independent fencing/idempotency.

11. AWS, **Choosing workflow type in Step Functions**. URL: https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html  
    Status: **verified** for: Standard Workflows provide exactly-once workflow execution; asynchronous Express is at-least-once; synchronous Express is at-most-once; Standard internally persists execution state; Express does not; same-name behavior and concurrent executions differ; Express same-name starts can be concurrent and state machine logic may need idempotence; history/logging retention and CloudWatch logging distinctions are documented.  
    Cannot prove: “exactly-once workflow execution” equals exactly-once external side effect, or that Express/Standard timeout prevents old external code from writing.  
    Safety inference: **inferred**—workflow execution guarantees must not be promoted to downstream effect guarantees.

## Cross-platform safety claims

12. **Fencing design recommendation (not a vendor claim).** Based on the verified semantics above: allocate a monotonic attempt/generation; carry it on every consequential mutation; atomically reject stale generations at the external target; combine with idempotency and conditional/version checks; preserve target receipts and reconcile ambiguous timeout outcomes. Status: **inferred**.  
    Cannot prove: any one cited platform automatically implements this protocol for arbitrary external resources.

13. **Evidence/incident recommendation (not a vendor claim).** Preserve assignment, heartbeats, attempts, versions/fences, status codes, target request IDs, timestamps, and operator actions; do not infer no external effect from heartbeat absence or platform timeout. Status: **inferred** operational guidance.  
    Cannot prove: the cited platforms retain every external request or provide a complete audit trail without configuration; AWS page specifically says execution history/logging coverage differs by workflow type and logging must be enabled for some cases.
