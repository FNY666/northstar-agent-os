# Executive summary

**As of 2026-09-22:** Public first-party documentation for Kubernetes, Temporal, and AWS Step Functions converges on a strict boundary: lease/heartbeat expiry changes the orchestrator’s view of eligibility or task state; it does **not** prove the old process has stopped and does **not** by itself fence writes to an external database, API, device, or other target.

- **Kubernetes Lease:** kubelet renews `spec.renewTime`; control plane uses it to determine Node availability. Lease supports leader election. Kubernetes API `resourceVersion` detects stale object updates and returns 409, but only on the Kubernetes API object path.
- **Kubernetes Jobs/Pods:** retries, deadlines, replacement, and termination are controller policy. Official docs warn old and replacement Pods can overlap in a replacement pattern. Job status is not external-effect serialization.
- **Temporal Activity:** heartbeat means progress/Worker-not-crashed observation; missed Heartbeat Timeout fails the Activity and Retry Policy may create a later attempt. Cancellation is delivered on heartbeat. Timeout does not document killing a stuck Worker or undoing effects.
- **AWS Step Functions:** `SendTaskHeartbeat` resets heartbeat clock for a taskToken; overall Task Timeout remains a hard maximum. Standard/Express workflow execution guarantees differ (exactly-once, at-least-once, at-most-once), but none is a general exactly-once guarantee for arbitrary downstream effects.

**Required safety pattern:** assign a monotonic fence/epoch per logical work item; include it in every consequential write; make the external target atomically accept only the current/allowed fence and record it with the mutation; add idempotency keys and compare-and-set/version checks; preserve stale-write rejection evidence. Treat retry, restart, cancellation, timeout, and network partition as potentially overlapping execution. Separate platform receipt, execution observation, target commit, and independent reconciliation.

**Operational rule:** on ambiguous timeout or suspected split-brain, freeze the logical key if possible, preserve append-only evidence (attempt IDs, fences, heartbeats, versions, response/request IDs, UTC and monotonic timestamps), reconcile target state, and record manual intervention. Never claim “no external effect” merely because a heartbeat stopped or a platform marked a task failed.

Detailed report and source-by-source verified/inferred/unknown boundaries are in `report.md` and `sources.md`.
