# Next-slice dispatch

- **Dispatch ID:** A81254C8-NEXT-RECOVERY-EVIDENCE-20260922
- **Created/access date:** 2026-09-22
- **Independent public-research slice (non-overlapping):** Agent runtime **recovery evidence and reconciliation after ambiguous outcomes**—how official platforms expose execution history, attempt identity, timeout/cancel/error receipts, and what operators must record to distinguish “platform accepted/failed” from “external effect committed/unknown.”
- **Non-overlap rule:** Do not re-research lease expiry, heartbeat semantics, or fencing-token design except where needed to define an evidence boundary. Focus on audit/event-history retention, request/attempt correlation, reconciliation workflows, and manual intervention/evidence preservation.
- **Required comparison candidates:** Temporal official Event History/activity failure and retry documentation; Kubernetes official Job/Pod conditions and events/status documentation; AWS Step Functions official execution history, redrive, logging, and API response/error documentation (or another first-party runtime with explicit official evidence semantics).
- **Source policy:** public first-party sources only; record full URL, access date 2026-09-22, verified/inferred/unknown, and what each source cannot prove. No private accounts, credentials, real services, shared targets, or prior-slice directories.
- **Output directory:** create a new isolated `/tmp/A81254C8-RECOVERY-EVIDENCE-20260922-<timestamp>/` and write `report.md`, `sources.md`, `summary.md`, `research-manifest.json` (if applicable), `SHA256SUMS`, and a dispatch record. Validate existence, size, SHA256, and manifest.
- **Safety stop:** if the slice would touch shared targets or permission boundaries, freeze and report immediately; do not modify anything.
