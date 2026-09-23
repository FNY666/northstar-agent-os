# Source register (S2 slice) — C-line trust-continuity research

All sources fetched 2026-09-22T07:53Z–08:00Z, all HTTP 200. Primary / official only.

| ID | Publisher | Document / URL | Fetched | Tier | Use |
|---|---|---|---|---|---|
| S1 | IETF (RFC 6749) | https://www.rfc-editor.org/rfc/rfc6749.txt | 2026-09-22 | primary | OAuth 2.0 core; §6 refresh; §5.1 refresh token endpoint |
| S2 | IETF (RFC 7009) | https://www.rfc-editor.org/rfc/rfc7009.txt | 2026-09-22 | primary | Token revocation; cascade + propagation-window conflict |
| S3 | IETF (RFC 7662) | https://www.rfc-editor.org/rfc/rfc7662.txt | 2026-09-22 | primary | Token introspection; `active` state at request time |
| S4 | IETF (RFC 9449) | https://www.rfc-editor.org/rfc/rfc9449.txt | 2026-09-22 | primary | DPoP: sender-constraint, ath, nonce, refresh binding |
| S5 | IETF (RFC 8705) | https://www.rfc-editor.org/rfc/rfc8705.txt | 2026-09-22 | primary | mTLS client auth + certificate-bound access/refresh tokens |
| S6 | IETF (RFC 8693) | https://www.rfc-editor.org/rfc/rfc8693.txt | 2026-09-22 | primary | Token exchange; `act` delegation chain; impersonation vs delegation |
| S7 | IETF (RFC 9700) | https://www.rfc-editor.org/rfc/rfc9700.txt | 2026-09-22 | primary | OAuth 2.0 BCP; §4.10 sender-constrained + audience-restricted tokens |
| S8 | OpenID Foundation | https://openid.net/specs/openid-connect-core-1_0.html | 2026-09-22 | primary | OIDC Core 1.0; §5.7 iss+sub stability; §11/§12 offline access |
| S9 | Kubernetes (official docs) | https://kubernetes.io/docs/reference/using-api/api-concepts/ | 2026-09-22 | primary | resourceVersion CAS → 409 Conflict; stale-writer rejection |
| S10 | Kubernetes (official docs) | https://kubernetes.io/docs/concepts/architecture/leases/ | 2026-09-22 | primary | Lease objects; node heartbeats; leader election; lock-release Alpha v1.36 |
| S11 | AWS (S3 User Guide) | https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html | 2026-09-22 | primary | Conditional writes (If-None-Match / If-Match ETag) |
| S12 | GCP (Cloud Storage) | https://cloud.google.com/storage/docs/request-preconditions | 2026-09-22 | primary | ifGenerationMatch / ifMetagenerationMatch → 412 |
| S13 | Microsoft Learn (Azure Blob REST) | https://learn.microsoft.com/en-us/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations | 2026-09-22 | primary | If-Match / If-None-Match / 412 semantics |
| S14 | AWS (Step Functions API) | https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html | 2026-09-22 | primary | StopExecution; not supported for EXPRESS state machines |
| S15 | GCP (Workflows) | https://cloud.google.com/workflows/docs/executing-workflow | 2026-09-22 | primary | Execute a workflow; no first-class cancel/terminate found (negative) |
| S16 | GCP (Workflows, linked) | https://cloud.google.com/workflows/docs/tutorials/workflow-waits-callback-sheets | not fetched | primary | "Pause and resume a workflow using callbacks" — pending S2-next |
| S17 | Temporal docs | https://docs.temporal.io/workflow-execution/workflow-cancellation | not accessible (404) | lead only | Cancellation doc moved; not usable as evidence in this slice |

## Access / negative-find log
- Temporal cancellation doc: 404 on 2026-09-22; no substitute primary source fetched → **unknown / not accessed**.
- GCP Workflows cancel/stop/terminate: page fetched, searched, absent → **unknown (not documented on that page)**.
- GCP Cloud Run / Azure Functions timeout-reauth: **not searched** in this slice.
