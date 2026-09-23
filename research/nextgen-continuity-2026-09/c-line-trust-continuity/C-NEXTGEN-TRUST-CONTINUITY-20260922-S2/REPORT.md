# C-line Public Research Slice — Next-Gen Agent Trust Continuity (S2)

## Question
What public, official, primary-source evidence exists for identity/authorization continuity of a next-generation agent across cancellation, timeout, stream disconnection, permission change, and recovery — and for resource-side rejection of stale writers?

## Scope
- Official primary sources only: IETF RFCs (rfc-editor), OpenID Foundation spec (openid.net), kubernetes.io official docs, AWS / GCP / Azure official docs.
- Access window: 2026-09-22T07:53Z to ~08:00Z. All HTTP fetches returned 200.
- Evidence labels per item: **verified** (direct primary text captured), **inferred** (my bounded deduction from verified text), **unknown** (no public primary evidence found), **conflict** (primary texts point different ways).

## Strict boundary (task constraint, honored throughout)
Token possession, leases, logs, and synthetic fixtures are **NOT** asserted anywhere below as real production authorization, fencing completion, or exactly-once delivery. Where a mechanism (DPoP, resourceVersion, lease, ETag/generation precondition) is described, its semantic limits are stated explicitly.

## Findings

### 1. Identity continuity — verified
- **OIDC Core 1.0 §5.7 (Claim Stability and Uniqueness)**: "The `sub` (subject) and `iss` (issuer) Claims from the ID Token, used together, are the only Claims that an RP can rely upon as a stable identifier for the End-User, since the `sub` Claim MUST be locally unique and never reassigned within the Issuer." → Across reconnects/rotations within one issuer, `iss+sub` is the only guaranteed-continuous identity anchor. **verified.**
- Consequence (inferred): a resumed agent session can re-anchor identity to the issuer without trusting local state; any claim besides `iss/sub` (email, preferred_username) "carry no such guarantees" (same §). **inferred** from §5.7 text.
- Limitation: uniqueness is **within one issuer**. Cross-issuer or multi-tenant agent identity continuity is not guaranteed by OIDC Core; that is **unknown** (no primary source in this slice).

### 2. Permission-change detection at request time — verified mechanism, unbounded window
- **RFC 7662 §2.2**: introspection response `active` "will generally indicate that a given token has been issued by this authorization server, has not been revoked by the resource owner, and is within its given time window of validity." → The resource side can *re-check live authorization on every request* instead of trusting a cached grant. **verified.**
- **RFC 7009 §2.2 (cited in RFC 7662)**: invalidation "takes place immediately" **but** "in practice, there could be a propagation delay, for example, in which some servers know about the invalidation while others do not. Implementations should minimize that window." → **conflict (documented, bounded)**: "immediate" vs "propagation delay can exist." The standards explicitly do not bound the window. Consequence (inferred): a post-revocation request can still be accepted by a stale edge; introspection narrows but does not close the gap. This is **not** fencing.
- Also (RFC 7009 §2): "A client compliant with [RFC 6749] must be prepared to handle unexpected token invalidation at any time" — i.e., agents MUST treat any 401/inactive as a normal recovery transition, not an error state to cache. **verified.**

### 3. Recovery re-authorization — verified
- **OIDC Core §11/§12 (Offline Access / Using Refresh Tokens)**: refresh tokens can be used to "request a new access token without further user interaction." On reconnect, the agent re-authenticates to the authorization server; the new token carries current scope/claims. **verified.**
- **RFC 7662 + §6749 §6 (RFC 6749 §5.1 refresh)**: reissued tokens are fresh grants — the *current* authorization state, not a replay of the old one. **inferred** from the combined texts (both RFCs say reissue returns a new access token whose validity derives from the grant).
- **RFC 7009 §2**: refresh-token revocation "SHOULD also invalidate all access tokens based on the same authorization grant." So permission *removal* cascades through refresh→access. **verified.**

### 4. Sender-constrained tokens (DPoP / mTLS) — verified mechanism, bounded scope
- **RFC 9449 §2**: "The primary aim of DPoP is to prevent unauthorized or illegitimate parties from using leaked or stolen access tokens, by binding a token to a public key upon issuance and requiring that the client proves possession of the corresponding private key when using the token." **verified.**
- **RFC 9449 §7 (ath claim)**: the proof is hashed-bound to the specific access token; "a rotated token value would require the calculation of a new proof." → after a token rotation during recovery, the old proof is unusable; the agent must re-prove possession. **verified.**
- **RFC 9449 §8 (nonce)**: authorization server MAY require a fresh nonce on each proof, "limiting the lifetime of DPoP proofs"; a nonce mismatch triggers `use_dpop_nonce` + retry. This is the standard's **replay-rejection** primitive for pre-computed/captured proofs. **verified.**
- **RFC 9449 §1**: DPoP "can also be used to sender-constrain refresh tokens issued to public clients." So recovery reissue inherits sender constraint. **verified.**
- **RFC 8705**: mutual-TLS client auth + certificate-bound access/refresh tokens; fingerprint association "obtained from the TLS stack." **verified.**
- **RFC 9700 §4.10.1**: "sender-constrained access tokens ... Two methods ... are in use in practice" (mTLS + DPoP). **verified.**
- Semantic limits (inferred, stated as such): DPoP/mTLS bind *who can present* the token to *which token value*; they do **not** assert the underlying grant's scope is still current. They reduce token-theft risk; they are **not** authorization checks. **inferred.**

### 5. Delegation / acting-party continuity — verified
- **RFC 8693 §1.1**: distinguishes *delegation* (A remains identifiable, acts for B) from *impersonation* (A becomes B within the rights context). For agents that resume after disconnection, the `act` claim chain in the exchanged token records the delegation history. **verified.**
- **RFC 8693 §4.1 ("act" claim)**: "A chain of delegation can be expressed by nesting one 'act' claim within another ... The nested 'act' claims serve as a history trail that connects the initial request and subject through the various delegation steps undertaken before reaching the current actor." Also: "For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor ... Prior actors identified by any nested 'act' claims are informational only." **verified.**
- Consequence (inferred): on resume, a re-exchanged token can carry forward the delegation trail; access control is decided on the *current* actor + top-level claims, not on stale nested actors. **inferred.**
- `may_act` (RFC 8693 §2.3/§4.3): "a chain of delegation" can be expressed via nested `act`; `may_act` is a boolean hint that the token is delegated/actor-restricted. **verified** (presence of the claim); **inferred** (semantics of how a resource MUST enforce it are at the AS/RS policy, not specified further in the RFC).

### 6. Resource-side rejection of stale writers — verified (Kubernetes)
- **kubernetes.io API Concepts (§ Updates: "Choosing an update mechanism")**: "For a PUT request, it is the client's responsibility to specify the resourceVersion (taking this from the object being updated). Kubernetes uses that resourceVersion information so that the API server can detect lost updates and reject requests made by a client that is out of date with the cluster. In the event that the resource has changed (the resourceVersion the client provided is stale), the API server returns a 409 Conflict error response." **verified.**
- "Clients that need effective detection of lost updates should consider making their request conditional on the existing resourceVersion (either HTTP PUT or HTTP PATCH), and then handle any retries that are needed in case there is a conflict." **verified.**
- **Lease objects (§ coordination.k8s.io)**: "Distributed systems often have a need for leases, which provide a mechanism to lock shared resources and coordinate activity between members of a set. In Kubernetes, the lease concept is represented by Lease objects in the coordination.k8s.io API Group." Used for node heartbeats + component-level leader election. **verified** (mechanism). "Kube controller manager lock release on exit — Feature state: Alpha since Kubernetes v1.36; disabled by default." **verified** (Alpha, not GA).
- Semantic limits (stated, inferred): a Lease object is a *coordination primitive* — it does not by itself fence writes to arbitrary resources; fencing in practice comes from the CAS layer above it (resourceVersion 409). The Lease API docs do **not** claim mutual-exclusion fencing of external side-effects. **inferred.** Lease ≠ production fencing token. **not asserted.**

### 7. Resource-side rejection of stale writers — verified (cloud object stores)
- **AWS S3 (§ "Conditional requests")**: "Conditional writes can ensure there is no existing object with the same key name in your bucket during PUT operations. This prevents overwriting of existing objects with identical key names." `If-None-Match: *` = write-only-if-absent; `If-Match: <etag>` = CAS update. "Conditional writes ... to check if an object's ETag is unchanged before updating the object. This prevents unintentional overwrites." **verified.**
- **GCS (§ "Request preconditions")**: `ifGenerationMatch` / `ifMetagenerationMatch` — "Request proceeds if the generation of the target resource matches the value used in the precondition. If the values don't match, the request fails with a 412 Precondition Failed response." Generation "changes when the object is replaced." **verified.**
- **Azure Blob (§ "Conditional headers")**: `If-Match` (ETag), `If-None-Match` (ETag or `*`); "Specify the wildcard character (*) to perform the operation only if the resource doesn't exist, and fail the operation if it does exist." Multiple conditional headers are evaluated as a logical expression; any false → 412. **verified.**
- Semantic limits: ETag/generation CAS is **optimistic concurrency control**, not exactly-once delivery and not a fencing token. A stale writer that *ignores* the 409/412 and retries with a fresh GET can succeed — the protection is conditional on the client respecting the precondition. **inferred.**

### 8. Workflow cancellation / timeout / disconnection — verified mechanism, unknown recovery semantics
- **AWS Step Functions (§ API_StopExecution)**: "Stops an execution. This API action is not supported by EXPRESS state machines." `error` and `cause` fields are optional. **verified.**
- **Google Cloud Workflows (§ "Execute a workflow")**: no first-class cancel/stop/terminate API documented on the page fetched (searched for "Stop a workflow", "cancel", "terminated", "Stop" — all absent from the page). **unknown** (negative result; not searched vs. not found in this slice).
- GCP Cloud Run / Serverless: no primary source fetched in this slice for timeout-driven reconnect authorization. **unknown.**
- Consequence (inferred): cancellation semantics in workflow engines are *stop the execution*; they do not automatically revoke the agent's in-flight credentials or fence already-dispatched side-effects. The standards in §§2–5 above operate at the *request* level; there is no public standard that binds "workflow execution terminated" to "all in-flight agent credentials immediately invalidated." **inferred.**

### 9. Timeout / reconnect — unknown
- No primary source in this slice defines a "timeout-then-reconnect identity continuity" guarantee for agent frameworks. The closest mechanisms are: OIDC refresh-token reissue (§3), DPoP nonce re-challenge (§4), and workflow resumption callbacks (GCP Workflows "Pause and resume a workflow using callbacks" — linked but not fetched in this slice). **unknown / not searched to completion.**

## Conflict register (documented, not resolved)
| ID | Topic | Source A | Source B | Status |
|---|---|---|---|---|
| C-1 | Revocation immediacy | RFC 7009 §2.2 "invalidation takes place immediately" | RFC 7009 §2.2 "in practice, there could be a propagation delay ... some servers know ... others do not" | **conflict (documented, window unbounded)** |
| C-2 | Lease fencing | K8s docs describe Lease for "locking shared resources" | K8s CAS 409 is the actual write-rejection layer; Lease alone does not fence | **inferred (not a direct text conflict)** |

## What is NOT claimed in this slice
- No assertion that DPoP / mTLS tokens constitute "real production authorization."
- No assertion that a Lease, a log entry, or a synthetic fixture constitutes fencing completion.
- No assertion that ETag/generation CAS provides exactly-once delivery.
- No assertion that GCP Workflows or AWS Step Functions support arbitrary post-cancellation credential revocation.

## Next-slice dispatch (do not stop the line)
1. **Fetch & verify** GCP Workflows "Pause and resume a workflow using callbacks and Google Sheets" doc — does a resumed workflow re-validate the caller's identity/token, or reuse the original execution context? Expected evidence class: B/C.
2. **Fetch & verify** AWS Step Functions "What is AWS Step Functions?" + "Error handling and retries" — are in-flight task callbacks cancelled on StopExecution, or do they complete in the background?
3. **RFC 6749 §6 (Refreshing an Access Token)** — capture the exact "the authorization server MAY issue a new refresh token" rotation language; combine with RFC 7009 to bound the refresh-revocation cascade.
4. **GCP Cloud Run / Azure Functions timeout docs** — does a timeout-triggered restart re-authenticate via service account, or reuse a cached JWT?
5. **K8s § "Server Side Apply" + "last-applied-configuration"** — does SSA record the *writer identity*? If yes, that is the strongest resource-side "reject stale writer by identity, not just version" primitive found so far.

## Artifacts
- `sources.md` — full source register
- `research-manifest.json` — machine-readable manifest (validator-compatible)
- `SHA256SUMS` — integrity of the three files above
