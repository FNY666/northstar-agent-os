# S8 synthetic-only evidence drill

- `synthetic_only=true`
- `production_verified=false`
- Run date: 2026-09-22 (Asia/Shanghai)
- Scope: offline deterministic simulation only; no cloud endpoint, Kubernetes API, SDK, credential, bucket/container/cluster, or pre-existing C-line artifact was read or modified.
- Working directory: `/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S8/`

## 1. Decision-ready conclusion

The harness validates a **fail-closed evidence state machine**, not platform behavior. With a fixed `operation_id` (`op-s8-20260922-fixed-0001`) and fixed payload SHA-256 (`89bf43244bd1b9f752a3063e7a03bbcca6bb7b182021e469f601f872dbbb3966`), it distinguishes conditional conflicts, authorization denial, ambiguous/lost responses, stale read-back, duplicate retry, identity mismatch, inaccessible real probing, and a deliberate residual UNKNOWN.

The synthetic matrix supports these bounded conclusions only:

1. A status/precondition branch can be represented in a common evidence schema.
2. A lost-response retry must reuse the same operation identity and payload digest; a matching synthetic read-back can close the **synthetic evidence case**.
3. A stale/no read-back, a status-only 409, or a missing branch must not be upgraded to success.
4. Platform-specific conditional tokens map to a common `precondition` family, but their semantics and status-code causes remain platform-specific.
5. The measured `W_ms` values are logical fixture-clock values, not latency, consistency, durability, fencing, production, or remote-state measurements.

No result proves exactly-once, fencing completion, remote state, crash durability, production readiness, or any behavior beyond the cited official documentation.

## 2. Evidence ledger

Status vocabulary is applied per claim: `confirmed`, `inferred`, `unverified`, `conflicting`, `inaccessible`.

| Claim / observation | Status | Basis and boundary |
|---|---|---|
| Kubernetes uses `resourceVersion` for optimistic concurrency and stale conditional update can yield HTTP 409 | confirmed | Official Kubernetes API concepts URL in `sources.md`; this is a documentation claim, not a live API test. |
| S3 conditional requests use ETag/version validators; documented conditional failures include 412, while some concurrent/multipart contexts can produce 409 | confirmed | Official Amazon S3 conditional requests and error docs in `sources.md`; exact operation-specific cause must be retained. |
| GCS generation/metageneration preconditions can fail with HTTP 412 | confirmed | Official Cloud Storage request-preconditions URL in `sources.md`; no GCS call was made. |
| Azure Blob conditional ETag and lease conditions can return 412; some lease conflicts can return 409 | confirmed | Official Azure Blob concurrency and lease docs in `sources.md`; no Azure call was made. |
| A lost response leaves commit outcome ambiguous until an independently scoped read-back matches identity and digest | inferred | Protocol/state-machine design inference; official docs do not establish this cross-platform matrix or a universal confirmation window. |
| `W_ms` can be measured as first matching synthetic read-back logical time minus synthetic acceptance/retry origin | inferred | Harness measurement definition; logical fixture clock only. |
| Matching read-back proves exactly-once or crash durability | conflicting | Deliberately rejected: a synthetic match cannot prove either property. |
| Cache/old-read behavior and a universal cross-platform visibility bound | unverified | Synthetic stale branches exist; no universal bound is inferred from vendor docs. |
| Real service behavior, remote state, or production crash durability | inaccessible | Explicitly excluded by S8 scope; no real endpoint was accessed. |

## 3. Fixed identity and payload

```text
operation_id  = op-s8-20260922-fixed-0001
payload       = {"action":"conditional-write","resource":"synthetic/object/alpha","value":"S8-fixed-payload-v1"}
payload_sha256= 89bf43244bd1b9f752a3063e7a03bbcca6bb7b182021e469f601f872dbbb3966
```

The harness rejects fixture identity drift. The digest is computed from canonical JSON (`sort_keys=true`, compact separators, UTF-8), and every case carries the same fixed identity.

## 4. Cross-platform field mapping

| Common evidence field | Kubernetes | S3 | GCS | Azure Blob | State-machine use |
|---|---|---|---|---|---|
| resource identity | API resource/name/UID (UID is stronger than name) | bucket + object key + optional version ID | bucket + object name + generation | account/container/blob | Bind to operation record; never infer identity from status alone. |
| optimistic validator | `metadata.resourceVersion` | ETag and/or version/conditional headers | `generation` / `metageneration` preconditions | ETag `If-Match` / `If-None-Match`; lease ID for lease condition | `precondition_token` with platform and token kind. |
| conflict signal | HTTP 409 for resourceVersion conflict | HTTP 412 for failed precondition; HTTP 409 in documented contextual cases | HTTP 412 for failed precondition | HTTP 412 condition not met; HTTP 409 for some lease conflict conditions | Map to `PRECONDITION_CONFLICT`, preserving raw status and cause. |
| write identity | client operation ID (synthetic in S8) | client operation ID (synthetic; not an S3 guarantee) | client operation ID (synthetic; not a GCS guarantee) | client operation ID (synthetic; not an Azure guarantee) | `operation_id`; must be stable over retry. |
| payload identity | SHA-256 of canonical request payload | same | same | same | `payload_sha256`; mismatch blocks retry. |
| read-back evidence | fresh GET/status read with matching UID/version/payload where available | HEAD/GET plus ETag/version/payload digest as applicable | GET/metadata with generation/metageneration and payload digest | GET/properties with ETag/lease-relevant context and payload digest | `read_back.state ∈ {matched,no_match,stale,not_attempted}`. |
| permission signal | 401/403 | 401/403 | 401/403 | 401/403 | `PERMISSION_DENIED`; stop, do not retry blindly. |
| caveat | resourceVersion is a server concurrency token, not a client idempotency key | 409 meaning is operation/context dependent | generation is object versioning/precondition context, not universal client idempotency | ETag and lease are distinct conditions | Keep `raw_status`, `validator_kind`, and `cause` rather than collapsing all 409/412. |

## 5. State machine and retry policy

```text
START
  -> WRITE_ATTEMPT
     -> ACCEPTANCE_UNOBSERVED / RESPONSE_LOST
        -> same operation_id + same payload_sha256 retry
           -> READ_BACK
              -> MATCHED      => synthetic confirmation only
              -> STALE         => VISIBILITY_UNKNOWN
              -> NO_MATCH      => UNKNOWN (not proof of non-commit)
              -> absent        => UNKNOWN
     -> 409/412 precondition => PRECONDITION_CONFLICT
        -> fresh read validator; bounded retry only if policy permits
        -> otherwise compensate / human review
     -> 401/403             => PERMISSION_DENIED; stop and escalate
     -> digest mismatch     => IDENTITY_MISMATCH; block and escalate
     -> unknown status/shape => UNKNOWN; fail closed
```

Retry is permitted only when the identity tuple is unchanged: operation ID, resource identity, payload digest, intended action, authorization context, and validator scope. A retry must not silently change payload, target, tenant, or precondition. This is a policy design for the synthetic harness, not a claim that any vendor API provides idempotency from an arbitrary client operation ID.

## 6. Minimum confirmation window W

### Definition

For an otherwise ambiguous write, record logical timestamps in one monotonic trace:

- `t0`: write attempt is emitted;
- `ta`: synthetic acceptance is observed, if any;
- `tr`: same-identity retry is emitted after response loss/timeout;
- `tb`: first read-back that is fresh enough for the selected platform and matches **all** of operation ID (client evidence), resource identity, intended action, and payload digest (plus the platform validator/version where available).

For this offline fixture, `W = tb - tr`; if the protocol defines the window from acceptance, report `W_accept = tb - ta` separately. Here the fixture records only logical `W_ms` for matched cases. A real deployment must define freshness/visibility and authoritative read path before choosing a numeric bound; S8 does not derive one from docs.

### Measurement method

1. Use a monotonic clock (never wall clock) and append-only trace entries.
2. Persist the fixed identity tuple before the first attempt.
3. On response loss, retry the identical tuple; never generate a new operation ID.
4. Read back through the authoritative path, bypassing or identifying caches; capture validator/version and payload digest.
5. Set `W` at the first matching read-back; keep all later observations for audit.
6. If no match, stale data, permission denial, or validator ambiguity persists until the configured deadline, set `W=UNKNOWN`, do not call it failure-to-commit, and enter compensation/human review.
7. Calibrate the deadline from an explicitly authorized service SLO/contract or an operator policy. No universal value is asserted here.

Synthetic matched fixtures: `S8-RESP-LOST-MATCH` = 120 ms; `S8-DUPLICATE-RETRY-MATCH` = 90 ms. These are test inputs, not measured platform timings.

## 7. Human escalation and compensation

Transfer to a human or compensation workflow when any of these holds:

- no read-back match by the authorized deadline (`W=UNKNOWN`);
- read-back is stale, cache provenance is unknown, or the authoritative path is unavailable;
- retry would change operation ID, payload digest, target, tenant, action, or validator scope;
- 409/412 cause cannot be disambiguated from raw status and operation context;
- 401/403, expired/missing authorization, or scope ambiguity;
- digest mismatch, duplicate side effect risk, or evidence-log integrity failure;
- service-specific docs do not define the needed precondition/read-back semantics;
- any proposed action would require a real endpoint or credentials (out of S8 scope).

Compensation must be an explicitly reviewed, domain-specific action (for example, a reverse operation or reconciliation record), not an automatic assumption that the original write failed. Preserve both possible outcomes and all evidence.

## 8. Synthetic run inventory

The matrix has 18 cases covering Kubernetes RV 409; S3 412 and 409; GCS 412; Azure ETag 412, lease 412 and lease 409; response loss with match and no match; stale/cache and old generation reads; 401/403; duplicate retry with match; payload mismatch; status-only 409; inaccessible real-probe guard; and missing-branch residual UNKNOWN.

The authoritative counts are in `outputs/results.json` and are generated by `harness.py`; rerun commands are in the manifest. No real service was contacted.

## 9. Explicit non-claims

This package does **not** demonstrate production operation, remote state, exactly-once semantics, successful fencing, crash durability, universal consistency/visibility, vendor idempotency, or a numeric production confirmation SLO. It validates only deterministic classification and evidence transitions over synthetic fixtures.

## 10. Next independent slice (do not continue in this slice)

**S9 proposal — synthetic trace-integrity and replay slice:** extend the offline matrix with signed/hashed append-only evidence records, reordered/duplicated/lost trace entries, clock rollback, validator rotation, authorization-context changes, and deterministic replay. Compare fail-closed versus fail-open decisions and report only state-machine coverage; retain the same no-network/no-credentials boundary and do not reuse or modify restricted directories.
