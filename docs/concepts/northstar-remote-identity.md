# Host-side credential issuance and rotation (T5 story)

> **Status: a story, not a system.** This page designs how a hosted worker
> gets and loses its credentials, mapped onto the token machinery that
> already exists in this tree. No new credential code ships here, and
> nothing on this page has been exercised against a real host. It is the T5
> answer to the P3-3 ops gap *"host-side credential issuance + rotation
> story"*.

The governing rule from
[`northstar-remote-worker.md`](northstar-remote-worker.md) is: **the host
holds the keys**. A worker never mints its own tokens; it presents what the
host issued, and the host can stop trusting it by letting the credential
expire or the policy revision move.

## 1. What credential machinery already exists (facts, from the code)

| Token | Sign/verify | Life | What it carries |
| --- | --- | --- | --- |
| Run binding | `binding.py::sign_binding` / `verify_binding` (caller supplies `now`) | short; `expires_at` is enforced at verify time (`verify_binding` refuses `now >= expires_at`) | `run_id`, `actor_id`, `workspace_id`, `expires_at` under `schema_version` |
| Run authorization | `authorization.py::authorize_run` → `sign_authorization`; verified by `verify_authorization` | bounded by `expires_at`; stamped with `policy_revision` | actor, run, workspace, capabilities, policy revision, expiry |
| Handoff grant / attestation | `handoff.py::authorize_handoff`, `sign_attestation`, `verify_attestation`, `verify_handoff_grant` | per-hop, narrowed | `GRANT_SCHEMA_VERSION` / `ATTESTATION_SCHEMA_VERSION` scoped delegation |
| Approval token | durable `action_gateway.py::sign_approval` (verified by the gateway) | per action | tool call + scope digest, approval state |

All of these are **symmetric keyed canonical-JSON MACs over a shared
`secret`** (the `_require_secret` convention) with integer epoch
`expires_at`, verified against a caller-supplied `now`. There is no PKI, no
asymmetric signing and no live revocation list in the tree — expiry-plus-
revision is the revocation mechanism, and that is a feature for a local
prototype and a constraint to design around for fleets.

Every authorization also lands in the audit feed as an
`authorization_grant` record (`host_audit.py::authorization_to_audit`), so
issuance is itself auditable: actor, run, workspace, capabilities, policy
revision, expiry.

## 2. Issuance story

Two distinct secrets, two lifetimes — keep them separate:

1. **Enrollment secret** (long-lived, per worker pair): provisioned once,
   out of band (ssh-copy-id class ceremony, secret injected via the env
   allowlist `_FIXED_ENV` pattern from `process_adapter.py` — never on the
   worker's writable disk, never in argv). It keys the *hop*: bindings the
   host signs for that specific worker.
2. **Run-scoped binding** (short-lived): the host signs per run with the
   enrollment secret — `run_id`, `actor_id`, `workspace_id`,
   `expires_at` — and the worker verifies with the same secret before it
   executes anything. Recommended TTL is minutes, not hours: a binding is
   re-issued per run and its whole purpose is to be useless after the run.

The authorization grant adds the policy dimension: the host signs what the
actor may do **under `policy_revision`**; a worker checks it before launch
(the interop adapter already verifies the handoff grant before starting any
process). Issuance therefore means: *policy checked once by the host,
cryptographically pinned to every artifact that travels*.

## 3. Rotation story

Symmetric shared secrets rotate as a pair update, not a replacement:

1. **Generate**: ≥ 32 random bytes at the host.
2. **Dual-key grace**: the host starts verifying with the new secret while
   still accepting the old one for one rotation window (the `verify_*`
   functions take the secret as an argument — running two verifies in the
   grace window is a wrapper concern, not a code change). Workers are
   re-provisioned during the window; the window is sized to the slowest
   worker, then the old secret is destroyed.
3. **Expiry is the backstop**: every token already carries `expires_at` and
   verification already takes `now` — a rotated-out secret becomes useless
   no later than the longest outstanding token's expiry, even if a worker
   was missed.
4. **Revision is the kill switch**: bumping `HostPolicy.revision` (a
   required id field on the policy) invalidates the *meaning* of older
   authorizations at verify time, independent of secret rotation — the
   emergency path for "that worker must stop now".

Clock skew is the one environmental assumption: `now` is supplied by the
caller, so all verifiers share the caller's clock. The design requires
NTP-disciplined hosts and an open decision on allowed skew versus TTL
(short TTLs make skew visible fast — a feature for a canary).

## 4. Failure and incident handling

| Incident | Response |
| --- | --- |
| Worker lost (disk gone) | rotate enrollment secret, re-enroll, let old bindings expire |
| Secret suspected leaked | rotate immediately + bump `policy_revision`; audit `authorization_grant` shows what the leaked key could have authorized |
| Clock skew breaks verification | fix NTP; skew vs TTL decision from §3; no tokens minted during outage |
| Mid-run credential expiry | run-scoped binding is checked before launch; a run that outlives it continues on the durable event history and its receipt, not on the token |
| Compromised host key (SSH layer) | host-key rotation + known_hosts surgery; the run layer is unaffected because SSH is only the byte pipe (see the transport page) |

## 5. What is genuinely missing (do not over-read this page)

- No asymmetric/mTLS story — Profile B (fleets) needs one; decision needed:
  mTLS per worker, or short-lived certs from an internal CA, or keeping
  symmetric bindings over an mTLS channel.
- No KMS/HSM or vault integration; the enrollment secret lives with the host
  process. Acceptable for a private worker, a real decision for fleets.
- No revocation list — expiry + revision only (stated above, by design).
- Nothing here has run end to end; the canary recipe
  (`examples/remote-canary`) is where that starts, against a real host.

Related: [transport specification](northstar-remote-transport.md),
[the remote-worker evaluation](northstar-remote-worker.md).
