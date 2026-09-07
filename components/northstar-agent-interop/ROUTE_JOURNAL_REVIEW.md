# RouteDecision Journal Research Review

## Status

Local research candidate only. This slice is implemented in the independent
`research-route-journal` worktree and is not part of the public checkout or the
existing local-only `BackendRouter` worktree.

## What this slice proves

- A route request can be represented by a precomputed opaque request digest.
- Candidate metadata is snapshotted without storing prompts, context contents, or
  backend output.
- Selected identity, provider, policy revision, and narrowed deadline are
  canonicalized into a deterministic decision fingerprint.
- Append-only JSONL writes flush and `fsync` each record, with a sidecar `flock` to serialize local multi-process idempotency checks.
- A truncated final line is ignored; a complete malformed line fails closed.
- Reusing an idempotency key with the same canonical record returns the prior
  record without calling the router again.
- Reusing it with a different record raises a conflict.
- Replay rejects changed candidate snapshots, policy revision, request digest,
  identity, deadline, or selection result.
- A journal decision cannot authorize a mismatched handoff; the handoff identity
  must match and its deadline must be no later than the route deadline.

## What this does not prove

- It does not prove backend health or execution success.
- It does not replace Handoff Grant verification or host authorization.
- It does not persist raw prompts, opaque context, model output, credentials, or
  tool output, so it cannot independently reconstruct a provider conversation.
- The integration uses a deterministic router protocol shim because the existing
  public stable baseline does not include `BackendRouter`; this slice must be
  evaluated against the local-only Router in a separate review.
- It does not provide distributed locking, multi-process atomic idempotency, or
  crash-consistent rotation/compaction of very large journals.
- It has no real Codex, Claude Code, Cursor, Hermes, or OpenBot dependency.

## Release boundary

Do not cherry-pick or publish this candidate automatically. It requires a
separate comparison against the local-only Router, a multi-process journal
experiment, recovery/rotation design, and an explicit generation release gate.
