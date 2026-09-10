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
- It does not provide distributed locking or cross-host multi-process atomic
  idempotency.

## Segmented rotation and compaction

- The log is append-only inside a segment. Rotation seals the active segment and
  publishes a `SegmentRef` (sequence bounds, record count, first/last record
  digest, segment digest) in a manifest written to a temporary file, fsynced, and
  atomically renamed.
- Roll-on-next-append keeps segments bounded without a background rotator: a full
  active segment is sealed only when the next record actually arrives.
- Recovery completes a rotation that crashed between the manifest publish and the
  segment rename, and it adopts the active file as the sealed segment only when
  the recomputed digest matches the manifest — never on filename evidence alone.
- An unregistered `segment-*.log` is reported as `orphan_segment` and is neither
  read nor deleted. A missing segment, a missing manifest with sealed segments,
  and a corrupt manifest all fail closed.
- Verification returns `replayable`, `digest-only`, or `unverifiable`. Compaction
  degrades readability, never provability: the compacted segment keeps its
  `last_digest`, so the following segment still chains to it, and re-reading the
  removed records is refused rather than approximated.
- The manifest is authoritative for what exists; the segment bytes are
  authoritative for what they say. Disagreement is `unverifiable`.

What this does not prove:

- That a compacted segment's records ever existed on this host. The digest is
  evidence about content that is no longer present, so a writer able to publish a
  manifest could publish a digest for content that was never written.
- That rotation survives a real power loss. The two interruption points are
  injected in-process, not by a filesystem fault injector.
- That rotation is safe across hosts. The lock is a local `flock`; no cross-host
  writer is excluded, and sequence identity is per-log, not global.
- It has no real Codex, Claude Code, Cursor, Hermes, or OpenBot dependency.

## Release boundary

Do not cherry-pick or publish this candidate automatically. It requires a
separate comparison against the local-only Router, a multi-process rotation
experiment on a real filesystem, a cross-host identity decision, and an explicit
generation release gate.
