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

## Signing-key lifecycle

- `KeyHistory` is an append-only, hash-chained record of `introduced` /
  `rotated` / `revoked` actions. It stores a material digest, never the material.
- A verdict is only ever derived from a chain that verified against the supplied
  anchor. A history whose first record is not the pinned anchor is
  `untrusted-anchor`; a chain with a revision gap, a broken link, or a
  recomputed-digest mismatch makes every key in it `unverifiable`.
- Rotation retires the previous key without forgetting it. The retired key still
  resolves as `trusted-retired`, so old attestations stay verifiable while the
  policy decision stays with the caller.
- Revocation is retrospective refusal, not retroactive invalidation. `KeyRing`
  stops resolving a revoked key immediately, and `proof_signing` then refuses an
  otherwise valid attestation rather than silently accepting it.

What this does not prove:

- That the writer of the key history is honest, or that a revocation happened at
  a specific wall-clock time. A host able to rewrite the history can also
  rewrite the anchor unless the anchor is pinned out of band.
- Anything about a signature made *before* a revocation. This slice has no
  as-of revision, so a past attestation is refused rather than judged — which is
  the fail-closed direction, not a verified answer.

## Attestation freshness

- A sealed attestation binds its signature domain to a single-use challenge id,
  the attestation digest, and the key id. A seal made against an earlier
  challenge fails on the challenge id, so a replay is refused without comparing
  clocks.
- `ChallengeBook` is the only party that knows which challenges exist: issuing is
  single-use, expiry is measured from the issue time, and a consumed challenge
  cannot be consumed again.
- The verifier must state the challenge it expects. The sealed record carries no
  freshness claim of its own, so its holder cannot assert that it is current.

What this does not prove:

- That the clock is honest, that the verifier stored the challenge it issued, or
  that the challenge reached the intended party. Freshness here is a binding
  property, not a measurement.

## Minimal-disclosure inclusion

- A disclosure carries the root, the leaf count, the index, and the sibling
  path. It does not carry the bundle, so a verifier no longer needs every leaf
  digest to check one event.
- Disclosures are byte-identical to what `make_proof` produces, so the two paths
  cannot drift apart.
- `verify_disclosure` refuses a disclosure whose root contradicts the caller's
  expected root, whose path length contradicts its leaf count, whose siblings are
  malformed, or whose recomputed root does not match the subject.

What this does not prove:

- That `leaf_count` and `index` are true. Neither enters the merkle computation,
  so both are self-reported metadata. The verdict reports them as `unverified`
  instead of implying they were checked.
- That other leaves stay hidden. When a sibling node is itself a leaf, its digest
  is exposed by construction. Padding the tree to a power of two is the fix, and
  this slice does not pad.
- That the root is honest. A disclosure carries its own root, so a verifier that
  does not pin `expected_root` accepts a self-consistent forgery. That case is
  reported as `verified-unpinned`, never as `verified`.

## Portable evidence notarization envelope

- `EvidenceEnvelope` composes a subject event, minimal disclosure, verified proof
  attestation, digest-only key-history records, checkpoint head, signer identity
  declaration, key id, and a signature. Its unsigned payload is canonical JSON,
  so the same bytes are signed and verified.
- The producer runs the existing full evidence verifier before emitting the
  envelope. The offline verifier then checks the signature, embedded key-history
  chain, key state, checkpoint root, attestation roots, and disclosure path. It
  does not re-authorize the signer: `signer` is a claim about identity, not a
  permission grant.
- `HMACSignatureScheme` is intentionally labeled `same-key`. It is a standard
  library compatibility scheme, not third-party independent verification. The
  `SignatureScheme` interface can accept a host-provided public-key scheme, but
  this research line does not ship an asymmetric cryptography dependency.
- A pinned evidence root and pinned key-history anchor are required for
  `verified`. Missing pins produce `verified-unpinned`; they never silently
  become `verified`. The envelope contains no signing secret or raw lineage.

What this does not prove:

- That HMAC evidence was independently verified by a party without the secret.
- That an injected public-key implementation is secure, that the signer is
  authorized, or that the key-history anchor was distributed honestly.
- That the checkpoint head alone proves the entire checkpoint history. The
  portable envelope deliberately carries a head, not the full chain; a producer
  must bind that head to a separately governed history before treating it as
  sufficient audit evidence.

## Persistent verifier-scoped challenge ledger

- `ChallengeLedger` persists `issued` and `consumed` events as a canonical,
  fsynced, hash-chained JSONL log. A new process reconstructs the consumed set,
  so a replay remains refused after restart.
- Every challenge carries a verifier audience. Consuming it under a different
  verifier id fails before appending anything; unknown, expired, and repeated
  challenges fail closed.
- Consumption holds a same-host `flock` across read/check/append. Two local
  processes racing the same challenge produce exactly one successful consume.
- A truncated final line is ignored as an incomplete write. A complete malformed
  line, digest mismatch, chain break, or missing history after the ledger began
  makes the ledger `unverifiable` and blocks mutation.
- `VerifierBoundSeal` is a v2 protocol separate from the existing v1 freshness
  seal. Its domain includes challenge id, verifier id, attestation digest, and
  key id. Existing v1 imports and signing semantics remain unchanged.

What this does not prove:

- That `flock` gives exactly-once semantics across hosts or network filesystems;
  this is a same-host persistence primitive only.
- That a verifier id is an authorization credential. It is an audience binding,
  not an identity proof or permission grant.
- That expiry is true wall-clock time. The clock remains injected and owned by
  the host; clock rollback/failure policy is outside this slice.
- That a consumed record can be safely garbage-collected. Forgetting it would
  reopen the replay window, so compaction requires a separate retention design.

## Release boundary

Do not cherry-pick or publish this candidate automatically. It requires a
separate comparison against the local-only Router, a multi-process rotation
experiment on a real filesystem, a key-anchor distribution decision, a
cross-host identity decision, and an explicit generation release gate.
