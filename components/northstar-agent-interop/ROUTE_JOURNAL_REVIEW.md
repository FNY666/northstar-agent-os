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

## Padded Merkle v2 and non-inclusion

- v1 remains unchanged. v2 uses `northstar.evidence-bundle.v2`, sorts unique
  real event leaf digests, and pads the leaf layer to the next power of two with
  a domain-separated constant pad digest. A pad digest can never be a real leaf.
- v2 inclusion paths therefore do not expose a real sibling merely because the
  tree has an odd number of leaves. Real inclusion indices are separate from
  padding positions, and a proof cannot request a pad position as an event.
- v2 absence proofs are relative to the committed sorted set. A target outside
  the first/last leaf uses one boundary neighbor; a target between leaves uses
  two adjacent real-leaf inclusion paths plus strict predecessor < target <
  successor ordering.
- Duplicate real leaves are rejected. This avoids pretending that a set absence
  proof is sound for an unaddressed multiset duplicate policy.
- Both inclusion and absence require a pinned expected root for `verified`.
  Without it they return `verified-unpinned`, never `verified`.

What this does not prove:

- That the target event never existed outside the committed set. Non-inclusion
  means only that the target digest is absent from this particular committed,
  sorted set.
- That `index`/`padded_count` are independently witnessed by the root; they are
  still metadata carried by the proof and reported as unverified.
- That the root is honest or that v2 is compatible with a v1 consumer. v1's
  strict schema rejects v2, by design; migration requires an explicit consumer.

## Cross-layer composition gate

- The composed verifier now invokes `verify_cross_layer` after the independent
  chain, lineage-bundle, Merkle, and checkpoint-root checks. It compares route
  identity, terminal lineage identity, bundle lineage binding, and handoff
  identity/deadline/payload/decision fields before returning `verified`.
- A failed lower layer remains `failed`; a cross-layer mismatch is `unknown`.
  The gate is evidence consistency only and does not authorize a signer or
  backend.
- Regression coverage fixes two previously accepted false positives: a
  terminal payload digest changed away from the route/handoff, and a terminal
  lineage event changed to another route id. Both now fail closed.

What this does not prove:

- That the cross-layer values are truthful. It proves only that the supplied
  artifacts agree with one another.
- That a signer, handoff, or backend is authorized. Authorization remains in
  the host and grant layers.

## Verifier receipts

- `VerificationReceipt` binds a verifier's signed observation to the exact
  envelope digest, one consumed persistent challenge, verifier audience,
  evidence root, claimed evidence state, and explicit unverified fields.
- Issuance verifies the envelope first, preflights the challenge without
  consuming it, signs the receipt, and consumes only after a valid signature
  exists. Restart and duplicate issuance cannot reuse a consumed challenge; a
  signing failure or challenge-key mismatch leaves the challenge available for
  retry.
- Offline verification returns `receipt-verified`, not `verified`. It checks the
  receipt statement and bindings but deliberately does not rerun evidence
  verification, so `receipt-only` remains visible.
- Missing expected root is reported as `root-unpinned`; same-key HMAC is reported
  as `same-key`. Neither is silently upgraded to independent trusted evidence.
- Verifier identity is an audience declaration, not an authorization grant, and
  a receipt is not permission to execute an action.

What this does not prove:

- That the verifier ran the evidence verifier honestly; this layer checks the
  signed receipt binding, not the verifier's internal execution.
- That the evidence is true, the signer or verifier is authorized, or an HMAC
  receipt can be independently checked without the shared secret.
- That a challenge reached the intended verifier or that the injected clock is
  trustworthy. Those remain host and transport responsibilities.

## Key-history snapshots and as-of verdicts

- `KeyHistorySnapshot` pins an exact prefix by revision, the first-record anchor,
  and the prefix head digest. Verification recomputes only that prefix and
  refuses a future, missing, corrupted, or head-mismatched snapshot.
- `verdict_at` derives `trusted`, `trusted-retired`, `revoked`, or `unknown-key`
  from the verified prefix rather than the current suffix. A later revocation
  therefore does not rewrite an earlier snapshot's state.
- A suffix corrupted after the pinned prefix does not invalidate the prefix;
  this is intentional prefix semantics, not evidence that the suffix is valid.
- An unpinned history returns `verified-unpinned` with `anchor_unpinned`; it is
  never silently promoted to trusted evidence. The revision is ordering metadata,
  not a timestamp and not proof of when a signature was made.
- Snapshots contain only digests and revision metadata. They never carry key
  material or claim that revocation was authorized.

What this does not prove:

- That a revision corresponds to wall-clock time, that the host's ordering is
  honest, or that a signature was produced before/after a revocation without an
  explicit caller-supplied historical binding.
- That a pinned anchor was distributed honestly. Anchor possession is a trust
  input, not a proof of key ownership or authorization.
- That a valid historical verdict can override a current revocation policy. It
  answers an as-of evidence question; the caller still decides whether old
  evidence is acceptable for the current action.

## Checkpoint-chain witnesses

- `CheckpointChainWitness` carries the complete ordered checkpoint list, the
  explicit checkpoint count, the head root, and a domain-separated canonical
  chain digest. Verification recomputes every checkpoint digest and continuity
  edge instead of trusting a portable head alone.
- A result is `verified` only when both the expected head root and expected chain
  digest are pinned out of band. Either missing pin returns
  `verified-unpinned`; a self-carried digest is integrity metadata, not a trust
  anchor.
- A valid historical prefix remains verifiable with its own pins and reports its
  `checkpoint_count` and `head_root`. This is prefix scope, not a claim that the
  prefix is the latest history.
- The witness contains no raw event, prompt, secret, or provider output.

What this does not prove:

- That the carried sequence is the latest checkpoint history. A shorter prefix
  with a recomputed self-carried digest is internally valid; only external pins
  detect rollback.
- That checkpoint roots represent truthful events or authorized actions. The
  witness proves the integrity and ordering of the records it carries.
- That the external pin was distributed honestly or retained durably.

## Portable evidence packages

- `EvidencePackage` canonically binds an envelope, complete checkpoint-chain
  witness, key-history snapshot, and optional verifier receipt. The package
  digest detects transport/component substitution, but becomes a trust anchor
  only when a verifier pins it externally.
- Construction checks that the envelope disclosure root, envelope checkpoint
  head, and witness head root agree; that the key snapshot binds the envelope's
  embedded key-history prefix; and that an optional receipt binds the exact
  envelope digest and evidence root.
- Verification re-runs envelope and witness verification, validates the key
  snapshot prefix, and optionally verifies the verifier receipt. All required
  external pins — package digest, checkpoint chain digest, evidence root, and
  key anchor — remain visible as `verified-unpinned` when absent.
- A verifier receipt remains `receipt-only` in the package result. It records a
  signed observation; it does not become evidence truth or authorization.

What this does not prove:

- That the package is the latest or complete world state. A package can carry a
  valid historical prefix; external pins, retention, and freshness policy are
  required to detect rollback or staleness.
- That the envelope subject, checkpoint facts, signer, or verifier is truthful
  or authorized. This composition proves bindings and verifier behavior only.
- That same-key HMAC gives an independent third-party result. The package keeps
  `same-key` explicit rather than elevating it to an external trust claim.

## Evidence admission and conflict preservation

- `EvidenceAdmissionPolicy` names which external pins are required, whether a
  verifier receipt is mandatory, which unresolved boundaries are forbidden, and
  whether an explicitly unpinned package is acceptable for a particular evidence
  use. It evaluates evidence only; it never grants action authorization.
- `admit_package` reuses package verification and returns `admissible`,
  `insufficient`, or `unverifiable`. Missing external root/package/chain/key
  pins remain explicit policy failures rather than being inferred from a
  self-carried digest.
- Claim identity is a canonical digest of route id, target agent, provider,
  payload digest, decision fingerprint, and event digest. It contains no raw
  prompt or output.
- `compare_admissions` preserves conflict: same claim with different evidence
  roots or claimed evidence states becomes `conflicting`; different claims are
  `incomparable`; no function chooses a winner.

What this does not prove:

- That an admissible package is true or authorizes any action. Admission is
  policy compliance for evidence, not a factual or permission decision.
- That a conflict identifies which package is false. It preserves conflicting
  package digests and reasons for a higher-level resolver or human.
- That policy defaults are universally safe. Required pins, receipt mandates,
  and allowed unresolved boundaries remain explicit caller policy choices.

## Policy-bound admission witnesses

- `AdmissionWitness` binds the complete canonical policy body and its digest to
  an exact package digest, claim digest, evidence root, admission state, reasons,
  and unresolved fields. A policy id alone is never treated as a policy
  commitment.
- Verification replays admission under the embedded policy and caller-supplied
  trust pins, then compares every replayed result field. Policy/package/claim/
  state/reason/unverified substitution fails closed rather than being silently
  normalized.
- Fully pinned witnesses return `witness-verified`; missing witness or policy
  digest pins return `witness-verified-unpinned`. Evidence-level boundaries such
  as `same-key`, `index`, and `leaf_count` remain visible even with all witness
  anchors supplied.
- Insufficient policy outcomes can be witnessed for audit. Unverifiable package
  outcomes are not turned into trustworthy witness artifacts.

What this does not prove:

- That an admissible outcome authorizes an action, that evidence is true, or
  that a policy's default requirements are safe for every use case.
- That a conflict between witness results identifies a false package. Conflict
  remains preserved for a higher-level resolver or human.
- That an external policy/witness digest was distributed honestly or is current.

## Evidence conflict ledger

- `EvidenceConflictLedger` persists same-claim admission witness conflicts as
  fsynced, hash-chained observations. A record contains only canonical witness,
  package, claim, root, state, and reason digests; it carries no raw event,
  prompt, secret, or provider output.
- The two witness digests are sorted solely for idempotency. Reversing input
  order returns the same observation and does not designate a winner or loser.
- Same evidence and different claims are rejected as non-conflicts. Same claim
  with a different evidence root or claimed state is preserved as
  `evidence_root_mismatch` or `claimed_evidence_state_mismatch`.
- Restart recovery, truncated-tail tolerance, complete-corruption detection, and
  same-host concurrent idempotency are verified. Metadata initialization uses a
  unique temporary file so concurrent first-open does not race on one `.tmp`
  name.

What this does not prove:

- Which conflicting witness is true, more trustworthy, authorized, or should be
  used for an action. The ledger preserves evidence for a higher-level resolver
  or human.
- Cross-host exactly-once recording. `flock` protects one host/filesystem only.
- That a conflict is exhaustive; it records only witnesses supplied to this
  ledger instance.

## Evidence state projection

- `EvidenceStateProjection` reduces admission witnesses and conflict observations
  into one deterministic claim state: `supported`, `conflicted`, `insufficient`,
  `unverifiable`, or `unknown`.
- Same-claim conflict observations dominate otherwise supported witness evidence.
  The projection preserves every conflict id, witness digest, package digest,
  and reason; it never chooses a winning witness.
- A fully pinned admissible witness projects to `supported`. Insufficient policy
  outcomes remain `insufficient`; unresolved external pins project to
  `unverifiable`; no witness projects to `unknown`.
- `actionable=True` appears only for `supported` as an evidence-readiness hint.
  It is explicitly not an authorization grant, and a host still owns the action
  decision.

What this does not prove:

- That the projected state is factual truth, exhaustive world state, or a
  resolution of a conflict. It is a conservative reduction of supplied evidence.
- That `actionable` allows execution. Authorization, capability policy, and
  postcondition checks remain outside this module.
- That all relevant witnesses were supplied to the projection; omitted evidence
  can still change a future state.

## Evidence readiness gates

- `EvidenceReadinessGate` evaluates a plan's declared claim requirements against
  projected evidence state and returns `ready`, `blocked`, or `unknown`.
  `conflicted`, `insufficient`, and `unverifiable` claims block; missing or
  unknown claims remain unknown rather than being assumed false or supported.
- Every gate binds canonical plan id, requirement list, observed projection wire
  forms, decision, blockers, unknown claims, reasons, and a gate digest. Replay
  rejects plan, requirement, projection, state, or digest substitution.
- `execution_authorized` is always false, including for `ready`. Ready is an
  evidence-readiness hint only; the host still owns policy, capability, approval,
  sandbox, and postcondition authorization.
- Projection provenance stays attached through the gate, so a blocked decision
  can expose its claim/package/witness/conflict reasons without serializing raw
  prompt, event, secret, or provider output.

What this does not prove:

- That a ready plan is safe, true, complete, or permitted to run. It says only
  that its declared evidence prerequisites were projected supported.
- That the requirement set is exhaustive. Missing requirements can lead to a
  ready gate that a higher-level planner should still reject.
- That a conflict has been resolved. Conflicted evidence remains blocked and no
  witness winner is selected.

## Evidence state witnesses

- `EvidenceStateWitness` binds canonical admission witness and conflict
  observation source wires to one replayed `ClaimProjection`. It detects
  substituted source, ordering, projection, claim, or state fields through a
  domain-separated state digest.
- A state witness cannot be created for source-free `unknown`: absence of
  supplied evidence is not transformed into an attested fact. Sources must be
  same-claim and canonical; conflict witnesses remain non-resolving.
- Reverification reparses all sources and reruns the projection. A pinned state
  digest returns `state-witness-verified`; absence of that external pin remains
  `state-witness-verified-unpinned` while preserving all source-level unresolved
  boundaries.
- State witnesses are deterministic provenance receipts. They do not assert
  truth, authorization, or that every relevant witness was supplied.

What this does not prove:

- That a projected state is factual world truth, complete evidence coverage, or
  an authorization to execute a plan.
- That a conflicted state can be resolved by ordering witness digests. Canonical
  order is serialization-only and never a winner selection.
- That an external state digest is current or honestly distributed.

## Plan evidence decisions

- `EvidencePlanManifest` binds only canonical step identifiers, evidence claim
  digests, and bounded rationales. It excludes executable actions, commands,
  prompts, raw output, and secrets.
- `PlanEvidenceDecision` binds the exact manifest, replayed readiness gate,
  readiness state, blocked/unknown claims, and a decision digest. Verification
  reparses the manifest and replays the gate under supplied projections.
- The decision states are `ready`, `blocked`, and `unknown`. Even `ready` has
  `execution_authorized=False`: it only means the manifest's declared evidence
  prerequisites were projected supported.
- External decision, manifest, and gate digest pins distinguish
  `decision-verified` from `decision-verified-unpinned`; projection-level
  unresolved boundaries remain visible in either result.

What this does not prove:

- That a ready plan is safe, complete, factually true, or permitted to execute.
  Host policy, capabilities, approval, sandboxing, and postconditions still own
  every execution decision.
- That the manifest enumerates every evidence claim a real plan needs. Omitted
  requirements can make a narrow manifest look ready.
- That a decision digest or manifest digest was distributed honestly or is
  current.

## Evidence dependency graphs

- `EvidenceDependencyGraph` makes claim-to-claim evidence prerequisites explicit
  and rejects duplicate nodes/edges, self-dependencies, undeclared dependencies,
  and cycles. Canonical graph ordering is only deterministic serialization.
- Direct `conflicted`, `insufficient`, and `unverifiable` states dominate every
  dependent result; blocked dependencies propagate `blocked`; unknown or missing
  direct evidence propagates `unknown` with the originating reason retained.
- `DependencyGraphWitness` binds canonical graph structure, direct projections,
  all derived projections, and a domain-separated witness digest. Replay rejects
  graph, projection, ordering, state, or digest substitution.
- Every derived projection and graph witness has `actionable=False`. The graph
  expresses evidence dependencies only; authorization remains with the host.

What this does not prove:

- That a declared dependency graph is complete, truthful, or an execution DAG.
  It is an evidence prerequisite graph, not a task scheduler.
- That a supported dependency authorizes a dependent claim or action. It only
  removes one evidence blocker from the reduced state.
- Cross-host graph witness consistency or an exhaustive set of observed claims.

## Evidence resolution agendas

- `EvidenceResolutionAgenda` converts non-ready plan evidence decisions into
  deterministic, non-executing suggestions: `escalate-conflict` for conflicts,
  `reacquire-evidence` for insufficient or unverifiable claims, and
  `collect-evidence` for missing or unknown claims.
- Items are canonically ordered by disposition severity then claim digest only
  for reproducible serialization. `escalate-conflict` preserves disagreement;
  it never chooses a witness winner or asserts which evidence is true.
- Agenda replay binds the exact plan evidence decision, every item disposition,
  evidence state, reason, unresolved boundary, and agenda digest. External
  decision and agenda digest pins distinguish `agenda-verified` from
  `agenda-verified-unpinned`.
- `execution_authorized` is always false for the agenda and every item. An
  agenda is decision support for evidence completion, not a command queue.

What this does not prove:

- That collecting evidence will resolve a conflict, or that a re-acquired item
  will become sufficient. The agenda names a gap; it does not predict outcomes.
- That a human escalation selects a correct witness or grants permission to act.
- That its item set is exhaustive beyond the plan manifest and currently
  supplied projections.

## Evidence readiness leases

- `EvidenceReadinessLease` binds an exact fully pinned `ready` plan evidence
  decision to injected issue/expiry values, decision/manifest/gate digests, and
  a domain-separated lease digest. It detects source drift before a prior ready
  conclusion is reused as current evidence.
- A lease can be issued only after the source decision replays as fully pinned
  `ready`. Blocked, unknown, and unpinned decision evidence cannot issue a
  lease; lease verification reruns that source decision and rejects changed
  plan, manifest, gate, projection, or digest bindings.
- A valid externally pinned active lease returns `lease-valid`; a missing
  external lease pin returns `lease-valid-unpinned`; expiry returns
  `lease-expired` regardless of its digest pins.
- `execution_authorized` is false for every lease state. A lease is freshness
  metadata for evidence, not permission to run a plan.

What this does not prove:

- That injected time is wall-clock truth, monotonic across hosts, or honestly
  supplied. Time remains caller policy input, not a cryptographic timestamp.
- That a valid lease makes a plan safe, complete, factual, or authorized.
  Capability/approval/sandbox/postcondition policy remains external.
- That every plan evidence requirement was declared; an incomplete manifest can
  still receive a valid lease for its narrower set of claims.

## Evidence-readiness lease registry

- `EvidenceReadinessLeaseRegistry` persists `registered` and `revoked` lease
  events as a canonical, fsynced, hash-chained JSONL log. Registration is
  idempotent for identical lease metadata; conflicting metadata is rejected.
- Revocation is monotonic and survives restart. An active lease becomes
  `revoked` rather than becoming valid again through replay or re-registration;
  expiry remains a separate `expired` state.
- Inspection returns `active`, `expired`, `revoked`, `unknown`, or
  `unverifiable`, and all states carry `execution_authorized=False`.
- Same-host `flock` covers first-open initialization and register/revoke
  read-check-append. Unique metadata temporary files prevent concurrent first
  initialization from racing on one path.
- The registry stores lease/digest metadata only; no prompt, action, event body,
  secret, or provider output is persisted.

What this does not prove:

- That the lease was originally issued from truthful evidence, or that an active
  registry lease authorizes execution. Freshness/revocation state is not
  permission.
- Cross-host revocation propagation or exactly-once semantics. Local `flock`
  cannot coordinate independent hosts/filesystems.
- That deletion of the registry is safe. Once history is missing after first
  registration, the registry fails closed rather than treating the lease as
  unknown-but-active.

## Readiness lease registry witnesses

- `LeaseRegistryWitness` binds a lease digest to the observed registry state,
  record sequence, registry head digest, and injected observation time. It lets a
  caller detect post-observation append/revoke/history drift before reusing a
  lease freshness conclusion.
- A registry append after the snapshot returns `stale`; a revoke returns
  `revoked` (revocation takes precedence over ordinary head drift); an expired
  or unknown observation remains explicit. Missing/tampered history is
  `unverifiable`.
- Missing external witness pin returns `current-unpinned`; `execution_authorized`
  remains false in every state.

What this does not prove:

- That the lease was originally issued from truthful evidence, that the clock is
  trusted, or that a current registry state grants permission to execute.
- Cross-host registry consistency or revocation propagation. This witness is
  bounded by the registry's same-host persistence and locking model.
- That an observation is latest without a retained external witness digest.

## Release boundary

Do not cherry-pick or publish this candidate automatically. It requires a
separate comparison against the local-only Router, a multi-process rotation
experiment on a real filesystem, a key-anchor distribution decision, a
cross-host identity decision, and an explicit generation release gate.
