# Stale-checkpoint gate: the checkpoint carries the external world, and recovery checks it

*Module:* `components/northstar-agent-runtime/stale_checkpoint_gate.py`
*Tests:* `components/northstar-agent-runtime/tests/test_stale_checkpoint_gate.py`
*Slice:* B173, branch `batch-173-moltbook-absorb`, commit `4041fdf3`

## The gap, read from the code

Northstar's three checkpoint layers each verify the checkpoint **against
itself**. None of them asks what the world looked like when the checkpoint
was written.

* `checkpoint_store.py` — file discipline. `FileCheckpointStorage._write_atomic`
  writes via an `O_CREAT | O_EXCL` temp file, fsyncs it and `os.replace`s it
  into place, so a destination is never seen half-written.
  `_validate_file_path` refuses ids containing `/`, `\`, `\x00`, `.`, `..`, or
  absolute paths, and refuses any id whose *resolved* path leaves the store
  (so a symlink out is refused too). `_decode`/`_decode_value` load only the
  registered checkpoint types. All of this is about **how the bytes are
  stored**.
* `checkpoints.py` — turn-boundary discipline. `Checkpoint` carries
  `transcript_len`, `transcript_digest`, the consumed counters, the
  `graph_signature_hash` and the `previous_checkpoint_id` lineage.
  `prepare_resume` refuses a transcript whose prefix does not hash to the
  recorded digest, a checkpoint taken under a different run graph
  (`run_graph_hash`), and a dangling lineage. Every one of those is
  **internal**: the transcript is compared against the transcript's own
  digest.
* `durable_resume.py` — durable-store discipline. `state_digest` hashes the
  checkpoint's own state; `DurableStore.verify` compares a checkpoint's
  state against that digest; `DurableRunner.resume` refuses a checkpoint that
  does not match its digest.

So the answer to "does a checkpoint recovery verify the external state?" is
**no**, and "where does the recovery happen?" is:

| Layer | Entry point | What it checks |
|---|---|---|
| turn boundary | `checkpoints.prepare_resume` | transcript prefix digest, run-graph hash, lineage |
| durable store | `durable_resume.DurableRunner.resume` → `DurableStore.verify` | the checkpoint's own state digest |

"What happens on drift?" — **nothing detects it.** A checkpoint holds a
belief about the external world ("the schema is v3", "the task table is
empty"). Recovery restores that belief verbatim, and no step in either
recovery path compares it against the live world. The agent continues from
a stale belief *confidently*, because nothing told it the belief was old.

## What this slice adds

A checkpoint carries a **witness** of the external world, and recovery
checks it before proceeding.

* `external_checksum` — a canonical SHA-256 over a snapshot of the external
  state. **Caller-supplied** (the runtime does not know what "the external
  state" is for a given agent; the host does), and **required**.
* `freshness_seq` — a caller-supplied integer sequence number for the
  external world, saying how far it has advanced. **Required**, with no
  default.
* `created_seq` — the sequence number of the write that created the
  checkpoint. Recorded separately: a checkpoint may be *about* a world at
  sequence `n` while being *written* at sequence `m`, and those are not the
  same fact.

`StaleCheckpointGate.verify(checkpoint, live_checksum, live_seq)` returns a
`GateVerdict` with one of three explicit statuses:

| Status | Condition | Recovery |
|---|---|---|
| `PASS` | live checksum == recorded checksum **and** live seq == recorded seq | proceeds |
| `FLAGGED` | live seq > recorded seq (the world advanced) | proceeds, but the caller must declare that the world has moved; the verdict carries the number of sequence steps |
| `REJECTED` | live checksum != recorded checksum (the world contradicts the checkpoint), **or** live seq < recorded seq (the world went backwards) | does not proceed |

A boolean cannot distinguish "recover, but the world moved" from "do not
recover", so the verdict is never a boolean.

### Fail-closed creation

`StaleCheckpointGate.create` refuses to create a checkpoint that cannot say
what the world looked like: no checksum, a malformed checksum, no
freshness sequence, a negative or non-integer freshness sequence, or both a
state and a checksum at once. Such a checkpoint never reaches the recovery
gate unverified, because it never exists.

### Canonical checksums

`checksum_of_state` (alias `external_checksum`) hashes the canonical JSON
of the state: sorted keys, compact separators (`","` / `":"`), UTF-8 — the
same canonical shape as `tool_pinning.hash_definition`. The same external
state spelled two ways therefore hashes the same.

Unlike the pinning helper, this one **refuses** what it cannot describe.
There is no `default=str` fallback and `allow_nan=False`:

* `NaN` / `inf` → `UncanonicalizableStateError` (no JSON spelling exists);
* non-string dict keys → `UncanonicalizableStateError` (`json.dumps` would
  coerce `{1: "a"}` to `{"1": "a"}`, so two different states could share a
  checksum);
* arbitrary objects → `UncanonicalizableStateError` (not hashed as their
  `repr`).

The checksum format is fixed: `sha256:` + 64 lowercase hex digits.

### The dirty-recovery drill (Northstar extension)

`dirty_recovery_drill(gate, initial_state, writes, ...)` is a **test helper**,
not a production path. It takes a checkpoint against `initial_state`, applies
the `writes` one at a time (each advancing the world's sequence), and then
attempts the recovery against the world as it stands afterwards.

`ExternalWorld` carries a `witness_keys` slice: the part of the world the
checkpoint vouches for. That lets the drill separate the two kinds of drift:

* a write that touches a **witnessed** key makes the checkpoint's belief
  false → `REJECTED`, the recovery does not proceed;
* a write that touches **only unwitnessed** keys leaves the belief standing
  but moves the world → `FLAGGED`, the recovery proceeds only with the
  movement declared.

Either way the drill never yields a bare `PASS`, which is the failure the
drill exists to make impossible. The control case (no writes) does pass —
that is what makes the dirty cases meaningful rather than vacuous.

## Mapping to the source

Values attributed to the source are quoted verbatim; Northstar extensions
are marked as such.

### Verbatim from the source

* "A checkpoint is a witness statement, not a video recording" — the source's
  core claim (SparkLabScout, "Stale checkpoints produce confident errors",
  https://www.moltbook.com/post/07749448-7c33-4e8b-9eb4-2c81a3821190 ,
  **12 up / 2 comments**). Recovery inherits the agent's beliefs as they
  were; the post's example is the **old schema from step 14** — an
  *illustration*, not a measurement.
* The checkpoint carries a **checksum and a freshness stamp of the external
  state**; on recovery the live state is checked against the checksum first,
  and drift is **refused or flagged** ("Your agent's checkpoint is not a
  memory. It is a witness statement.",
  https://www.moltbook.com/post/8d065239-e710-40d0-a713-2cb0dbacfdaa ,
  **7 up / 2 comments**). A checksum that is not checked is a decoration.
* Test the **dirty** recovery — revert from a point that has *later writes*
  and *real drift* — not only the clean immediate rollback (lightningzero,
  "I tested recovery instead of rollback",
  https://www.moltbook.com/post/7c232215-aa2a-471d-ac9c-811303fdbe29 ,
  **20 up / 14 comments**). Rank: 5.

The three up/comment counts are the post heat as seen on the 2026-11-14
00:48 sweep. The "step 14" schema is the post's example, not a measurement.

### Northstar extension (this module, not the source)

* Fail-closed creation: no checksum and no freshness sequence means no
  checkpoint.
* Canonical, refusal-on-ambiguity checksums (the source says "checksum"; it
  does not specify a canonicalisation, and the refusal behaviour for
  NaN/inf, non-string keys and arbitrary objects is this slice's choice).
* An explicit three-state verdict rather than a boolean.
* The `witness_keys` slice of the external world, which is what makes
  "the world moved" (flag) and "the world contradicts me" (reject)
  distinguishable rather than collapsing into "the checksum differs".
* The drill lives in the module as an importable test helper.

## Honest scope

* The checksum and the sequence number are **caller-supplied**. This module
  does not measure or observe the external world; it applies a recorded
  witness to an observed one and reports the difference. A caller that
  lies about either gets a useless gate.
* The gate is pure and in-memory. It holds no checkpoints and persists
  nothing; the caller owns storage.
* It is a **library**: no existing runtime module is modified to call it. A
  host adopts it by running `gate.verify(...)` before a recovery proceeds.
  `checkpoints.py`, `checkpoint_store.py`, `sessions.py` and
  `durable_resume.py` are untouched by this slice.
* The drill is a test helper. It does not run in production.
* **The module is not declared in `pyproject.toml`.** The runtime
  component's `test_module_layout.test_every_module_is_installed` asserts
  that every module on disk appears in `[tool.setuptools] py-modules`. That
  test already fails at this slice's parent commit — with `annotation_pin`,
  `artifact_authority`, `cancellation_tombstone`, `coverage_manifest`,
  `endpoint_identity`, `evidence_independence`, `key_custody`,
  `ledger_concurrency`, `retry_config`, `state_budget` and
  `strands_checkpoint` undeclared — and `stale_checkpoint_gate` joins the
  same list, so **no new test failure appears**. The declaration is still
  owed; this slice's writable-file set covers only the module, its tests and
  this design doc, so it is left to the slice that owns the packaging
  metadata.

## Verification

* Focused suite: `tests/test_stale_checkpoint_gate.py` — 44 new test methods,
  all passing.
* Full runtime suite: **19 690 tests, 27 failures** (17 `FAIL` + 10
  `ERROR`) — **identical item-for-item to the baseline** at the parent
  commit, no new failure.
* Governance bench: **161/169 passed, 8 failed** — identical to the baseline.
  Output saved to `/home/muse-newapi/b173-stale-checkpoint-gate-bench-final.txt`.
