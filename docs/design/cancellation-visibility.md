# A cancellation must be legible wherever a transcript is read

## The rule

> **A cancellation, on every path that reads a transcript, says what
> was revoked, on what, and who declared it -- never a wall of hashes.**
> **And it says whether the stop is still standing.**

> **A cancellation is `error` level in the audit feed**, because it is a
> withheld authorization, exactly as a denial is.

> **A lifted cancellation says it was lifted.**  A reader cannot
> otherwise tell a standing stop from a lifted one.

## What a cancellation is

Commit `695a25b7` (B173 tombstone) added the `cancellation` record
type to the runtime's `RECORD_TYPES` in
`components/northstar-agent-runtime/sessions.py`.  A principal revoking
an action ("stop, do not publish") writes one of these records: it is
structure beside the conversation, not prose inside it, so a compaction
cannot prune it.

`SessionStore.record_cancellation(tombstone)` writes:

```
{"tombstone": {grant_id, action, subject, declarer, declarer_channel,
                declared_at, kind, expires_at, measurement, reason},
 "digest": "sha256:...", "kind": "permission"}
```

and `SessionStore.record_cancellation_lift(tombstone, lift)` writes the
same plus a `lift` block naming who lifted it, on which channel, and
the instruction that authorized the lift.

## What was wrong

The record is written correctly.  Every path that **reads** a
transcript fell through to a generic fallback that rendered the
record's own JSON -- and because JSON sorts its keys alphabetically,
the visible prefix was `chain`, `chain_hash`, `digest`, `genesis`,
`hlc`.  The action, the subject, the declarer and the reason fell
outside the preview entirely.

Measured on a record written by the runtime's own `SessionStore`, the
replay frame's label was:

```
cancellation: {"chain": "northstar-audit-chain/2", "chain_hash": "d7620650ffc16035d945482bb0485e0125...
```

and it contained:

| the reader needs to see | in the label? |
| --- | --- |
| `publish` (the action) | **no** |
| `the release` (the subject) | **no** |
| `user` (the declarer) | **no** |
| `stop, do not publish` (the reason) | **no** |
| `tombstone` | **no** |
| `g1` (the grant) | **no** |

Three read paths were affected:

| path | what it did | what it should do |
| --- | --- | --- |
| `audit_export.record_to_audit` | `_ERROR_TYPES = {"denial"}`, so a cancellation was `level: "info"` -- the same level as an ordinary assistant turn | `level: "error"`: a revocation is a withheld authorization, the same category as a denial |
| `session_replay.build_replay` | no case for `cancellation`, so it fell through to the generic `kind="note"` branch and rendered a truncated JSON blob | its own frame kind, with the shared description as the label |
| `session_view._record_text` | same generic fallback, same truncated JSON blob | the same shared description |

And in `session_replay`, the count of denials was the count of
withheld authorizations -- but a *revocation* the principal declared
was not counted at all, so a reader asking "was anything stopped?" got
a number that did not include the stops.

## The drift class this belongs to

The previous slice, `panel-record-vocabulary`, found the same class in
`examples/session-panel/session-panel.html`: a hand-maintained mirror
of the runtime's record vocabulary that had fallen behind the runtime
(`cancellation` was missing, and `isErrorRecord` returned a truthy
*string* for a checkpoint and a postconditions record, so the
errors-only filter listed a resumable boundary among the errors).

This slice is the runtime-side half of that class.  The rule is the
same -- **what the runtime writes, every read path must show** -- and
the fix is the same in kind: one authoritative rendering, shared, with a
guard that compares the two.

## How the guard measures

The guard asks the **runtime** to write the records -- its own
`SessionStore`, its own `Tombstone`, its own `record_cancellation_lift`
-- and then measures what the three read paths DO with them.

That matters because the record shapes are exactly what a hand-written
sample list gets wrong.  During this slice, the shapes were read out
of the runtime rather than guessed: the tombstone is a **nested**
`"tombstone"` key (not top-level), the lift is a nested `"lift"` key,
and the record carries a chain envelope (`chain`, `chain_hash`,
`genesis`, `prev_hash`) around the payload.

## The fix

### One rendering

`components/northstar-agent-runtime/cancellation_view.py` owns
`describe_cancellation(record)`.  It names the action, the subject,
the grant, the kind, the declarer and the channel, the reason, and --
in capitals, because it is the part a reader must not miss -- whether
the stop is **STANDING** or **LIFTED**.

The rendering is deliberately **defensive**.  A record that does not
carry a usable tombstone still produces a readable line with `?` for
whatever is missing; a field that is present but not a string is shown
as `str(value)`, because a surprising value in a revocation is worth
seeing rather than hiding.  A reader must never be shown a traceback
instead of a revocation, and must never be shown nothing at all.

### Three read paths

* `audit_export.py`: `_ERROR_TYPES` gains `"cancellation"`.
* `session_replay.py`: a `cancellation` frame kind, labelled with the
  shared description; `Replay.counts` gains `"cancellations"`, counted
  separately from `"denials"`; `Replay.summary()` mentions it.
* `session_view.py`: `_record_text` renders the same description on the
  `sessions show` path.

## The honest ceiling

* The `session_ui.py` offline HTML replay page renders the record with
  its own `recordText`, which still shows the chain hashes and the
  digest rather than the action.  It is a **separate JavaScript
  implementation** of the same idea, and this slice does not reach
  into it: the shared rendering is Python, and the page is generated
  from Python but its script is not.  The offline HTML *panel* in
  `examples/session-panel/` was fixed by the previous slice; the
  runtime's own generated page is still open.
* The rendering says what was revoked; it does not decide whether the
  revocation is currently *enforced*.  The enforcement point is the
  sealed ledger's CAS (`forward_seal_ledger`), not this reader.
* The description shows the reason as the principal's own words, but
  the reason is never matched on -- the tombstone's identity is the
  `(grant_id, action, subject)` triple.

## What did not change

* No record type was added or removed.
* `sessions.py` is untouched: the runtime wrote the record correctly
  before this slice and writes it correctly now.
* The `cancellation_tombstone` semantics are untouched.
* No version change, no tag, no release, no push, no merge.
