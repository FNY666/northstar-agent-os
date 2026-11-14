# Refusal hold: a refusal row blocks the re-dispatch of the same action

Status: implemented (`components/northstar-agent-runtime/refusal_hold.py`).
Version pin: `refusal-hold.v1`. Schema pin: `northstar.refusal-hold.v1`.

## 1. The problem this slice solves

Northstar has two complete "refusal" concepts. Neither sits on the
re-dispatch path.

| concept | what it is | where it lives |
| --- | --- | --- |
| **refusal row** | an auditable "no": verdict, evidence hash, ruleset hash, verifier key, population digest, "two instruments or none" | `refusal_row.py` |
| **denial row** | per-scope `denied` / signed `clear`; no row means `outcome_unknown`, never a clean read | `scope_qualifier.py` (`DenialRow`, `DenialRowStore`) |

The two paths that actually **send the action again** know nothing about
either:

* `JobQueue.retry()` puts a reserved job back into `ready`
  (`components/northstar-agent-runtime/job_queue.py`, the `retry` method:
  `entry["state"] = _STATE_READY`);
* `LeasedTaskClaim.fail()` puts a leased task back into `ready`
  (`components/northstar-agent-runtime/leased_task_claim.py`, the `fail`
  method: `STATE_DEAD if dead else STATE_READY`).

The consequence is concrete: a refusal is faithfully recorded as a row
(perfect on the ledger), then the same job is re-dispatched, fails again,
and another row is recorded. Refusals pile up on the books while behavior
does not change at all. This is *recorded but not enforced*, which is worse
than *not recorded*: the ledger creates the illusion that the refusal was
handled.

The repository already owns the correct shape for "sticky blocking":
`cancellation_tombstone.TombstoneSet.blocked()` is a **query function**
answering "is this action blocked right now", and a permission-class
tombstone never expires by the clock. This slice builds the same shape for
refusal rows -- but the hold's input is refusal rows (queryable by scope /
action / verdict), not tombstones.

### Source

**Source (hermesagentj, "The most useful thing I built this month is a
check that refuses to run", Moltbook post
`abe9e16f-21a4-4d38-a2b1-03fd84c3543c`).**  The source names the refusal
row itself ("verdict, evidence hash, ruleset hash, verifier key; 'two
instruments or none'; the missing population digest field"). It does **not**
name a hold, a key, a re-dispatch gate, an expiry, or a fail-closed
taxonomy for a broken gate.

**The Moltbook conclusion this slice implements** ("a refusal row does not
block re-dispatch") was *not* found as a file: neither
`/home/muse-newapi/` nor the repository contains the discussion file
(`moltbook-discussions.md`). The evidence for this slice is therefore
**repository code**, and the repository code is cited by line number
throughout this document. Nothing in this design is attributed to the
source that the source does not say.

**Northstar extensions** (not in the source): the key shape, the hold
object and its query API, the fail-closed taxonomy, the expiry fork, the
row-reference carry, and the decision on what a single-instrument refusal
blocks. Each is marked where it appears below.

## 2. The key: what does one refusal block?

A hold key answers exactly one question: **is this re-dispatch the same
thing the refusal was about?** It is a frozen, normalized triple:

```
(scope_kind, scope_id, action)
```

* `scope_kind` -- `"queue"` or `"task"`. The two granularities the brief
  names: "queue q / job j / action a" and "task t / action a".
* `scope_id` -- the job id (for `queue`) or the task id (for `task`).
* `action` -- what the action is (a slug: `checkout`, `send_email`, ...).

Two keys are the *same action* exactly when all three fields are equal.
A key therefore carries enough information that a reader can tell, from
the key alone, whether a given re-dispatch is the same thing: the same
queue-scope kind, the same job, the same action.

The key is a **string**, not a tuple, so it can be stored, logged and
compared without a custom encoder. Its canonical form is
`"<scope_kind>:<scope_id>:<action>"`, and `RefusalHoldKey.identity`
returns exactly that string. A scope id or an action containing `":"`
would make the string ambiguous, so both are validated on the way in
(`RefusalHoldKeyError`).

**Why not a broader key?** A key like "queue q / action a" (dropping the
job id) would block *every* job in the queue after one job is refused --
that is a different policy (a queue-level quarantine), and it is not what
a refusal row about one action says. A key with no scope id at all would
block unrelated work. Northstar's rule is that a refusal blocks **the
action it names, in the scope it names**; widening is a different
mechanism (`cancellation_tombstone`'s subject-scoped cover) and is out of
scope for this slice.

## 3. The hold: rows in, a query out

`RefusalHold` holds **refusal rows**, and answers one question:

> Given an action key, is it blocked by a refusal, and if so, by **which
> row**?

```python
hold = RefusalHold(rows=[row_a, row_b])
result = hold.check(RefusalHoldKey("queue", "job-1", "checkout"), now=1_700_000_100)
```

`check()` returns a `RefusalHoldResult`, which is never a bare boolean:

| field | meaning |
| --- | --- |
| `blocked` | True when the re-dispatch must not proceed |
| `reason` | a stable slug: `blocked_by_refusal`, `blocked_store_unreadable`, `blocked_row_tampered`, `blocked_key_invalid`, `allowed_no_refusal` |
| `row` | the blocking `RefusalRow` itself, or `None` |
| `row_digest` | the `sha256:` digest of the blocking row, or `None` |

The **row reference** is the point. A refusal that blocks a dispatch must
be *auditable by the blocked caller*: the caller gets the row, not just a
"no". That is the difference between a hold and a boolean flag.

### Rows are not copied

The hold stores the refusal rows **by reference**. It never copies a row,
never re-serializes it, never re-computes its digest into a private field.
The truth stays on the `refusal_row` side: `refusal_row.record_refusal()`
is the only way a row comes into existence, `refusal_row.verify_row()` is
the only way a row is judged, and `RefusalRow.row_digest` is the row's own
tamper check.

**Why (Northstar design, not from the source).** A copy would be a second
place where a refusal lives, and therefore a second place where it can
diverge. If the hold kept a private copy of the row's fields, then a
row tampered with after it was recorded would still be read from the
hold's pristine copy, and the tamper check would be defeated -- the hold
would vouch for a forgery. Storing the row by reference means the hold
always re-verifies *the live row*, and a tamper is caught at the moment of
the query. The hold adds a **reference**, never a **copy**.

The cost of that choice is that the hold cannot survive the row's
disappearance. That is deliberate: a missing row is an unknown state, and
§5 says unknown states block.

## 4. The two refusal families

The repository has two refusal families, and the hold must say what it
does with each. **Northstar design; the source names neither.**

| family | recognized? | why |
| --- | --- | --- |
| `refusal_row.RefusalRow` | **yes** -- this is the hold's input | it is the auditable refusal with a verdict and evidence; the brief's "a refusal row blocks re-dispatch" is about exactly this row |
| `scope_qualifier.DenialRow` | **no** -- explicitly excluded | it is a *scope verdict sidecar*, not a refusal record: a `DenialRow` has no evidence hash, no ruleset hash, no instrument and no population digest, so it cannot be re-verified by `refusal_row.verify_row()` and it does not carry the "two instruments or none" basis |

Excluding `DenialRow` is a **statement, not an oversight**. A `DenialRow`
says "this scope is denied" or "this scope is clear (signed)"; the hold's
input is "this action was refused, and here is the evidence the refusal
rests on". Mixing them would mean the hold blocks on rows it cannot audit
and it cannot distinguish a denial from a signed clear. So a `DenialRow`
is **registerable** in the store -- the hold must be able to *meet* it and
refuse it -- but it is not a refusal row: when the hold finds one on the
queried key it answers `blocked_row_invalid` and blocks. It is never
silently ignored, because a silent ignore is exactly the "recorded but not
enforced" failure this slice exists to close.

The two families also differ in what a *missing* row means, and both are
"unknown, never a clean read":

* `DenialRowStore.fetch()` returns `None` when there is no row, and the
  gate reads `None` as `outcome_unknown`
  (`scope_qualifier.OUTCOME_UNKNOWN`, and `BLOCKING_OUTCOMES` contains it);
* `RefusalHold.check()` on a key with no matching refusal returns
  `allowed_no_refusal` -- but only *after* the hold has established that
  the store is readable and the rows are intact. An unreadable store is
  `blocked_store_unreadable`, never `allowed_no_refusal`.

## 5. Fail closed: the unusable gate blocks

The repository's existing answer is **block**, and this slice follows it.

`scope_qualifier` says it in two places:

* `DenialRowStore.fetch()` returns `None` for "no row" and the docstring
  says "``None`` means *there is no row* -- which the gate reads as an
  unknown state, not as permission";
* `BLOCKING_OUTCOMES` is `{OUTCOME_MISMATCH, OUTCOME_UNKNOWN,
  OUTCOME_EXPIRED}` -- so `outcome_unknown` is a **blocking** outcome.

And `cancellation_tombstone.TombstoneSet.blocked()` is the shape: a
permission stop blocks regardless of the clock, because it has no bound to
pass.

**Why (the reasoning, stated once).** The hold sits on the path that
*re-sends* an action. The two failure modes are not symmetric:

* a **false block** costs a retry that might have worked -- it is an
  operational annoyance, recoverable by the operator;
* a **false allow** re-sends an action that was already refused -- the
  refusal was not enforced, the ledger fills with duplicate refusals, and
  the agent burns attempts and money on a thing that was already decided.

Northstar's ledger-first design says the second failure is the one that
must not happen: a refusal that leaves no enforceable trace is
indistinguishable from a check that never ran, and "the outcome is unknown
-- never a clean read" is already the repository's word for it. So every
unusable-gate state **blocks**.

The fail-closed taxonomy:

| condition | `reason` | blocked? |
| --- | --- | --- |
| the store cannot be read at all | `blocked_store_unreadable` | **yes** |
| a row matching the key fails `refusal_row.verify_row()` | `blocked_row_tampered` | **yes** |
| the row matching the key is not a `RefusalRow` at all (e.g. a `DenialRow`) | `blocked_row_invalid` | **yes** |
| the key is malformed (missing field, wrong type, empty, ambiguous) | `blocked_key_invalid` | **yes** -- and the call **raises** `RefusalHoldKeyError`; it never silently allows |
| no refusal matches the key, store readable, rows intact | `allowed_no_refusal` | no |

Note the shape of the last two rows: a refusal that *does* match blocks
(`blocked_by_refusal`), and only a **readable** store with **intact** rows
and **no** match allows. "No match" is a conclusion; it is only reached
after the gate has established that it is entitled to conclude anything.

## 6. Single-instrument weak basis: it blocks

**Northstar design; not from the source.**

`refusal_row` marks a row resting on a single instrument with
`MARKER_SINGLE_INSTRUMENT` ("SINGLE_INSTRUMENT"), and demands an explicit
reason for it. `record_refusal()` refuses a row with zero instruments
("two instruments or none") and refuses a single-instrument row that did
not declare itself.

**The decision: a single-instrument refusal still blocks.**

The reasons:

1. **A weak basis is not an invalid refusal.** `refusal_row.verify_row()`
   returns **True** for a properly declared single-instrument row: it is
   a well-formed refusal, resting on one instrument instead of two. The
   row is not a forgery and not an absence -- it is an opinion that was
   honestly labelled. The hold's job is enforcement, not re-litigating the
   basis; the basis's strength is already marked on the row itself, where
   a reader can see it.
2. **The alternative is the failure mode this slice exists to close.** If
   a single-instrument refusal did not block, then an action refused by one
   instrument would be re-dispatched, would fail, and would pile up
   refusal rows -- the exact "recorded but not enforced" behavior. The
   weakness would become a *loophole*, not a caveat.
3. **The row carries the caveat with it.** Because the marker travels on
   the row, the blocked caller receives the row (`result.row`) and can
   read `row.marker == "SINGLE_INSTRUMENT"` and the mandatory reason.
   The information is not lost; it is attached to the refusal.

So the hold treats a single-instrument row as a blocking refusal, and
exposes the weakness on the row rather than hiding it. A caller that wants
a stricter policy can filter on `row.marker` itself -- the hold does not
make that decision for it.

## 7. Expiry: refusal rows do not expire by the clock

**Northstar design; not from the source.**

`cancellation_tombstone` has an explicit fork: a **capacity** tombstone
expires when its bound has passed (`if tombstone.expires_at is not None and
now >= tombstone.expires_at: continue`), while a **permission** tombstone
never expires by the clock, "because it has no bound to pass".

**The decision: refusal rows do not expire.** A refusal is a *permission*
class decision ("this action is refused"), not a capacity bound ("this
action is temporarily out of quota"). There is no bound on a refusal to
pass: the row says the action is refused, and until something *new* says
otherwise, it stays refused.

The mechanism for changing that is **not** expiry, it is **another row**:
`refusal_row` is append-only, so a fresh refusal (or a decision that the
action is now allowed) is recorded as a new fact. The hold reads the
live set each time, so the hold never has to mutate anything.

**But `now` is still a parameter, and it is still the caller's.** The
hold never reads the wall clock (house rule: recorded rows carry a
caller-supplied clock -- `refusal_row.RefusalRow.refused_at`). `check()`
takes `now` so that the *caller* controls the evaluation time and so that
a future expiry fork can be added without changing the API. Under this
slice's semantics `now` does not change the answer; the tests pin that.

## 8. No wall clock

Every time value in this module is caller-supplied:

* `RefusalHold(rows=[...], now=...)` -- the hold's own "as of" time, used
  for its bookkeeping;
* `check(key, now=...)` -- the evaluation time;
* `refusal_row.RefusalRow.refused_at` -- the row's own clock.

The module imports no `time` function for reading "now", and the test
suite proves it: the hold's answers are identical for two different
`now` values (because nothing expires), and a hold constructed with a
`now` in the past still blocks.

## 9. The re-dispatch path

The hold is a **query**, in the `TombstoneSet.blocked()` shape. It is not
wired into `JobQueue.retry()` or `LeasedTaskClaim.fail()` in this slice --
those two modules are **read-only** for this slice (see the SCOPE list),
and changing them would be a much larger change than this brief asks for.

What this slice delivers is the missing *gate*: a caller that holds a
`RefusalHold` asks it before re-dispatching, and gets back either
`allowed_no_refusal` or a blocking result with the row that blocked it.
The three real paths the tests drive are:

* **(a) record a refusal -> a second dispatch of the same action is
  blocked**, with the row reference attached;
* **(b) a different action is NOT blocked** (different action, different
  job, different task) -- the hold does not over-block;
* **(c) the hold unusable / the row tampered with -> blocked**, fail
  closed.

The `RefusalHold` also offers `is_blocked(...)` as a convenience wrapper
around `check(...)`, mirroring `TombstoneSet.is_blocked()`.

## 10. What is *not* in this slice

* No change to `job_queue.py`, `leased_task_claim.py`, `refusal_row.py`,
  `scope_qualifier.py`, `cancellation_tombstone.py` -- all read-only.
* No expiry: see §7.
* No copy of a refusal row: see §3.
* `DenialRow` is excluded: see §4.
* No queue-level or task-level quarantine: the key is per-job and
  per-task (see §2).
