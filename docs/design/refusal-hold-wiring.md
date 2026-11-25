# Refusal-hold wiring: a recorded refusal blocks the re-seal of the same grant pin

Status: implemented
(`components/northstar-agent-runtime/refusal_hold_wiring.py`).
Version pin: `refusal-hold-wiring.v1`. Schema pin:
`northstar.refusal-hold-wiring.v1`.

## 1. The problem this slice solves

Northstar has two complete "refusal" concepts, and neither sits on a
re-issue path:

| concept | what it is | where it lives |
| --- | --- | --- |
| **refusal row** | an auditable "no": verdict, evidence hash, ruleset hash, verifier key, population digest, "two instruments or none" | `refusal_row.py` |
| **denial row** | per-scope `denied` / signed `clear`; no row means `outcome_unknown`, never a clean read | `scope_qualifier.py` (`DenialRow`, `DenialRowStore`) |

The previous slice added the **refusal hold** (`refusal_hold.py`): a query
that answers *is this re-dispatch blocked by a refusal, and by which row?*
— a `RefusalHoldKey`, a `RefusalHoldStore`, a fail-closed reason taxonomy
(`allowed_no_refusal`, `blocked_by_refusal`, `blocked_key_invalid`,
`blocked_row_invalid`, `blocked_row_tampered`,
`blocked_store_unreadable`).

**Nothing consulted it.** The place that actually *signs the same action
again* is the seal ledger's commit:

* `forward_seal_ledger.py:240` — `ForwardSealLedger.__init__` takes an
  optional `tombstones` registry;
* `forward_seal_ledger.py:265` — `set_tombstones()` installs it;
* `forward_seal_ledger.py:488-500` — `append_grant()` takes the ledger's
  lock and calls `_authorize_under_tombstone_locked()` **inside** it;
* `forward_seal_ledger.py:533` — that method asks the registry
  `registry.blocked(pin.grant_id, action, subject_value, now=now)`;
* `forward_seal_ledger.py:543-547` — on a hit it raises
  `ForwardSealError` and **no record lands**.

That is exactly the refusal hold's isomorphism, and it was not wired. The
consequence is as bad as "not recorded", and more hidden: **refusal rows
keep piling up while the same action keeps getting signed.**

This slice supplies the **wiring component**: the identity mapping, the
registry adapter the ledger's injection point accepts, and the
authorization function the seal path calls. It does **not** modify
`forward_seal_ledger.py` (that file is read-only in this slice), so the
wiring is delivered as a module with an executable example instead of an
edit.

### Source

**Source (hermesagentj, "The most useful thing I built this month is a
check that refuses to run", Moltbook post
`abe9e16f-21a4-4d38-a2b1-03fd84c3543c`)** — the source names the refusal
row and the refusal's own fields ("verdict, evidence hash, ruleset hash,
verifier key; 'two instruments or none'; the missing population digest
field"). It does **not** name a hold, a key, a seal path, a grant pin, a
subject layer, or a concurrency contract.

**The evidence for this slice is therefore repository code**, cited by
line number throughout: `forward_seal_ledger.py`, `cancellation_tombstone.py`,
`grant_pin_ledger.py`, `refusal_row.py` and `refusal_hold.py`. Nothing
in this document is attributed to the source that the source does not say.

**Northstar extensions** (not in the source): the identity mapping
(`grant_id` → `scope_id`), the declared scope kind, the subject
collapse, the registry adapter, the refusal-cannot-be-lifted rule, the
lock binding that makes "refusal recorded but still issued" impossible,
and the executable wiring helpers `authorize()` and
`install_refusal_gate()`.

## 2. The identity problem, answered

The two sides use different keys:

| side | key | source |
| --- | --- | --- |
| seal ledger side | `(grant_id, action, subject)` | `forward_seal_ledger.py:533` calls `registry.blocked(pin.grant_id, action, subject, now=now)`; `Tombstone.covers` (`cancellation_tombstone.py:157`) reads `grant_id` / `action` / `subject` |
| refusal hold side | `(scope_kind, scope_id, action)` | `refusal_hold.RefusalHoldKey` |

### Question 1 — how is a `RefusalHoldKey` built from `(grant_id, action, subject)`?

The conversion table is:

| ledger side | hold side | why |
| --- | --- | --- |
| `grant_id` | `scope_id` | the hold's `scope_id` is "the identifier of the queue/task the action lives in" (`refusal_hold.py:184-197`). The grant id is the only identifier the ledger side holds, and it identifies the *authorization* under which the action is taken. `grant_id` is **not** a job id — one grant covers many jobs — so the mapping is a *naming* correspondence, not an identity correspondence. |
| `action` | `action` | verbatim. The hold's action is the same notion the tombstone gate compares (`Tombstone.covers`, `cancellation_tombstone.py:165`). |
| `subject` | **collapsed** | see question 3. |

So: `RefusalHoldKey(scope_kind, grant_id, action)`, whose canonical string
form is `<scope_kind>:<grant_id>:<action>` — e.g. `task:grant-42:checkout`.

The mapping lives in exactly one function, `refusal_hold_key()`
(`refusal_hold_wiring.py`), and **both** sides of a refusal go through it:
the recording side (`RefusalHoldRegistry.record`) and the checking side
(`RefusalHoldRegistry.check`). A refusal cannot therefore be recorded under
one scope and checked under another — which would be a refusal that is
never enforced, i.e. the gap this slice closes, re-opened one level down.

**Malformed input fails closed.** An empty grant id, a non-string action,
an action containing a colon, a non-string subject: each raises
`RefusalHoldKeyMappingError` (which is also a `RefusalHoldKeyError` and a
`forward_seal_ledger.ForwardSealError`). An empty key would name *every*
action, so a malformed identity must never produce a usable key.

### Question 2 — what goes in `scope_kind`?

The hold's scope vocabulary is **closed**: `queue` and `task`
(`refusal_hold.py:112-116`, `SCOPE_KINDS`). The ledger side has no
queue/task dimension at all — a grant pin is `(grant_id, version,
counter)` (`grant_pin_ledger.py:163`), and `version` / `counter` are the
grant's *ordering* fields, not a scope.

**Answer: the scope kind is a *declared* attribute of the action
namespace, not a derived one.** This slice declares `DEFAULT_SCOPE_KIND =
"task"` (`SCOPE_KIND_TASK`), on the grounds that a grant pin authorizes one
concrete action on one concrete subject — a task-scoped authorization —
and the key reads `task:<grant id>:<action>`.

It is deliberately **not** derived from the action's text. Deriving a
refusal's scope from a string would make the meaning of a refusal depend
on string matching, and a name collision (an action called `queue:foo`
against a `queue` kind) would silently re-scope refusals. Instead,
`scope_kind_for()` takes an explicit per-action override table plus one
default, and the same function is used on both sides.

A host that wants a different namespace passes `scope_kind=` (or
`scope_kind_overrides=`) to `RefusalHoldRegistry`. A scope kind outside
`SCOPE_KINDS` is **refused**, not defaulted.

### Question 3 — how is the third `subject` layer expressed?

**It is not. The refusal hold's key has no subject field, and this slice
does not add one** (`refusal_hold.py` is the previous slice's delivery and
is read-only here). The wiring therefore **collapses** the subject: a
refusal recorded for `(grant_id, action, subject=order-7)` also covers
`(grant_id, action, subject=order-8)`.

**The declared consequence: a refusal is coarser than a cancellation.**

* The tombstone gate **narrows** by subject: a tombstone that names a
  subject covers that subject, an unscoped tombstone covers all of them,
  and a caller that names no subject is covered by a scoped tombstone too
  (`Tombstone.covers`, `cancellation_tombstone.py:157-171`).
* The refusal gate **cannot** narrow: it has one `action` and no subject
  layer.

The asymmetry is stated, not hidden:

* **Over-blocking is the safe direction.** A refused action stays refused
  until the refusal is withdrawn. A host that needs subject-level
  granularity must use the **cancellation** gate, not the refusal gate.
* **Under-blocking is the unsafe direction** — and it is what the gap was:
  the same action being signed again. Collapsing the subject cannot
  under-block.

The semantics live in **code**, in `subject_covers()`, and are pinned by
tests (`SubjectSemanticsTests`), so the declaration is verifiable rather
than prose.

### Question 4 — on which side is the refusal row recorded?

**On the `refusal_row` side, and the scope lives on the hold side.**

The reason is structural: `RefusalRow` (`refusal_row.py:193-219`) carries
`verdict`, `evidence_hash`, `ruleset_hash`, `verifier_key`,
`population_digest`, `refused_at`, `reason`, `instruments` and
`single_instrument` — and **no scope field at all**. Its `row_digest` is
computed over exactly those fields (`RefusalRow.body()` /
`content_digest()`, `refusal_row.py:302-319`), and `verify_row()`
(`refusal_row.py:426`) re-derives that digest. Adding a scope field to the
row would therefore either break the tamper check or force the row's
digest to cover a field the row does not own. The row is the **evidence**;
the scope is the **hold's** business.

So the answer is **both sides, with a conversion table**:

| what | where it lives | why |
| --- | --- | --- |
| the refusal itself (verdict, evidence, instruments, reason, timestamp) | `refusal_row.RefusalRow` | it is the auditable artifact; its digest must cover exactly the evidence |
| the scope (`(scope_kind, scope_id, action)`) | `refusal_hold.RefusalHoldEntry.key` | the hold is the gate; it needs to name what it blocks |
| the join | `refusal_hold_wiring.refusal_hold_key()` | one function, used by both sides, so they cannot drift |

The wiring's `RefusalHoldRegistry.record()` holds the row **by reference**
in the hold's entry, and the hold re-verifies the live row on every query
(`RefusalHoldEntry.is_intact()`, `refusal_hold.py:295-303`) — a row that
is tampered with *after* it was recorded is still caught, and a copy would
be a second place where the refusal could diverge from the truth.

## 3. The wiring example (executable)

At `forward_seal_ledger.py`'s injection point, the three lines are:

```python
# 1. build the gate: a TombstoneSet-shaped refusal registry
registry = RefusalHoldRegistry()

# 2. install it at the ledger's injection point
ledger.set_tombstones(registry)

# 3. bind the gate to the ledger's commit lock, so a refusal recorded
#    concurrently with a seal is serialized with it
registry.bind_gate(ledger._lock)
```

These three lines are **executed by the test suite**
(`tests/test_refusal_hold_wiring.py`, `WiringExampleTests`), against a
real `ForwardSealLedger`, with a real `append_grant()` — not merely
printed in this document. The assertions are: the seal is **refused**
(`ForwardSealError`), and the ledger's **row count does not change**.

Why line 3 exists: the ledger's `append_grant()` takes its lock across
the check **and** the write (`forward_seal_ledger.py:488-511`), so a
check performed before the send would leave the race open — the module's
own docstring says so ("the check and the consumption of a lift happen
inside the append's critical section ... so a re-read before the send
(which would still leave the race open) is never the mechanism"). If the
refusal is *recorded* under that same lock, then a seal and a recording
are serialized with respect to each other:

* a seal that commits **before** the refusal lands is a seal of an action
  that was not yet refused — legitimate, and the action is refused
  afterwards;
* a recording that lands **before** the seal means the seal sees the
  refusal and is refused.

**"The refusal is on the books and the action was issued anyway" cannot
happen.** `ConcurrencyTests` asserts this on the registry's own audit
trail, which is written under the same lock, so the trail *is* the
serialization order.

### The shape the injection point accepts

`RefusalHoldRegistry` has the shape of `cancellation_tombstone.TombstoneSet`:

| method | tombstone set | refusal registry |
| --- | --- | --- |
| `blocked(grant_id, action, subject, *, now)` | `Tombstone \| None` | `RefusalHoldResult \| None` — `None` means *no refusal covers this action* |
| `is_blocked(grant_id, action, subject, *, now)` | `bool` | `bool` |
| `lift(lift)` | consumes a named lift | **always refuses**: a refusal is not a cancellation and cannot be lifted by a tombstone lift |

One deliberate difference: `blocked()` returns `None` for "not blocked",
exactly like the tombstone set, but the **full** answer is available
through `check()`, which never returns `None` — it always carries a
reason, so an operator can tell *allowed* from *the gate was unusable*.

### Fail closed

The repository's own answers, followed:

* `scope_qualifier.BLOCKING_OUTCOMES` contains `OUTCOME_UNKNOWN` — an
  unknown state is never a clean read;
* `cancellation_tombstone`: permission-class refusals never expire because
  of the clock;
* `refusal_hold.RefusalHold.check()` already implements the order: store
  unreadable → `blocked_store_unreadable`; row is not a refusal row →
  `blocked_row_invalid`; row tampered → `blocked_row_tampered`; a
  verified refusal row → `blocked_by_refusal`; a malformed key → raises
  `RefusalHoldKeyError`.

This slice **does not change that semantics** — it only wires it onto the
issue path. The three unusable-gate cases, each pinned by a test:

| case | result |
| --- | --- |
| `RefusalHoldStore.break_reads()` | `blocked_store_unreadable` → the seal is refused, no record lands |
| the row no longer verifies (`verify_row()` is False) | `blocked_row_tampered` → the seal is refused, no record lands; the tampered row is **not** returned |
| the identity is malformed (empty grant id / colon in the action / wrong-typed subject) | raises `RefusalHoldKeyMappingError` — **no silent pass** |

### Expiry

**Nothing expires.** `now` is threaded through (the caller owns the
clock) but it does not change the answer: a permission-class refusal has
no "upper bound" to pass against. `ExpiryTests` pins this by asking the
same question at four different clocks and getting the same answer.

If a `capacity`-class split is wanted later, the change belongs in
`RefusalHold`'s **policy layer**, not in this wiring layer — so the split
is not baked into the wiring.

## 4. Where the queue re-dispatch paths' check belongs

The strategy brief's earlier claim — "the re-dispatch path =
`job_queue.retry()` / `leased_task_claim.fail()`" — needs correcting, and
this slice states where the check for those paths belongs **even though it
does not wire them**.

**Why not here:** those two paths hold no grant pin. `JobQueue.enqueue()`
takes `job_id`, `queue`, `task`, `payload_digest` (`job_queue.py:696-706`)
— no grant id, no subject, no action identity in the ledger's sense.
`LeasedTaskClaim.enqueue_task()` takes `task_id`, `task`, `payload`
(`leased_task_claim.py:663`). The seal ledger is the only place that
already holds `action` / `subject` / `grant_id` **and** already implements
"hit means refuse, inside the lock, record not written". So this slice
wires the ledger side.

**Where the queue-side check belongs** (a later slice):

* **`JobQueue.retry()`** (`job_queue.py:893`) — the check belongs in the
  same critical section that flips the job back to `ready`, i.e. inside
  the method's `with self._lock:` block, immediately before
  `entry["state"] = _STATE_READY`. The query identity must be the job's
  `(queue, job_id)` plus the job's **action identity** — which
  `JobQueue` does not currently carry. So the queue side needs a
  **grant-pin-shaped field on the job** (or a mapping from job to
  `(grant_id, action)`) before a refusal hold can be asked about it.
  The refusal row's scope on that side is `(scope_kind="queue",
  scope_id=job_id, action=<the job's action>)` — note this is a *different*
  scope namespace from the ledger side's `task:<grant id>:<action>`, and
  the two must not be conflated: the same refusal row can be registered
  in both namespaces, but the two keys are not interchangeable.
* **`LeasedTaskClaim.fail()`** (`leased_task_claim.py:992`) — the check
  belongs inside its transaction, immediately before the `UPDATE` that
  sets `STATE_DEAD if dead else STATE_READY`. The identity there is
  `(scope_kind="task", scope_id=task_id, action=<the task's action>)`.

**Both queue-side checks need one thing this slice does not provide:** the
queue and the lease ledger must carry the **action identity** of the work
item, so that the hold can be asked a question in the hold's own
vocabulary. Adding that field is a change to `job_queue.py` /
`leased_task_claim.py`. **AMENDED 2026-11-23:** those two files are no
longer read-only in this slice (§13), but the **action identity field**
itself is still not added — §13 closed two *different* defects (the mirror
disagreeing with the ledger), not this one. So the honest open item stands,
and it is stated here rather than left silent.

## 5. Open items

1. **The queue-side wiring** (section 4): needs the work item to carry an
   action identity first.
2. **The subject layer**: the refusal hold has no subject field, so a
   refusal is coarser than a cancellation. If subject-level refusals are
   wanted, the change belongs in `refusal_hold.py` — the hold's key, not
   this wiring.
3. **A refusal cannot be lifted.** `RefusalHoldRegistry.lift()` always
   refuses. If a host needs a "refusal withdrawn" path, it belongs in the
   hold's policy layer as well.
4. **`forward_seal_ledger.py` is not modified.** The wiring is delivered
   as a module plus an executable example. Landing the three lines in the
   ledger itself is a one-line change to
   `_authorize_under_tombstone_locked()` (which would consult the refusal
   registry next to the tombstone registry), but that file is read-only in
   this slice.

## 6. RESOLVED — the ledger holds BOTH gate families

Open item 4 above said the ledger itself was not modified, and named the
one-line change that would close it. It is closed now, and closing it
turned up a **fail-open** that was not in the open items at all.

### 6.1 What the ledger actually did

`ForwardSealLedger` has **one** injection point, `set_tombstones()`, and
**two** gate families that are installed into it:

* the **cancellation tombstone** (`cancellation_tombstone.TombstoneSet`),
  and
* the **refusal hold** (`refusal_hold_wiring.RefusalHoldRegistry`).

They are deliberately interchangeable in shape — the wiring exists to be
dropped into the tombstone's slot — but they are **different gates**: one
answers "was this action cancelled?", the other "was this action
refused?". A host that installs both means to be stopped by both.

The slot held **one** object, so the second install **replaced** the
first. Measured on this branch, before the fix:

```python
ledger.set_tombstones(tombstone_set)      # the cancellation gate
ledger.set_tombstones(refusal_registry)    # the refusal gate
ledger.append_grant(grant_id="grant-1", action="dispatch")
# -> len(ledger) == 1
```

The seal **landed**. The cancellation tombstone that covered exactly that
identity was silently dropped, and the ledger sealed the action it named.
A host that installed the refusal gate — the way this slice's own test
suite installs it — **disarmed the cancellation gate**.

This is the same shape of defect the batch already knows by another name:
the second half of a guard is not exercised, so the first half's
protection is assumed rather than measured.

### 6.2 The fix

1. **Two slots, not one.** The ledger keeps `_cancellations` and
   `_refusals` separately, and `_authorize_under_tombstone_locked()`
   consults **both**: a seal is refused when *either* family blocks.
   The refusal is checked first and on its own terms — a refusal is not
   a cancellation and cannot be lifted by a tombstone lift, so it never
   goes through the lift path.
2. **The family is decided by shape, not by name.** A registry is the
   refusal family when it declares `is_refusal_registry` (the refusal
   registry does) or when it carries a `row`/`row_digest`; otherwise it is
   the cancellation family. The classification is made on the *declared
   surface* of the object, so a host's own registry is filed by what it
   actually is rather than by what it is called.
   **AMENDED by §9:** this decides which *slot* a registry is installed
   into.  What a block *means* is decided separately, by the shape of
   the answer at the seal — and that half was missing, which is how a
   host's refusal became liftable.
3. **A second install is refused, not silently applied.** Installing a
   *different* object into a family that already holds one raises
   `ForwardSealError` rather than dropping the first. Installing the
   **same** object again is idempotent, and passing `None` clears both
   families — clearing is a deliberate act and must not leave one gate
   behind.
4. **The historical name still reads back the consulted gate.**
   `ledger.tombstones` returns the refusal registry when that is the only
   gate installed, so the existing caller (`test_refusal_hold_wiring.py`
   asserts `ledger.tombstones is registry`) keeps its meaning.
   `ledger.cancellations` and `ledger.refusals` are the explicit slots.

### 6.3 What it does NOT change

* The refusal hold's own semantics are untouched. This is a change to
  *where the gate is installed*, not to what it answers.
* The tombstone lift path is untouched: a lift still only lifts a
  tombstone, and a refusal still cannot be lifted.
* The ledger's default behaviour — no gate installed — is untouched: a
  ledger with no gates seals exactly as before.
* The queue-side wiring (open item 1) is still open. It needs the work
  item to carry an action identity first, and it is a different seam
  from this one.

## 7. RESOLVED — the queue side carries its own action identity

Open item 1 above said the queue-side wiring could not land because
"the work item must carry an action identity first", and that adding
that field was "a change to `job_queue.py` / `leased_task_claim.py`".
**It is closed, and the premise was wrong in a useful way.**

### 7.1 The action identity was already there

The open item asked for a *grant-pin-shaped field* on the job. The job
already carries an action:

* `JobQueue` keeps the work item's `task` string on every entry, and
* `LeasedTaskClaim` keeps it in the `ltc_task.task` column.

Neither is a grant id, and neither needs to be. The hold's key is
`(scope_kind, scope_id, action)`, where `scope_id` is a **job id** or a
**task id** and `action` is the work item's action. So the queue side
needed a **mapping**, not a schema change — and no schema change means
no migration, no requeue of in-flight jobs, and no change to the
`job_queue.py` / `leased_task_claim.py` table layout.

### 7.2 The three namespaces, and the collision that proved they must be three

The wiring adds three namespaces, and the third exists because the
first two were not enough:

```
ledger side    task:<grant id>:<action>
queue side     queue:<job id>:<action>
lease side     lease:<task id>:<action>
```

`task_hold_key()` originally used the ledger side's scope kind, `task`.
That is a **collision**, and it was found by a test, not by reading:
the ledger side's `scope_id` is a grant id and the lease side's is a
task id, and **both are plain strings**. So on a shared scope kind
`task:<grant id>:<action>` and `task:<task id>:<action>` are the *same
key* whenever the id strings match — and a refusal recorded against a
grant blocked an unrelated lease. The failure direction is "stops
work", so it fails safe; but it blocks the *wrong* work, which is not
safe at all.

`refusal_hold.py` therefore gains a third scope kind, `SCOPE_KIND_LEASE`
(`"lease"`), and `SCOPE_KINDS` now names three. The hold's own key
format is unchanged — this is a new *namespace*, not a new key shape.

### 7.3 What landed

* `refusal_hold_wiring.queue_hold_key(job_id, action)` — the queue-side
  key. `task_hold_key(task_id, action)` — the lease-side key. Both fail
  closed on a malformed identity (they raise; they never construct an
  empty key, because an empty key would name *every* action).
* `refusal_hold_wiring.RefusalHoldQueueGate` — one registry, two
  namespaces, with `check_queue` / `check_task` and the matching
  `require_*_allowed` / `record_*`. It **fails closed**: an unreadable
  store, a tampered row or a malformed identity refuses the re-dispatch.
* `RefusalHoldRegistry.record_entry(key, row=...)` — a recording path
  that takes an **already-built** key. `record()` now delegates to it,
  so the two sides share the row check, the lock order, the store
  rebuild and the event, and those semantics cannot drift apart.
* `install_queue_refusal_gate(queue, gate, job_id=..., action=...)` — a
  context manager that binds the gate into the queue's lock, so the
  check and the re-dispatch are serialized against the queue's own
  critical section.
  **AMENDED by §10:** the queue side now ALSO carries the gate inside
  the object (`JobQueue(refusal_gate=...)` / `set_refusal_gate()`), so
  the context manager is no longer the only way to get a gate onto a
  queue — and a plain `retry()` is refused without any wrapping.
* `LeasedTaskClaim` gains an optional, **duck-typed** refusal gate
  (`refusal_gate=` / `set_refusal_gate()`), and **all three** of the
  paths that put a task back to `ready` consult it **inside the
  transaction**, immediately before the `UPDATE`. A refusal raises, the
  transaction rolls back, and the task keeps its state, its failure
  count and its delay.
* `JobQueue` gains the same seam — see §10. The lease side's gate was
  always inside the object; the queue side's was not, and that gap is
  what let a recorded refusal be followed by a re-dispatch anyway.

The gate is duck-typed on purpose: `leased_task_claim.py` does not
import `refusal_hold_wiring` (the wiring imports the hold, and the
hold must not drag the lease ledger in). The lease side asks the gate
for `require_task_allowed(task_id, action, now=...)`, and a gate that
does not offer it is a `TypeError` at the call site rather than a
silent pass-through.

### 7.4 The three re-dispatch paths, not one

Guarding `fail()` alone is **not** enough, and the reason is worth
recording: `LeasedTaskClaim` has **three** paths that put a task back
to `ready`, and a refusal that covers only one of them can be walked
around.

| path | how the task goes back to `ready` | what it costs the worker |
|---|---|---|
| `fail()` | the worker reports a failure | a failure record, a backoff, the failure budget |
| `reap()` | the lease **expires** and the reaper sweeps it | nothing -- a crash eats no backoff |
| `release()` | the worker **gives up** its lease voluntarily | nothing -- releasing is not a failure |

The second and third are the cheap routes, and a guard that only
covers the first is a guard with a door next to it.  Both were found
by asking the uncomfortable question -- *can a refused task be
laundered back into the queue?* -- and both answered yes until the
gate was installed on them.

**AMENDED 2026-11-23 (§11): this enumeration was still incomplete.**
The three paths above are the three ways a task goes **back** to
`ready`.  There is a **fourth** path -- `claim()` -- that takes a task
**out** of `ready` and offers it to a worker, and it is the moment the
refused action is actually re-offered.  §11 closes it.

`reap()` and `release()` differ in how they answer it, and the
difference is deliberate:

* **`release()`** reports ONE lease for ONE task, so it uses the
  raising form (`require_task_allowed`).  The transaction rolls back
  and the worker keeps its lease.
* **`reap()`** sweeps a **batch** of expired leases.  A raise there
  would abandon the whole sweep -- one refused task would stop every
  other expired lease from being requeued, which is a denial of
  service the refusal never asked for.  So `reap()` asks the
  **boolean** form (`task_allowed`) and **skips** the refused task.
  The refused task keeps its state, its crash count and its lease; its
  lease keeps expiring and the next sweep asks again.

Both refuse a gate that cannot answer: an unreadable store or a
tampered row blocks, because the hold fails closed.

`complete()` is the fourth `UPDATE`, and it is **not** a re-dispatch
-- it writes the terminal state and the outbox row.  It is out of
scope for the hold.

### 7.5 Measured

`tests/test_refusal_hold_queue_wiring.py` — 55 tests. Among them:

* a refused `fail()` leaves `state='leased'`, `failures=0` and
  `delay_until=0.0`, and the queue-mirror job stays `reserved`;
* the queue-side and lease-side keys for the *same* id string are
  **different** keys (the collision above), and the ledger-side and
  lease-side keys are different too;
* the gate is bound under the queue's own lock, so a refusal recorded
  concurrently with a re-dispatch cannot interleave;
* a refused `release()` leaves `state='leased'` and the mirror job
  `reserved`;
* a refused `reap()` sweeps **nothing** for that task, its crash count
  stays 0, and the mirror job stays `reserved`;
* one refused task does **not** stop the other expired leases from
  being swept -- the refusal is scoped to one task.

The targeted suites (`test_leased_task_claim`, `test_refusal_hold`,
`test_refusal_hold_wiring`, `test_refusal_hold_queue_wiring`,
`test_job_queue`) are green, and the repo-level suite is green (452
tests) after the regenerated `docs/api` page.

### 7.6 What is still open

Open items 2 (the subject layer), 3 (no lift path) and 4 (the ledger
file itself) are unchanged by this section — item 4 was closed by §6.
Open item 1 is closed by this section.

## 8. AMENDED 2026-11-23 — the queue side was not audited

### 8.1 The defect

The registry's audit trail is documented as **"what was recorded and what
was checked"** (`RefusalHoldRegistry.events`).  The ledger side honoured
that: every `registry.check(...)` appends a `checked` event.

**The queue side did not.**  `RefusalHoldQueueGate.check_queue` and
`check_task` reached *past* the registry into `registry.hold.check` and
read the hold directly:

```python
key = queue_hold_key(job_id, action)
result = self._registry.hold.check(key, now=int(now) if now is not None else None)
return result
```

So a queue-side check produced **no event at all**.  Measured on the tree
before the fix:

```
registry.check("grant-1", "seal")            ->  1 event
gate.check_queue("job-1", "dispatch")        ->  still 1
gate.check_task("task-1", "dispatch")        ->  still 1
```

Two queue-side checks, and the audit trail does not know they happened.

### 8.2 Why it matters

The queue gate is the thing that stops a job from going back to
`ready`.  A check that leaves no trace cannot answer *"was this job ever
refused?"* after the fact — which is exactly the question the trail
exists for, and exactly the question a host asks when a job is stuck.

The shape of the defect is the shape this batch keeps hitting: **the two
sides are supposed to be the same gate, and one of them took a different
path through it.**  §7's whole point is that "a host can record a
refusal once and consult it from either side" — the queue gate reused
the registry's *answer* and not its *recording*.

There is a second, smaller asymmetry the same line carried: it cast
`now` to `int` (`int(now) if now is not None else None`) while the
ledger side did not.  `now` does not affect the answer today (nothing
expires), so the cast was behaviour-neutral — but two sides of one gate
disagreeing about a parameter is how a real difference grows later.

### 8.3 The fix

One new method on the registry:

```python
def check_key(self, key: RefusalHoldKey, *, now: Optional[float] = None) -> RefusalHoldResult:
    result = self._hold.check(key, now=now)
    self._record_event("checked", key, result)
    return result
```

`RefusalHoldRegistry.check` is now `check_key` plus the key
construction, and **both** queue-gate methods go through `check_key`.
One method, three sides, one audit trail.

The `now` cast is gone with it: the queue side now passes `now` through
exactly as the ledger side does.

### 8.4 The guards, and why they can fail

Six new tests in `test_refusal_hold_queue_wiring.py`
(`QueueGateAuditTests`), each verified by running it against the
pre-fix code:

| test | what it pins |
|---|---|
| `test_a_queue_side_check_is_audited` | one queue check → one `checked` event, keyed `queue:<job>:<action>` |
| `test_a_task_side_check_is_audited` | one lease check → one `checked` event, keyed `lease:<task>:<action>` |
| `test_a_blocking_queue_side_check_is_audited_as_blocked` | the **blocked** answer is recorded as blocked, with the refusal's `row_digest` — the one an operator will ask about |
| `test_the_queue_side_and_the_ledger_side_agree_on_being_audited` | three sides, three events: neither side is the privileged one |
| `test_a_refusing_gate_is_audited_too` | the **raising** form leaves the same trace as the boolean form — a caller that catches the refusal still needs the trail |
| `test_the_batch_sweep_form_is_audited_per_item` | `task_allowed` (the batch-sweep form) is one event **per item** — three items, three checks |

The last two are the ones a "just call `check_key`" fix would miss: the
raising form and the batch form are separate code paths, and a sweep that
recorded one event for the whole sweep would be just as blind as the
original defect.

### 8.5 What this does NOT change

* The gate's **answers** are unchanged — only the recording of them
  changed.  The targeted suites (`test_refusal_hold`,
  `test_refusal_hold_wiring`, `test_refusal_hold_queue_wiring`,
  `test_leased_task_claim`, `test_job_queue`) are green.
* The **namespaces** are unchanged: `queue:` and `lease:` are still
  distinct, and a refusal in one still does not block the other.
* The **open items** are unchanged: 2 (the subject layer) and 3 (no lift
  path) are still open.  This section closes neither; it fixes an
  asymmetry in the auditing of a gate that already existed.

## 9. AMENDED 2026-11-23 — a host's refusal was LIFTABLE

### 9.1 The defect

Section 6.2 (2) says:

> The family is decided by shape, not by name.  A registry is the
> refusal family when it declares `is_refusal_registry` … or when it
> carries a `row`/`row_digest`; otherwise it is the cancellation family.

And `_is_refusal_registry`'s own docstring says:

> They are told apart by what they return when they block: a **refusal**
> comes back with the row that refused (`row` and `row_digest`), a
> **cancellation** comes back with the tombstone that cancelled (neither).
> … a host that writes its own registry is classified by what it actually
> returns rather than by what it is called.

**A host's own registry was lifted.**  Measured on this branch before the
fix, with a registry that is exactly the shape the docstring describes —
`TombstoneSet`-shaped, answering `blocked()` with an object that carries
`row` and `row_digest`:

```python
ledger.set_tombstones(host_refusal_registry)
ledger.append_grant(..., lift=some_lift)
# -> SUCCEEDED      the refusal was lifted
# host.lift called: [<Lift object ...>]
```

The house `RefusalHoldRegistry`, filed correctly, refuses the same seal:

```text
ForwardSealError: a lift was offered but this ledger holds no tombstone
registry, so nothing can be lifted
```

So the defect was not "a host's registry is filed in the wrong drawer".
It was **"a host's refusal is liftable"** — the one thing the refusal
gate exists to prevent.  A cancellation can be lifted by a named
tombstone-lift; a refusal cannot, because "a refusal is not a
cancellation".  That distinction is the entire reason the two families
are kept apart, and the lift path did not honour it.

### 9.2 Why the two halves of the rule live at different moments

The docstring's rule is right, and the code was wrong — but the rule
cannot be implemented where the docstring says, and saying so is the
first half of the fix.

**Filing** (which slot does the registry go in?) cannot be decided by
what the registry *returns*.  The return value only exists once the
registry has been **asked**, and asking has side effects: the house
registry's `check` records an **audit event** (see §8), so probing it at
install time would write a phantom event into the trail.  So filing is
read from what the registry **declares** — `is_refusal_registry`, or a
row carried on the registry itself.

**Meaning** (what does a block mean?) is decided by the shape of what
the registry **returns**, and it is available at every seal:

| the answer carries | it is a | and therefore |
|---|---|---|
| `row` / `row_digest` | a **refusal** | refused, and **NOT** liftable |
| neither (a `Tombstone`) | a **cancellation** | liftable by a named lift |

The old code consulted the cancellation slot's answer and, finding a
block, lifted it — without ever asking what kind of block it was.

**A measured no-op.**  The first attempt at this slice reordered
`_is_refusal_registry` so that the declaration check came first.  That
reorder is a **no-op**: the original was already declaration-based, and
the reordering killed nothing in the mutation run (MUT-A below
survived).  The function's *body* is unchanged in this commit — only
its docstring, which now says what the function actually decides and
what it does not.

### 9.3 The fix

1. **`_looks_like_a_refusal(result)`** — the answer's shape decides what
   it means.  The test is on the attribute's **presence**, not its
   value: a refusal that could not name its row (an unreadable store)
   still refuses, so a `row` that is present but `None` is still the
   refusal family's shape.
2. **The backstop in `_authorize_under_tombstone_locked`** — a block in
   the cancellation slot whose answer carries a refusal row is **refused**,
   and refused before the lift call, so no tombstone-lift can undo it.
3. **`_query_refusal` / `_refusal_blocks`** — the two query methods have
   **different contracts**, and the seal path now honours both:
   * `check` answers with a result carrying a `blocked` flag, and owes
     the caller a **reason** ("the caller always gets a reason, whether
     the action is refused, allowed, or the gate was unusable").  A
     `None` from `check` is therefore an **anomalous answer** — the gate
     said nothing, and nothing is not consent, so it **blocks**.
   * `blocked` answers `None` for *not blocked*, and there `None`
     genuinely means "no block".
   * A registry that can answer **neither** method, or that **raises**,
     is a gate that cannot be consulted — and a gate that cannot be
     consulted **blocks**.  "The gate could not answer" is not "the gate
     allowed it".

### 9.4 The guards, and why they can fail

Every guard below was checked by planting the defect and re-running.  A
guard that was not killed was **fixed**, not waived; two of them
survived their first version and are recorded here because that is the
part that matters.

| guard | what it pins | killed |
|---|---|---|
| `test_a_hosts_refusal_cannot_be_lifted` | the security consequence: an **undeclared** host registry's refusal is not liftable, and the lift is never consumed | MUT-B |
| `test_a_declared_refusal_cannot_be_lifted_either` | the same for a **declared** registry (the house path) | — |
| `test_a_hosts_refusal_is_consulted_before_the_lift_path` | the refusal is reported as a **refusal**, not as a cancellation | — |
| `test_an_undeclared_host_registry_is_filed_by_its_declaration` | filing is by declaration; the safety comes from the answer's shape | MUT-A (survives — by design) |
| `test_a_cancellation_is_still_liftable` | the control: a genuine `Tombstone` still lifts, so the backstop did not refuse every lift | — |
| `test_a_check_that_answers_nothing_blocks` | an anomalous `None` from `check` **blocks** | MUT-D |
| `test_a_blocked_that_answers_none_does_not_block` | the control: `blocked`'s `None` still means "no block" | — |
| `test_a_gate_that_raises_blocks` | a gate that raises **blocks** | MUT-G |
| `test_a_gate_that_answers_neither_method_blocks` | a gate with no query method **blocks**, and says so | MUT-H |

**Two survivors, and what they cost.**

* **MUT-D survived the first version of the guards.**  Reading `None`
  as "allowed" killed nothing, because the house registry's `check`
  never returns `None` — the path was unreachable from the house code.
  The guard was added by planting the mutation and re-running, and it
  now kills it.  A guard that cannot be reached is not a guard.
* **MUT-H survived the first version too, and for a worse reason.**  With
  the explicit "can answer neither" branch deleted, the registry fell
  through to calling a missing method; the resulting `TypeError` was
  caught by the generic handler, which **failed closed by accident**, with
  a different message.  Every test still passed.  The guard now asserts
  the **message**, so the branch is load-bearing rather than
  accidentally-necessary.  A guard that fails for the wrong reason is a
  guard that can be deleted without anyone noticing.

### 9.5 Measured

| measurement | result |
|---|---|
| targeted suites (`refusal_hold`, `refusal_hold_wiring`, `refusal_hold_queue_wiring`, `forward_seal_ledger`, `cancellation_gate`) | 316 passed, 10 subtests passed |
| the two refusal-wiring files alone | 141 passed |
| mutants planted and re-run | MUT-B, MUT-C, MUT-D, MUT-E, MUT-F, MUT-G, MUT-H, MUT-I, MUT-J, MUT-K all **killed**; MUT-A **survives**, and the no-op it exposes is why `_is_refusal_registry`'s body is unchanged |
| the ORIGINAL (pre-fix) ledger against the new guards | 3 guards fail — the defect is caught by the guards, not assumed |

### 9.6 What this does NOT change

* The house `RefusalHoldRegistry` path is **untouched**: it declares
  `is_refusal_registry`, and it was already refusing correctly.
* The **lift** path for genuine tombstones is untouched — a real
  `Tombstone` carries neither `row` nor `row_digest`, and
  `test_a_cancellation_is_still_liftable` pins that it still lifts.
* The **open items** are unchanged: 2 (the subject layer) and 3 (no lift
  path) are still open.  This section closes neither.
* The gate's **answers** are unchanged.  Only the *meaning* of an
  answer, and what the ledger does with it, changed.

## 10. AMENDED 2026-11-23 — the QUEUE side has no gate at all

### 10.1 The asymmetry

`refusal_hold.py`'s module docstring names the two re-dispatch paths that
actually send the action again:

> The two paths that actually **send the action again** --
> ``JobQueue.retry()`` returning a job to ``ready`` and
> ``LeasedTaskClaim.fail()`` returning a task to ``ready``.

And it says neither sits on the refusal path.  §7 landed the *identity*
for both sides and §8 landed the *auditing* for both sides.  But the
**gate itself** is installed on only one of them:

| | gate installed in the object? | how a caller consults it |
|---|---|---|
| `LeasedTaskClaim` (lease side) | **yes** -- `refusal_gate=` / `set_refusal_gate()` | the object asks it itself, inside its own transaction |
| `JobQueue` (queue side) | **no** -- `job_queue.py` mentions "refusal" **zero** times | the caller must wrap the call in `install_queue_refusal_gate(...)` **by hand** |

`install_queue_refusal_gate` is a correct, tested context manager.  The
problem is that it is **opt-in at every call site**, and the call sites
are the host's, not the runtime's:

```python
queue = JobQueue()
gate = RefusalHoldQueueGate(registry)
gate.record_queue("job-1", "dispatch", row=make_row())
queue.retry("job-1", 3)
# -> the job goes back to "ready"
```

Measured on this branch, 2026-11-23, with the refusal recorded and the
gate built but **not** wrapped around the call:

```
reserved: reserved
after a plain retry, job-1 state = ready
=> the refusal was on the books, and the job went back to ready: True
```

The refusal is faithfully recorded, the gate can answer, and the job goes
back to ``ready`` anyway.  That is the exact failure `refusal_hold.py`'s
docstring warns about -- *"recorded but not enforced ... which is worse
than not recorded, because the ledger creates the illusion that the
refusal was handled"* -- reproduced on the side that has the identity
and the auditing but not the gate.

The lease side avoids it because the gate is **inside the object**:
`fail()` calls `self._require_refusal_allows(...)` itself, inside its
transaction, immediately before the ``UPDATE`` that flips the task back
to ``ready``.  There is no call site for the host to forget.

### 10.2 The fix

`JobQueue` grows the same seam the lease side has:

* `JobQueue.__init__(..., refusal_gate=None)` and
  `set_refusal_gate(gate)` / a `refusal_gate` property;
* `retry()` asks the gate **inside its own lock**, immediately before it
  flips the entry to ``ready`` -- so the gate's answer and the write are
  serialized, exactly as the lease side's are.

The action identity is the job's own ``task`` string, which `JobQueue`
already carries on every entry -- no schema change, and the same
identity §7 established.

**The gate is duck-typed**, as on the lease side: `job_queue.py` does
not import the wiring (the wiring imports the hold, and the hold must
not drag the queue ledger in).  It must offer
`require_queue_allowed(job_id, action, now=...)`.

**The check is raised, not boolean.**  `retry()` reports ONE job for ONE
call, so a refusal can raise -- the caller asked about that job and
nothing else.  (The lease side has a second, boolean path for `reap()`,
which sweeps a **batch**; `JobQueue` has no batch sweep over retries, so
there is no boolean form here, and inventing one would create a second
question with a different answer.)

**`install_queue_refusal_gate` stays.**  It is not removed: it is the
way a host binds the gate into a queue it does not own, and its
context-manager form is still correct.  But it is no longer the *only*
way to get a gate onto a queue -- and a host that installs the gate in
the object gets the guarantee without having to remember.

### 10.3 The guards, and why they can fail

| guard | what it pins |
|---|---|
| `test_a_refused_retry_leaves_the_job_reserved` | the observable proof: the job does **not** go back to ``ready`` |
| `test_the_gate_is_consulted_without_any_wrapping` | the defect itself: a plain `retry()` with the gate installed in the object is refused -- **no context manager** |
| `test_an_allowed_retry_puts_the_job_back_to_ready` | the control: no refusal, the re-dispatch happens |
| `test_a_different_action_is_not_refused` | the refusal covers one action, not the whole job |
| `test_a_broken_gate_leaves_the_job_reserved` | an unusable gate fails **closed** |
| `test_the_gate_is_asked_under_the_queue_lock` | the gate's answer and the write are serialized |
| `test_a_refusal_recorded_concurrently_never_loses_to_a_retry` | "recorded but still re-dispatched" must never happen |
| `test_a_queue_without_a_gate_behaves_exactly_as_before` | the default is unchanged: a queue with no gate seals as before |

The second guard is the one that can fail on the defect: it makes the
plain `retry()` call -- the one a host writes -- the thing under test,
with no wrapping to hide behind.

### 10.4 Measured, and what the mutation run found

**The defect, measured on the tree before the fix:**

```
reserved: reserved
after a plain retry, job-1 state = ready
=> the refusal was on the books, and the job went back to ready: True
```

**The mutants.**  Every guard was checked by planting the defect and
re-running.  A guard that was not killed was **fixed**, not waived.

| mutant | what it plants | killed by |
|---|---|---|
| MUT-A | the gate call deleted from `retry()` | 5 guards |
| MUT-B | the gate asked **outside** the queue's lock | 5 guards (incl. `test_the_gate_is_asked_under_the_queue_lock`) |
| MUT-C | the action identity is the `job_id`, not the job's `task` | 3 guards |
| MUT-D | a gate that does not offer the required method is **ignored** (fail-OPEN) | 1 guard |
| MUT-G | the registry is **not bound** to the queue's lock | 1 guard (the concurrency guard) |

**The concurrency guard was rewritten once, because the first version
could not fail.**  The first version asserted on the **final state** —
"the job is not back in ``ready``".  That assertion **survived** MUT-G,
and it survived for a structural reason: the final state is ``ready`` in
BOTH the legal order and the illegal one.  The retry winning the race
leaves the job in ``ready`` (the action was issued, and is then
refused), and the recording winning it also leaves the job in
``ready`` (the refusal was recorded, and the re-dispatch went out
anyway — the defect).  A single final state cannot tell those apart;
only the **order** can.

The rewritten guard asserts on completion order: the recording must
never complete before the retry.  It also **widens the window
deliberately** — the gate pauses inside the queue's lock just before it
answers — because with plain timing the recording thread rarely wins the
race, and a guard that cannot lose is not a guard.  With the pause, the
mutant is caught every time:

```
E  AssertionError: 'record' != 'retry'
E    the refusal was recorded BEFORE the retry completed, so the retry
E    had the refusal on the books and must have been refused -- the job
E    went back to ready anyway
```

**Suites.**  87 passed across `test_refusal_hold_queue_wiring.py` and
`test_job_queue.py`; 347 passed + 10 subtests across the five
targeted refusal/lease/ledger suites; the repo suite 461 passed +
6230 subtests under pytest and `Ran 461 tests ... OK` under unittest;
`job_queue`'s own self-check: `job-queue OK: enqueue, priority,
dequeue, ack, retry, delay, dead`.

## 11. AMENDED 2026-11-23 — `claim()` hands a refused action to a worker

### 11.1 The defect

§7.4 says `LeasedTaskClaim` has **three** paths that put a task back to
`ready`, and that all three consult the gate.  That is true, and it is
also **the wrong enumeration**.

`claim()` does not put a task back to `ready`.  It takes a task **out
of** `ready` and hands it to a worker:

```python
conn.execute(
    "UPDATE ltc_task SET state = ?, worker = ?, token = ?, ...",
    (STATE_LEASED, worker, token, float(now), expires_at, task_id),
)
```

That is the **re-dispatch itself** -- the moment the action is offered
to somebody.  And it consults no gate.

Measured on this branch, 2026-11-23, with the lease-side gate
installed and a refusal recorded against the lease namespace
(`task:task-1:dispatch`):

```
=== CASE 1: FIRST claim of a READY task ===
  claim SUCCEEDED -- the refused action was offered to w1
=== CASE 2: TAKEOVER claim of an EXPIRED lease ===
  TAKEOVER SUCCEEDED -- the refused action was offered to w2
=== CASE 3: for contrast, reap() on the same expired lease ===
  reap returned: ()
  lease state after reap: leased
```

Case 3 is the contrast that makes the defect legible: the **reaper**
(which merely *cleans up* an expired lease) refuses, while the
**claim** (which actually hands the work to a worker) succeeds.  The
guard is on the cheap path and not on the one that matters.

So the three paths §7.4 enumerated are the three ways a task goes
**back** to ``ready``, and there is a **fourth** path that takes it
**out** of ``ready`` again.  A refusal says "this action may not be
offered again", and `claim()` is where it is offered again.

**Why this is worse than the queue side's gap (§10).**  On the queue
side, the gate existed but the host had to remember to install it.  On
the lease side, the gate is inside the object -- and `claim()` simply
does not ask.  The lease side's `release()` docstring states the rule
the code is missing:

> The question is not whether the work item failed; it is whether the
> work item may be **offered again**, and a refusal says no by any
> route.

`claim()` is exactly "offered again", and it asks no route.

### 11.2 The fix

`claim()` consults the gate **inside the same transaction**, immediately
before the `UPDATE` that installs the lease.  A refusal raises, the
transaction rolls back, and the task keeps its state and its worker.

**Which form: raising or boolean?**  `claim()` reports ONE task for ONE
call, and the caller asked about that task and nothing else -- so it
uses the **raising** form (`require_task_allowed`), exactly like
`fail()` and `release()`.  The boolean form (`task_allowed`) exists for
`reap()`, which sweeps a **batch** and must not abandon the sweep; there
is no such concern here.

**The takeover case matters.**  A claim of a task whose lease has
expired is a takeover, and it is the case a refusal is most likely to
want to stop: the previous holder crashed, and the work item is being
offered to somebody new.  `claim()` refuses both the first claim and
the takeover, because the gate is asked on every claim.

**What this does NOT change.**  `claim()` still refuses a terminal task
(`completed`, `dead`) and still refuses a live lease
(`LeaseHeldError`); those checks come first and are untouched.  The gate
is asked **after** the state checks and **before** the `UPDATE`, so a
task that is not claimable at all still fails for its own reason.

### 11.3 The guards, and why they can fail

| guard | what it pins |
|---|---|
| `test_a_refused_claim_leaves_the_task_ready` | the observable proof: the task does **not** go to ``leased``, and no worker gets it |
| `test_a_refused_takeover_leaves_the_task_leased` | the takeover case: an expired lease is **not** taken over |
| `test_a_refusal_recorded_before_the_claim_blocks_it` | the ordering: the refusal is on the books *before* the claim, so the claim is refused |
| `test_an_allowed_claim_still_hands_the_task_over` | the control: no refusal, the claim works exactly as before |
| `test_a_different_action_is_not_refused` | the refusal covers one action, not the whole task |
| `test_a_broken_gate_refuses_the_claim` | a gate that cannot answer fails **closed** |
| `test_a_gate_without_the_required_method_is_refused` | an unusable gate is refused, not ignored |
| `test_a_terminal_task_is_still_refused_for_its_own_reason` | the gate does not change the *other* refusals |
| `test_a_terminal_and_refused_task_fails_for_its_own_reason` | the **order** of the two checks, made observable |
| `test_no_gate_leaves_the_claim_path_unchanged` | the default is unchanged: no gate, no behaviour change |

The first two are the ones that can fail on the defect: both make the
**plain `claim()` call** -- the one a host writes -- the thing under
test, with no wrapping to hide behind.

**The mutation run.**  Every guard above was checked by planting the
defect it is supposed to catch and re-running `LeaseClaimWiringTests`.
Six defects, five killed, one proved to be an equivalence:

| # | the planted defect | result |
|---|---|---|
| MUT-1 | the gate call deleted from `claim()` | **KILLED** by 5 guards |
| MUT-2 | the gate asked about the wrong action (`task_id` instead of the action) | **KILLED** by 3 guards |
| MUT-3 | an unusable gate ignored instead of refused (fail **open**) | **KILLED** by 1 guard |
| MUT-4 | a gate that raises swallowed (fail **open**) | **KILLED** by 4 guards |
| MUT-6 | the gate asked **outside** the transaction | **KILLED** by 5 guards |
| MUT-7 | the gate asked **before** the terminal/live-lease checks | **KILLED** by 1 guard |
| MUT-5 | the gate asked **after** the lease `UPDATE`, still inside the transaction | **SURVIVED** -- and that is an equivalence, proved below |

**MUT-5 is an equivalence, not a missing guard.**  The transaction
rolls back on the raise, so asking the gate immediately before or
immediately after the `UPDATE` inside the same transaction produces the
**same observable outcome**.  Measured by running both versions of the
module against the same probe and comparing the full task row (state,
worker, token, failures, crashes, delay) and the exception raised, for
the refused first claim, the refused takeover and the allowed claim:

```
ORIGINAL : {"A": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": "RefusalRefusedError", "state": "ready",
                   "token": 0, "worker": ""},
            "B": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": "RefusalRefusedError", "state": "leased",
                   "token": 1, "worker": "w1"},
            "C": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": null, "state": "leased",
                   "token": 1, "worker": "w1"}}
MUT-5    : {"A": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": "RefusalRefusedError", "state": "ready",
                   "token": 0, "worker": ""},
            "B": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": "RefusalRefusedError", "state": "leased",
                   "token": 1, "worker": "w1"},
            "C": {"crashes": 0, "delay_until": 0.0, "failures": 0,
                   "raised": null, "state": "leased",
                   "token": 1, "worker": "w1"}}

EQUIVALENT
```

MUT-6 is the one that shows the *transaction* is load-bearing: the
same check asked **outside** the transaction leaves the lease
**installed** and the task gone to `leased`, so it is killed by five
guards.  Moving the call *within* the transaction cannot change
anything, because the rollback undoes it either way.

**MUT-7 needed a guard that did not exist yet.**  The first version of
the terminal-task guard had no refusal on the books, so it could not
tell the two checks apart and MUT-7 survived it.  The order is only
observable when the task is **both** terminal **and** refused, so
`test_a_terminal_and_refused_task_fails_for_its_own_reason` was added
to make the order visible: the task's own terminal state is the reason
the claim fails, and the refusal is a second, unrelated reason.  If the
gate were asked first, the caller would be told the action is *held*
when the truth is that the task is *done* -- and would go looking for a
refusal that is not why the claim failed.

### 11.4 The interaction with the mirror's own retry

`claim()` and `release()` and `fail()` all end with `_mirror_reserve()`
or `_mirror_release()`, which call `self._queue.retry(...)` on the
**queue mirror**.  Now that the queue side carries a gate of its own
(§10), a host that installs a queue-side gate on a queue that is also
acting as a lease mirror would have the mirror's **internal
bookkeeping** refused by the gate.

Measured, before this section's fix:

```
release RAISED: RefusalRefusedError : job 'task-1' may not be
re-dispatched for action 'dispatch': a recorded refusal covers it
```

The mirror's `retry()` is not a re-dispatch of the work item -- it is
the mirror's own bookkeeping, keeping the queue's view of the task in
step with the lease's view.  The two namespaces are different
(``queue:`` versus ``lease:``), so a **lease**-namespace refusal does
not block a **queue**-namespace check; but a host that records the
refusal in the *queue* namespace, on a queue that is a lease mirror,
would block the mirror's own bookkeeping.

This is recorded here rather than fixed in this slice, because it is a
**composition** question -- "what happens when a queue is also a lease
mirror" -- and it is a question about the mirror's bookkeeping, not
about the claim path this section closes.  The honest statement is: the
queue-side gate treats **every** `retry()` as a re-dispatch, including
the mirror's internal ones, and that is a decision this slice has not
yet made deliberately.

**RESOLVED 2026-11-23 — see §13.**  The decision was made deliberately
there, and making it surfaced two **pre-existing** defects that this
section had not found: a completed task's mirror job went back to
`ready`, and the mirror's release ran outside the lease transaction.

**CLOSED 2026-11-23 — see §16.2.**  The composition question that
remained after §13 -- what happens to the **mirror's own reservation**
when a queue-namespace refusal covers a mirror job -- was measured, and
the answer is safe: the mirror takes the refusal, the lease transaction
rolls back, and the two ledgers stay in step.

## 12. OPEN 2026-11-23 — the strands slice's BENCH_DIFF is a baseline-pointer question, not a strands question

`b173-accept.sh strands` reports `FAIL (10/11, 1 skipped)` with one failing
item, `BENCH_DIFF`:

```
FAIL BENCH_DIFF 8 item(s) differ from baseline 2db42e939477bc2ceca9f20d35384dfc7731e972 set
```

**The mechanism, measured.**  `b173-accept.sh`'s `BENCH_DIFF` compares the
slice's bench artifact's failing-item SET against the baseline file the
pointer `b173-bench-baseline-CURRENT` names.  The pointer names

    b173-bench-baseline-2db42e939477bc2ceca9f20d35384dfc7731e972.failures.txt

which holds **8** failing items.  A newer baseline file exists on the
machine and is **EMPTY** --
`b173-bench-baseline-69578b51b45d823e106ea48b1ca4c31366c101f0.failures.txt`
-- because A-1..A-3 (the seccomp fd rewind, the Landlock path filter, the
bench command rewrites) turned all 8 green.  The pointer was never moved.

**And no single pointer satisfies every slice.**  The bench failing-item set
is **per-era**: an artifact run before the fixes carries the 8 items, and an
artifact run after them carries 0.  Measured with the pointer moved to the
new file, on two slices that sit on opposite sides of the fix:

| slice | pointer at OLD (8 items) | pointer at NEW (0 items) |
|---|---|---|
| `strands` (artifact re-run 2026-11-23, after the fixes) | FAIL 10/11 | **PASS 11/11** |
| `fable` (artifact run 2026-11-14, before the fixes) | PASS 12/12 | **FAIL 11/12** |

**So re-pointing the bench baseline is not a fix -- it is a trade**, and it
is the **coordinator's** call (`docs/design/r6-baseline-unify.md` §5.1: "a
slice that legitimately fixes a pre-existing failure will show 'fewer items
than the baseline', which is a real finding to report, not a reason to
re-take the baseline").  This slice therefore reports it and does not do it.

**The repo's own CI is not affected.**  `scripts/b173-baseline-check.sh`
prefers the coordinator's file but falls back to
`docs/baseline/current.failures.txt`, which is **EMPTY** and matches the
current tree.  A CI runner has no `/home/muse-newapi`, so it selects the
local copy and reports MATCH.  The full-suite pointer
`b173-baseline-CURRENT` names the same retired 26-item baseline, and it is
the same question.

**A note on how this was measured.**  The pointer was moved and restored
while the component suite was running in the background, and the
`test_r8_tests_ran_ownership` test -- which shells out to `b173-accept.sh`
-- read the moved pointer mid-run and failed.  That failure was **this
measurement's interference**, not a defect: re-running the test clean gives
9 passed.  A file in the coordinator's directory is shared state, and
changing it while another job reads it is the same mistake as editing a
file another agent is working in.

---

## 13. AMENDED 2026-11-23 — the mirror and the ledger disagreed in two ways

§11.4 recorded the composition question as **open**: "the queue-side gate
treats **every** `retry()` as a re-dispatch, including the mirror's internal
ones, and that is a decision this slice has not yet made deliberately."

This section makes that decision, and in making it found two defects that
were **pre-existing** -- they reproduce at `372f5225` (before the `claim()`
work) and date to the module's first commit `1c7e44b1`.

### 13.1 The decision: what the mirror's own `retry()` IS

The mirror's `retry()` is **not** a re-dispatch of the work item.  It is the
mirror's own bookkeeping: it keeps the queue's view of the task in step with
the lease's view.  The distinction is the same one the whole slice turns on:

| the write | what it means | is it a re-dispatch? |
|---|---|---|
| a worker is handed a task | the action is **offered** | **yes** |
| a task goes back to `ready` | the action is **offered again** | **yes** |
| a task goes to `completed` / `dead` | the action is **withdrawn** | **no** |

So a **refusal** -- which is about the offer -- does not block a withdrawal.
A refusal that could keep a finished work item in the queue forever would be
the refusal's own denial of service.  This is why `JobQueue.ack()` never
consults the gate, and why the new `JobQueue.dead()` does not either.

### 13.2 DEFECT 1 — a terminal task's mirror job went back to `ready`

Every terminal path called `_mirror_release()`, which calls `queue.retry()`.
And `retry()` is the **re-dispatch** operation.  So a **completed** task's
mirror job went back to `ready`:

```
=== a COMPLETED task's mirror job goes back to 'ready' ===
  mirror state after complete(): ready
  ledger state: completed
=== so the mirror can DEQUEUE a completed task's job ===
  dequeue -> t1
=== and can it be CLAIMED again? (lease side says no) ===
  claim REFUSED: TerminalTaskError
=== the same for a DEAD task ===
  mirror state after fail(): ready
  ledger state: dead
```

The work was not re-run -- the lease side refused the re-claim with
`TerminalTaskError` -- but the mirror **advertised a finished work item as
available**, and the queue is the ledger the dispatcher reads.  The two
ledgers disagreed about a task that is over.

**The fix.**  The queue had an `ack()` for terminal success, which the mirror
never used.  It had **no** terminal-failure operation at all: the only way to
make a job terminal-failed was to exhaust its retry budget, which also books
a `MaxRetriesExceededError`.  So `job_queue.py` gains `dead()`, and the
mirror's terminal transition is the queue's OWN terminal operation:
`ack()` for a completion, `dead()` for an exhausted budget.

After the fix:

```
=== a COMPLETED task's mirror job ===
  mirror state after complete(): done
  ledger state: completed
  dequeue -> None
=== a DEAD task's mirror job ===
  mirror state after fail(): dead
  ledger state: dead
```

### 13.3 DEFECT 2 — the mirror's release ran OUTSIDE the lease transaction

`_mirror_release` was called **after** the lease transaction committed, in
`complete()`, `fail()`, `release()` and `reap()`.  Only `claim()` called its
mirror inside the transaction.  A structural scan of the module, before the
fix:

```
line 895:  def claim(...)     -> INSIDE   the transaction
line 1108: def complete(...)  -> OUTSIDE  the transaction
line 1185: def fail(...)      -> OUTSIDE  the transaction
line 1230: def release(...)   -> OUTSIDE  the transaction
line 1292: def reap(...)      -> OUTSIDE  the transaction
```

A refusal recorded in the **queue** namespace -- the mirror's own gate, and a
namespace deliberately distinct from the lease's -- made the mirror's
`retry()` refuse, and that refusal arrived **after** the lease ledger had
already committed:

```
=== (a) queue-namespace refusal on release ===
  release RAISED: RefusalRefusedError
  ledger state: ready
  mirror state: reserved
  audit kinds: ['task.enqueued', 'lease.claimed', 'lease.released']
```

Three things are wrong at once:

* the ledger says `ready` and the mirror says `reserved` -- the two ledgers
  disagree, which is exactly what `QueueMirrorError` exists to prevent;
* a `lease.released` audit row was written for a release that was **refused**
  -- the trail says the release happened;
* the task was **stuck**: the ledger said `ready` (so the reaper found no
  lease to sweep) while the mirror said `reserved` (so the claim refused to
  reserve it again).  Neither ledger would move it.

**Why "move the call inside", and not "swallow the refusal".**  Swallowing
would hide the refusal: the caller would believe the release happened, and the
trail would say so, while the mirror kept the job reserved.  That is the
"recorded but not enforced" failure the hold's own docstring warns about.

Moving the call inside the transaction fixes all three symptoms at once: a
refused mirror release rolls the lease write back, so the task stays
**leased** by the same worker, no `lease.released` row is written, and the
mirror stays `reserved` -- which is the state a leased task's mirror job is
in.  The worker can still finish the work it was doing.

After the fix:

```
=== (a) queue-namespace refusal on release ===
  release RAISED: RefusalRefusedError
  ledger state: leased
  mirror state: reserved
  audit kinds: ['task.enqueued', 'lease.claimed']
  claim REFUSED: LeaseHeldError task t3 is leased by worker-A until 110.0
  reap -> ()
```

The two namespaces now say the **same thing** about the same write: a
lease-namespace refusal and a queue-namespace refusal both leave the task
leased and the mirror reserved.

### 13.4 The sweep is a different shape, and stays that way

`reap()` sweeps a **batch** of expired leases.  A raise there would abandon
the sweep: one refused task would stop every other expired lease from being
requeued, which is a denial of service the refusal never asked for.  So the
sweep uses the **boolean** form at both levels:

* the lease-side question is already the boolean `task_allowed`;
* the mirror-side question is now the boolean `retry_allowed`.

`JobQueue.retry_allowed()` is the new batch-safe form of `retry()`: it
returns `None` for "not re-dispatched" -- a refused job, a job that is not
reserved, an unknown job, or a job whose retry budget is spent -- and it
leaves the job exactly where it was.  `None` means "not re-dispatched", the
same way `dequeue`'s `None` means "no job": data, not a failure.

The two forms share **one writer** (`JobQueue._retry`), so the gate is
consulted **once** per job whichever form is used.  That matters because the
gate's check is audited: a double ask would book a double event and double
the gate's own cost for no reason.

### 13.5 The guards, and why they can fail

| the guard | the defect it can fail on |
|---|---|
| `test_a_completed_task_is_done_in_the_mirror` | the terminal job stayed `ready` |
| `test_a_completed_task_cannot_be_dequeued_from_the_mirror` | the queue handed out a finished task |
| `test_a_dead_task_is_not_ready_in_the_mirror` | the exhausted task stayed `ready` |
| `test_a_released_task_is_still_ready_in_the_mirror` | the control: a release is still a re-dispatch |
| `test_a_reaped_task_is_still_ready_in_the_mirror` | the control: a crash-requeue is still a re-dispatch |
| `test_a_failed_task_that_still_has_budget_is_ready` | the control: a failure with budget left is a re-dispatch |
| `test_a_refused_release_leaves_the_task_leased` | the ledger committed while the mirror refused |
| `test_a_refused_release_leaves_the_ledger_and_the_mirror_in_step` | the two ledgers disagreed |
| `test_a_refused_release_writes_no_released_audit_row` | the trail recorded a release that was refused |
| `test_a_refused_release_leaves_the_worker_able_to_finish` | the release half-happened |
| `test_a_refused_release_does_not_book_a_failure` | the refusal consumed the failure budget |
| `test_a_refused_release_in_the_lease_namespace_is_the_same` | the two namespaces disagreed |
| `test_one_refused_task_does_not_stop_the_sweep` | the sweep was abandoned |
| `test_a_refused_task_stays_reserved_in_the_mirror` | the skipped task was re-offered |
| `test_a_refused_task_is_not_swept_again_either` | a later sweep silently took it |
| `test_dead_never_hands_the_job_out_again` | a dead job stayed eligible |
| `test_dead_does_not_consult_the_refusal_gate` | a refusal could freeze a finished job |
| `test_retry_allowed_asks_the_gate_once_when_the_job_is_allowed` | the gate was asked twice |

**Measured.**  Eight mutants planted and re-run; all eight killed:

| mutant | verdict |
|---|---|
| M1 `dead()` -> `retry()` (the original defect) | **KILLED** |
| M2 the mirror's release moved back OUTSIDE the transaction | **KILLED** |
| M3 `reap()` uses the RAISING mirror form | **KILLED** |
| M4 `reap()` asks the mirror AFTER the `UPDATE` | **KILLED** |
| M5 `dead()` consults the refusal gate | **KILLED** |
| M6 `retry_allowed` asks the gate twice | **KILLED** |
| M7 `retry_allowed` raises instead of returning `None` | **KILLED** |
| M8 `dead()` does not set the state | **KILLED** |

**M6 needed a second guard, and that is worth recording.**  The first
version of the counting guard used a gate that **refuses** every job -- and a
refused job returns before the write, so a second ask was never reached and
the mutant **survived**.  The guard that kills it asks an **allowing** gate,
which reaches the write.  A guard that exercises only the refused path does
not cover the ordinary path, and a mutant that only shows up on the ordinary
path is a mutant the guard was blind to.

### 13.6 What this does NOT change

* The two namespaces stay separate.  A lease-namespace refusal still does
  not block a queue-namespace check, and the mirror's own bookkeeping is
  still the queue's business.
* The lease side's own gate is unchanged: `fail()`, `claim()` and
  `release()` still ask it inside their own transaction, and `reap()`
  still asks it in the boolean form.
* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`); `dead()` and
  `retry_allowed()` are new **operations** on the existing ledger, not a
  new record shape -- `DeadRecord` is a new record, but it carries the
  same schema pin as `AckRecord`, and the audit kinds are the existing
  `job.dead` and `job.retried`.
* `leased_task_claim.py`'s version and schema pins are unchanged.
* The design doc's own open item 1 ("the queue mirror and the lease ledger
  are two ledgers ... a crash between the SQLite commit and the mirror
  update would leave the two out of step") is **narrowed**, not closed:
  the mirror calls are now inside the transactions, so the window is much
  smaller, but the mirror is still an in-process ledger and a crash
  between the two commits is still possible.  The reconciliation is still
  the host's job.

---

## 14. AMENDED 2026-11-23 — the registry half-recorded a refusal it refused, and it healed a broken gate

§13 fixed the mirror.  The same round found **two more defects** in the
refusal **registry** itself (`refusal_hold_wiring.py`), both of them
**fail-open** in the direction that matters, and both of them
pre-existing.

### 14.1 DEFECT 3 — a refused record was half-recorded

`RefusalHoldRegistry.record_entry()` appended to `self._entries` and
**then** rebuilt the store.  The rebuild is what enforces the hold's
bound (`MAX_HOLD_ENTRIES`, 256), and it raises when the bound is passed --
so the append had already happened when the raise arrived.

Measured on the tree before the fix:

```
BEFORE the failing record:
  reg._entries len  : 256        # the store's bound
  reg.hold entries  : 256
  reg.store entries : 256
  to_dict entries   : 256
  events            : 256

FAILED RECORD: RefusalHoldWiringError wiring: a hold carries at most 256
                refusals, got 257

AFTER the failed record:
  reg._entries len  : 257        # <-- grew, despite the failure
  reg.hold entries  : 256
  reg.store entries : 256
  to_dict entries   : 257        # <-- and is now UNRECONSTRUCTIBLE
  events            : 256
```

Three consequences, in increasing order of severity:

1. **The registry's own view of itself is a lie.**  `to_dict()` reports
   257 entries while the store holds 256, so the two disagree about
   what was recorded.

2. **The registry can no longer be rebuilt.**  `to_dict()` is the shape
   a host persists and restores, and restoring it raises: `a hold
   carries at most 256 refusals, got 257`.  A host that persisted a
   registry and tried to restore it gets a hard failure -- and it gets
   it *because of* a record that was REFUSED.

3. **The refusal mechanism is FROZEN.**  Every subsequent record fails
   the same way, because the store is already at its bound and the
   refused append keeps pushing `_entries` further past it.  Measured:
   after the first failure, three further records all failed and
   `_entries` grew to 259; after 200 more failed records `_entries` was
   459 while the store stayed at 256.  So the registry grows without
   bound and stores nothing new: **a host that records refusals for
   more than 256 actions has a gate that can no longer refuse anything
   it is asked about afterwards.**  The gate does not fail closed -- it
   keeps answering "allowed".

**The fix.**  The bound is checked **before** the mutation, the way
`cancellation_tombstone.TombstoneSet` checks `MAX_TOMBSTONES` before it
adds:

```python
if not any(entry.key == key for entry in self._entries):
    if len(self._entries) >= MAX_HOLD_ENTRIES:
        raise RefusalHoldWiringError(...)
    self._entries = list(self._entries) + [RefusalHoldEntry(key=key, row=row)]
    self._rebuild_store(now=now)
    self._record_event("recorded", key, None)
```

And a **duplicate key is not a new refusal**: the store returns the
FIRST entry whose key matches, so a second entry for the same key is
unreachable -- it shadows nothing and is shadowed.  Recording the same
key twice therefore needs no second slot, is a no-op for the store, and
must be a no-op for the registry too.  Before the fix, a duplicate
consumed a slot of the bound, so 256 duplicates exhausted a registry
that held exactly one refusal.

### 14.2 DEFECT 4 — the registry healed a broken gate and dropped a host's rows

`RefusalHoldRegistry.__init__` accepts a `hold`, and the hold may carry
a **host's own store** -- `RefusalHoldStore`'s own docstring says so:
"A caller with rows on disk supplies its own store; the hold only
requires the store to answer `fetch`".  But the registry did not keep
the hold's store: it built a **fresh** `RefusalHoldStore(self._entries)`
and a fresh hold over it.

So two things the host configured were silently dropped.

**The unreadable flag.**  A store the host broke (or one that is
unreadable because the disk is gone) came back READABLE:

```
the hold's own answer (broken store): blocked_store_unreadable
REGISTRY store readable after construction: True
registry check: blocked_by_refusal
```

The direction is **fail OPEN**: the registry's own contract says "a
broken gate blocks" and "an unreadable store is not a clean read: it
blocks", and the construction path turned a blocked answer into an
allowed one.

**The rows.**  A store that carries the host's rows (the shape
`RefusalHold(entries=[], store=disk_store)` produces) was emptied by
the registry:

```
the HOLD's own answer for job-1: blocked_by_refusal
the REGISTRY's answer for job-1: allowed_no_refusal
registry entries: 0   store entries: 0
```

A host that loaded its refusals from disk and handed them to the
registry got a gate that **knows about no refusals at all** -- and the
answer is "allowed".  That is the one answer that must never be given
by accident.

**And the rebuild dropped them again.**  `_rebuild_store()` replaces the
store with a fresh one built from the registry's own `_entries` -- and
for a registry built over a host store, those are empty.  So even after
the construction was fixed, the **first recording** discarded every
refusal the host had loaded:

```
before record: check job-1 = blocked_by_refusal
AFTER  record: check job-1 = allowed_no_refusal
```

**The fix.**  The registry reads the store it was handed
(`RefusalHold` now exposes `store`), and the rebuild **seeds the new
store from both** the registry's own entries and whatever the store
already carries.  A broken store stays broken through both paths, which
is the rule `_rebuild_store` already stated for itself ("a store that
was broken stays broken: a recording must not heal the gate") but only
honoured for the store the registry owned.

### 14.3 The guards

Thirteen new test methods in `tests/test_refusal_hold_wiring.py`:

| # | guard | what it pins |
|---|---|---|
| 1 | `test_a_refused_record_leaves_the_entries_unchanged` | a refused record adds no entry |
| 2 | `test_the_registry_and_its_store_agree_after_a_refused_record` | `to_dict()` and the store agree |
| 3 | `test_a_refused_record_leaves_to_dict_reconstructible` | the payload still restores |
| 4 | `test_a_refused_record_leaves_the_events_unchanged` | no event is left behind |
| 5 | `test_a_refused_record_does_not_freeze_the_registry` | the gate still answers for what it has |
| 6 | `test_the_registry_does_not_grow_without_bound` | 50 refused records leak no entries |
| 7 | `test_a_duplicate_key_does_not_consume_a_second_slot` | a duplicate is one refusal |
| 8 | `test_a_duplicate_key_is_refused_at_the_bound` | a duplicate needs no slot at the bound |
| 9 | `test_a_broken_host_store_stays_broken` | construction does not heal a broken store |
| 10 | `test_a_host_store_with_rows_is_not_emptied` | construction does not drop the host's rows |
| 11 | `test_a_host_store_with_rows_is_the_registry_store` | the registry reads the store it was handed |
| 12 | `test_a_recording_does_not_drop_the_host_s_rows` | the rebuild does not drop them either |
| 13 | `test_a_broken_host_store_stays_broken_after_a_recording` | the rebuild does not heal it either |

The same round found a **fourth, separate** defect -- the referee
convicting slices that have not started -- which is not a runtime
defect and is written up in
`docs/design/r8-delivered-slice-scope.md`.

**A note on how the capacity defect was found.**  It was found by
*reading the code against the sibling*, not by reading the code alone.
`cancellation_tombstone.TombstoneSet.add` checks its bound **before**
it mutates; the refusal registry appended **first** and rebuilt
**second**, so the bound was enforced by a step that ran after the
mutation.  The two modules do the same thing -- carry a bounded set --
and one of them checks first and the other checks last.  That
difference is the defect.

### 14.4 What this does NOT change

* `refusal_hold.py`'s and `refusal_hold_wiring.py`'s version and schema
  pins are unchanged.  `RefusalHold.store` is a new **read-only
  property**, not a new record shape and not a new operation on the
  ledger.
* The hold's own semantics are unchanged: a refusal still blocks, a
  broken store still blocks, a tampered row still blocks, and a
  malformed key still raises.
* The subject layer is still collapsed, and a refusal still cannot be
  lifted.  Open items 2 and 3 above are unchanged.
* The bound itself is unchanged: `MAX_HOLD_ENTRIES` is still 256, and
  it is still enforced -- it is now enforced **before** the write, and a
  duplicate no longer consumes a slot.

---

## 15. AMENDED 2026-11-23 — `dequeue()` handed out a refused action

### 15.1 The defect

§10 landed the gate **inside** `JobQueue`, so a host cannot forget to
install it, and §11 landed the lease side's `claim()` guard.  But the
queue side guarded **one** of the two re-dispatch routes.

`job_queue.py` has two operations that constitute a re-dispatch:

| operation | what it does | is it a re-dispatch? | guarded? |
|---|---|---|---|
| `retry()` | puts a **reserved** job back to `ready` | **yes** -- the action is offered again | **yes** (§10) |
| `dequeue()` | takes a **ready** job out and hands it to a worker | **yes** -- the action is *issued* | **no** |

`dequeue()` consults no gate.  Measured on this branch, 2026-11-23,
with the refusal recorded in the queue namespace
(`queue:job-1:send_email`) and the gate installed **in the queue**:

```
check job-1/send_email: blocked_by_refusal
DEQUEUE RESULT: ('job-1', 'send_email', 'w-1')
job state: reserved
audit kinds: ['job.enqueued', 'job.dequeued']
```

The refusal was on the books, the gate could answer it, and the action
was handed to a worker anyway.  And the audit trail recorded the
hand-out as a fact.

**What exposed it: the asymmetry with the lease side.**  The lease side
guards **both** routes -- `fail()`/`release()`/`reap()` (back to
`ready`) and `claim()` (out of `ready` into a lease).  §11 closed the
`claim()` hole there.  The queue side guarded only one, and the one it
did not guard is the **more direct** one: `dequeue()` is the ordinary
call a dispatcher writes.

A gate that guards one route is a gate with a door next to it, and
this door was the front door.

### 15.2 The fix

`dequeue()` asks the gate **inside the queue's own lock**, immediately
before the entry is flipped to `reserved`:

```python
self._require_refusal_allows_dequeue(job_id, str(entry["task"]), now)
```

A refusal raises, so the job stays `ready`, no worker holds it, no
attempt is booked, and no `job.dequeued` audit row is written.

**The check is raised, not boolean.**  `dequeue()` reports ONE job for
ONE call, and the caller asked about that job and nothing else --
exactly like `retry()`.  There is no batch sweep over dequeues, so
there is no boolean form, and inventing one would create a second
question with a different answer.

**Which jobs are asked about.**  The gate is asked about the job that
is **about to be handed out** -- the head of the eligible list -- and
not about the jobs behind it.  A refused head **blocks the whole
dequeue**, because the queue's contract is FIFO-by-priority: skipping
the refused job and handing out the next one would silently reorder
the queue, and the refused job would sit at the head forever, blocking
everything behind it.  The refused job stays `ready` and the caller is
told.  (The lease side's `reap()` is the opposite case -- it sweeps a
batch, so it skips one refused task rather than abandoning the sweep.
Different shape, different answer: §13.4.)

**WITHDRAWN 2026-11-23 -- see §16.**  The decision above was **wrong**:
a refusal is scoped to ONE (job, action) pair, not to the queue, and
asking only about the head let one refusal wedge the **entire** queue
**permanently** -- the refused job could never be handed out *and* never
retired (every terminal operation needs it `reserved`), and it blocked
every job behind it forever.  The gate is now asked about the candidates
**in order**, and a refused candidate is **skipped**.  §15's fix -- the
gate is asked inside the queue's own lock, before the write -- stands;
only the *scope* of the question changed.

**The action identity** is the job's own `task` string -- the same
identity §7 established and the same one `retry()` uses.  No schema
change.

**A new `now` parameter.**  `dequeue()` did not take one; it now does,
because the gate takes `now=` and the queue's other two guarded paths
(`retry()`, `retry_allowed()`) already take it.  It defaults to
`None`, so **every existing call site is unchanged**.

### 15.3 The guards, and why they can fail

Eleven new guards: ten in `QueueDequeueGateTests`
(`tests/test_refusal_hold_queue_wiring.py`) and one rewritten in
`tests/test_job_queue.py`.

| guard | what it pins |
|---|---|
| `test_a_refused_dequeue_does_not_hand_the_job_out` | the defect itself: a plain `dequeue()` is refused |
| `test_a_refused_dequeue_leaves_no_worker_holding_the_job` | no worker, and no attempt booked |
| `test_a_refused_dequeue_books_no_dequeued_audit_row` | the trail does not claim a hand-out that did not happen |
| `test_an_allowed_dequeue_still_hands_the_job_out` | the control: no refusal, the dequeue works as before |
| `test_a_refusal_against_a_different_action_is_not_refused` | the refusal covers one action, not the whole queue |
| `test_a_broken_gate_refuses_the_dequeue` | a gate that cannot answer fails **closed** |
| `test_a_gate_without_the_required_method_is_refused` | an unusable gate is refused, not ignored |
| `test_no_gate_leaves_the_dequeue_path_unchanged` | the default is unchanged: no gate, no behaviour change |
| `test_the_gate_is_asked_under_the_queue_lock` | the gate sees the job as `ready` -- it is asked BEFORE the write |
| `test_a_refusal_recorded_concurrently_never_loses_to_a_dequeue` | "recorded but still handed out" must never happen |
| `test_dead_does_not_consult_the_refusal_gate` (rewritten) | the withdrawal is still not gated -- and the count is now taken **after** the dequeue |

**The last one is the interesting one.**  `dead()` must not consult the
gate (a refusal must not be able to keep a finished work item in the
queue forever -- §13.1), and the test counted the gate's asks.  But
now `dequeue()` asks too, so the count included the dequeue and the
guard could no longer tell "the withdrawal asked the gate" from "the
hand-out asked the gate".  The guard now takes its **baseline after
the dequeue**, and the dequeue is made with the gate out of the way
(`_dequeue_around_the_gate`).

That is the same lesson §9.1d's "a count is not a verdict" teaches, in
a new costume: **a count that spans two questions cannot answer either
of them.**

**The mutation run.**  The defect was planted -- the gate call deleted
from `dequeue()` -- and the suite re-run:

```
7 failed, 104 passed
  test_a_broken_gate_refuses_the_dequeue
  test_a_gate_without_the_required_method_is_refused
  test_a_refusal_recorded_concurrently_never_loses_to_a_dequeue
  test_a_refused_dequeue_books_no_dequeued_audit_row
  test_a_refused_dequeue_does_not_hand_the_job_out
  test_a_refused_dequeue_leaves_no_worker_holding_the_job
  test_the_gate_is_asked_under_the_queue_lock
```

Seven of the eleven fail on the defect.  The four that do not are the
**control** (`test_an_allowed_dequeue_still_hands_the_job_out`), the
**scope** guard (`test_a_refusal_against_a_different_action_is_not_refused`),
the **default** guard (`test_no_gate_leaves_the_dequeue_path_unchanged`)
and the **withdrawal** guard (`test_dead_does_not_consult_the_refusal_gate`)
-- each of which must pass on the defective version too, because each
of them is about something the defect does not change.

### 15.4 What this does NOT change

* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`), and no audit kind is
  added or changed.  `dequeue()`'s new `now` parameter is an
  **optional** one: every existing call site is unchanged.
* `ack()` and `dead()` still do not consult the gate -- a **withdrawal**
  is not a re-dispatch (§13.1), and a refusal must not be able to keep
  a finished work item in the queue forever.
* `retry()` and `retry_allowed()` are unchanged, including the
  "one check per job" count that §10 established.
* The lease side is unchanged: `claim()`, `fail()`, `release()` and
  `reap()` ask exactly what they asked before.
* The queue's **ordering** is unchanged.  A refused head blocks the
  dequeue; it does not reorder the queue.
* The mirror composition question is unchanged: §13.1's decision --
  the mirror's internal `retry()` is bookkeeping, not a re-dispatch --
  is unaffected.  (The mirror's internal `dequeue()` is a
  **reservation**, and it is the same operation as a hand-out; a host
  that records a queue-namespace refusal against a mirror job will now
  find that the mirror's own reservation is refused, which raises
  `QueueMirrorError` through the lease transaction and rolls the lease
  write back -- the safe direction.  **CLOSED 2026-11-23 -- see
  §16.2**: that composition was measured, not guessed.  The mirror
  takes its refusal, it does NOT hand out another task's job, and the
  two ledgers stay in step.)

---

## 16. AMENDED 2026-11-23 — a refused head wedged the whole queue

### 16.1 The defect

§15 landed the `dequeue()` gate, and it landed it with a **decision**:
the gate is asked about the **head** of the eligible list only, and "a
refused head blocks the whole dequeue, because the queue's contract is
FIFO-by-priority: skipping the refused job and handing out the next one
would silently reorder the queue."

That decision was **wrong**, and it was wrong in the direction that
matters most: it turned one refusal into a **permanent** denial of
service for the whole queue.

Measured 2026-11-23, on the tree as §15 left it, with a refusal
recorded against `queue:j1:dispatch` and two healthy jobs behind it:

```
--- refused HEAD, two healthy jobs behind it ---
dequeue raised: RefusalRefusedError
states: [('j1', 'ready'), ('j2', 'ready'), ('j3', 'ready')]

--- can the refused job ever be retired? ---
ack   raised: JobStateError job j1 is ready, only reserved jobs may be acked
dead  raised: JobStateError job j1 is ready, only reserved jobs may be killed
retry raised: JobStateError job j1 is ready, only reserved jobs may be retried

--- does j2 ever become reachable? ---
dequeue raised: RefusalRefusedError   (x3, forever)
```

Read that carefully: **nothing could move the refused job again.**
`ack()`, `dead()` and `retry()` all require the job to be `reserved`, and
the refused job could never be reserved -- because the gate refused it.
So the wedge had two halves, and both had to close for the job to come
back:

* the refusal stops it being **handed out** (that was the point of §15);
* and the refusal also stops it being **retired**, because every
  terminal operation needs `reserved` first.

And because the refused head blocked the whole dequeue, **every job
behind it was blocked too**, forever.

So one refusal against one (job, action) pair denied the queue to every
other job, permanently, with no way out.  §13.1's own table says a
refusal is about the **offer**, and this is the refusal's own denial of
service -- exactly what §13.1 said a refusal must not be able to do:

| the write | what it means | is it a re-dispatch? |
|---|---|---|
| a task goes to `completed` / `dead` | the action is **withdrawn** | **no** |

**The justification was the wrong worry.**  "Skipping the refused job
would silently reorder the queue" is true in general and irrelevant
here: the refusal has already made the refused job **not the next one to
be handed out**.  A refused job is not eligible in the first place.  The
reordering worry applies to a job that is eligible and *should* be
handed out; a refused job is not that job.

### 16.2 The fix

The gate is now asked about the candidates **in the queue's own order**,
and the first candidate it **allows** is the one handed out.  A refused
candidate is **skipped**, and the next candidate is asked about.

```python
for candidate in eligible:
    candidate_entry = self._entries[candidate]
    try:
        self._require_refusal_allows_dequeue(
            candidate, str(candidate_entry["task"]), now
        )
    except Exception as exc:
        if not _is_refusal(exc):
            raise          # a BROKEN gate, not a refusal: fail closed
        ...
        continue          # a refused candidate: skip it
    job_id = candidate
    entry = candidate_entry
    break
```

**When EVERY candidate is refused**, the call raises **the gate's own
refusal error** -- the host catches it with the vocabulary it already
knows, and no new error class is introduced.  Nothing is handed out: no
job is reserved, no worker holds one, and no attempt was booked.  A
`job.rejected` row is booked, so the trail records the refusal rather
than a hand-out that did not happen.

**A broken gate is NOT a refusal, and is not skipped.**  This is the
load-bearing distinction in the fix.  The skip is only sound for a
**per-job** refusal; a gate that cannot answer at all is a property of
the **gate**, and skipping it would turn a broken gate into a silently
degraded queue -- fail-**OPEN**.  So the classification is explicit
(`_is_refusal`), and it is drawn on the error's own vocabulary: the
error carries a `reason` attribute whose value is one of the hold's
`blocked_*` reasons, or its class name is `RefusalRefusedError`.  A
`RuntimeError` from a broken gate and the `TypeError` this module
raises for an unusable gate are both **not** refusals, and both fail the
whole call.

**Why the skip is safe in the queue and NOT safe in the mirror.**  The
queue's own dispatcher reads the ledger and chooses which job to offer;
skipping a refused one is the dispatcher's business.  The **mirror's**
reservation is a by-task operation with a **fixed target**: the mirror
must reserve *that* task's job, and there is no "the next one" for it to
fall back to.  Handing out a **different** task's job there would break
the correspondence between the two ledgers -- which is what
`QueueMirrorError` exists to prevent.  So the mirror takes its refusal,
and the lease transaction rolls back.

That is safe **because each mirror task has its own queue**:
`LeasedTaskClaim.queue_name_for()` returns `task:<task id>`, so the
mirror's reservation has exactly **one** candidate and the skip has
nothing to skip to.  Measured:

```
mirror queue names: ['task:t1', 'task:t2']
claim raised: RefusalRefusedError job 't1' may not be re-dispatched ...
mirror: ready   ledger: ready
audit: [('job.enqueued', 't1'), ('job.enqueued', 't2'), ('job.rejected', 't1')]
```

Both ledgers stay `ready`, the lease write is rolled back, and the
mirror job is not handed out.  This is the composition §11.4 recorded as
**open**, and it is now **closed by measurement**: the queue-namespace
refusal refuses the mirror's reservation, it does not hand out another
task's job, and the two ledgers stay in step.

### 16.3 The guards, and why they can fail

Twelve new guards in
`RefusedCandidateDoesNotWedgeTheQueueTests`
(`tests/test_refusal_hold_queue_wiring.py`):

| guard | what it pins |
|---|---|
| `test_a_refused_head_does_not_block_the_jobs_behind_it` | the defect itself: the job behind the refused one is handed out |
| `test_the_refused_candidate_is_still_ready_and_still_eligible` | the skipped job is not consumed -- still `ready`, no worker, no attempt |
| `test_the_refused_candidate_is_asked_about_first` | the queue's order is kept: the head is asked about first |
| `test_every_refused_candidate_raises_and_hands_nothing_out` | nothing is handed out when nothing is allowed |
| `test_every_refused_candidate_books_a_rejected_row` | the trail records the refusal, not a hand-out — **AMENDED 2026-11-24, see §17.1: this guard asserted a predicate, not a count, so it could not see the under-count** |
| `test_a_broken_gate_is_NOT_skipped` | a broken gate fails the whole call -- **not** skipped |
| `test_a_gate_without_the_required_method_is_NOT_skipped` | an unusable gate is refused, not ignored and not skipped |
| `test_an_unreadable_store_hands_out_nothing` | the hold's fail-closed direction survives the skip |
| `test_a_refusal_scoped_to_another_action_does_not_skip_anything` | the control: a refusal about another action blocks nothing |
| `test_a_refused_job_cannot_be_retired_and_does_not_need_to_be` | the wedge's two halves cannot be reassembled |
| `test_the_mirror_may_NOT_fall_back_to_another_tasks_job` | the mirror takes its refusal; each task has its own queue |
| `test_the_skipped_candidate_is_audited_by_the_gate` | the gate books a `checked`/`blocked=True` event for the skip |

**The mutation run.**  Five mutants planted and re-run; all five killed:

| mutant | verdict | killed by |
|---|---|---|
| M1 revert to head-only (the §15 defect) | **KILLED** | 5 guards |
| M2 skip a **broken** gate as well (fail-open) | **KILLED** | `test_a_broken_gate_is_NOT_skipped` |
| M3 never ask the gate at all | **KILLED** | 17 guards |
| M4 do not book the `job.rejected` row | **KILLED** | `test_every_refused_candidate_books_a_rejected_row` — **AMENDED 2026-11-24, see §17.3: this guard is a predicate, so it is killed by §17's count guards, not by this one** |
| M5 reverse the candidate order | **KILLED** | 3 guards |

**M2 needed a second pass, and that is worth recording.**  The first
version of the broken-gate guard used a gate that fails on **every**
job, and it **survived** M2.  The reason is that a gate which fails on
every job raises in **both** versions -- so the guard could see "the
call raised" but not "the call raised *instead of* handing out a job
behind a broken gate".  A guard that exercises only the all-fail path
cannot cover the mixed path, and a mutant that only shows up on the
mixed path is a mutant the guard was blind to.

This is §13.5's M6 lesson in a new costume: **a guard that exercises
only the refused path does not cover the ordinary path.**  The fixed
guard uses a gate that fails on the FIRST job and works on the second,
so the two behaviours differ in **outcome** and not just in "did it
raise".

### 16.4 What this does NOT change

* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`), and no audit kind is
  added or changed.  `job.rejected` is an existing kind.
* `dequeue()`'s signature is unchanged: the `now` parameter §15 added is
  still optional, and every existing call site is unchanged.
* The gate is asked **once per candidate**, and the skip means a queue
  of N candidates can produce up to N checks.  That is the price of not
  wedging the queue, and it is the same shape as §13.4's batch
  question: a queue with a refused head asks twice where it used to ask
  once.
* `ack()` and `dead()` still do not consult the gate -- a **withdrawal**
  is not a re-dispatch (§13.1).
* `retry()` and `retry_allowed()` are unchanged, including the "one
  check per job" count §10 established.
* The lease side is unchanged: `claim()`, `fail()`, `release()` and
  `reap()` ask exactly what they asked before.
* The queue's **ordering** is unchanged.  The skip does not reorder the
  queue: the candidates are asked in the queue's own order, and the
  first one the gate allows is the one that is handed out.
* §15's "the refused head blocks the whole dequeue" decision is
  **withdrawn**.  §15's fix -- the gate is asked inside the queue's own
  lock, before the write -- stands; only the *scope* of the question
  changed.

## 17. AMENDED 2026-11-24 — the queue's own trail named one refused candidate out of three

### 17.1 The defect

§16 landed the skip: the gate is asked about the candidates in the
queue's own order, and the first one it **allows** is handed out.  That
fix is correct, and it stands.  But it left the **queue's own audit
trail** naming only the **first** refused candidate -- and naming
**none at all** when a later candidate was allowed.

Measured 2026-11-24, on the tree as §16 left it:

```
--- ONE refused head + 1 healthy -> handed j2
   job.rejected rows: 0 -> []
--- BOTH refused -> raised RefusalRefusedError
   job.rejected rows: 1 -> [(10, {'reason': 'RefusalRefusedError', 'job_id': 'j1'})]
--- THREE refused -> raised RefusalRefusedError
   job.rejected rows: 1 -> [(10, {'reason': 'RefusalRefusedError', 'job_id': 'j1'})]
```

Read the middle and bottom rows together: **three** candidates were
refused and the trail named **one** of them.  And the top row is worse
than an under-count -- the refused head left **no trace at all** in
the queue's trail, because a healthy job was handed out instead and
the rejection was never booked.

So a host reading the queue's trail could not tell "the queue skipped a
refused job" from "the queue never looked at it".  That is the very
distinction §8's `checked` event exists to make on the **registry's**
side; the queue's own trail did not carry it.

**Two things had to be true of a refusal row, and only one was.**

1. *That* a candidate was refused.  -- only true for the first one.
2. *Which* candidate, *what* action, and *why*.  -- true, but the row
   carried only the error's **class name** and the job id.

The second point is its own defect, and §16.2's own wording created
it: the row was booked as `{"reason": type(first_refusal).__name__,
"job_id": blocked[0]}`.  The class name is `RefusalRefusedError` for
**every** refusal the hold can produce -- a recorded refusal
(`blocked_by_refusal`), an unreadable store
(`blocked_store_unreadable`), a tampered row
(`blocked_row_tampered`), a row of the wrong family
(`blocked_row_invalid`), and a malformed identity
(`blocked_key_invalid`).  The hold's **reason slug** is what
distinguishes them, and the trail threw it away.  A trail built from
the class name alone cannot tell a policy refusal from a gate that
could not read its own store -- which are opposite events for an
operator.

**And the guard that claimed to hold this down did not.**  §16.3's
table lists

> `test_every_refused_candidate_books_a_rejected_row` | the trail
> records the refusal, not a hand-out

and the guard's body was

```python
kinds = [row["kind"] for row in queue.audit_log()]
self.assertNotIn("job.dequeued", kinds)
self.assertIn("job.rejected", kinds)
```

`assertIn` is satisfied by **one** row.  A guard whose NAME says
"every" must **count** them.  The guard passed, and the property it
claimed was false.  That is the §16.3 M2 lesson in a third costume: a
guard that asserts a *predicate* instead of a *count* cannot see an
under-count.

### 17.2 The fix

Every refused candidate now books **its own** `job.rejected` row, in
the queue's own trail, naming **who** was refused, **what** action,
and **why**:

```python
self._reject_refusal(seq, candidate, candidate_action, exc)
```

```python
{
    "reason": type(exc).__name__,      # the SHAPE of the refusal
    "refusal_reason": slug,            # the hold's reason SLUG
    "job_id": job_id,                  # WHO was refused
    "action": action,                  # WHAT was refused
}
```

`job.rejected` is an **existing** kind -- no new kind is added, and the
version and schema pins are unchanged.

Three properties follow, and each is a guard:

* **Per candidate.**  N refused candidates, N rows, in the queue's own
  order.  The count of rejected rows now equals the count of the
  registry's blocked `checked` events -- the two trails agree on how
  many candidates were refused.
* **Per refusal, not per call.**  A refused candidate that is *skipped*
  (a healthy job behind it is handed out) is audited too.  Before the
  fix, a skip booked **nothing**; now it books its row.
* **The slug is carried.**  `refusal_reason` is the hold's slug
  (`blocked_by_refusal`, `blocked_store_unreadable`,
  `blocked_key_invalid`, ...), so the trail says *which* condition
  refused the candidate, not merely that something did.  The slug is
  optional: a host that re-implements the gate's contract may raise an
  error carrying only the class name, and then the slug is `None` --
  the row still says *that* the candidate was refused.

**A broken gate books no row.**  A broken gate fails the whole call
(§16.2) and refuses nothing in particular; booking a `job.rejected`
row for it would put a refusal in the trail that never happened.
The row is booked in the **refusal** branch only, so a broken gate
leaves no `job.rejected` row.

**The all-refused path books nothing more.**  Before the fix, the
all-refused path booked one row naming `blocked[0]`.  Now every
refused candidate has already booked its own row on the way through,
so that path books no additional row -- a second row would
double-count the first candidate's refusal.

### 17.3 The guards

Eleven new guards in `RefusedCandidatesAreAllAuditedTests`
(`tests/test_refusal_hold_queue_wiring.py`):

| guard | what it pins |
|---|---|
| `test_a_skipped_candidate_is_named_in_the_queue_trail` | the defect: a skipped head leaves **no** row today; now it leaves one |
| `test_every_refused_candidate_is_named_not_just_the_first` | N refused candidates, N rows -- the count, not a predicate |
| `test_the_rejected_row_names_the_reason_and_the_action` | the row names the job, the reason and the **action** |
| `test_the_refusal_slug_is_carried_not_just_the_class_name` | `refusal_reason` is the hold's slug, not the class name |
| `test_the_trail_and_the_registry_trail_agree_on_the_count` | the two trails disagree about neither the count nor the truth |
| `test_an_allowed_candidate_books_no_rejected_row` | the control: the trail does not invent refusals |
| `test_a_broken_gate_books_no_rejected_row` | a broken gate is not recorded as a refusal |
| `test_the_rejected_rows_come_before_the_hand_out` | the trail is chronological |
| `test_the_rejected_row_books_the_same_seq_as_the_call` | one call, one seq -- the refusals are booked under it |
| `test_the_rejected_row_carries_no_payload` | the audit boundary still holds |
| `test_a_malformed_identity_is_audited_as_a_refusal_not_a_hand_out` | a job whose task name cannot become a hold key is **named**, not vanished |

**The mutation run.**  Five mutants planted and re-run; all five killed:

| mutant | verdict | killed by |
|---|---|---|
| M1 never book the per-candidate rejection row | **KILLED** | 7 guards |
| M2 book only the FIRST refusal (the old behaviour) | **KILLED** | 2 guards |
| M3 drop the `refusal_reason` slug | **KILLED** | 2 guards |
| M4 drop the `action` from the row | **KILLED** | 1 guard |
| M5 double-book the all-refused path | **KILLED** | 1 guard |

**M2 is the one worth recording.**  It restores §16's exact
behaviour -- book the first refusal only -- and it is killed by
**two** guards, both of which assert a **count**.  That is the point:
the §16 guard asserted a *predicate* (`assertIn`), so it could not see
the under-count, and M2 is exactly the mutant it was blind to.  A
guard that asserts "the kind is present" cannot distinguish one row
from three.

### 17.4 What this does NOT change

* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`), and **no audit kind is
  added or changed**.  `job.rejected` is an existing kind.
* `dequeue()`'s signature is unchanged, and every existing call site is
  unchanged.
* The **skip** is unchanged: the candidates are still asked about in
  the queue's own order, and the first one the gate allows is still the
  one handed out.  §16 stands.
* The **broken gate** is still not skipped and still fails the whole
  call, closed (§16.2).  The only change is that it books no row.
* The gate is still asked **once per candidate**; the trail now books
  one row per refused candidate, which is the same number.
* `ack()`, `dead()`, `retry()` and `retry_allowed()` are unchanged,
  including the "one check per job" count §10 established.  The rows
  this section adds are booked by `dequeue()` only.
* The lease side is unchanged: `claim()`, `fail()`, `release()` and
  `reap()` ask exactly what they asked before, and the mirror's
  `job.rejected` row (which §16.2 measured) is still booked by the
  queue's own `dequeue()`.
* `retry()`'s refusal is still **not** booked in the queue's trail.
  That is a separate gap, and it is left open here for one reason only:
  this slice is about the candidates the **hand-out** refused, and
  `retry()`'s refusal is a refusal of the **re-dispatch** -- a
  different question, on a different path, that wants its own
  measurement.

  **A correction to what this section first claimed.**  An earlier
  draft of this paragraph said that booking a row on the `retry()` path
  "changes the 'one check per job' audit count §10 pinned".  That is
  **wrong**, and it is worth recording why.  §10's "one check per job"
  is about the **gate's calls** -- it is the *registry's* `checked`
  events that count, because a double ask would book a double event.
  The queue's own trail is a **different** trail, and a row there
  changes neither the number of gate calls nor the number of
  `checked` events.  Measured:

      gate 'checked' events on the retry path: 1 -> ONE
      QUEUE trail rows: ['job.enqueued', 'job.dequeued'] -> NO rejection row

  So the gap is real, and it is NOT blocked by a count.  It is simply
  a different slice.

## 18. AMENDED 2026-11-24 — a refused re-dispatch left no trace in the queue's trail

### 18.1 The defect

§17 fixed the **hand-out** side: every refused candidate books its own
`job.rejected` row.  The **re-dispatch** side had the same gap, and the
same shape of blindness.

Measured 2026-11-24, on the tree as §17 left it:

```
retry() raised: RefusalRefusedError

What an operator reading the QUEUE trail sees:
    job.enqueued {'job_id': 'j1', 'queue': 'q', 'task': 'dispatch', ...}
    job.dequeued {'job_id': 'j1', 'queue': 'q', 'worker_id': 'w', ...}
job state: reserved

What the REGISTRY trail sees:
    recorded queue:j1:dispatch blocked= False None
    checked  queue:j1:dispatch blocked= True blocked_by_refusal
```

Read the two trails together.  The queue's trail says **"dequeued, then
nothing"** -- which is **indistinguishable from a worker that died
mid-flight**.  The registry's trail knows the re-dispatch was refused,
but the registry is a *different* ledger, and a host reading the
queue's own audit cannot tell a refusal from a crash.

**And the batch form was worse.**  `retry_allowed()` returns `None` for
"not re-dispatched", and it asks the gate through the **boolean** form,
which catches the gate's exception and throws it away:

```
retry_allowed -> None
  (the reason is GONE: the batch form returns a bare None)
```

So on the batch path the reason was lost **entirely** -- not merely
unnamed in the queue's trail, but gone from the caller's hands too.

### 18.2 The fix

Both re-dispatch forms now book the refusal in the queue's own trail,
through the same helper §17 landed (`_reject_refusal`), so the row
names **who** was refused, **what** action, and **why** -- including
the hold's reason slug.

The **raising** form (`retry()`) books the row in the refusal branch
and re-raises:

```python
try:
    self._require_refusal_allows(job_id, retry_action, now)
except Exception as exc:
    if _is_refusal(exc):
        self._reject_refusal(seq, job_id, retry_action, exc)
    raise
```

The **batch** form (`retry_allowed()`) books the row and returns
`None`.  For that to be possible the boolean helper had to stop
throwing the reason away, so `_refusal_allows()` now returns a
**tuple**:

```python
def _refusal_allows(self, job_id, action, now) -> Tuple[bool, Optional[BaseException]]:
```

`(allowed, exc)` -- the boolean is exactly what it was, and the second
element is the exception that caused the refusal, or `None` when the
job is allowed.  A caller that ignores the second element gets the old
behaviour exactly.

**A broken gate books no row**, on either form -- same rule as §17: a
broken gate refuses nothing in particular, so a `job.rejected` row
would put a refusal in the trail that never happened.

**The two forms agree.**  The raising form and the batch form are one
writer (`_retry`), so a refusal must leave the same trail whichever
form asked.  A guard asserts that the two rows are equal.

### 18.3 The guards

Thirteen new guards in `RefusedRetryIsAuditedTests`
(`tests/test_refusal_hold_queue_wiring.py`):

| guard | what it pins |
|---|---|
| `test_a_refused_retry_is_named_in_the_queue_trail` | the defect: a refused re-dispatch left **no** row |
| `test_the_refused_retry_row_names_the_action_and_the_slug` | the row says WHO, WHAT and WHY |
| `test_a_refused_retry_allowed_is_named_in_the_queue_trail` | the **batch** form books a row too |
| `test_the_batch_form_does_not_lose_the_reason` | the batch form must not throw the reason away |
| `test_the_raising_and_the_batch_form_book_the_same_row` | two forms, one truth -- the rows are equal |
| `test_an_allowed_retry_books_no_rejected_row` | the control: the trail does not invent refusals |
| `test_a_broken_gate_books_no_rejected_row` | a broken gate is not recorded as a refusal |
| `test_a_refused_retry_leaves_the_job_exactly_where_it_was` | booking the row did not disturb the job |
| `test_the_trail_and_the_registry_trail_agree_on_the_refusal` | one gate call, one refusal, one row in each trail |
| `test_the_refused_retry_row_books_the_calls_seq` | one call, one seq |
| `test_the_refused_retry_row_carries_no_payload` | the audit boundary still holds |
| `test_a_refused_retry_is_still_visible_to_a_later_sweep` | the trail is a **history**: two refusals, two rows |
| `test_a_non_string_reason_is_not_written_into_the_trail` | the slug slot holds a slug or nothing -- never a stray value |

**The mutation run.**  Eight mutants planted and re-run; all eight
killed (one of them only after a guard was added -- see M8):

| mutant | verdict | killed by |
|---|---|---|
| M1 never book the batch form's refusal row | **KILLED** | 3 guards |
| M2 never book the raising form's refusal row | **KILLED** | 7 guards |
| M3 the **live** batch branch throws the reason away | **KILLED** | 2 guards |
| M4 book a row for a broken gate as well | **KILLED** | 1 guard |
| M5 the two forms disagree | **KILLED** | 1 guard |
| M6 the shared helper drops the action | **KILLED** | 2 guards |
| M7 the shared helper drops the slug | **KILLED** | 4 guards |
| M8 the shared helper drops the slug's type check | **KILLED** | 1 guard — **and this one SURVIVED the first pass**; see below |

**M8 needed a second pass too, and it found a real gap.**  The
mutant dropped the `isinstance(slug, str)` check in the shared helper,
so a gate raising an error whose ``reason`` attribute is *not* a
string would write that value straight into the row's
``refusal_reason`` slot.  The first mutant run reported it as
**survived**, and it was: no guard covered it.  The slot documents a
**slug**, so a number or a list in it is a value the reader cannot
interpret -- and the trail is machine-read.

A guard was added (`test_a_non_string_reason_is_not_written_into_the_trail`:
a gate raising ``RefusalRefusedError(reason=12345)`` must leave the
slug slot ``None`` while the class name still says a refusal
happened), and M8 is now **KILLED** by it.  A surviving mutant is a
finding about the *guards*, not about the mutant: see
[[b173-accept-metric-is-not-a-census]].

**M3 needed a second pass, and the reason is worth recording.**  The
first version of M3 was planted in `_refusal_allows()`'s
`queue_allowed` branch -- and it **survived**.  That branch is
**unreachable** with the repository's own gate: `RefusalHoldQueueGate`
offers `require_queue_allowed` and `task_allowed`, but **no**
`queue_allowed`, so the `queue_allowed` branch never runs.  The
surviving mutant was in dead code, and no guard could have killed it.

So the mutant was re-targeted at the **live** branch -- the
`require_queue_allowed` fallback -- and killed there.  The lesson is
§16.3's M2 lesson again, in a third costume: **a mutant in an
unreachable branch is not evidence that the guards are weak; it is
evidence that the mutant was mis-aimed.**  The way to tell the two
apart is to ask *which* branch the repository's own gate takes, and
plant the fault there.

### 18.4 What this does NOT change

* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`), and **no audit kind is
  added or changed**.  `job.rejected` is an existing kind.
* `retry()`'s and `retry_allowed()`'s **signatures** are unchanged, and
  every existing call site is unchanged.
* The gate is still asked **once** per job, on both forms.  §13.4's
  "one check per job" count is unchanged -- it is the count of the
  *gate's* calls, and the registry's `checked` events are unaffected:
  a row in the queue's own trail is a **different** trail.
* `retry_allowed()` still returns `None` for "not re-dispatched".  The
  second element of `_refusal_allows()`'s tuple is **internal**; the
  public contract of the batch form is unchanged.
* The **lease** side is unchanged: `claim()`, `fail()`, `release()`
  and `reap()` ask exactly what they asked before, and the lease
  ledger's own trail is unchanged.  §18 fixes the **queue's** trail;
  the lease ledger's equivalent gap is a separate slice.
* `ack()` and `dead()` still do not consult the gate -- a
  **withdrawal** is not a re-dispatch (§13.1).
* The **hand-out** side is unchanged: §17's per-candidate rows stand,
  and §17.4's correction (the "one check per job" count is about the
  *gate's calls*, not the queue's trail) is unaffected.

## 19. AMENDED 2026-11-24 — every record carried a schema pin that nothing checked

### 19.1 The defect

`job_queue.py` books five kinds of record, and each one carries a
`schema` field pinned to `JOB_QUEUE_SCHEMA`:

| kind | where |
|---|---|
| `EnqueueRecord` | `job_queue.py:408` |
| `DequeuedJob` | `job_queue.py:449` |
| `AckRecord` | `job_queue.py:489` |
| `DeadRecord` | `job_queue.py:509` |
| `RetryRecord` | `job_queue.py:536` |

Each one's `verify()` recomputes the digest and checks the schema in
the same expression:

```python
return recomputed == self.digest and (
    self.schema == JOB_QUEUE_SCHEMA
)
```

So the schema pin was **written** in the code.  It was **checked** by
nothing.

Measured 2026-11-24 by the whole-file census over `job_queue.py`
(the accept probe's `MUTANT` check is an accept *metric*, not a
census -- it stops at the first kill; the census is
`b173-mutant.py --file <abs> --no-early-stop`):

```
MUTANT RESULT: killed 42/81
```

(That is the **two-suite** scope -- `test_refusal_hold_queue_wiring`
and `test_job_queue`.  §22 re-measures the whole series over the
**union** of every suite that references the module, which is the
scope to quote; see §22.1 for both series.)

The survivors include the `and` that joins the digest check to the
schema check, at **five** places -- one per record kind.  Inverting
the schema comparison in all five at once:

```python
return recomputed == self.digest and (
    self.schema != JOB_QUEUE_SCHEMA
)
```

leaves the **whole suite green**: at the time of the measurement
(before these five guards existed) 23373 tests, `OK (skipped=20)`.
The pin was carried by every record and verified by none.

**Why that matters.**  The digest says "this record is internally
consistent"; the schema says "this record is the shape the reader
expects".  A record from a *different* schema -- a future revision
with a different field set, or a record that crossed a boundary it
should not have -- carries a digest computed over its own fields, so
`verify()` says `True` because the digest matched.  A verifier that
checks only the first is verifying the wrong thing.

This is §17's lesson, one level down: the property was **written** in
the code, so every reader of the code believed it was **held**.

### 19.2 The fix

No code change: the expression was already correct.  What was missing
was the **evidence**.  Five guards now cover it, in
`tests/test_refusal_hold_queue_wiring.py::RecordSchemaPinIsVerifiedTests`.

The guards do not hand-build the records.  They ask the **ledger** for
one real record of every kind, so the digests under test are the ones
the module actually books:

```python
queue.enqueue("j1", "q", "dispatch", DIGEST, 1)   # EnqueueRecord
queue.dequeue("worker-1", "q", 2)                  # DequeuedJob
queue.ack("j1", 3)                                 # AckRecord
queue.enqueue("j2", ...); queue.dequeue(...); queue.dead("j2", 6)   # DeadRecord
queue.enqueue("j3", ...); queue.dequeue(...); queue.retry("j3", 9)  # RetryRecord
```

A record is then forged with `dataclasses.replace(record, schema=...)`
-- the shape is frozen, so the *only* way to change it is to rebuild
it, and the digest stays the original one.  That is the point: the
forged record is **internally consistent but of a foreign schema**,
which is exactly the case the digest check cannot see.

### 19.3 The guards

| guard | what it holds |
|---|---|
| `test_every_records_verify_is_true_for_a_real_record` | the control: the pin is not simply broken |
| `test_every_record_rejects_a_foreign_schema` | the defect: a foreign schema must not verify |
| `test_every_record_rejects_an_empty_schema` | an empty schema is a foreign schema too |
| `test_the_digest_still_verifies` | the control for the control: the schema check is *additional* to the digest check, not a replacement |
| `test_every_record_type_is_covered` | the **count**: all FIVE kinds are covered |

`test_every_record_type_is_covered` is the guard that matters most.
It names the five kinds it expects and compares them as a **set**
against the kinds the fixture produced.  A guard that only checked
`EnqueueRecord` would be a predicate, not a count -- and the census
found the survivor at **five** places, so a one-kind guard would have
left four of them uncovered while the suite stayed green.

### 19.4 The mutants

| # | mutation | before | after |
|---|---|---|---|
| M1 | `self.schema == JOB_QUEUE_SCHEMA` -> `!=`, all 5 kinds | **survived** | killed (`FAILED (failures=3)`) |
| M2 | `recomputed == self.digest and (...)` -> `or (...)`, all 5 kinds | **survived** | killed (`FAILED (failures=3)`) |

Both were re-planted after the guards landed and re-run against
`tests.test_refusal_hold_queue_wiring` + `tests.test_job_queue`, with
`__pycache__` cleared between every plant and restore (a
length-preserving mutate-then-restore within one second loads the
mutant's `.pyc`, so a killed mutant reads as a survivor).

M2's lesson: **the `and` was the load-bearing operator**.  Turning it
into `or` means a record with a *correct* digest but a *foreign* schema
verifies, and a record with a *wrong* digest but a *correct* schema
verifies.  Only the digest-only forgery is caught by
`test_the_digest_still_verifies` alone; the schema-only forgery needs
`test_every_record_rejects_a_foreign_schema`.

### 19.5 What this does NOT change

* `job_queue.py` is **unchanged** -- not one byte.  This slice adds
  evidence for a property the module already held.
* No version, schema or audit kind is added or changed.
* The gate is not consulted by `verify()` and was not consulted
  before either; `verify()` is a pure integrity check.
* §17's and §18's trail rows are unaffected.

### 19.6 A sibling survivor, NOT closed here

The same census reported a survivor on the `except JobQueueError:
return False` clause of each `verify()`.  That one is a **live
branch** -- but the finding is a separate defect with a separate fix,
so it is recorded here and taken as its own slice rather than folded
into an evidence slice:

> `job_queue.py` catches `JobQueueError` around `_pin()`.  But
> `_canonical()` uses `canonical_json.jcs_dumps()` whenever the
> sibling helper is importable, and **that** raises `JcsError` -- a
> `ValueError`, not a `JobQueueError`.  So in the shipped
> configuration the `except` clause is **dead**: a record whose
> `attempts` is `float('inf')` makes `verify()` **raise**
> `JcsError` instead of returning `False`.
>
> The stdlib fallback (`_cj is None`) *does* raise `JobQueueError`,
> so the clause is live only there -- which is why the mutant
> survives the shipped configuration.
>
> `graph_database.py` has the identical clause (the same house
> pattern), so this is repo-wide, not specific to this module.

Left open deliberately: fixing it changes the module's error taxonomy,
which is a design decision, not an evidence gap.

## 20. AMENDED 2026-11-24 — the canonicalizer's own error escaped the queue's taxonomy

### 20.1 The defect

§19 left one census survivor open, and it was not a mis-aimed mutant:
the `except JobQueueError: return False` clause of each record's
`verify()` is **live** -- but only in the *fallback* configuration.

`_canonical()` (`job_queue.py:363`) uses the sibling JCS helper
whenever it is importable:

```python
def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")
    ...
```

And `canonical_json.jcs_dumps()` refuses input it cannot canonicalize
-- a lone surrogate, a non-finite float, an unsupported type -- with
**its own** error type, `JcsError`, which is a `ValueError`:

```
class JcsError(ValueError):
    """Input that JCS cannot canonicalize ..."""
```

`JcsError` is **not** a `JobQueueError`.  So the `except JobQueueError`
clause never fired in the shipped configuration, and the stdlib
fallback -- which *does* raise `JobQueueError` -- was the only place
the clause was live.  Two configurations, two answers to the same
question.

Measured consequences, all in the shipped configuration:

| # | input | before |
|---|---|---|
| 1 | `verify()` on a record whose field is a lone surrogate | **raised** `JcsError` instead of answering `False` |
| 2 | `verify()` on a record whose field is `float('inf')` | **raised** `JcsError` |
| 3 | `enqueue()` with a lone-surrogate job id | raised, and booked **no** `job.rejected` row |
| 4 | `dequeue()` with a lone-surrogate worker id | raised, and left the job **`reserved`** with `dequeued=0` |

**#1 and #2 are the worst.**  `verify()` is the module's integrity
predicate: a caller asks "is this record intact?" and gets an
exception instead of an answer.  And because `JcsError` is a
`ValueError`, a caller guarding with `except ValueError` treats a
**tampered record** as a **parse error** and moves on -- so the record
is neither verified nor rejected.

**#4 is a stranded job.**  `dequeue()` flipped the entry to `reserved`
*before* it computed the digest, so the refusal left the job
`reserved`, with `stats()` reporting `reserved=1, dequeued=0` and no
`job.dequeued` row: a job nobody holds, that no worker ever got, and
that the trail never mentioned.

**#3 is the §17 property, one layer down.**  §17 established that a
refusal that leaves no trail row is invisible.  A refused
`enqueue()` left the trail showing *nothing at all* -- the queue
could not tell "the queue refused this job" from "the queue never
saw it".

### 20.2 The fix

Three parts, all in `job_queue.py`.

**(a) Translate the error at the boundary.**  `_canonical()` now
converts the helper's `ValueError` into this module's own taxonomy:

```python
if _cj is not None:
    try:
        return _cj.jcs_dumps(payload).encode("utf-8")
    except ValueError as exc:
        raise JobQueueError(f"unencodable payload: {exc}") from exc
```

One place, so the two configurations cannot drift again: the fallback
already raised `JobQueueError`, and now the shipped path raises the
same type for the same inputs.

**(b) Compute each digest INSIDE the guarded block.**  Every mutator
now computes its digest before the entry is flipped and inside the
`try` that books the rejection:

| mutator | before | after |
|---|---|---|
| `enqueue()` | digest computed after the `except` | inside the guarded block |
| `dequeue()` | digest computed after the entry was flipped to `reserved` | before the flip, inside a guarded block that books the rejection |
| `ack()` | digest computed after the `except` | inside the guarded block |
| `dead()` | digest computed after the `except` | inside the guarded block |
| `retry()` | digest computed after the `except` (both branches) | inside the guarded block (both branches) |

So a refused digest now (i) books a `job.rejected` row naming the
job, and (ii) leaves the job **exactly where it was** -- `ready` after
a refused `dequeue()`, `reserved` after a refused `ack()`.

**(c) Order the `dequeue()` computation before the flip.**  This is
the part that fixes the stranded job: the digest is computed while
the entry is still `ready`.

### 20.3 The guards

Nine guards in two classes.

`RecordVerifyErrorTaxonomyTests` (4):

| guard | what it holds |
|---|---|
| `test_an_unencodable_record_answers_false_and_does_not_raise` | `verify()` **answers** `False`; it does not raise |
| `test_a_non_finite_field_answers_false_and_does_not_raise` | the same, for a float the canonicalizer refuses |
| `test_the_answer_is_false_in_the_stdlib_fallback_too` | the two configurations **agree** |
| `test_the_control_a_real_record_still_verifies` | the control: the working path still works |

`UnencodableIdentityIsAuditedTests` (5):

| guard | what it holds |
|---|---|
| `test_an_unencodable_enqueue_books_a_rejected_row` | a refused `enqueue()` leaves a trail row |
| `test_the_rejected_row_names_the_job` | the row names the job, and is booked exactly once |
| `test_a_refused_dequeue_does_not_strand_the_job` | the job stays `ready`: `reserved=0, ready=1, dequeued=0` |
| `test_a_refused_dequeue_books_a_rejected_row` | the refusal is visible, and **no** `job.dequeued` row is booked |
| `test_the_job_is_still_handable_out_after_the_refusal` | the refusal is per-call, not permanent |

### 20.4 The mutants

| # | mutation | before | after |
|---|---|---|---|
| M1 | `except JobQueueError: return False` -> `return True`, all 5 kinds | **survived** (§19's open item) | killed (`FAILED (failures=3)`) |
| M2 | `_canonical`'s `except ValueError` -> `except _NeverRaised` | n/a (the fix) | killed (`FAILED (failures=6)`) |
| M3 | `dequeue()`'s digest moved **after** the entry flip | n/a (the fix) | killed (`FAILED (failures=2)`) |
| M4 | `dequeue()`'s refusal **not booked** as a rejection | n/a (the fix) | killed (`FAILED (failures=1)`) |
| M5 | `enqueue()`'s digest moved back outside the guarded block | n/a (the fix) | killed (`FAILED (failures=2, errors=124)`) |

M1 is §19's open item, now closed: the clause is **live** in both
configurations, so the mutant that inverts it dies.

M3 is the one worth remembering: the mutant that puts the digest back
*after* the entry flip restores the stranded job exactly, and the
guard that kills it is `test_a_refused_dequeue_does_not_strand_the_job`
-- which asserts the **counters**, not the exception.  A guard that
only asserted "the call raised" would not have seen the difference.

### 20.5 What this does NOT change

* `job_queue.py`'s version and schema pins are unchanged
  (`job-queue.v1` / `northstar.job-queue.v1`), and **no audit kind is
  added or changed**.  `job.rejected` is an existing kind.
* The **digests** are unchanged: `_canonical()`'s bytes are the same
  for every input the module accepts, so every existing record's
  digest still verifies.  (The two configurations never agreed on the
  bytes -- the shipped path emits `[...]` and the fallback emits
  `{"t":"list",...}` -- so there was no cross-configuration digest to
  preserve; the fallback is a *fallback*, not a second format.)
* The **stdlib-only** promise is unchanged: `canonical_json` was
  already the only non-stdlib import, and `test_stdlib_only` still
  passes.
* The gate is not consulted by any of this.
* §17's, §18's and §19's guards are unaffected.
* The **lease** side is unchanged: `leased_task_claim.py`'s mirror
  calls are unaffected, because the mirror's worker and task ids are
  the ones the module already validated.

### 20.6 The sibling defect, still open

`graph_database.py` has the **identical** clause --
`except GraphDatabaseError` around its own `_pin()`, with the same
`canonical_json` behind it.  So the same `verify()`-raises bug is
there.  It is a separate module with its own scope, and the repo's
house pattern is consistent, so it is left for a slice that owns
`graph_database.py` rather than folded in here.

And the bigger one, still open: `canonical_json` serializes an
integer outside the safe range as an IEEE-754 **double**, so at
`|seq| >= 2**53` two different seqs canonicalize to the same bytes.
A **real** record's digest then stops pinning its `seq`:

```
real DequeuedJob seq: 9007199254740992
tampered seq:         9007199254740993   same digest
tampered.verify() = True
```

The stdlib fallback refuses that integer outright, so the two
configurations also disagree about whether a large seq is legal at
all.  This is a **digest-fidelity** defect, not a taxonomy defect,
and it is not fixed here -- fixing it means deciding what the module
promises about `seq`, which is a design decision.

## 21. AMENDED 2026-11-24 — a record's digest stopped pinning its seq above the safe range

### 21.1 The defect

§20.6 left one thing open, and it was the more serious of the pair:
the **fidelity** of a record's digest.

`canonical_json` serializes an integer outside the safe range as an
IEEE-754 **double** (RFC 8785 Appendix B note (2)):

```
jcs_dumps([2**53])   == b'[9007199254740992]'
jcs_dumps([2**53+1]) == b'[9007199254740992]'
```

So two different seqs canonicalize to the **same bytes** above
`2**53 - 1`.  `job_queue.py`'s `seq` was **unbounded** -- the only
integer in a digest that was -- so a real record's digest stopped
pinning its seq there, and a **tampered** seq still verified:

```
real DequeuedJob seq: 9007199254740992
tampered seq:         9007199254740993   same digest
tampered.verify() = True
```

The stdlib fallback *refuses* such an integer outright
(`JobQueueError: integer outside safe range`), so the two
configurations also disagreed about whether a large seq was legal at
all -- the same divergence §20 found, one level deeper.

**Why that matters.**  A digest's job is to pin the fields it covers.
A field that the digest cannot distinguish is a field the digest does
not protect.  A record whose `seq` was altered would verify, and `seq`
is the ledger's logical clock -- the thing that says **when** the
record happened.

### 21.2 The fix

One bound, in `_check_seq()`:

```python
if seq > _MAX_INT:
    raise SeqOrderError("seq exceeds the safe range")
```

`_MAX_INT` is `2**53 - 1`, already defined in the module.

This is the repo's **house pattern**, not a new invention:

| module | bound |
|---|---|
| `grant_pin_ledger.py` | `_MAX_COUNTER = 2**53 - 1`; a counter above it raises `MalformedPinError("... exceeds the safe range")` |
| `profiler.py` | `_canonical()` refuses an integral above `2**53` fail-closed ("integral magnitude > 2**53 cannot be pinned safely") -- it accepts `2**53` itself, which is safe because that value **is** exactly representable as a double and so collides with nothing above it |
| `job_queue.py` | `seq` was the **outlier** -- the one unbounded integer in a digest |

`job_queue.py`'s bound (`> 2**53 - 1`) is **one value more
conservative** than the minimum safe bound: `2**53` itself is exactly
representable as a double and so collides with nothing above it, which
is why `profiler.py` accepts it.  The tighter bound is deliberate --
it matches `grant_pin_ledger.py`, and it leaves no room for a future
change to the canonicalizer's edge.

And `seq` was the *only* unbounded integer in a digest here:

| field | bound |
|---|---|
| `priority` | `[-100, 100]` (`_PRIORITY_MIN`/`_PRIORITY_MAX`) |
| `max_retries` | `[1, 64]` (`_MAX_RETRIES_CAP`) |
| `delay_seqs` | `[0, 2**53-1]` (`_MAX_INT`) |
| `attempts` | `<= max_retries`, so `<= 64` |
| `seq` | **was unbounded** -- now `[0, 2**53-1]` |

### 21.3 Which convention the refusal follows

The module has **two** conventions for a refused call, and they are
not interchangeable.  Measured:

| the refusal is... | consumes the seq? | books a trail row? |
|---|---|---|
| a malformed **seq** (not an int, negative) | no | no |
| a malformed **argument** at a valid seq (bad job id) | yes | yes |

An oversized seq is a malformed **seq**, so it follows the first rule:
the call never reached the ledger, so it consumes nothing and books
nothing.  `test_a_refused_seq_does_not_consume_the_seq` holds that
line, so a future change cannot quietly move the oversized-seq refusal
into the other category.

### 21.4 The guards

| guard | what it holds |
|---|---|
| `test_a_seq_at_the_safe_range_is_accepted` | the upper edge is legal -- `2**53 - 1` works, and the record verifies |
| `test_a_seq_one_over_the_safe_range_is_refused` | `2**53` is refused, and the refusal says why |
| `test_a_tampered_seq_is_caught` | the property at a small seq |
| `test_a_tampered_seq_is_caught_at_the_safe_range_edge` | the property **at the edge**, where the loss was |
| `test_every_mutator_refuses_an_oversized_seq` | the **count**: `enqueue`, `dequeue`, `ack` and `retry` all refuse |
| `test_a_refused_seq_does_not_consume_the_seq` | the convention of §21.3 |

### 21.5 The mutants

| # | mutation | after |
|---|---|---|
| M1 | the seq bound removed (`if seq > _MAX_INT:` -> `if False:`) | killed (`FAILED (failures=3)`) |
| M2 | the edge moved (`>` -> `>=`) | killed (`FAILED (errors=2)`) |
| M3 | the bound removed from `seq` and left nowhere | killed (`FAILED (failures=3)`) |

M2 is the edge case, and it is killed by
`test_a_seq_at_the_safe_range_is_accepted` alone -- the guard that
says the *last legal value* is legal.  A guard that only checked "a
huge seq is refused" would not have seen the edge move.

### 21.6 What this does NOT change

* No version, schema, or audit kind is added or changed.
* The **digests** of every record that was legal before are
  **unchanged** -- the bound only refuses seqs that were never
  pinnable.
* Every seq the module's own production caller uses is legal: the one
  caller, `leased_task_claim.py`, gets every seq from `_next_seq()`,
  a monotonic counter starting at 0.
* No behaviour changes for a seq in `[0, 2**53 - 1]` -- the whole
  legal range is untouched.
* §17's, §18's, §19's and §20's guards are unaffected.

## 22. AMENDED 2026-11-24 — the census found two gaps in the slices that came before it

### 22.1 The measurement

With §19, §20 and §21 landed, the whole-file census over
`job_queue.py` was re-run.  The scope is the **union of every suite
that references the module** -- `test_job_queue`,
`test_leased_task_claim`, `test_refusal_hold` and
`test_refusal_hold_queue_wiring` -- because a module's real coverage
is the union, and a narrower scope understates it:

```
before §19-§21:  MUTANT RESULT: killed 45/81
after  §19-§21:  MUTANT RESULT: killed 54/82
after  §22:      MUTANT RESULT: killed 73/82
after  §22.8:    MUTANT RESULT: killed 76/85   (the scope fix, §22.9)
after  §22.8 + §27.1:  MUTANT RESULT: killed 84/85  (the spelling fix, §27.1)
```

The survivor count fell from **36** (81 candidates, 45 killed) to
**28** (82 candidates, 54 killed) across §19-§21, and to **9** (73
killed) across §22.

§22 closed **nineteen** of the twenty-eight §19-§21 left open.

**AMENDED 2026-11-25.**  The `73/82` above was measured at the
four-suite scope but with the census SCRIPT pairing the module with
**one** suite -- so the scope the script used was not the scope this
section describes.  Re-measured at the union scope, with the script
fixed (§22.9), the same tree reads `76/85`: **33** of the narrow
scope's "survivors" were caught by the sibling suites and were false
accusations.  Then the eight self-check survivors were killed (§22.8),
each killed mutant verified by planting it and re-running the scope.
Then the equivalence PROOF was fixed, because it had been killing the
last survivor for the wrong reason (§27.1), and the tree reads `84/85`.

So the four-suite scope's final reading over `job_queue.py` leaves
**one** survivor -- the equivalent mutant `or@1405`, which no guard can
kill.  A survivor count is meaningless without its scope: at the narrow
scope the same tree reads 43/85.

(§19 and §20 recorded the **narrower two-suite** scope
(`test_refusal_hold_queue_wiring,test_job_queue`).  Re-measured at
that scope the same series reads `42/81` -> `51/82` -> `73/82` -- the
same progression, measured over fewer suites.  The two scopes are
stated so they are never compared as if they were the same
measurement; the four-suite scope is the one to quote, because a
module's real coverage is the union of every suite that references
it.)

Two of the survivors §22 found were gaps in the slices that came
before -- **in my own work**.

### 22.2 The gap in §20: the taxonomy guard covered ONE record kind

§20 fixed the taxonomy so that all five record kinds answer `False`
instead of raising.  Its guard, `RecordVerifyErrorTaxonomyTests`,
built **one** record -- an `AckRecord` -- and checked it.

So the census's mutant (the `except JobQueueError: return False`
clause turned into `return True`) was:

| kind | census | why |
|---|---|---|
| `AckRecord` | killed | §20's taxonomy guard builds one |
| `DequeuedJob` | **survived** | nothing built one |
| `DeadRecord` | **survived** | nothing built one |
| `RetryRecord` | **survived** | nothing built one |
| `EnqueueRecord` | **survived** | nothing built one -- §19's schema guard builds one, but it asserts the *schema*, not the *taxonomy*, so the `return True` plant still verifies |

Planting the mutant in `DeadRecord.verify()` **alone** leaves the
whole suite green.

**This is §17's lesson, one level down, and it landed on my own
work.**  §17's guard was named `test_every_refused_candidate_books_a
_rejected_row` and asserted `assertIn("job.rejected", kinds)` -- one
row satisfies that.  §20's guard was named
`test_an_unencodable_record_answers_false_and_does_not_raise` and
built one kind -- one kind satisfies that.  Both names said "a" where
they meant "every", and both bodies did what the name said.

The fix is the same shape as §19's `test_every_record_type_is_covered`:
a guard that **counts** the kinds it covers.

| guard | what it holds |
|---|---|
| `test_every_record_kind_answers_false_for_an_unencodable_field` | all **FIVE** kinds answer `False` -- and it asserts `len(records) == 5` first, so a dropped kind fails the guard |
| `_all_record_kinds()` | the fixture: one **real** record of every kind, made by the ledger |

### 22.3 The gap in `stats()`: a counter nothing read

The census also reported the `stats()` `done` counter as a survivor
(`eq@1033`, the `== _STATE_DONE` comparison).  Nothing asserted it --
and, measured, **nothing read it either**: `stats().done` had no
assertion anywhere in the component suite or the repo suite, and no
production caller reads it.

A counter that is silently wrong is also silently useless.  Three
guards now hold the whole set:

| guard | what it holds |
|---|---|
| `test_every_counter_counts_what_it_says` | each counter, after a known sequence of transitions |
| `test_the_done_counter_counts_only_acked_jobs` | a **dead** job is not a **done** job -- the two states cannot be conflated |
| `test_the_counters_add_up_to_the_ledger` | the state counters sum to the number of jobs enqueued, so a job cannot be in two states or in none |

The third is the one that generalises: a guard that checks one
counter cannot see another being wrong.  Checking the whole set
against the ledger is what makes them agree with each other.

### 22.4 The mutants

The census reported **twenty-eight** survivors at this point (§22.1).
Nineteen of them were in the validation functions and the record
taxonomy; §22 closed **all nineteen**, which is exactly the drop from
`54/82` to `73/82`.

**Five** were the taxonomy and the counters -- the `return False`
clause, in each of the **four** record kinds that had no guard of its
own, and the `stats()` counter:

| # | site | mutation | before | after |
|---|---|---|---|---|
| M1 | `EnqueueRecord.verify()` (`job_queue.py:498`) | `return False` -> `return True` | survived | killed |
| M2 | `DequeuedJob.verify()` (`job_queue.py:538`) | the same | survived | killed |
| M3 | `DeadRecord.verify()` (`job_queue.py:585`) | the same | survived | killed |
| M4 | `RetryRecord.verify()` (`job_queue.py:624`) | the same | survived | killed |
| M5 | `stats()`'s done counter (`job_queue.py:1033`) | `== _STATE_DONE` -> `!= _STATE_DONE` | survived | killed |

Each of M1-M4 is a **single-kind** plant, so the guard that kills it
has to be a single-kind-agnostic one -- the count.  M5 is killed by
`test_the_done_counter_counts_only_acked_jobs`, which is the guard
that says the two states are different.

**Fourteen** were in the validation functions.  Every one is a
**bound** or a **type** check, and every one survived for the same
reason: the existing guard asserts only the **base** class.

| # | site | mutation | before | after |
|---|---|---|---|---|
| V1 | `job_queue.py:219` | `job_id`'s type check `or` -> `and` | survived | killed |
| V2 | `job_queue.py:231` | `queue`'s type check `or` -> `and` | survived | killed |
| V3 | `job_queue.py:243` | `worker_id`'s type check `or` -> `and` | survived | killed |
| V4 | `job_queue.py:249` | `worker_id`'s length bound `>` -> `>=` | survived | killed |
| V5 | `job_queue.py:255` | `task`'s type check `or` -> `and` | survived | killed |
| V6 | `job_queue.py:267` | `digest`'s type check `or` -> `and` | survived | killed |
| V7 | `job_queue.py:286` | `priority`'s upper bound `>` -> `>=` | survived | killed |
| V8 | `job_queue.py:286` | `priority`'s lower bound `<` -> `<=` | survived | killed |
| V9 | `job_queue.py:294` | `max_retries`' type check `or` -> `and` | survived | killed |
| V10 | `job_queue.py:312` | `delay_seqs`' bound `>` -> `>=` | survived | killed |
| V11 | `job_queue.py:318` | `seq`'s type check `or` -> `and` | survived | killed |
| V12 | `job_queue.py:320` | `seq`'s sign check `<` -> `<=` | survived | killed |
| V13 | `job_queue.py:427` | the fallback's int bound `>` -> `>=` | survived | killed |
| V14 | `job_queue.py:431` | the fallback's non-finite check `or` -> `and` | survived | killed |

Every one of the nineteen was planted and re-run individually and
observed **killed**; the census then re-run over the whole file
confirmed the drop.

The first case list killed only **four** of the fourteen.  The other
ten needed two things the first list did not have:

* the **edge** -- a case that says the last *legal* value is legal
  (this is what kills V4, V7, V8, V10, V12 and V13, all of which move
  a boundary by one), and
* the **other fields** -- `queue`, `task`, `digest` and `worker_id`
  each have their own type rule, and `queue`, `task` and `worker_id`
  each have their own length rule; the first list covered only
  `job_id`.

The site numbers above are the census's own, and they are **not**
interchangeable with a hand-written list: an earlier draft of this
section named `gt@225` (`job_id`'s length) and `gt@261` (`task`'s
length) among the survivors, and neither is one -- both were already
killed before this slice.  The list above is the census's output,
copied.

### 22.5 What this does NOT change

* **No code change.**  `job_queue.py` is unchanged by this slice --
  it is not one byte different from `e07cc869`.  This slice closes
  *evidence* gaps, exactly as §19 did.
* The **validation rules** are unchanged -- every bound and every type
  check was already correct (measured, §22.6), and this slice only
  pins them.
* No version, schema, or audit kind is added or changed.
* No digest changes: the records the fixtures build are the ones the
  module already books.
* §17's, §18's, §19's, §20's and §21's guards are unaffected.

### 22.6 The validation functions: a guard that asserts the BASE class

The census reported **fourteen** survivors in the validation
functions -- and the number is a **count**, so it says how many
rules are unverified, not which.  Every one of them is a **bound** or
a **type** check (the full site list is §22.4's table):

```
or@219   isinstance(job_id, bool) or not isinstance(job_id, str)
or@231   isinstance(queue, bool) or not isinstance(queue, str)
or@243   isinstance(worker_id, bool) or not isinstance(worker_id, str)
gt@249   len(worker_id) > 256
or@255   isinstance(task, bool) or not isinstance(task, str)
or@267   isinstance(digest, bool) or not isinstance(digest, str)
gt@286   priority > _PRIORITY_MAX
lt@286   priority < _PRIORITY_MIN
or@294   isinstance(max_retries, bool) or not isinstance(max_retries, int)
gt@312   delay_seqs > _MAX_INT
or@318   isinstance(seq, bool) or not isinstance(seq, int)
lt@320   seq < 0
gt@427   abs(v) > _MAX_INT            (the fallback canonicalizer)
or@431   v != v or v in (inf, -inf)    (the fallback canonicalizer)
```

**The validation is not wrong.**  Measured, every bad input raises the
right error type with the right message.  The reason the mutants
survived is that the existing test asserts only the **base** class:

```python
with pytest.raises(JobQueueError):
    jq.enqueue(...)
```

Every one of these errors IS a `JobQueueError`, so a mutant that
replaces a *specific* rule with a *different* specific rule -- a
bool check for a str check, a bound moved by one -- still raises
`JobQueueError` and the test still passes.

**A guard that asserts the base class cannot see which rule fired.**

So the guard asserts the **exact type** and the **message**, for
**every** field:

| guard | what it holds |
|---|---|
| `test_each_bad_input_raises_its_own_error_type` | the exact type, for `job_id`, `queue`, `task`, `digest`, `worker_id`, `priority`, `max_retries`, `delay_seqs` and `seq` |
| `test_each_bad_input_says_which_rule_was_broken` | the message names the rule |
| `test_each_limit_edge_value_is_accepted` | the **last legal value is legal** -- this is what kills an *edge* mutant |
| `test_the_case_list_covers_every_validation_rule` | the **count**: 19 cases, and a rule that loses its case fails the guard |
| `test_every_other_field_has_its_own_error_type` | the same, for the other four fields |
| `test_every_other_field_says_which_rule_was_broken` | the same, for the other four fields |
| `test_the_other_fields_edge_values_are_accepted` | the edge, for the other four fields |
| `test_the_case_list_covers_every_other_field` | the **count**: 12 more cases |

The **edge** guards are the ones worth remembering.  The first case
list covered "over the limit is refused" and nothing else, so six
mutants survived it: `gt@249` (worker id length), `gt@286` and
`lt@286` (priority's two bounds), `gt@312` (delay_seqs), `lt@320`
(seq's sign) and `gt@427` (the fallback's int bound).  All six move a
boundary **by one**, and all six are killed by a case that says the
boundary *value* is legal.  A guard that only checks "too big is
refused" cannot see the edge move.

### 22.7 The fallback canonicalizer

Two of the survivors (`gt@427`, `or@431`) are in the **stdlib
fallback** branch -- the one the module marks `# pragma: no cover`,
and the one that only runs when `canonical_json` cannot be imported
(it is a declared dependency, so in practice never).

A mutant in a branch nothing exercises is a **mis-aimed** mutant, not
a weak guard.  But the fallback is a *configuration*, and §20
established that the two configurations must agree -- so the fallback
is exercised **deliberately**, with the same inputs:

| guard | what it holds |
|---|---|
| `test_the_fallback_canonicalizer_refuses_the_same_inputs` | the fallback refuses a big int, a non-finite float and an unsupported type, **and says which rule**; and the **last legal integer is accepted** |
| `test_the_fallback_and_the_shipped_path_agree_on_the_error_type` | both configurations refuse with the module's **own** `JobQueueError` -- never with the sibling helper's `JcsError` |

The two configurations do **not** agree on *how much* they refuse, and
need not: the fallback is **stricter** (it refuses an integer above
the safe range; the shipped path accepts it, and the JCS helper
serializes it losslessly as a double).  A stricter fallback is safe --
it refuses more, never less.  What would not be safe is the fallback
refusing something the shipped path accepts *silently*, which is
exactly what a differing error type looks like to a caller.

### 22.8 What the census still reports

Nine survivors remain, and they are two shapes:

| site | what it is |
|---|---|
| `or@1273` | the `or` in the dequeue skip loop (`job_id is None or entry is None`) |
| `and@1681`, `and@1685`, `and@1686`, `and@1691`, `and@1696`, `and@1701`, `and@1718`, `and@1725` | the `and` in the module's own `main()` self-check's **assertion chains** |

The `main()` survivors are a different shape: each conjunct of an
`assert a and b` is individually untested, so flipping one leaves the
assertion still true.  `main()` is exercised -- `test_main_self_check`
runs it as a subprocess -- but a *self-check* is not a *test*: it
asserts what the author believed, and a conjunct that is never
false is never checked.

That is a separate category (the self-check's own assertions are
untested), and it is recorded here rather than folded in.

**AMENDED 2026-11-25 -- `or@1405` (the dequeue skip loop) is EQUIVALENT.**
The nine are not all the same kind, and saying so is the finding rather
than a fix.  The skip loop's guard is

```python
job_id = None
entry = None
for candidate in eligible:
    ...
    job_id = candidate
    entry = candidate_entry
    break
if job_id is None or entry is None:      # or@1405
    raise first_refusal
```

and its two operands are **always equal**:

* `job_id` and `entry` are assigned in exactly two places, and always
  **together** -- `(None, None)` before the loop, `(candidate,
  candidate_entry)` after it.  There is no path that sets one without
  the other.
* `candidate_entry` is `self._entries[candidate]`, and `candidate`
  comes from `_ordered_ready()`, which builds its list from
  `self._entries.items()` -- so `candidate_entry` is never `None`.

So `job_id is None` iff `entry is None`, and `a or b` and `a and b`
select the same branch on every input.  **No guard can kill it.**

Proved, not asserted, and with a **non-vacuity control**:

* the differential harness loads the module twice -- as it is on disk and
  with the mutation applied -- and compares the outcomes over a corpus of
  crafted queue states (empty, one allowed, one denied, one allowed and
  one denied, all denied, broken gate).  Every outcome is identical.
* the **control** breaks the pairing invariant (`entry = None` while
  `job_id` holds the candidate), so the two operands DISAGREE and the
  `or`/`and` forms must select different branches.  The harness must
  notice it, and it does -- so the harness is not blind, and the
  equivalence result is worth something.
* the **premise** is checked directly: the two operands are recorded at
  the guard over the same corpus, and they agree every time.

The comparison is symmetric, so the result holds whichever form is on
disk -- including when the mutation probe has already applied the fault.

Guards: `TheDequeueSkipLoopIsEquivalentTests` in
`components/northstar-agent-runtime/tests/test_refusal_hold_queue_wiring.py`.

So the nine survivors are now: **one equivalent mutant** (`or@1405`) and
**eight self-check assertion chains** (`and@1860`, `and@1864`,
`and@1865`, `and@1870`, `and@1875`, `and@1880`, `and@1897`,
`and@1904`).

**AMENDED 2026-11-25 -- the eight are KILLED, and they were never a
product gap.**  Two measurements, in this order, because the order
matters:

1. **The PROPERTIES are covered.**  Breaking each property the eight
   conjuncts assert -- the attempts counter, the priority order, the
   backoff, the ``done`` and ``dead`` terminal states, the records'
   digests -- makes MANY real tests fail at the four-suite scope, and
   ``test_main_self_check`` among them.  (Measured: breaking the
   attempts counter fails 3 tests; breaking the ``done`` state fails
   13; breaking the priority order fails 2; breaking the backoff fails
   2.)  So the product's behaviour is covered, and the eight survivors
   weaken only the self-check's own redundancy.

2. **The self-check's redundancy is now killed.**  A self-check is not
   a test: it asserts what the author believed, and a conjunct that can
   never be false is never checked.  So the eight are killed the way
   the repository already kills ``leased_task_claim.py``'s
   (``SelfCheckAndAssertKillerTests``): the accessor the assertion
   reads is **patched** so the FIRST operand is false and the SECOND is
   still true.  The original then raises ``AssertionError`` and the
   mutant (``or``) passes -- so the test kills it.

   Two traps, both found by planting the mutant and re-running:

   * a patch that makes **both** operands false kills nothing -- the
     mutant fails too, for the wrong reason.  So the record's
     ``verify()`` is patched to hold alongside the counter;
   * a patch that is **too broad** kills for the wrong reason: patching
     every dequeue's attempt count made the self-check raise on a
     *different* assertion.  So each patch is narrowed to the exact
     hand-out its assertion names.

   Measured: **8 of 8 killed** at the four-suite scope, with every
   mutant planted and re-run.

Guards: `TheSelfCheckAssertionChainsAreKilledTests` in
`components/northstar-agent-runtime/tests/test_refusal_hold_queue_wiring.py`.

So the census over `job_queue.py` at the union scope now reports **one**
survivor -- the equivalent mutant `or@1405`, which no guard can kill.

### 22.9 The scope was a CLAIM until the census script agreed with it

§22.1 prescribed the four-suite scope in prose.  But
`scripts/b173-census-all.sh` -- the script that actually runs the census
-- paired each module with **one** test file: the module's own, or the
first suite whose text mentioned the module's name.  So the scope the
docs described and the scope the census ran were **different scopes**, and
the census log never said which one it used.

Measured 2026-11-25 on `job_queue.py`, same tree, same probe, same
tries:

| scope | result | survivors |
|---|---|---|
| `test_job_queue` alone | **killed 43/85** | **42** |
| the four-suite union | **killed 76/85** | **9** |

**Thirty-three of the narrow scope's 42 "survivors" were caught by the
sibling suites.**  Every one of them was a false accusation of a weak
test suite -- the same shape as the stale-bytecode false kill, only
pointed the other way.

The nine that remain at the union scope are §22.8's nine, reproduced
exactly: `or@1405` (the dequeue skip loop) and the eight `and`s in the
`main()` self-check's assertion chains.

Two things this exposed, and both are now fixed:

* **The scope is now RESOLVED, not typed.** `scripts/census-scope.py`
  finds every suite that genuinely **imports** the module, read from the
  AST.  A grep cannot do this: `test_graph_database.py` and
  `test_status_page.py` both *mention* `job_queue.py` -- they quote its
  rules in a comment -- and neither imports it or exercises it.  A
  grep-based scope would have counted two suites that never touch the
  module.  The module's own suite comes first, so a census log is
  comparable between runs.
* **A scope must be STATED with its measurement.** A survivor count is
  meaningless without the scope it was taken at: 42 and 9 are both true
  of the same tree, and quoting either alone is a claim, not a
  measurement.  §22.1 already says this about the two-suite and
  four-suite series; it now says it about the census script too.

**The defect is not confined to `job_queue.py`.**  Measured 2026-11-25
over the runtime's **1620** top-level modules, **123** of them are
referenced by MORE THAN ONE test suite -- so the old single-suite
pairing understated the scope for **7.6%** of the runtime.  `agents.py`
alone is exercised by **eleven** suites (`test_agents`,
`test_context_budget_subagent`, `test_hooks`, `test_plugin_install`,
`test_plugin_metadata_bytes`, `test_run_setup`, `test_scaffold`,
`test_session_lease`, `test_streaming`, `test_tracing`,
`test_workspace_ext`).  A census that paired `agents.py` with
`test_agents` alone reports survivors that eleven suites would have
caught.

`tests/test_census_scope.py` pins the resolver's definition -- both
import shapes, prose-mention-is-not-a-reference, own-suite-first,
determinism, and the empty scope (which must SKIP rather than fall back
to an arbitrary suite).

## 23. AMENDED 2026-11-24 — the census found four unreached branches in the chain's own modules

### 23.1 The measurement

§19-§22 closed the census over `job_queue.py`.  The chain spans
**three** modules, and the other two had never been censused.  Run
over the union of every suite that references each one:

| module | suites | before | after |
|---|---|---|---|
| `refusal_hold.py` | `test_refusal_hold`, `test_refusal_hold_queue_wiring`, `test_refusal_hold_wiring` | **killed 14/14** | 14/14 |
| `refusal_hold_wiring.py` | `test_refusal_hold_wiring`, `test_finding_gate`, `test_refusal_hold_queue_wiring` | **killed 22/23** | **killed 22/23** -- the one survivor is an EQUIVALENT mutant (§23.4), so no guard can close it |
| `leased_task_claim.py` | `test_leased_task_claim`, `test_refusal_hold`, `test_refusal_hold_queue_wiring` | **killed 38/42** | **42/42** |

**AMENDED 2026-11-25 — the `refusal_hold.py` row named a suite that does
not reference it.**  The row listed `test_finding_gate`, but
`test_finding_gate.py` imports `refusal_hold_wiring` and **not**
`refusal_hold`; the resolver (`scripts/census-scope.py`, an AST import
read, not a grep) reports the union as the three suites in the row now.
The other two rows already matched the resolver exactly.  The measurement
is unchanged -- `refusal_hold.py` was clean either way -- but a scope row
that names a suite outside the scope is the same defect as §22.9's, in a
place where it was not caught: **the row was a claim, not a
measurement.**  Every scope row in this document now comes from the
resolver.

`refusal_hold.py` was already clean.  The other two had **five**
survivors between them, and they are the same shape: **branches the
repo's own code never takes**.

**Four** of the five were closed by this slice.  The fifth is an
**equivalent mutant** -- a mutation that changes no observable
behaviour, so no guard can kill it -- and §23.4 says so rather than
claiming it as a fix.

### 23.2 Three of them are one helper's unreachable half

`leased_task_claim.py`'s `_refusal_allows_reap` is the batch-safe
form of the refusal question, and it is the ONLY consumer of the
gate's boolean method:

```python
allows = getattr(gate, "task_allowed", None)
if callable(allows):
    try:
        return bool(allows(task_id, action, now=now))
    except Exception:
        return False          # <- leased_task_claim.py:666
require = getattr(gate, "require_task_allowed", None)
if not callable(require):
    raise TypeError(...)
try:
    require(task_id, action, now=now)
except Exception:
    return False              # <- leased_task_claim.py:677
return True                   # <- leased_task_claim.py:678
```

The repo's own gate (`RefusalHoldQueueGate`) offers **both**
methods, so:

* the boolean branch is always taken, and the **fallback** branch --
  the raising one -- is **never reached**; and
* the boolean method never raises (it answers `False`), so the
  `except Exception` inside it is **never reached** either.

So the whole fail-closed contract of this helper -- *a gate that
cannot answer blocks* -- was verified by **nothing**.  Three mutants
survived, and each one is a way to turn "the gate could not answer"
into "the re-dispatch is allowed":

| site | mutation | what it would break |
|---|---|---|
| `leased_task_claim.py:666` | the catch's `return False` -> `return True` | a gate whose boolean method **raises** (an unreadable store) is read as an ALLOW: the task goes back to `ready` behind a gate that never answered |
| `leased_task_claim.py:677` | the fallback's `return False` -> `return True` | a gate that offers only the raising method, and **refuses** by raising, is read as an ALLOW |
| `leased_task_claim.py:678` | the `return True` after the fallback -> `return False` | a gate that offers only the raising method, and does **not** refuse, is read as a REFUSAL -- the sweep skips every task forever |

**An unreached branch is not a weak guard; it is a branch nothing
reaches.**  The fix is to reach it -- the new guards install gates
that are shaped to take each branch on purpose:

| guard | branch it reaches |
|---|---|
| `test_a_gate_whose_boolean_method_raises_blocks_the_sweep` | the boolean branch's `except Exception` -- the fail-closed direction |
| `test_the_boolean_helper_answers_false_when_the_gate_raises` | the same, one level down, so the helper's own answer is pinned |
| `test_a_gate_that_only_offers_the_raising_method_blocks_the_sweep` | the **fallback** branch, with a refusal that RAISES |
| `test_the_fallback_branch_allows_when_the_gate_does_not_refuse` | the fallback branch's CONTROL -- without it, a helper that answered "not allowed" forever would pass the guard above |

The last two are a **pair**: one pins the answer in the refusing
direction and one in the allowing direction, so a helper that always
answered the same thing fails one of them.  That is the same shape as
§22's edge guards.

### 23.3 The mirror's release, in neither direction

`leased_task_claim.py:1035` is the fourth survivor:

```python
if view.state != "reserved":
    return True
```

A mirror job that is not `reserved` has **nothing to release**, so
the release is allowed -- a no-op must not block the sweep.  And a
`reserved` job's release is owed, so it is allowed only when the
queue's own gate allows.  The census found the answer pinned in
**neither** direction.

The guards are a pair for the same reason as §23.2's:

| guard | direction |
|---|---|
| `test_a_mirror_job_that_is_not_reserved_needs_no_release` | not `reserved` -> allowed |
| `test_a_reserved_mirror_job_is_released_only_when_the_gate_allows` | `reserved` -> allowed only when the gate allows, and **refused** when it does not |

Note what this guard found about the **wiring**, not the code: the
mirror's release is judged by the **queue's** gate
(`JobQueue.refusal_gate`), not the manager's.  The manager's gate
answers the *lease* question; the queue's answers the *queue*
question.  A guard that installed only one of them would have been
testing a gate the real path never consults.

### 23.4 The fifth survivor is EQUIVALENT -- and saying so is the finding

`refusal_hold_wiring.py:753` is the registry's event cap:

```python
if len(self._events) > MAX_WIRING_EVENTS:
    del self._events[: len(self._events) - MAX_WIRING_EVENTS]
```

The census reports the `>` -> `>=` mutation as surviving.  **It is
an equivalent mutant, and no guard can kill it.**  The reason is
arithmetic: at `len(self._events) == MAX_WIRING_EVENTS` the deletion
is `self._events[:0]` -- a no-op.  So the two variants keep exactly
the same trail for every number of events.

Verified exhaustively, not by eye:

```
for MAX in (1, 2, 3, 5, 4096):
    for n in 1 .. MAX + 11:
        ">"  and  ">="  produce identical trails   # always true
```

and at the real numbers:

```
MAX = 4096, 4106 events:
  ">"   -> 4096 kept, first is job-10, last is job-4105
  ">="  -> 4096 kept, first is job-10, last is job-4105
```

So the honest thing is to **say so** rather than to claim the cap is
now verified.  The three guards that ship with this slice do not
target that mutation; they pin the properties that ARE observable:

| guard | property |
|---|---|
| `test_the_registry_keeps_exactly_the_cap` | the trail holds exactly `MAX_WIRING_EVENTS` |
| `test_the_cap_drops_the_OLDEST_events` | the cap keeps the NEWEST and drops the OLDEST -- a cap that kept the newest-but-N would discard the refusal recorded first |
| `test_the_cap_never_exceeds_the_limit` | the trail is never LONGER than the cap, so the registry's memory is bounded |

**A mutant that changes no observable behaviour is not a coverage
gap.**  Reporting it as one would be a false finding.

### 23.5 What this does NOT change

* **No code change.**  `leased_task_claim.py`, `refusal_hold.py` and
  `refusal_hold_wiring.py` are unchanged by this slice -- not one byte
  different from `719c4cb5`.  This slice closes *evidence* gaps,
  exactly as §19 and §22 did.
* No version, schema, or audit kind is added or changed.
* No digest changes.
* §17's through §22's guards are unaffected.

### 23.6 What the census still reports

* `job_queue.py`: **one** survivor (§22.8, amended 2026-11-25) -- the
  dequeue skip loop's `or`, which is EQUIVALENT.  It was nine when
  this section was written: the other eight were the `main()`
  self-check's assertion chains, and they are now KILLED (§22.8).
  **RE-MEASURED 2026-11-25 at killed 84/85 (§27.5)** -- the census had
  reported 85/85 because the equivalence proof asserted a SPELLING and
  so killed the mutant for the wrong reason (§27.1).
* `leased_task_claim.py`: **none**.
* `refusal_hold_wiring.py`: **one**, and it is EQUIVALENT -- the
  event cap's `>` -> `>=`, which changes no observable behaviour
  (§23.4).  It is reported, not closed.  **RE-MEASURED 2026-11-25 at
  killed 22/23 (§27.5)** -- the census had reported 23/23 because the
  scope was already failing on the pristine source (§27.2).
* `refusal_hold.py`: **none**.

The one survivor that remains everywhere is the **self-check** shape:
`main()` asserts what the author believed, and each conjunct of an
`assert a and b` is individually untested.  That is a separate
category, and it is recorded rather than folded in.

**AMENDED 2026-11-25 (§27):** the last sentence is now HISTORICAL.  The
self-check shape is closed -- the eight assertion chains are KILLED
(§22.8) -- and the survivors that remain are the two EQUIVALENT mutants
above, which no guard can kill because they change no observable
behaviour.

## 24. AMENDED 2026-11-24 — the batch form asked a DIFFERENT question than the raising form

### 24.1 The defect

§18 gave the batch form (`retry_allowed()`) its reason, and its
docstring says the gate "is consulted **once**, by the same writer that
:meth:`retry` uses".  But the two forms did **not** ask the gate the
same question.

`retry()` asks the **raising** form:

```python
require = getattr(gate, "require_queue_allowed", None)
...
require(job_id, action, now=now)
```

`retry_allowed()` asked the **boolean** form first, and only fell back
to the raising one when the gate did not offer the boolean one:

```python
allows = getattr(gate, "queue_allowed", None)
if callable(allows):
    try:
        return bool(allows(job_id, action, now=now)), None
    except Exception as exc:
        return False, exc
require = getattr(gate, "require_queue_allowed", None)
```

A host gate that offers **both** is expected to answer both the same
way -- they are the same question -- but nothing enforced it, so the
batch form could be **more permissive** than the raising form.

Measured 2026-11-24, on the tree as §23 left it, with a gate whose
boolean form allows and whose raising form refuses:

```
--- the RAISING form ---
retry raised: RuntimeError refused
state j1: reserved

--- the BATCH form, the SAME gate, the SAME job, the SAME action ---
retry_allowed -> RetryRecord(job_id='j1', attempts=1, ..., state='ready')
state j1: ready
```

The gate **refused** the re-dispatch and the batch form re-dispatched it
anyway.  The job went back to `ready` -- so the refused action was
offered again.

**And the boolean branch was dead code against the real contract.**
The repo's own queue gate offers **only** `require_queue_allowed`; the
queue side has no boolean method at all.  Measured over the whole
repository:

```
$ grep -rn "def queue_allowed" --include=*.py . | grep -v build/
components/northstar-agent-runtime/tests/test_refusal_hold_queue_wiring.py:89
```

Every hit is a **test** helper.  So the one path that could fail open
was a path **no host takes** -- and the path that every host *does*
take was the one the batch form used only as a fallback.

That is the same shape §22 and §23 found elsewhere in the chain: a
branch that the repo's own code never takes, verified by nothing.

### 24.2 Two further consequences of the same wrong question

The boolean form could not tell a refusal from a broken gate, because
the hold **fails closed**: both answer `False`.  So the batch form
booked a `job.rejected` row for a gate that "refused nothing in
particular" -- the exact row §17's rule forbids.

```
--- a BROKEN gate, the RAISING form ---
retry raised: RuntimeError the gate cannot answer
audit: [('job.enqueued', ...), ('job.dequeued', ...)]            <- no row

--- a BROKEN gate, the BATCH form ---
retry_allowed -> None
audit: [..., ('job.rejected', {'reason': 'RuntimeError', ...})]   <- a row
```

Same broken gate; two forms; two different trails.  §18's rule -- "a
broken gate books no row" -- was implemented on the raising form only.

And when the boolean form answered `False` **without raising**, the
helper's exception slot was empty, so the row's `reason` was the class
name of the *missing* exception:

```
the row: {'reason': 'NoneType', 'refusal_reason': None, 'job_id': 'j1', 'action': 'dispatch'}
```

A reader of the trail sees a refusal whose reason is the **absence** of
an exception.

### 24.3 The fix

`_refusal_allows()` now asks the **raising** form first, and falls back
to the boolean form only when the gate offers no raising one:

```python
require = getattr(gate, "require_queue_allowed", None)
if not callable(require):
    allows = getattr(gate, "queue_allowed", None)
    if not callable(allows):
        raise TypeError(...)
    ...
```

That fixes all three consequences at once:

* the batch form is no longer **more permissive** than the raising form
  -- both ask the same question, of the same gate;
* the reason comes from an **exception**, so it names a real class and a
  real refusal;
* `_is_refusal` can tell a refusal from a broken gate, because the
  raising form distinguishes them by what it raises.

The batch form's **booking** now uses the same rule the raising form
uses -- a broken gate books no row:

```python
if not allowed:
    if exc is not None and _is_refusal(exc):
        self._reject_refusal(seq, job_id, retry_action, exc)
    return None
```

**A gate that offers ONLY the boolean form** still works, because a
host that implements the contract partially must not be broken by the
queue.  Its refusal carries no reason, so the queue raises its own
`UnnamedRefusalError` -- a **real** class, named in the row -- instead
of the class name of a missing exception:

```python
class UnnamedRefusalError(JobQueueError):
    """The refusal gate refused without saying WHY."""
```

`_is_refusal` recognises it, so the row is still booked.

**No version, schema, or audit kind is added or changed.**  The gate is
still asked **once** per job on both forms -- §13.4's "one check per
job" count is the count of the **gate's** calls, and it is unchanged.
The registry's `checked` events are unaffected.

### 24.4 The guards

Eight new guards in two classes
(`tests/test_refusal_hold_queue_wiring.py`):

| guard | what it pins |
|---|---|
| `test_the_batch_form_refuses_what_the_raising_form_refuses` | the defect: the batch form re-dispatched a REFUSED action |
| `test_the_batch_form_leaves_a_refused_job_where_it_was` | the job keeps its state and its attempts |
| `test_the_two_forms_agree_on_a_gate_that_offers_only_the_raising_one` | a one-form gate is unchanged |
| `test_an_allowed_gate_still_re_dispatches` | the control: the ordinary path is intact |
| `test_a_broken_gate_books_no_rejected_row_on_the_batch_form` | a broken gate is not recorded as a refusal |
| `test_a_refused_row_names_a_reason_that_is_not_the_absence_of_one` | the row never says `NoneType` |
| `test_a_refused_row_still_names_the_job_and_the_action` | the control: WHO and WHAT survive |
| `test_the_raising_form_and_the_batch_form_book_the_same_rows` | two forms, one trail |

### 24.5 The measurements

**The whole-file census** over `job_queue.py`, run over the union of
every suite that references it (`test_refusal_hold_queue_wiring`,
`test_job_queue`, `test_leased_task_claim`, `test_refusal_hold_wiring`):

| | before | after |
|---|---|---|
| sites | 82 | **84** |
| killed | **73/82** | **75/84** |

The two new sites are the two new constructs in `_refusal_allows` --
the reordered `if not callable(require)` and the `if allowed:` inside
the boolean-only fallback -- and **both are killed**.  The survivor set
is **unchanged**: the same nine survivors, shifted by the line offsets
of this change:

| before | after | what it is |
|---|---|---|
| `or@1273` | `or@1353` | the `or` in the dequeue skip loop |
| `and@1681`, `and@1685`, `and@1686`, `and@1691`, `and@1696`, `and@1701`, `and@1718`, `and@1725` | `and@1771`, `and@1775`, `and@1776`, `and@1781`, `and@1786`, `and@1791`, `and@1808`, `and@1815` | the `and` in the module's own `main()` self-check's assertion chains |

Those nine are §22.8's survivors, and §22.8 says why they are a
separate category (each conjunct of an `assert a and b` is
individually untested).  This slice does not claim them.

**Four targeted mutants** were planted into the changed code and
re-run against the four suites.  All four are **killed**:

| mutant | verdict |
|---|---|
| never prefer the raising form (fall back to the boolean one always) | **KILLED** |
| book a row for a broken gate too (drop the `_is_refusal` check) | **KILLED** |
| `UnnamedRefusalError` is not a refusal (drop the `_is_refusal` special case) | **KILLED** |
| `UnnamedRefusalError` is an ordinary error (swap the class) | **KILLED** |

### 24.6 What this does NOT change

* **No version, schema, or audit kind** is added or changed.  The only
  new public name is `UnnamedRefusalError`, and it is a `JobQueueError`
  subclass like every other error in the module's taxonomy.
* The gate is still asked **once** per job on both forms -- §13.4's
  "one check per job" count is the count of the **gate's** calls, and
  it is unchanged.  The registry's `checked` events are unaffected.
* `dequeue()`'s hand-out path is untouched: it already asked the
  raising form.
* `leased_task_claim.py`, `refusal_hold.py` and `refusal_hold_wiring.py`
  are **unchanged** by this slice.
* §17's through §23's guards are unaffected -- the four suites are
  green.

### 24.7 The bench baseline is stale, and that is a SEPARATE slice

This slice's bench artifact is `169/169, 0 failed`.  The bench baseline
the referee compares against -- `b173-bench-baseline-CURRENT` ->
`b173-bench-baseline-2db42e93....failures.txt` -- names **eight**
failing items, so `BENCH_DIFF` compares an empty set against an
eight-item set and fails.

The baseline is not wrong for its commit: measured on `2db42e93` in a
throwaway worktree, the bench scores **161/169, 8 failed** -- exactly
the eight items.  The baseline is simply pinned to a commit from
**2026-11-06**, and the slice `1b2b0ad9` ("make the five live sandbox
cases actually executable", 2026-11-22) moved the score from 161/169
to **169/169** without re-pinning the baseline.

So this is a **baseline-attribution** question, not a refusal-hold
question, and it is reported here rather than fixed by this slice:
re-pinning the baseline is the coordinator's call, and every slice
that lands after `1b2b0ad9` will fail `BENCH_DIFF` for the same
reason.  The refusal-hold chain's own bench never touched the sandbox
cases.

## 25. AMENDED 2026-11-25 — the two forms did not leave the SAME trail

§24 fixed the batch form's *question*.  It did not fix the
*trail*: §18.2 states the rule —

> **The two forms agree.**  The raising form and the batch form are one
> writer (`_retry`), so a refusal must leave the same trail whichever
> form asked.  A guard asserts that the two rows are equal.

— and the guard it names did not hold it.  §24's guard compared the
two forms' *row counts* for a **broken** gate, where both are zero.
For a **refusal**, the two forms left **different** trails.

This section was found by measurement, not by reading: the guards
were moved into `tests/test_job_queue.py` (the file that owns the
`retry_allowed` API and that the slice's own manifest names), and
the first run of the moved guards failed.  Three distinct
asymmetries, all in the RAISING form's favour or against it.

### 25.1 DEFECT 1 — one refusal booked TWO rows

The raising form books the refusal inside its own `except` block and
then **re-raises**.  The exception continues into the generic
`except JobQueueError` handler further out, which books a **second**
`job.rejected` row for the same refusal -- with a different shape.

Measured 2026-11-25, on the tree as §24 left it:

```
raising form, one refused job:
  job.rejected {'reason': 'RefusalRefusedError',
                'refusal_reason': 'blocked_by_refusal',
                'job_id': 'j1', 'action': 'send_email'}
  job.rejected {'reason': 'RefusalRefusedError', 'job_id': 'j1'}
```

Two rows, one refusal, and **two different stories about it**: only
one of the rows names the ACTION, and only one names the reason.  Which
one a reader picked determined what they learned.  The batch form
booked one row, so the two forms disagreed.

### 25.2 DEFECT 2 — a broken gate booked a row on the raising form only

The generic handler books a row for **any** `JobQueueError`, including
one that came out of the **gate**.  But §16.2's rule is explicit: a
broken gate refuses nothing in particular, so a `job.rejected` row
would put a refusal in the trail that never happened.

The batch form honoured that (it asks `_is_refusal`); the raising
form did not, for a gate whose vocabulary `_is_refusal` does not
recognise.

Measured 2026-11-25, on the tree as §24 left it:

```
plain JobQueueError gate   raising rows=1  batch rows=0
RuntimeError gate          raising rows=0  batch rows=0
```

The first row is the asymmetry: the SAME gate, the SAME refusal, and
the two forms disagreed about whether it happened.

### 25.3 DEFECT 3 — a dead job booked a rejection on the raising form only

The **dead** path (the job's retry budget is spent) raises
`MaxRetriesExceededError` on the raising form, and the generic handler
booked the rejection.  The batch form returns `None` — "not
re-dispatched" — and booked **nothing**.

Measured 2026-11-25, on the tree as §24 left it:

```
RAISING dead  rejected rows: [('job.rejected',
                                {'reason': 'MaxRetriesExceededError',
                                 'job_id': 'j-1'})]
BATCH   dead  rejected rows: []
```

The `job.dead` row is booked on both forms, so the trail did name the
death -- but the REJECTION was on one form only, and the rejection is
what says the job was not re-dispatched.

### 25.4 The fix

Three changes, all in `_retry`:

1. **The gate's exception is not a queue-level rejection.**  A flag
   (`_gate_raised`) records that the exception reaching the generic
   handler came from the gate, so the generic handler does not book a
   row for it.  A REFUSAL books its own row in the refusal branch,
   where the reason AND the action are both in hand; a BROKEN gate
   books no row at all.
2. **The dead path books the same row on both forms.**  The batch
   form books `MaxRetriesExceededError` explicitly before returning
   `None`, because the raising form's row arrives through the generic
   handler.
3. **The batch form's row is booked once.**  Unchanged from §24, but
   now the two forms agree on the row's *shape* too: the surviving
   row is the one that names the action and the reason.

### 25.5 The guards

Ten new guards in `tests/test_job_queue.py` — the file that owns the
`retry_allowed` API, and that this slice's manifest names.  They live
beside the other `retry_allowed` tests rather than in the wiring
suite, because a test file that another slice introduced is not
evidence for this one (see `test_r8_commit_attribution.py`'s rule:
a manifest file is accounted for only when the commit that introduced
it also introduced one of the manifest's files, or is the slice's own
subject commit).

| guard | what it pins | RED before the fix |
|---|---|---|
| `test_the_batch_form_refuses_what_the_raising_form_refuses` | the §24 defect: a refused action was re-dispatched | §24's fix |
| `test_the_batch_form_leaves_a_refused_job_where_it_was` | the job keeps its state and its attempts | §24's fix |
| `test_the_two_forms_agree_on_a_gate_that_offers_only_the_raising_one` | a one-form gate is unchanged | §24's fix |
| `test_a_boolean_only_gate_still_refuses` | a gate with no raising form is not treated as allowing | §24's fix |
| `test_an_allowed_gate_still_re_dispatches` | the control: the ordinary path is intact | §24's fix |
| `test_the_batch_form_asks_the_gate_exactly_once_on_the_refused_path` | one job is ONE check | §24's fix |
| `test_a_broken_gate_books_no_rejected_row_on_the_batch_form` | a broken gate is not recorded as a refusal | §24's fix |
| `test_a_refused_row_names_a_reason_that_is_not_the_absence_of_one` | the row never says `NoneType` | §24's fix |
| `test_a_refused_row_still_names_the_job_and_the_action` | WHO and WHAT survive | **RED** |
| `test_the_raising_form_books_exactly_ONE_row_for_one_refusal` | **DEFECT 1**: one refusal, one row | **RED** |
| `test_a_plain_queue_error_gate_is_booked_the_same_way_on_both_forms` | **DEFECT 2**: the forms agree on an unrecognised vocabulary | **RED** |
| `test_the_dead_path_books_the_same_rows_on_both_forms` | **DEFECT 3**: the dead path agrees | **RED** |

**Verified RED against the pre-fix tree.**  The four guards marked
**RED** were run against `job_queue.py` as of `481d2366` (the tree as
§24 left it), with this round's test file in place:

```
$ python3 -m pytest -q tests/test_job_queue.py     # pre-fix job_queue.py
FAILED tests/test_job_queue.py::test_the_raising_form_and_the_batch_form_book_the_same_rows
FAILED tests/test_job_queue.py::test_the_raising_form_books_exactly_ONE_row_for_one_refusal
FAILED tests/test_job_queue.py::test_a_plain_queue_error_gate_is_booked_the_same_way_on_both_forms
FAILED tests/test_job_queue.py::test_the_dead_path_books_the_same_rows_on_both_forms
4 failed, 38 passed
```

and against the fixed tree: `42 passed`.

### 25.6 What this does NOT change

* **The refusal's vocabulary is unchanged.**  `_is_refusal` still draws
  the line on the error's own vocabulary: a `reason` attribute whose
  value is one of the hold's `blocked_*` reasons, or the class name
  `RefusalRefusedError`.  §25.2 does not widen it -- it makes the two
  forms agree on an UNRECOGNISED vocabulary, and the only consistent
  answer there is **neither** books a row, because a gate the queue
  cannot answer refuses nothing in particular.  A host that wants its
  refusals recorded raises the shape the wiring raises.
* **The raising form still raises**, and the batch form still returns
  a bare `None` for "not re-dispatched".
* **The queue's own validation errors still book a row.**  A
  `BadDelayError` from `retry()`'s own argument check is a
  queue-level rejection, and it is still booked.
* **`dequeue()` is unchanged.**  It has its own refusal path (§15,
  §16), and it books one row per refused candidate.

---

## 26. AMENDED 2026-11-25 — a `blocked_*` prefix was not enough to make a refusal PER-JOB

### 26.1 The finding

§16.2's load-bearing rule is:

> **A broken gate is NOT a refusal, and is not skipped.**  The skip is
> only sound for a **per-job** refusal; a gate that cannot answer at all
> is a property of the **gate**, and skipping it would turn a broken
> gate into a silently degraded queue -- fail-**OPEN**.

and §17.2 adds:

> **A broken gate books no row.**  A broken gate fails the whole call
> and refuses nothing in particular; booking a `job.rejected` row for
> it would put a refusal in the trail that never happened.

`_is_refusal` drew the line on the error's own vocabulary, and the
vocabulary it used was a **prefix**:

```python
reason = getattr(exc, "reason", None)
if isinstance(reason, str) and reason.startswith("blocked_"):
    return True
```

But the hold's own taxonomy puts **two different things** under that
prefix (`refusal_hold.py`'s reason constants):

| reason | whose condition is it? |
| --- | --- |
| `blocked_by_refusal` | the (job, action) PAIR -- a refusal row covers it |
| `blocked_key_invalid` | the (job, action) PAIR -- its identity is malformed |
| `blocked_store_unreadable` | the **GATE** -- it could not read its own store |
| `blocked_row_invalid` | the **GATE** -- the row is not a refusal row at all |
| `blocked_row_tampered` | the **GATE** -- the row was forged |

The first two are per-job: they name one (job, action) pair, and a
different pair is unaffected.  The last three are the gate's own
condition.

**The real gate reports its brokenness as one of the last three.**  So
the prefix test could not tell the two apart, and the broken gate was
classified as a per-job refusal: skipped, and booked a row.

### 26.2 The measurement

Measured 2026-11-25, on the tree as §25 left it, with the REAL gate over
a store that cannot be read (`RefusalHoldStore.break_reads()`):

```
--- the real gate, its store broken ---
dequeue raised: RefusalRefusedError job 'j1' may not be re-dispatched
  for action 'send_email': a recorded refusal covers it
  (blocked_store_unreadable); the job stays where it is
states after: ready ready
--- queue audit trail ---
  job.enqueued {...}
  job.enqueued {...}
  job.rejected {'reason': 'RefusalRefusedError',
                'refusal_reason': 'blocked_store_unreadable',
                'job_id': 'j1', 'action': 'send_email'}
  job.rejected {'reason': 'RefusalRefusedError',
                'refusal_reason': 'blocked_store_unreadable',
                'job_id': 'j2', 'action': 'send_email'}
```

Two refusals booked for a gate that refused nothing in particular --
exactly what §17.2 forbids.

And with the gate breaking **MID-LIST** -- candidate 1 refused for
real, candidate 2 hits the broken store:

```
dequeue raised: ... (blocked_store_unreadable)
  job.rejected rows: j1 (blocked_by_refusal),
                     j2 (blocked_store_unreadable),
                     j3 (blocked_store_unreadable)
```

The broken answer was skipped like a refusal and the walk continued, so
the queue could hand out a job behind a broken gate -- the fail-OPEN
§16.2 names.

### 26.3 Why the existing guard could not see it

`test_a_broken_gate_books_no_rejected_row` used a gate that raises
`RuntimeError`:

```python
class _Broken:
    def require_queue_allowed(self, job_id, action, *, now=None):
        raise RuntimeError("the gate cannot answer")
```

A `RuntimeError` is an **UNRECOGNISED** broken gate.  It was never
classified as a refusal in the first place, so the guard was already
green and the prefix was never exercised.  The real gate never raises
`RuntimeError` -- it raises `RefusalRefusedError` carrying a
`blocked_*` reason.  **The guard tested the shape the rule did not
contain.**

### 26.4 The fix

`job_queue.py` now names the gate's own conditions explicitly:

```python
_GATE_CONDITION_REASONS = frozenset(
    {
        "blocked_store_unreadable",
        "blocked_row_invalid",
        "blocked_row_tampered",
    }
)
```

and `_is_refusal` returns `False` for them.  The prefix test is kept
for the **per-job** reasons, so a host that raises a `blocked_*` slug
the repo has not seen is still treated as a refusal (fail-safe toward
skipping, which is the safe direction for a per-job answer).

The set is a literal, not an import: the queue must not import the
wiring (the wiring imports the hold, and the hold must not drag the
queue in).

### 26.5 The guards

Three new guards in `BrokenGateIsNotAPerJobRefusalTests`
(`tests/test_refusal_hold_queue_wiring.py`):

| guard | what it pins |
| --- | --- |
| `test_a_gate_whose_store_is_unreadable_books_no_rejected_row` | the defect: the REAL gate over a broken store books no row |
| `test_a_gate_that_breaks_mid_list_is_not_skipped` | the broken answer STOPS the walk -- the reason that reaches the caller is `blocked_store_unreadable`, and no job is handed out |
| `test_the_per_job_refusal_is_still_a_refusal` | the control: narrowing the rule must not narrow it to nothing -- a real per-job refusal is still skipped and still books its row |

### 26.6 The verification

RED first, on the unfixed tree:

```
$ python3 -m pytest -q tests/test_refusal_hold_queue_wiring.py \
      -k BrokenGateIsNotAPerJobRefusal
FAILED ...::test_a_gate_that_breaks_mid_list_is_not_skipped
FAILED ...::test_a_gate_whose_store_is_unreadable_books_no_rejected_row
2 failed, 1 passed, 198 deselected
```

GREEN on the fixed tree: `3 passed`.

The mutation run -- the fix reverted in place, the tests re-run:

```
$ # remove the _GATE_CONDITION_REASONS branch
FAILED ...::test_a_gate_that_breaks_mid_list_is_not_skipped
FAILED ...::test_a_gate_whose_store_is_unreadable_books_no_rejected_row
2 failed, 1 passed, 198 deselected
```

**MUTANT KILLED.**  The fix is what makes the two tests pass; they do
not pass for another reason.

The adjacent suites, on the fixed tree:

```
$ python3 -m pytest -q tests/test_refusal_hold_queue_wiring.py \
      tests/test_job_queue.py tests/test_refusal_hold.py \
      tests/test_refusal_hold_wiring.py tests/test_cancellation_tombstone.py \
      tests/test_leased_task_claim.py
581 passed, 32 subtests passed
```

### 26.6a The whole-file census, and a FALSE KILL caught in the act

The whole-file census over `job_queue.py`, run over the union of every
suite that references it (`test_refusal_hold_queue_wiring`,
`test_job_queue`, `test_leased_task_claim`, `test_cancellation_tombstone`):

| | before this slice | after |
|---|---|---|
| sites | 84 | **85** |
| killed | **75/84** | **76/85** |
| survivors | **9** | **9** |

The survivor set is **unchanged** -- the same nine, shifted by this
slice's line offsets:

| before | after | what it is |
|---|---|---|
| `or@1353` | `or@1405` | the `or` in the dequeue skip loop |
| `and@1808`, `and@1812`, `and@1813`, `and@1818`, `and@1823`, `and@1828`, `and@1845`, `and@1852` | `and@1860`, `and@1864`, `and@1865`, `and@1870`, `and@1875`, `and@1880`, `and@1897`, `and@1904` | the `and` in the module's own `main()` self-check's assertion chains |

Those nine are §22.8's survivors, and §22.8 says why they are a
separate category (each conjunct of an `assert a and b` is
individually untested).  This slice does not claim them.

**The false kill, and why it matters.**  The "before" number above was
measured by putting the PREVIOUS `job_queue.py` back while this
slice's NEW test file was still in the tree.  The new tests fail
against the old source -- that is what RED means -- so **every**
mutant died from the unrelated failure and the census reported a
flattering `84/84`.

That is the mirror image of the stale-bytecode false kill the probe
already guards against: there, a stale `.pyc` made the suite "kill" a
fault that survived; here, a failing test file made the suite "kill"
faults it never measured.  **The pre-flight does not catch it**, because
the pre-flight only asks whether the suite COLLECTED -- and this suite
collects fine, it just fails.

The honest baseline was measured by putting BOTH the previous source
AND the previous test file back: `75/84`, nine survivors.  That is the
number the comparison above uses, and it is the number the slice's own
§24.5 already reports.

**How to apply:** a census baseline must be measured with the WHOLE
slice reverted -- source AND tests -- or the new tests will fail on
the old source and manufacture kills.  A census that reports a
suspiciously perfect score against a tree that has a new test file in
it is reporting the test file, not the mutants.

### 26.7 What this does NOT change

* **A per-job refusal is still a per-job refusal.**  `blocked_by_refusal`
  and `blocked_key_invalid` still classify as refusals, are still
  skipped, and still book their row.  The control guard pins that.
* **The raising form still raises** and the batch form still returns a
  bare `None`.
* **`_is_refusal` still draws the line on the error's own vocabulary.**
  The vocabulary was the problem, not the duck-typing.
* **An unrecognised `blocked_*` slug is still a refusal** -- the safe
  direction for a per-job answer.

### 26.8 The general lesson

**A prefix is not a taxonomy.**  `blocked_` groups five reasons, and
two of them name a (job, action) pair while three name the gate.  A
rule that reads the prefix reads the group, not the category.

The measure that found it was not reading the code.  It was asking
**"what would the real gate do when it is broken?"**, building that
gate, and running the queue against it.  The existing guard had
already tested "a broken gate" -- but with a broken gate the queue had
never been given.

## 27. AMENDED 2026-11-25 — the census had a FALSE KILL, and it was in the PROBE

This round started by checking a number that looked too good: the
`job_queue.py` census reported **killed 85/85**.  Nine mutants had been
closed in §22.8 and the last one, `or@1405`, had been *proved* equivalent
(§9.1's table).  A proved-equivalent mutant cannot also be killed, so one
of the two was wrong.

It was the census.  This section records why, because the defect is not
in the product -- it is in the **measuring instrument**, and it produced
false evidence in the exact direction that flatters.

### 27.1 DEFECT 1 — an equivalence proof that asserted a SPELLING

`tests/test_refusal_hold_queue_wiring.py`'s
`test_or_at_1405_the_operands_really_do_agree` instrumented the guard by
matching a **literal**:

```python
instrumented = original_source.replace(
    "            if job_id is None or entry is None:",
    "            with open(_OPERAND_LOG, 'a') as _f:\n" ... )
self.assertNotEqual(instrumented, original_source)
```

When the `or` -> `and` mutant was planted on disk, that literal was
**gone**.  So `instrumented == original_source`, the `assertNotEqual`
fired, and the test failed -- **for a spelling reason, not a behavioural
one**.  The census read that failure as "the mutant was killed".

Measured, on the same tree, by hand:

| tree | result |
|---|---|
| pristine | 402 passed |
| `or@1405` planted, **before** the fix | **1 failed** -- the spelling assertion |
| `or@1405` planted, **after** the fix | **402 passed** -- the mutant survives |

So the honest `job_queue.py` figure is **killed 84/85**, with `or@1405`
SURVIVED -- exactly what §9.1's equivalence table says it should be.

The fix anchors the instrumentation on the guard's **shape** (a regex
over the `if job_id is None (or|and) entry is None:` line) instead of one
spelling of it, so it lands on whichever form is on disk.

This is the second time this exact trap has been hit in this repo, and
the first time it was hit **by the proof itself**: see
`docs/design/mutant-evidence-closure.md` §9.1 and the note that a proof
of equivalence must be run against a mutation that IS observable.  The
control here was already present and it did not fire -- because the
control used a DIFFERENT mutation (the broken pairing invariant), not the
one the census applies.  **A non-vacuity control must be run against the
mutant the census actually applies**, not merely against some observable
mutation.

### 27.2 DEFECT 2 — a scope that was broken BEFORE the probe started

The `refusal_hold_wiring.py` census reported **killed 23/23**.  §23.4
had proved the event cap's `>` -> `>=` an equivalent mutant -- by
arithmetic, at the real numbers.  It cannot be both.

Planting it and running the scope's suites by hand:

```
359 passed, 5 errors        # the MUTANT tree
359 passed, 5 errors        # the PRISTINE tree -- the SAME 5 errors
```

The five errors are `test_finding_gate.py`'s `DesignDocTests`, which
read `docs/design/bughunter-finding-gate.md` from the **repo root** via
`Path(__file__).resolve().parents[3]`.  The census worktree copies only
the component directory, so the doc is absent and those tests error at
setup.

And that error is on the **pristine** source -- so the suite's exit code
was non-zero **before any mutant was applied**.  `scripts/b173-mutant.py`
took a pre-flight reading of the pristine suite for exactly this
distinction, and it computed the signal:

```python
preflight_collection_failed = collection_failed(_pf_out)
```

and then **never used it**.  The probe only skipped when the suite
collected NOTHING.  A suite that COLLECTS tests but FAILS passed
straight through, and every round's non-zero exit was read as "mutant
killed".

**All 23 kills were false.**  With the worktree fixed to carry the repo
root, and the probe treating a pristine-source failure as a SKIP, the
census reports `gt@753 SURVIVED` -- which is what §23.4 said.

### 27.3 The scale

The defect is not confined to one module.  **17** of the runtime's
suites resolve a path that leaves the component directory, and **16** of
the runtime's **1620** modules have a census scope that includes one:

```
audit_export   cli   code_task   events   ed25519   finding_gate
audit_chain    hlc   loop        postconditions   runtime_evidence
sdk   blind_rerunner   dataflow_policy   refusal_hold_wiring
```

For each of those, every mutant in the scope could have been reported
killed by a suite that was already failing.

### 27.4 The fix, and its guards

Two defects, two fixes:

1. **`scripts/b173-census-all.sh`** now copies the repo root's `docs/`,
   `scripts/` and `tests/` into the census worktree, so the suites that
   read outside the component can actually run.
2. **`scripts/b173-mutant.py`** now treats a pristine-source FAILURE as a
   SKIP.  The exit code is the primary signal, because a setup error
   leaves tests COLLECTED but failing -- which `collected_nothing` cannot
   see.

`tests/test_mutant_probe_pristine_failure.py` pins both, with a
**non-vacuity control**: a synthetic worktree where the suite FAILS on
the pristine source must produce a SKIP and no kill, and **the same
probe against a healthy suite must still kill the mutant**.  Without the
second half, a probe that skipped everything would satisfy the first.

Both halves were verified load-bearing: breaking the probe's fix fails
the first test, and breaking the census's copy fails the second.  The
probe is also pinned to leave the module it mutated pristine.

**A THIRD GUARD CAUGHT A VIOLATION OF THIS SECTION'S OWN RULE.**
`test_equivalence_table_coverage.py` requires every site §9.1's table
names to be proved by CODE in a test file -- a comment naming a site is
a note about the site, not a test of it.  Adding `gt@753` to that table
with only §23.4's prose proof made the repo suite red:

```
FAILED tests/test_ci_runner_artifacts.py::
  CoordinatorArtifactSimulationTests::test_the_files_that_read_the_coordinator_survive_its_absence
  -> tests/FAILED (failures=1, skipped=105)
```

The guard fired from inside the CI simulation, because
`test_equivalence_table_coverage.py` is one of the files that read the
coordinator's directory.  The fix was to write the proof as code
(§27.5), not to weaken the guard.

### 27.5 The corrected measurements

| module | before | after | the survivor |
|---|---|---|---|
| `job_queue.py` | 85/85 | **84/85** | `or@1405` -- EQUIVALENT (§9.1), proved |
| `refusal_hold_wiring.py` | 23/23 | **22/23** | the event cap's `>` -> `>=` -- EQUIVALENT (§23.4), proved |
| `leased_task_claim.py` | 42/42 | **42/42** | none -- the scope was not contaminated |
| `refusal_hold.py` | 14/14 | **14/14** | none -- the scope was not contaminated |

**§23.6 is corrected by this section.**  It said `job_queue.py` had one
survivor (`or@1405`) and `refusal_hold_wiring.py` had one (the cap) --
both right, and both right for a reason the census had hidden.  The two
survivors are EQUIVALENT mutants, so no guard can close them; they are
reported, not claimed as gaps.

**THE TWO PROOFS ARE NOW EXECUTABLE, NOT PROSE.**  §9.1's table names
every site it carries, and `test_equivalence_table_coverage.py` requires
each named site to be proved by **code** in a test file -- a comment
naming a site is a note about the site, not a test of it.  Adding
`gt@753` to that table therefore required writing the §23.4 arithmetic
proof as a test, and that is now
`TheEventCapIsEquivalentTests` in
`tests/test_refusal_hold_queue_wiring.py`:

* the **differential proof** loads the module twice -- once with the
  `>` guard and once with the `>=` guard -- and drives both through the
  same sequence of recordings for every count from 0 to ``cap + 12``,
  at caps 1, 2, 3, 5 and 64, requiring IDENTICAL trails;
* the **non-vacuity control** deletes one event too many, which shrinks
  the trail, so the two forms must DIVERGE -- the harness has to notice
  it, or it is blind and the equivalence is worthless;
* the **premise** is checked directly: at exactly the cap the two forms
  keep the same number of events, so the deletion is a no-op.

**THE CONTROL WAS WRONG ON THE FIRST PASS, AND THAT MATTERED.**
Lowering the cap's BOUND is not a control: the deletion's length is
``len(self._events) - MAX_WIRING_EVENTS``, which does not depend on the
bound, so ``> MAX - 1`` still deletes ``[:0]`` at the cap and is
EQUIVALENT too.  The measured control showed no divergence, and the
fix was to change what is DELETED rather than when.

**AND THE PROOF ANCHORS ON SHAPE, NOT SPELLING -- THE §27.1 TRAP,
TWICE.**  The first version of this proof matched the literal
``"if len(self._events) > MAX_WIRING_EVENTS:"``, and planting the
mutant made it fail -- for the same spelling reason as `or@1405`.  The
anchor is now a regex over the guard's shape, so it lands on whichever
spelling is on disk.  **Verified by planting:** with the `>=` mutant on
disk, all three proof tests PASS (the mutant correctly survives).

### 27.6 What this does NOT change

* **No product code changed.**  `job_queue.py`, `refusal_hold_wiring.py`,
  `refusal_hold.py` and `leased_task_claim.py` are byte-identical to
  their pre-round state.
* No version, schema, or audit kind is added or changed.
* No digest changes.
* No branch, tag, or release was touched.

### 27.7 The general lesson

**A perfect score is the shape a broken instrument makes.**  Both false
certs ran the same way: the census reported a number with no survivors,
which is exactly what a measuring tool reports when it cannot measure.
The pre-flight existed to catch that and computed the signal without
using it.

Three separate defects in this round -- the scope that was a claim
(§22.9), the spelling assertion (§27.1), the pristine failure that was
counted as a kill (§27.2) -- all produced the SAME artefact: a clean
number that no longer described the tree.  A census figure is evidence
only if the thing that produced it was itself measured.

## 28. AMENDED 2026-11-25 — the census found the SECOND false kill, in a different module

§27 fixed the probe and the worktree, and re-measured the chain's own
modules.  But the defect was not confined to them: the census's master
artifact carries a row for **every** module of the runtime, and 16 of
the runtime's 1620 modules have a scope that includes a suite reading
outside the component directory.  Those rows were measured through the
broken worktree.

### 28.1 `blind_rerunner.py` — 13/13 was FALSE; the real figure was 6/13

`docs/baseline/mutant-census/census-v3.txt` records:

```
blind_rerunner MUTANT RESULT: killed 13/13
```

A perfect score.  But `test_blind_rerunner.py` runs `git rev-parse` on
a NAMED COMMIT and builds a delivery bundle from the range -- so it
needs a repository, and the census worktree (a plain copy of the
component directory) had none.  The suite therefore failed on the
**pristine** source, and every non-zero exit was read as "mutant
killed".

With the worktree fixed (a `git clone`, so it has the history), the
same tree reads:

```
MUTANT RESULT: killed 6/13
```

**Seven survivors**, and they are seven branches that reject malformed
input and were never exercised with malformed input:

| site | what it rejects | why it was untested |
|---|---|---|
| `or@47` | a `BlindCheck`'s empty id / blank description / multiline command | every `BlindCheck` in the suite is constructed VALID |
| `or@183` | a claim that is not a trimmed single-line sentence | every claim in the suite is well-formed |
| `or@200` | a candidate-material path or content that is not a string | the suite passes string paths with EXCLUDED names, which the evidence-path check rejects first |
| `or@232` | a delivery seal whose `check_inputs_unchanged` is false | the suite's seal has an empty pin LIST, which the NEXT check rejects |
| `or@237` | a seal whose `start_commit` is not a full object id | the suite always supplies `"a" * 40`, which MATCHES |
| `or@239` | a seal whose `start_tree_hash` is not a usable digest | the suite always supplies `"c" * 40`, which MATCHES |
| `retT@163` | a path inside an evidence DIRECTORY | only the evidence BASENAME check was tested, and the TEXT check does not catch a directory |

All seven are now killed: **13/13**, with `TestTheInputValidationIsExercised`
in `tests/test_blind_rerunner.py` driving each branch with the
malformed input it exists to reject.

### 28.2 TWO of the seven killers passed for the WRONG reason

Both were caught by planting the mutant and re-running, and both are
the same shape as §27.1: **a test that passes for the wrong reason is
worse than no test.**

1. **The claim's validation (`or@183`).**  The first version of the
   test passed `"  " + CLAIM + "  "` -- a claim with trailing
   whitespace.  But `CLAIM` ends in a full stop, so the
   single-sentence regex fired FIRST and raised -- in BOTH the original
   and the mutant.  The mutation survived.  The distinguishing input is
   the **EMPTY** claim: the mutation flips the FIRST `or` to `and`, so
   the two forms differ only when `not isinstance(claim, str)` and
   `not claim.strip()` disagree -- and with an empty claim the third
   disjunct (`claim != claim.strip()`) is also False, so it cannot mask
   the difference.  A whitespace-only claim does NOT work, because
   `"   " != ""` makes the third disjunct raise anyway.
2. **The start commit.**  The first version passed `"a" * 40`, which
   fails the check ABOVE the claim's -- so the claim's own check was
   never reached.  The test now builds a real repository and uses its
   real commit.

### 28.2b EVERY one of the seven killers is LOAD-BEARING

A test that never fails is decoration, so each of the seven was
measured the hard way: **plant the mutant, re-run, and confirm the
expected test -- and only that test -- goes red.**  Measured
2026-11-25, one at a time, with the module restored between rounds:

| planted mutant | the test that caught it | other tests that went red |
|---|---|---|
| `or@47` (`or` -> `and` in `BlindCheck.__post_init__`) | `test_a_blind_check_rejects_an_empty_id` | `test_a_blind_check_rejects_a_blank_description` (same check, same branch) |
| `or@183` (`or` -> `and` in the claim guard) | `test_a_claim_must_be_a_single_trimmed_sentence` | none |
| `or@200` (`or` -> `and` in the candidate-material guard) | `test_candidate_material_paths_must_be_strings` | none |
| `or@232` (`or` -> `and` in the seal's pin guard) | `test_a_seal_without_both_pins_is_unavailable` | none |
| `or@237` (`or` -> `and` in the seal's start-commit guard) | `test_a_seal_with_an_unusable_start_commit_is_unavailable` | none |
| `or@239` (`or` -> `and` in the seal's tree-hash guard) | `test_a_seal_with_an_unusable_tree_hash_is_unavailable` | none |
| `retT@163` (the evidence-directory `any(...)` -> `False`) | `test_candidate_material_in_an_evidence_DIRECTORY_is_rejected` | none |

Two of the seven (`or@47`'s two tests) are the same BRANCH reached by
two inputs, so they are one killer with two witnesses -- which is why
the table records the other failing test rather than hiding it.  The
remaining five each kill exactly one mutant, which is the strongest
statement a test can make: **the mutant changes nothing else in the
suite's behaviour.**

The census agrees, and the two numbers are independent: the census
counts a mutant as killed when the suite's exit code changes, and this
table identifies WHICH test changed it.  A census score alone cannot
distinguish "the right test caught it" from "some unrelated test
tripped" -- which is exactly the trap §27.1 walked into.

Note the second row of `or@183`: with the FIRST version of that test
(the whitespace-only claim), planting the mutant left the suite
**green**, which is the only way that defect could have been found.
A mutant that survives a test is a fact about the test.

### 28.3 The second kind of file the worktree needs: GIT HISTORY

Copying the repo's `docs/`, `scripts/` and `tests/` was not enough.
`test_blind_rerunner.py` needs a **repository whose history contains
a named commit**, so the census worktree is now a `git clone` of the
repo rather than a plain copy of the component directory.  The clone's
working tree is then overwritten with the tree as it is NOW, because
the census measures the tree as it is, not as it was committed.

The repo-root copies are kept EXPLICIT alongside the clone, so the
requirement is visible in the script and survives the clone step being
replaced.  `test_mutant_probe_pristine_failure.py` pins all three
properties: the worktree is a clone, the repo-root files are copied,
and the preparation precedes the probe run.

This is what the coordinator's own `b173-mutant.sh` already did -- it
uses `git worktree add`, which has the history.  The defect was in the
REPO's `scripts/b173-census-all.sh`, which is a different harness.

### 28.4 What this does NOT change

* **No product code changed.**  `blind_rerunner.py` is byte-identical
  to its pre-round state; the seven sites were validation branches, and
  the fix is TESTS that exercise them.
* No version, schema, or audit kind is added or changed.
* No digest changes.
* The census artifact in `docs/baseline/mutant-census/` is **not**
  edited here.  It is a snapshot of a measurement on a NAMED tree, and
  the rule for it is that re-measuring is the coordinator's decision.

### 28.5 What this says about the artifact

The coordinator's `census-v3.txt` records `blind_rerunner` at **13/13**
with every site individually KILLED.  That row was measured through
`b173-mutant.sh`, which uses a real worktree -- so it was measured on a
different tree, with a different harness, and it is **not** the same
measurement as this round's.

The two figures are both true and they are not comparable:

| harness | tree | figure |
|---|---|---|
| the coordinator's `b173-mutant.sh` (a real worktree) | a pinned historical commit | **13/13** |
| the repo's `scripts/b173-census-all.sh` (a plain copy -- BROKEN) | the tree as it was | **13/13**, falsely |
| the repo's `scripts/b173-census-all.sh` (fixed: a clone) | the tree as it is NOW | **6/13** before this slice's tests, **13/13** after |

**The middle row is the point of this section**: the broken harness
agreed with the good one, on a different tree, for the wrong reason.

### 28.6 The blast radius, MEASURED: one row of 270

The defect was in a HARNESS, and a harness is used for many things, so
the honest question is how many other measurements it produced.  The
answer was measured, not estimated.

The 17 suites of the runtime that resolve a path OUTSIDE the component
directory:

```
test_audit_chain            test_r6_check_accuracy
test_audit_export           test_r6_manifest_integrity
test_blind_rerunner         test_r6_manifest_subject
test_finding_gate           test_r6_worktree_rename
test_hlc                    test_r8_acceptance_conformance
test_judge_hygiene          test_r8_commit_attribution
test_equivalence_table_coverage  test_r8_promised_test_methods
test_run_evidence           test_sdk
test_unittest_blind_slices
```

`census-v3.txt` holds **270** module rows.  Each row's scope is the
UNION of every suite that imports the module, so the rows at risk are
the ones whose union includes one of the 17 above.  The import map was
built in ONE pass over the runtime's test files with an AST read (the
same decision `scripts/census-scope.py` makes, done once instead of
270 times), and every one of the 270 rows was tested against it.

**Exactly one row is affected: `blind_runner`, the row this section is
about.**  The other 269 were measured on scopes that do not reach
outside the component directory, so the broken worktree did not affect
them.

That is a smaller blast radius than §28.1's "16 of 1620 modules"
figure suggests, and the two are not in conflict: the 16 is the number
of modules whose scope includes a repo-root-reading suite, and this is
the number of those 16 that appear in the artifact with a row that the
broken harness produced.  The other 15 are simply not in `census-v3.txt`
-- they were never measured by it, so there is no row to be wrong.

The honest summary is therefore: **the false kill was ONE row, and it
is now corrected.**  The fix to the harness is worth much more than
that one row, because the harness is what every FUTURE measurement
runs through.

### 28.7 The general lesson for a harness defect

The defect had a property that made it nearly invisible:

* it produced a PERFECT score, which is what a reader scans for;
* it agreed with a second, independently-produced measurement of the
  same module, so there was no visible disagreement to investigate;
* and it was a defect in the INSTRUMENT, so the natural response --
  "the tests pass, the score is perfect, move on" -- is exactly what
  the defect wants.

The only thing that broke it was a SECOND claim about the same module
that could not both be true: §23.4's arithmetic proof of `gt@753`'s
equivalence, against a census that said the mutant was killed.  That
is the general shape worth remembering: **when two measurements of the
same thing disagree, the disagreement is the finding** -- and one of the
two is usually the instrument, because the instrument is the thing that
has never been checked against a case where it could fail.

