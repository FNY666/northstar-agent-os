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
