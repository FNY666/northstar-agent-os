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
`leased_task_claim.py`, which are read-only in this slice. That is the
honest open item, and it is stated here rather than left silent.

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
