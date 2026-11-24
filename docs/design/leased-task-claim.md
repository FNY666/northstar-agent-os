# leased-task-claim — lease claim with a fencing token + reaper

**Slice:** `B173 leased-task-claim: fencing-token claim wiring + lease reaper`
**Module:** `components/northstar-agent-runtime/leased_task_claim.py`
**Tests:** `components/northstar-agent-runtime/tests/test_leased_task_claim.py` (60 test methods)

Scope: this slice wires **the reaper and the fencing-token claim** between the
existing queue ledger and a lease. It does **not** port the whole
`agent-task-runtime` repository. `distributed_lock.py`, `outbox_pattern.py`, `dead_letter_queue.py` and
`checkpoints.py` are **read-only reused** — this module imports their public
shapes and never edits them. `job_queue.py` was read-only reused at first and
is **AMENDED 2026-11-23** to be edited — see §4.

---

## 1. Source mapping

### 1.1 Verbatim (agent-task-runtime, commit `bbad5e3`)

The source excerpts below are **verbatim** from the task book's source text.
Every claim marked *verbatim* in this document is a direct restatement of one
of these five lines; nothing has been added to them.

| # | Verbatim source text | Where it lands in Northstar |
|---|---|---|
| V1 | 认领即在一个 `BEGIN IMMEDIATE` 事务里拿限时租约并递增单调 fencing token（token 就是认领计数器）。 | `LeasedTaskClaim.claim` — the lease and the token increment are written in one `BEGIN IMMEDIATE` transaction (`_Store.transaction`). The token is the per-task claim counter (`token = row["token"] + 1`). |
| V2 | `complete / fail / heartbeat / save_checkpoint / release` 每次写都校验当前 token，过期持有者的写以 `StaleLeaseError` 拒绝且什么都不改。 | `LeasedTaskClaim._check_token` is called by all five write paths. A stale or expired token raises `StaleLeaseError` before any write, so the state, the checkpoint and the outbox rows are unchanged. |
| V3 | 租约收割器（reaper）扫过期租约直接重排队（崩溃不算任务过错，不吃退避延迟）；上报的失败才走指数退避。 | `LeasedTaskClaim.reap` sweeps expired leases straight back to `ready` with `delay_until = 0` and no change to the failure counter. `LeasedTaskClaim.fail` is the *only* path that books a backoff, and it is the *only* path that touches `failures`. |
| V4 | 每步 checkpoint，换人接手从 checkpoint 续跑不重做；终态与 outbox 行同事务提交，at-least-once 投递 + 稳定幂等键 `<task_id>:<event_type>`。 | `save_checkpoint` records one checkpoint per step; `resume_from` returns the newest one after a hand-over; `complete` writes the terminal state and the outbox row in one transaction; the message id is `idempotency_key(task_id, event_type)`. |
| V5 | 演示：worker-A 拿 token 1、checkpoint 两步后崩溃 → 租约过期 → worker-B 拿 token 2 从 checkpoint 续跑 → 苏醒的僵尸 A 三次写全被拒。 | `SourceDemonstrationTests.test_worker_a_crashes_and_worker_b_resumes` drives exactly this, and `leased_task_claim.main()` is the same path as a self-check. |

### 1.2 Northstar extensions (not in the source text)

These are additions this slice makes. They are marked as such everywhere they
appear in the code (`#:` comments and docstrings).

| # | Extension | Why |
|---|---|---|
| N1 | **Per-task queue in the shared `JobQueue`.** | `JobQueue.dequeue(worker_id, queue, seq)` reserves *the next eligible job in a queue*, not a job named by id. A by-task claim therefore needs a by-task queue: `queue_name_for(task_id)` returns `task:<task_id>`, truncated to the 128 characters `job_queue` allows. |
| N2 | **The failure budget lives here, not in `JobQueue.retry`.** | `JobQueue.retry` counts *executions* (`attempts` is incremented by `dequeue`), so a crash requeue would consume the same budget a reported failure consumes — which would contradict V3. The queue mirror is therefore given `QUEUE_MAX_RETRIES = 64` so it never self-deaths, and the *reported*-failure budget (`max_failures`, default 3) is counted here. |
| N3 | **Wall-clock expiry instead of a logical sequence.** | `distributed_lock.LockLease` expires on a logical `current_seq`. A lease must expire while nobody is looking at it, so this module uses wall-clock seconds (`acquired_at` / `expires_at`) and a caller-supplied `now`. Expiry stays **inclusive** (the lease is valid *through* `expires_at`), matching `LockLease.is_expired`. |
| N4 | **SQLite `BEGIN IMMEDIATE` store.** | The source's own transaction is reproduced with stdlib `sqlite3` (zero dependencies), so the claim, the token increment, the checkpoint and the outbox row are genuinely atomic. |
| N5 | **The outbox ledger is this module's own table.** | `outbox_pattern.Outbox` is in-process only and has no row persistence, so the transactional-outbox *shape* (`OutboxMessage`, `MessageState`, the stable key) is reproduced over SQLite. `outbox_pattern` is still reused for the message/state shapes. |
| N6 | **`checkpoints.py` is not used for the task checkpoint.** | `checkpoints.py` checkpoints a *transcript* (turn boundary, transcript digest, lineage). A task's progress is a step counter plus an opaque payload, so the task checkpoint is its own record. `checkpoints.py` is read-only reused in the sense that its *rule* — a checkpoint may not move backwards — is honoured (`CheckpointOrderError`). |
| N7 | **`dead_letter_queue` is booked with the stable id `<task_id>:dead`.** | The DLQ never recycles ids, so the stable key is the natural id: one dead task is one dead message. |

---

## 2. API

### 2.1 `LeasedTaskClaim`

```python
LeasedTaskClaim(*, path=":memory:", queue=None, dead_letters=None,
                max_failures=3, base_backoff_seconds=1.0,
                backoff_factor=2.0, max_backoff_seconds=300.0,
                clock=time.time)
```

| Method | Returns | Meaning |
|---|---|---|
| `enqueue_task(task_id, task, payload="")` | `TaskView` | Register a task; it starts `ready` with token `0`. |
| `claim(task_id, worker, ttl, now=None)` | `TaskLease` | Take a limited-time lease and a **new** fencing token. |
| `heartbeat(task_id, token, now=None, extend_seconds=0.0)` | `TaskLease` | Extend a live lease (never shorten it). |
| `save_checkpoint(task_id, token, step, payload, now=None)` | `CheckpointRecord` | Record progress for the current holder. |
| `complete(task_id, token, payload=None, now=None, destination=...)` | `TerminalRecord` | Commit the terminal state **and** the outbox row together. |
| `fail(task_id, token, reason="", now=None)` | `FailRecord` | Report a failure: backoff, or the dead letter. |
| `release(task_id, token, now=None)` | `ReleasedRecord` | Give the task back voluntarily (no penalty). |
| `reap(now=None)` | `tuple[ReapedLease, ...]` | Sweep expired leases back into the queue. |
| `expired_leases(now=None)` | `tuple[ReapedLease, ...]` | What `reap` would sweep, without sweeping it. |
| `resume_from(task_id)` | `CheckpointRecord \| None` | The checkpoint the new holder resumes from. |
| `pending_steps(task_id)` | `int` | How many steps the task has checkpointed. |
| `task(task_id)` | `TaskView \| None` | Pure read view. |
| `checkpoint(task_id)` | `CheckpointRecord \| None` | The newest checkpoint. |
| `outbox_rows(task_id)` | `tuple[OutboxRow, ...]` | The outbox rows of a task. |
| `outbox_messages(task_id)` | `tuple[OutboxMessage, ...]` | The rows as `outbox_pattern` messages. |
| `mark_delivered(task_id, message_id, now=None)` | `str` | Mark a row `sent` (the row stays: it is the idempotency record). |
| `delivered(task_id)` | `tuple[str, ...]` | The delivered message ids. |
| `audit_log()` | `tuple[dict, ...]` | The append-only audit trail. |
| `close()` | `None` | Close the SQLite connection. |

### 2.2 Module-level functions

| Function | Meaning |
|---|---|
| `idempotency_key(task_id, event_type)` | The stable key `"<task_id>:<event_type>"`. |
| `digest_of(text)` | `"sha256:" + hex` — the digest shape `job_queue` and `dead_letter_queue` expect. |
| `queue_name_for(task_id)` | `"task:<task_id>"`, truncated to 128 chars. |

### 2.3 Errors

`LeasedTaskClaimError` is the base. Its subclasses:

| Error | Raised when |
|---|---|
| `UnknownTaskError` | The task id was never registered. |
| `LeaseHeldError` | The task already has a **live** lease. |
| `BackoffError` | The task is in backoff after a reported failure. |
| `TerminalTaskError` | The task is already `completed` or `dead`. |
| `StaleLeaseError` | The presented token is not the current one, or the lease has expired. |
| `CheckpointOrderError` | The checkpoint would move the task's progress backwards. |
| `QueueMirrorError` | The queue mirror and the lease ledger disagree. |

---

## 3. Rules and thresholds (hard-coded)

| Rule | Value |
|---|---|
| Fencing token | strictly increasing per task, starts at `1`, never reused or reverted |
| Token check | on **every** write: `complete`, `fail`, `heartbeat`, `save_checkpoint`, `release` |
| Stale write | `StaleLeaseError`; the state, the checkpoint and the outbox rows are unchanged |
| Lease expiry | **inclusive** — the lease is valid *through* `expires_at`, dead after it |
| Crash (reap) | `delay_until = 0`, `failures` unchanged, `crashes += 1` |
| Reported failure | `delay = base_backoff_seconds * backoff_factor ** (failures - 1)`, capped at `max_backoff_seconds` |
| Failure budget | `max_failures` (default `3`); the last failure is **dead** and carries no backoff |
| Dead letter | booked in `dead_letter_queue` with the id `"<task_id>:dead"` |
| Queue mirror | one queue per task, `"task:<task_id>"`; `QUEUE_MAX_RETRIES = 64` so the mirror never self-deaths |
| Idempotency key | `"<task_id>:<event_type>"`; `completed` and `dead` |
| Terminal commit | the terminal state and the outbox row are written in **one** transaction |
| Checkpoint order | a checkpoint below the newest step is refused (`CheckpointOrderError`) |

---

## 4. What the slice does *not* do

* It does not port `agent-task-runtime`. Only the reaper + the
  fencing-token claim are cut.
* It does not change `distributed_lock.py`, `outbox_pattern.py`,
  `dead_letter_queue.py` or `checkpoints.py`.
* **AMENDED 2026-11-23:** it now changes `job_queue.py`. The
  original slice left it read-only, but the mirror turned out to need
  two operations the queue ledger did not have: a **terminal failure**
  (`JobQueue.dead()`, for a task whose failure budget is exhausted) and
  a **batch-safe re-dispatch** (`JobQueue.retry_allowed()`, for the
  reaper's sweep). Without them a *completed* task's mirror job went
  back to `ready` -- the queue then handed out a finished task's job --
  and a refused mirror release left the two ledgers out of step. The
  queue's version and schema pins are unchanged; the reasoning is in
  `docs/design/refusal-hold-wiring.md` §13.
* It does not implement a delivery loop: the outbox rows are written and
  marked; *sending* them is the host's job (`outbox_pattern` has no
  dispatcher either).
* It does not implement the retry *delay* in the queue ledger beyond
  booking `not_before_seq` — the delay is this module's `delay_until`.
* It does not persist across processes beyond the SQLite file: the queue
  mirror and the dead-letter ledger are in-process ledgers, as they are
  everywhere else in the repo today.

---

## 5. Open items

1. **The queue mirror and the lease ledger are two ledgers.** They are
   updated in sequence inside one SQLite transaction, but the `JobQueue`
   and `DeadLetterQueue` objects are in-process: a crash between the SQLite
   commit and the mirror update would leave the two out of step. The
   `QueueMirrorError` fails closed when the mirror disagrees, but the
   reconciliation is the host's job.
   **AMENDED 2026-11-23 (`refusal-hold-wiring.md` §13):** the mirror
   calls are now inside the transactions — a refused mirror release
   rolls the lease write back, so the two ledgers cannot be left
   disagreeing by a *refusal*. The crash window itself is narrowed,
   not closed: the mirror is still an in-process ledger.
2. **The clock is wall-clock.** A clock that jumps backwards can extend a
   lease; one that jumps forward can expire it early. The source has the
   same property. A monotonic clock would be better but cannot be persisted
   across processes.
3. **The lease is per task, not per queue.** With `max_failures` counted
   here, the retry budget is per task; a task that is re-enqueued as a new
   id gets a fresh budget.
4. **The outbox is at-least-once with no de-duplication downstream.** The
   stable key is the contract; a transport that does not honour it will
   deliver twice.
5. **`heartbeat` extends but never shortens.** A worker that wants to give
   up early should call `release`.

---

## 6. AMENDED 2026-11-23 — the mirror's queue name was not injective

### 6.1 The defect

§1.2's extension N1 is the load-bearing one: `JobQueue.dequeue` reserves
*the next eligible job in a queue*, not a job named by id, so a by-task
claim needs a **by-task queue** — one task, one queue — so that the
mirror's reservation can never pick up another task's job.

The name was `"task:" + task_id`, **truncated** to the 128 characters
`job_queue` allows.  But a task id may be up to **256** characters long
(`enqueue_task` refuses more than 256).  So the plain form does not fit,
the truncation dropped the distinguishing tail, and **two task ids that
share their first 123 characters landed in the same mirror queue**.

That breaks the invariant N1 exists to provide: the mirror's reservation
stopped being by-task.

Measured 2026-11-23, before the fix:

```
queue names equal: True
queue name: 'task:aaaa...aaaa'      # 128 chars, BOTH tasks

--- claim task a (b is at the head of the SHARED queue) ---
claim raised: QueueMirrorError queue mirror refused to reserve aaa...X
mirror states: [('aaaaX', 'ready'), ('aaaaY', 'reserved')]
ledger states: [('aaaaX', 'ready'), ('aaaaY', 'ready')]
```

Read the two states lines: the mirror had **reserved `b`'s job** while
the ledger still had **both** tasks `ready`.  And then `a`'s claim was
refused — `QueueMirrorError`, "queue mirror refused to reserve a" —
because the mirror would not hand a worker a job that was not `a`'s.

So the collision did not merely fail a claim: it made the mirror reserve
the **wrong task's** job.  The two ledgers disagreed in exactly the way
`QueueMirrorError` exists to prevent, and it happened **inside** the
mirror's own bookkeeping.

A census over the accepted id space, before the fix: ids of length 1..256
with six random ids each, plus prefix-sharing families at the boundary
lengths — **10 ids of length 124 produced 1 distinct queue name**.

### 6.2 The fix

The name carries a **digest of the whole id** whenever the plain form
would be truncated:

```python
name = f"task:{task_id}"
if len(name) <= _MAX_QUEUE_NAME:
    return name
digest = digest_of(task_id).split(":", 1)[-1][:16]
head = name[: _MAX_QUEUE_NAME - len(digest) - 1]
return f"{head}:{digest}"
```

Three properties, and each one is load-bearing:

* the digest is over the **whole** id, not the prefix — so two ids that
  share a prefix still get different names;
* the digest is **appended** to the truncated id — so the name still
  reads like the task it belongs to, and the common case (a short id) is
  **unchanged**: no digest, no surprise, `queue_name_for("t1")` is still
  `"task:t1"`;
* the head is shortened to make room, so the name **always** fits the
  128-character limit.

The name is never parsed back into a task id anywhere in the repo, so
changing its shape breaks no reader.

### 6.3 The guards, and why they can fail

Eight new guards in `MirrorQueueNameIsInjectiveTests`
(`tests/test_leased_task_claim.py`):

| guard | what it pins |
|---|---|
| `test_two_long_task_ids_that_share_a_prefix_do_not_collide` | the defect itself: the shared prefix is not the whole name |
| `test_the_name_always_fits_the_queue_limits` | the name never exceeds 128 characters, at any id length |
| `test_a_short_task_id_keeps_the_plain_name` | the control: the common case is unchanged |
| `test_the_digest_covers_the_whole_id_not_just_the_prefix` | the digest is over the whole id |
| `test_the_name_is_injective_over_many_ids` | a **census**, not a sample: 1,636 ids, every accepted length, zero collisions |
| `test_the_mirror_hands_out_the_right_task_after_a_collision` | the end-to-end shape: claiming `a` does not reserve `b`'s job |
| `test_both_tasks_can_be_claimed_and_the_ledgers_stay_in_step` | neither task is starved, and the two ledgers agree |
| `test_the_queue_name_is_stored_and_reported_unchanged` | the ledger books the same name the mirror uses |

**The mutation run.**  Four mutants planted and re-run; all four killed:

| mutant | verdict | killed by |
|---|---|---|
| M1 revert to the truncation | **KILLED** | 5 guards |
| M2 digest only the **prefix**, not the whole id | **KILLED** | 5 guards |
| M3 digest truncated to one character | **KILLED** | the census guard only |
| M4 no digest for long ids | **KILLED** | 5 guards |

**M3 is worth recording.**  A one-character digest still gives 16
possibilities, so the *pairwise* guards (`a...X` vs `a...Y`) all passed
on it — the collision needs 17 ids to show up.  Only the **census**
guard caught it.  That is the same lesson as the acceptance metric's
"not a census" finding: **a pairwise guard cannot see a collision that
needs a wider family to appear.**  The census is what gives the mapping
its guarantee; the pairwise guards only pin the specific defect.

### 6.4 What this does NOT change

* `leased_task_claim.py`'s version and schema pins are unchanged, and no
  new column, table or audit kind is added.
* The queue name of a task **up to 123 characters long** is unchanged:
  the plain `"task:<id>"` form still fits, so the common case is
  byte-identical to before.
* The `ltc_task.queue_name` column is unchanged in shape; it now holds a
  name with a digest suffix for the long ids that used to collide.
* The ledger's own `task_id` column is unchanged — it always held the
  **whole** id.  Only the *queue name* was lossy.
* The refusal-hold wiring is unaffected: the queue namespace is keyed by
  **job id** (`queue:<job id>:<action>`), and the job id is the task id,
  not the queue name.  So a refusal recorded against a long task id
  still matches the mirror's job.
