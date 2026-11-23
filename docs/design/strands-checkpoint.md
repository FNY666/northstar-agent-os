# A versioned resume marker and hook-based retry

This document describes one slice of Northstar: a **resume marker** that says
where a run stopped and carries no state, an **explicit precedence** between
the claims on a run (interrupt / checkpoint / cancel), and a **retry
mechanism that is a hook** rather than loop code.

Source: Strands Agents, the AWS open-source agent SDK (harness SDK, commit
`4330e22`, recorded 2026-11-11). The upstream repository was **not** cloned
during this slice; the field names, the docstring wording and the numeric
values quoted below are the ones the slice brief carries, and they are marked
as *verbatim as briefed* wherever they are attributed to the source.

The module: `components/northstar-agent-runtime/strands_checkpoint.py`.
The tests: `components/northstar-agent-runtime/tests/test_strands_checkpoint.py`.

---

## 1. What Northstar has today (read from the code, not assumed)

### 1.1 The checkpoint today

`components/northstar-agent-runtime/checkpoints.py` defines a `Checkpoint`
dataclass (line 140) with **nineteen** fields:

    session_id, record_index, transcript_len, transcript_digest, turns,
    tool_calls, cost_usd, usage, model, provider, permission_mode, run_id,
    policy_revision, denials, tool_limit_prefix, composition_history,
    composition_policy_digest, previous_checkpoint_id, graph_signature_hash

Its `as_dict()` writes every one of them. `prepare_resume()` (line 503) reads
the record back, checks the session id, the graph signature hash, the lineage
chain, and the transcript digest, and returns the verified transcript prefix.

`checkpoint_store.py` adds `FileCheckpointStorage`: an id that names a file,
an atomic write (temp file, `fsync`, `os.replace`), a per-destination write
queue, and a restricted loader with a `"module:qualname"` allowlist.

**What it is:** a *state store* that happens to carry a position. It holds
budget counters, usage, the transcript digest and the permission mode - all
of which are state the run had at that moment.

### 1.2 How "where did it stop" and "what was its state" are mixed

They are the same object. `checkpoint.transcript_len` says *where*; the
counters beside it say *what*. The record is written by
`loop.py:_checkpoint()` (line 2896) at a boundary, and the boundary name is
passed as a string (`"after_tools"`, `"after_text"`) but is **not** one of the
checkpoint's fields - it lives inside the `payload` the loop builds.

Consequence: a reader of a stored checkpoint cannot ask "which boundary was
this?" without parsing a payload the checkpoint module does not own.

### 1.3 What happens when a cancelled run resumes today

`loop.py` (around line 1915) takes `config.resume_from` - a `Checkpoint` -
and calls `prepare_resume()`, then inherits `turns`, `tool_calls` and the
cost, and checks the composition policy digest. The resume path checks the
**checkpoint's own consistency** (graph hash, lineage, digest). It does not
ask whether the run was revoked.

`cancellation_tombstone.py` holds the revocation: a `Tombstone` keyed by
`grant_id` + `action` (+ `subject`), with `PERMISSION` (no expiry) and
`CAPACITY` (bounded) kinds, a `Lift` naming the declarer and channel, and a
`TombstoneSet`. `sessions.py` carries a tombstone into every session record
so that compaction cannot drop it.

**The gap:** the tombstone answers "may this action run?", and the checkpoint
answers "where do I continue?". Nothing joins them at the resume boundary. A
revoked run that is resumed from a checkpoint inherits its counters and
continues; the revocation is only noticed later, when the next revoked action
is attempted. The marker and the revocation are two vocabularies that never
meet.

### 1.4 Where retry lives today

Two mechanisms, two layers:

* `retry_config.py` - **declarative configuration**: `RetryConfig`
  (idempotent waits, jitter windows), `CallKind` (which calls may be
  retried at all), `classify_call()`, `RetryGate.execute()`, `SessionGuard`.
  This is *what to do*, as data.
* `provider_retry.py` - **mechanism**: `RetryPolicy`, `classify(error)`,
  `plan(attempt, fault)`, `execute()`. This is *how* the retry happens.
* `loop.py:_retry_step()` (line 1596) - the retry decision is made **inside
  the loop**: it classifies the error, plans the attempt, adds to the
  counters, calls `self._sleep(...)` and returns `(should_retry, notes)`.

So the retry decision is loop code. A pluggable strategy means editing the
loop, which the brief's rule - *don't add new modules to stack features* -
is exactly the shape of thing to avoid.

---

## 2. The marker

### 2.1 What it is

A frozen dataclass with three fields:

| field | type | meaning |
| --- | --- | --- |
| `position` | `str` | the boundary that fired: `"after_model"` or `"after_tools"` |
| `cycle_index` | `int` | the agent loop's cycle number at that boundary |
| `schema_version` | `int` | the shape of the payload (currently `1`) |

`to_dict()` writes exactly those three keys. `from_dict()` reads them back.

### 2.2 What it is not

The marker has **no field for state**: no transcript, no counters, no
credentials, no usage. This is enforced twice over:

* the dataclass has three fields and no more
  (`test_the_marker_has_no_field_that_could_hold_state`);
* `from_dict()` refuses a payload carrying any extra key
  (`test_a_marker_carrying_state_is_refused`), so a dict that *claims* to be
  a marker but carries conversation state is rejected rather than half-read.

`from_dict()` also raises `CheckpointException` when `schema_version` is not
the version this module knows.

### 2.3 Where the state goes instead

Not in this slice, and deliberately: the source's own docstring says to
"pair with a SessionManager for cross-process state continuity". Northstar's
session layer (`sessions.py`) and the lineage checkpoint store
(`checkpoint_store.py`) are that partner, and they are **read-only** for this
slice. The marker and the state store are two artefacts; this slice builds
the first and does not claim the second.

---

## 3. The precedence

`resolve_outcome(interrupt=..., checkpoint=..., cancel=...)` returns one of
`"interrupt"`, `"checkpoint"`, `"cancelled"`, `"none"`.

The source states the order in a comment: **interrupt > checkpoint > cancel**.
This module enforces it, with one deliberate refinement:

    1. an interrupt wins outright (any answer, falsy answers included);
    2. a cancel **already in force** wins over a checkpoint;
    3. a checkpoint wins over a cancel that is merely **requested**;
    4. otherwise the outcome is "none".

### 3.1 Why the refinement, and what it is not

The source's order is about three claims competing at one moment. In
Northstar a cancel is also a *fact about the run*: the run was revoked. A
revoked run must not come back as a checkpoint, so the kill switch has to
outrank the marker.

`Cancel(reason=..., applied=...)` makes the difference explicit: a cancel
with `applied=False` is a *requested* cancellation, and a cancel with
`applied=True` (or any plain value - a reason string, `True`, a tombstone)
is one that has been carried out. Reading every cancel as applied is the
conservative direction: the cost of assuming a revocation is pending is a
killed run quietly resuming.

**This refinement is a Northstar extension, not Strands'.** The source states
a flat order; the source does not distinguish a pending cancel from an
applied one.

### 3.2 Falsy answers

`has_answer()` treats `False`, `0` and `""` as answers. Only the sentinel
`NO_INTERRUPT` and `None` mean "nothing was answered". The failure mode -
a falsy answer read as "not answered" - comes from an AG-UI report
(PR #2451, 2026-08). AG-UI's code was **not** read for this slice, so it is
used as a *test-case inspiration* and implemented as Northstar's own rule; it
is not presented as a verified upstream behaviour.

---

## 4. Retry as a hook

`ModelRetryStrategy` is the strategy object: it registers callbacks for the
model-call events, and its callback decides whether a failed call is
retried.

### 4.1 The values (verbatim as briefed)

| value | source |
| --- | --- |
| backoff `4s → 8s → 16s → 32s → 64s` | Strands `ModelRetryStrategy` |
| ceiling `240s` | Strands `ModelRetryStrategy` |
| `max_attempts = 6` | Strands `ModelRetryStrategy` |
| retries only throttling errors | Strands `ModelRetryStrategy` (`is_retryable()` overridable) |
| state resets after a success | Strands `ModelRetryStrategy` |
| registered on `AfterModelCallEvent` / `AfterInvocationEvent` | Strands `_retry.py:21` |

### 4.2 The Northstar shape

* The event names are Northstar's own: `after_model`, `after_tools`,
  `after_invocation`. The Strands event *classes* are not imported and not
  reimplemented.
* The strategy **never sleeps**. It returns the number of seconds the caller
  should wait, so the schedule is assertable without waiting for it.
* `is_retryable()` is an ordinary method a subclass overrides.

### 4.3 The loop has no retry in it

`ModelCallLoop` in this module exists to make the separation checkable: it
calls the provider, and on failure it **emits** `after_model` and returns
what the hooks said. The test
`test_the_loop_contains_no_retry_call` parses the class's source with `ast`
and asserts that no call named `retry`, `should_retry` or `backoff_for`
appears in it, and that `emit` does.

`ModelCallLoop` is **not** wired into `loop.py` (read-only for this slice),
and it does not claim to be the runtime's agent loop. It is a small,
explicit statement of the separation, with a test.

---

## 5. Relationship to the existing modules (all read-only, none changed)

| module | what it owns | what this slice does to it |
| --- | --- | --- |
| `checkpoints.py` | the lineage checkpoint: position **and** state, digest, counters | nothing. Read to see what "today's checkpoint" is. |
| `checkpoint_store.py` | where a checkpoint payload is stored (atomic write, id validation) | nothing. The snapshot hook's `save` callable is left to the caller; wiring it to the store is not done here. |
| `cancellation_tombstone.py` | the sticky revocation and its named lift | nothing. `Cancel` here is a *claim* about the run, not a tombstone; the two vocabularies are not joined in this slice. |
| `retry_config.py` | declarative retry *configuration* and call-kind classification | nothing. This slice is the *mechanism* layer, and it deliberately does not read `RetryConfig`. |
| `provider_retry.py` | the provider-transport retry mechanism inside `loop.py` | nothing. The two mechanisms coexist; which one governs a given call is a wiring decision that this slice does not make. |
| `loop.py` | the agent loop, including `_retry_step()` | nothing (read-only). |

**The two retry layers are not the same layer.** `retry_config.py` answers
*what the policy is*; `provider_retry.py` answers *how a provider fault is
handled today*; `ModelRetryStrategy` here answers *whether a model call is
retried, and how long to wait* - as a hook, so that the decision is
pluggable without editing the loop. A future wiring would have to say which
one wins; that is an open item (§8).

---

## 6. How the tests drive the paths

The tests do not only assert the parts:

* **mark → crash → resume.** The snapshot hook writes a marker at
  `after_model`; the "crash" is the end of the process; the marker is read
  back and `plan_resume()` says the run continues from `after_model` at
  cycle 3 - not from the start, and not from the other boundary.
* **cancel beats the marker.** The same marker, plus a cancel in force, and
  the plan comes back `cancelled` with no marker attached.
* **retry.** A provider that throttles once and then answers: the loop
  emits, the hook says "retry, wait 4s", the call succeeds. A provider that
  raises a non-throttle: the hook says "do not retry", the attempt counter
  stays at zero, and the provider is called once.

55 new test methods in total: 32 for the rules above, plus 17 more that
drive the second half of every guard in the module (`_require_int`'s boolean
half, `max_attempts`' bound, the `ResumePlan.resumes` conjunction) - the
mutant-lift work that follows this slice's first commit - plus 6 that name
every public function of the module (`RetryDecision.as_dict`,
`ModelRetryStrategy.reset`, `ModelRetryStrategy.register_callback`,
`CheckpointSnapshotHook.last_marker`, `ResumePlan.as_dict`), so that no
public name is exercised only indirectly.

---

## 7. Mapping to the source: verbatim vs Northstar extension

**Verbatim as briefed** (the brief carries these from the Strands harness
SDK, commit `4330e22`; the upstream repository was not cloned here, so
"verbatim" means verbatim *as the brief quotes the source*):

| source item | where it lands here |
| --- | --- |
| `Checkpoint` is a frozen dataclass with `position` / `cycle_index` / `schema_version` | `strands_checkpoint.Checkpoint` |
| `position` is `"after_model" \| "after_tools"` | `POSITION_AFTER_MODEL`, `POSITION_AFTER_TOOLS` |
| `from_dict()` raises `CheckpointException` on a `schema_version` mismatch | `Checkpoint.from_dict` |
| the module docstring: "It captures the position (which boundary fired) and the cycle index. It does not capture conversation state — pair with a SessionManager for cross-process state continuity." | the module docstring of `strands_checkpoint.py` |
| the priority comment: interrupt > checkpoint > cancel | `resolve_outcome` |
| `ModelRetryStrategy` is a `HookProvider` registering on `AfterModelCallEvent` / `AfterInvocationEvent` | `ModelRetryStrategy.register()` |
| only `ModelThrottledException` is retried by default; `is_retryable()` may be overridden | `is_retryable()` |
| backoff 4 → 8 → 16 → 32 → 64, ceiling 240 | `DEFAULT_BACKOFF_SECONDS`, `DEFAULT_MAX_BACKOFF_SECONDS` |
| `max_attempts = 6`; state resets after a success | `DEFAULT_MAX_ATTEMPTS`, `reset()` |

**Northstar extensions** (ours, marked as such):

* the precedence is a *callable* that returns the winner, not a comment;
* `Cancel(applied=...)` distinguishes a requested cancellation from one in
  force, and an applied cancel outranks the checkpoint (§3.1);
* the falsy-answer rule, taken from the AG-UI report as inspiration (§3.2);
* the event names are Northstar's own, and the Strands event classes are
  neither imported nor reimplemented;
* the strategy returns the wait instead of sleeping;
* `CheckpointSnapshotHook` and `ModelCallLoop` are Northstar's own shapes,
  built here to make the separation testable (§4.3);
* the module's `CheckpointError` alias for readers who expect that spelling.

**Not claimed.** Nothing here claims to be a port of Strands, and nothing
claims a live-provider behaviour: no provider was contacted during this
slice, so every statement about retry behaviour is about this module's
own code.

---

## 8. Open items

These are the questions the source and the existing code do not settle.
They are recorded rather than answered by invention.

1. **Which retry mechanism governs a given call?** `provider_retry.py`
   (inside the loop) and this slice's hook mechanism both exist. A wiring
   decision has to say which one applies to a model call, and whether the
   hook's backoff replaces or defers to the provider policy's jitter
   windows. Not decided here.
2. **How does the marker reach the store?** `CheckpointSnapshotHook` takes
   a `save` callable. Wiring it to `checkpoint_store.FileCheckpointStorage`
   would make the marker durable, but that store validates its payloads and
   the marker is a different shape. Not wired here.
3. **How does the marker meet the tombstone?** `Cancel` is a claim about a
   run; `cancellation_tombstone.Tombstone` is a sticky revocation keyed by
   grant and action. The resume path needs a rule that reads "this run was
   revoked" out of the tombstone set. The join is not made here.
4. **The crash-between-recording-and-disabling window.** The AG-UI report
   (PR #2451, 2026-08) names a second failure mode: a crash between
   "the answer was recorded" and "the checkpoint was disabled" leaves a
   persisted checkpoint that blocks the thread forever. This slice takes
   that only as a test-case inspiration; it does not implement the
   disable step, so the window is not closed here.
5. **The module is not declared in `pyproject.toml`.** The runtime
   component's `test_module_layout` test asserts that every module on disk
   appears in `[tool.setuptools] py-modules`. That test already fails at
   this slice's parent commit, and `strands_checkpoint` joins the list of
   undeclared modules — so no new failure appears, but the declaration is
   owed. This slice's writable file set does not include `pyproject.toml`.
6. **The module is not in the API reference manifest.** `tests/docbuild.py`
   lists the runtime's public modules explicitly; a module in neither the
   manifest nor the exclusions list fails the documentation coverage test.
   That test already fails at this slice's parent commit, and
   `strands_checkpoint` joins the list. The declaration is owed to the
   slice that owns the docs build.
7. **`checkpoint_turns` and the existing boundary names.** The runtime's
   loop writes checkpoints at `after_tools` and `after_text`; the marker's
   vocabulary is `after_model` and `after_tools`. The two vocabularies are
   not aligned, and no mapping is defined.
