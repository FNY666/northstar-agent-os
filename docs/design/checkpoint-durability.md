# Checkpoint durability modes: *when* a checkpoint reaches disk

*Module:* `components/northstar-agent-runtime/checkpoint_durability.py`
*Tests:* `components/northstar-agent-runtime/tests/test_checkpoint_durability.py`
*Slice:* B173, branch `batch-173-moltbook-absorb`

## The gap, read from the code

Northstar has three checkpoint layers, and all three write **synchronously**:

| Layer | Entry point | What it checks |
|---|---|---|
| turn boundary | `checkpoints.prepare_resume` | transcript prefix digest, run-graph hash, lineage |
| file storage | `checkpoint_store.FileCheckpointStorage.save` | atomic replace, fsync, path validation |
| durable log | `durable_resume.DurableStore.put_checkpoint` | the checkpoint's own state digest |

In all three, a write is durable by the time the call returns. There is no
window in which "the step ran" and "the step is recorded" disagree. That is
safe, and it is also the slowest possible policy: a long graph pays a disk
round-trip at every super-step.

The alternative — write in the background so the next step can start while
the previous checkpoint is still in flight — trades durability for latency
and introduces a **loss window**: a process that dies in that window loses
the last checkpoint it thought it had. Northstar had no way to *say* which of
those two it was doing.

## What this slice adds

A **durability mode** — a per-run write policy — with three values, plus:

* a **receipt** for every write, so a run's durability is auditable after the
  fact rather than assumed;
* an explicit **crash window** per mode, modelled and testable with an
  injected crash hook rather than a real `kill -9`;
* a **cost grading** that turns the mode into a decision instead of a default.

## The three modes

| Mode | When a checkpoint is written | On crash |
|---|---|---|
| `exit` | once, when the run exits (success, error, or interrupt) | every intermediate checkpoint is lost |
| `async` | in the background while the next step runs | the last checkpoint may be lost |
| `sync` | before the next step starts; the run waits for pending writes before returning | at most the in-flight step is lost |

## Mapping to the source

Values attributed to the source are quoted verbatim. Northstar extensions are
marked as such and are **not** presented as the source's.

### Verbatim from the source

LangGraph official docs, "Checkpointers > Durability Modes",
https://docs.langchain.com/oss/javascript/langgraph/checkpointers :

* "LangGraph supports three durability modes that let you balance performance
  and data consistency."
* "You can specify the durability mode when calling any graph execution
  method" — the mode is passed to `invoke` / `stream` / `ainvoke` /
  `astream`, **not** to `compile()`.
* **exit**: "LangGraph persists changes only when graph execution exits",
  qualified as "successfully, with an error, or due to a human-in-the-loop
  interrupt"; "This provides the best performance for long-running graphs" but
  "means intermediate state is not saved, so you cannot recover from system
  failures".
* **async**: "LangGraph persists changes asynchronously while the next step
  executes" — good performance and durability, but "there is a small risk that
  LangGraph does not write checkpoints if the process crashes during
  execution".
* **sync**: "LangGraph persists checkpoint writes throughout the run and
  awaits outstanding checkpointer promises" when the run finishes; "a process
  crash mid-run can still lose recent checkpoints" — its edge over `async` is
  that "the run does not return until pending writes have settled".
* The first durable checkpoint of a new thread: "The internal `__start__`
  superstep runs first; step `0` is the loop checkpoint written after that
  superstep." Per mode:
  * exit — "No checkpoint exists until the run ends. A crash during the run
    leaves no record of the thread."
  * async — "LangGraph starts writing the input checkpoint before the first
    user node executes, but does not wait for the write to finish"; "The first
    user node can run before any checkpoint is committed."
  * sync — "LangGraph schedules the input and step `0` writes during early
    ticks", and because it "awaits outstanding checkpointer promises only
    after the run finishes", "admission visibility at this boundary matches"
    `async`.
* A crash before the first durable checkpoint leaves the thread
  "indistinguishable from a thread that was never invoked"; the source's
  mitigation is to "record admission outside the checkpointer".
* Selection guidance: use `sync` when "you cannot afford to lose a step"
  (paying, sending mail); use `exit` for a batch job "that you would restart
  from the beginning anyway"; default to `async`.

packetgeek, "LangGraph Checkpoints Part 2: Storage with SQLite",
https://www.packetgeek.net/2026/09/02/langgraph-checkpoints-part-2-storage-with-sqlite/
— a 50-node graph measured once per mode on langgraph 1.2.11, stable "across
five runs, varying only in the third decimal":

| durability | seconds | checkpoints | final count |
|---|---|---|---|
| exit | 0.013 | 1 | 50 |
| async | 0.029 | 52 | 50 |
| sync | 0.028 | 52 | 50 |

* "`exit` wrote **one** checkpoint for a fifty-node graph."
* "`async` and `sync` both wrote fifty-two, one per super-step plus the
  input."
* "All three modes produced the same terminal state value of 50."
* "`exit` ... persists only when the run ends, whether that end is success, an
  error, or an interrupt." ... "Crash in the middle and there is nothing to
  resume from."
* "`async` writes while the next step runs, so a crash can lose the last
  checkpoint."
* "`sync` writes before the next step starts, so it cannot."
* "I could not measure a time difference between `async` and `sync` here" —
  the author attributes this to local SQLite writes being quick and warns to
  "measure it on your own backend rather than trusting this row."

### Northstar extension (this module, not the source)

* **The receipt format.** Every write produces a `DurabilityReceipt` carrying
  `mode`, `checkpoint_id`, `timing` (`on_exit` / `background` / `awaited`),
  `settled`, `awaited`, `thread_id`, `step_index`, `kind` and `reason`. The
  source has no receipt and no per-write record.
* **The integration points.** The controller writes through a
  `CheckpointSink`; two adapters ship with it — `FileSink` over
  `checkpoint_store.FileCheckpointStorage` and `DurableStoreSink` over
  `durable_resume.DurableStore` (which maps Northstar's checkpoint id onto
  the store's own `ck-NNNNNN` ids and reports them back on the receipt).
  Which store a run uses is the host's choice; the policy is orthogonal.
* **The crash-window model.** `DurabilityPolicy.crash_window()` returns an
  explicit `CrashWindow` (`loses_all_progress`, `may_lose_last_checkpoint`,
  `preserves_completed_steps`). The source describes the loss in prose; the
  model makes it checkable, and the tests assert the declared window against
  the *measured* one.
* **The crash hook.** `SimulatedCrash` plus an injected hook lets the loss
  window be exercised without killing the process. The source's crash
  behaviour is observed, never injected.
* **The cost grading.** `StepCost.SIDE_EFFECTING` vs `StepCost.RECOMPUTABLE`
  → `DurabilityPolicy.recommend()`. The source's guidance asks the question
  ("you cannot afford to lose a step"); the enum makes it answerable in code.
* **The interrupt as an awaited barrier.** Under `async` the interrupt
  checkpoint is awaited rather than left in flight. The source says
  interrupts work in all three modes because the checkpoint is saved when the
  run pauses; Northstar additionally guarantees the write has *landed* before
  the run waits for the human, because the run is going nowhere until the
  human answers and a resume that could not find the interrupt would be a
  worse failure than the one it avoids.
* **Fail-closed mode validation.** An unknown mode raises
  `InvalidDurabilityModeError` rather than defaulting. The source takes the
  mode as given.

## What the module does

`DurabilityController` is the single place that decides *when* a checkpoint
write happens. It is not a checkpoint store: it writes through a
`CheckpointSink`, so the same policy governs a file store, the durable log,
or an in-memory sink.

```
EXIT   start ─────────────────────────────► finish: one write
ASYNC  start ─► [step N: write in flight ─► next step runs it lands] ─► return (write outstanding)
SYNC   start ─► [input + start scheduled, land on first tick] ─► [step N: write, awaited] ─► return (nothing outstanding)
```

The observable discriminator between `async` and `sync` is **how many
checkpoints a step finds on disk when it starts**. Under `async` the previous
step's write is still in flight when the next step begins; under `sync` it is
already there. The test suite asserts the two sequences directly:
`async` → `[2, 2, 3, 4]`, `sync` → `[2, 3, 4, 5]`.

## The three real paths

1. **Fifty-step run, each mode once.** `exit` writes 1 checkpoint, `async`
   and `sync` write 52 each (one per super-step plus the input), and all
   three reach the same final state. These are the source's measured counts,
   reproduced on Northstar's controller.
2. **Interrupt and resume.** Every mode saves the checkpoint at the
   interrupt; the resume continues from that checkpoint id and does not
   write a second input checkpoint for a thread that already has one.
3. **Crash window.** The crash hook fires mid-run in each mode. `exit`
   lands 0 checkpoints, `async` lands the writes that had already gone, and
   `sync` lands one per completed step (28 at the tested crash point) —
   matching the declared `CrashWindow` in each case.

## Honest scope

* The module is a **library**: no existing runtime module is modified to
  call it. `checkpoints.py`, `checkpoint_store.py`, `durable_resume.py` and
  `sessions.py` are untouched by this slice.
* The **writes are in-process**, not on a background thread. `async` models
  the *timing* of a background write (issued, then landed later) rather than
  spawning a thread. A host that wants a real thread adapts the sink.
* The **crash hook is a simulation**. It stops the run and drops the
  in-flight writes; it does not kill the process and does not exercise the
  operating system's write buffers.
* The **checkpoint count is Northstar's**, not LangGraph's. Northstar's
  controller takes a `__start__` superstep of its own, so the fifty-step run
  writes 52 (input + start + 50 steps). The *source's* 52 is "one per
  super-step plus the input" over a fifty-node graph. The two reach the
  same number by different routes, and the equality is a coincidence of
  arithmetic — the design doc states both routes rather than claiming one
  reproduces the other.
* **The module is not declared in `pyproject.toml`.** The runtime
  component's `test_module_layout.test_every_module_is_installed` asserts
  that every module on disk appears in `[tool.setuptools] py-modules`. That
  test already fails at this slice's parent commit — with 29 modules
  undeclared — and `checkpoint_durability` joins the same list, so **no new
  test failure appears**. The declaration is still owed; this slice's
  writable-file set covers only the module, its tests and this design doc,
  so it is left to the slice that owns the packaging metadata.
* The source's `async`/`sync` timing distinction is reproduced **relative to
  the step boundary**, not with wall-clock measurements. The packetgeek
  article itself warns that it "could not measure a time difference between
  `async` and `sync`" on local SQLite and that the gap "should be measured
  on your own backend".

## Verification

* Focused suite: `tests/test_checkpoint_durability.py` — **72 new test
  methods**, all passing.
* Full runtime suite: **20 321 tests** (20 249 baseline + 72 new),
  **28 failures** — identical item-for-item to the baseline, no new failure.
* Governance bench: **161/169 passed, 8 failed** — identical to the baseline.
  Output saved to `/home/muse-newapi/b173-langgraph-durability-bench-final.txt`.
