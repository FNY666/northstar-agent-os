# Fault-plant proof: a check earns trust only after it is watched failing

Status: implemented (`components/northstar-agent-runtime/planted_fault.py`).
Batch: B173 fieldnotes.

## The problem this slice answers

The kill-switch / config-drift alert triggers were unwired for a long time,
and the monitor log kept recording the shape of a check that never failed:
*"tested 34, auto-disabled 0"*. A count of what was exercised is not a
demonstration that anything can fire. Nothing in the repository could show
that a trigger had ever rung.

The method came from the fieldnotes_ai Moltbook post *A check that has never
failed has not shown it can: plant the fault under seal*
(`https://www.moltbook.com/post/e8f7aba8-c225-4aa8-afab-5d1c7010a8e8`, 16 up,
16 comments; links arXiv 2610.11835, Fault-Enforcing Tests). The post is not
in this repository; the quoted text below is the source as reproduced in the
B173 task book, and nothing else was consulted.

## The method, as stated by the source

**fieldnotes_ai (verbatim, from the task book):**

> a check earns trust only after someone has watched it fail on a fault it
> was not told about, and… the planting has to be hidden from the checker,
> including a later run of oneself.

**KitSinclair (verbatim, from the task book):**

> The plant does not go in those notes. A second process, one that does not
> wake as the checker, writes the absence.

Three rules emerged in that thread's comments:

1. **Plant in the input, never in the memory.** A plant written into shared
   notes becomes an instruction the next run follows.
2. **The planter is never the checker.** A second subject that does not wake
   as the checker writes the fault.
3. **A miss voids the earlier evidence.** If the check misses the planted
   fault, every pass it reported stops counting as evidence, back to the last
   occasion it was seen to catch something.

## What this repository had before

Read from the code, not assumed:

* `components/northstar-agent-runtime/alert_trigger_registry.py` declares two
  triggers: `permission-deny-kill-switch` (kind `kill-switch`, outcomes
  `("permission.deny",)`) and `permission-config-drift` (kind `config-drift`,
  outcomes `("permission.config-drift", "config-drift")`). `matches()` fires a
  trigger when the record's `outcome` is in its outcomes, or -- for
  `config-drift` only -- when `"config-drift"` appears in the record's
  `intent`.
* `components/northstar-agent-runtime/loop.py` (`_scan_alert_sink`) reads the
  sealed ledger and calls `alert_trigger_registry.matches(fields)` on each
  new event, then announces the alert. That is the production path; it is
  the path the registry's own tests drive.
* `components/northstar-agent-runtime/sealed_audit_sink.py` maps a gate audit
  record into an 8-field sealed event (`intent`, `action`, `subject`,
  `authorization`, `inputs_digest`, `logic_digest`, `execution_digest`,
  `outcome`). The check's input therefore comes from the **gate's audit
  record** -- it is an input record, not a note and not a memory.
* There was **no** place in the repository that proved a trigger had ever
  fired *on a fault it was not told about*. The counts in the monitor log
  ("tested 34, auto-disabled 0") are counts of what was exercised, not
  evidence that anything can fire.

## The Northstar extension

The three rules are the source's. The following are Northstar's own
extensions, stated here so they are not mistaken for the thread's claims.

**Extension N1 — a commitment is posted before the check runs.** The source
says the planting must be hidden from the checker. "Hidden" is enforced by
publishing the note's `sha256:` digest *before* the check, and comparing it
at reveal. The checker therefore cannot read the answer off the note, and a
note that was changed after the commitment was posted is detected
(`VOID_PLANT`). The commitment is the canonical-JSON `sha256:` of the note's
payload, computed the same way as the rest of the repository's digest pins
(`canonical_json.jcs_canonical_json`).

**Extension N2 — a plant aimed at shared state is refused fail-closed.**
The source's rule 1 is a prohibition; this module makes it mechanical:
`plant()` raises `PlantTargetError` when the note's `target_kind` is
`"memory"`, `"notes"` or anything else but `"input"`. There is no code path
that writes a plant into shared notes.

**Extension N3 — separation is by subject id, and holds across runs.** The
source says "a second process" and "including a later run of oneself". This
module keys separation on the *subject id* rather than the process: a
subject that planted may not check, and that holds for its own later run.
Identity in Northstar is the subject, not the process.

**Extension N4 — a voided plant stays voided, and a plant is revealed
once.** A note whose digest does not match the posted commitment, or that is
revealed before the check ran, is `VOID_PLANT`; a second reveal cannot
revive it and turn it into evidence.

**Extension N5 — the void boundary is the last observed catch.** The source
says the passes stop counting "back to the last occasion it was seen to
catch something". This module makes the boundary explicit: on a miss, every
`PASS` row with a seq **after** the last observed `CATCH` becomes `VOID`;
passes **before** that catch are untouched; a ledger with no catch yet voids
**all** its passes, because there is no earlier occasion it was seen to catch
anything. `VOID` is not "unproven" -- the row is voided.

**Extension N6 — the module never changes a check.** `run_check` calls
whatever callable it is handed and records what came back. It does not
narrow, weaken, or replace the check under test.

**Extension N7 — the blind check cannot read the plant metadata.** The check
is handed the faulted *mapping*; the plant id, the planter id and the true
value live in attributes of the `FaultedInput` wrapper, not in mapping keys.
A blind check therefore has no way to read which run was planted or what the
true value was.

## The shape of a trial

1. `post_commitment(note, ledger)` -- publish the note's `sha256:` digest.
   This happens **before** the check runs.
2. `plant(input_record, note, planter_id)` -- write the wrong value into a
   **copy** of the input record. The original record is not touched.
3. `run_check(check_fn, faulted_input, checker_id, ledger)` -- run the check
   blind. The check sees the faulted mapping only.
4. `reveal(note, commitment, ledger)` -- unseal. The digest is compared with
   the posted commitment; a catch or a miss is booked.

Dead plants:

* the note was changed after the commitment was posted -> `VOID_PLANT`;
* the note was revealed before the check ran -> `VOID_PLANT` (the checker may
  already have had access to the answer).

## The real path, driven end to end

The test file `components/northstar-agent-runtime/tests/test_planted_fault.py`
drives the whole path, not just the parts:

* `test_the_real_path_is_driven_from_commitment_to_catch` -- post the
  commitment; plant a `permission.deny` into run 3 of 5; run the **real**
  kill-switch check (`DEFAULT_REGISTRY.matches`) blind; reveal; the catch is
  booked.
* `test_the_miss_path_voids_the_passes_after_the_last_catch` -- plant a fault
  a deliberately narrowed **test double** cannot see; run it blind; reveal;
  the miss is booked; every pass after the last observed catch becomes
  `VOID`; the earlier catch survives.
* `test_the_real_check_is_not_weakened_by_the_miss_demo` -- the real check
  still fires afterwards. The miss demo used a double; no repository check
  was narrowed to make a miss happen.

## Relation to the rest of the repository

* **`alert_trigger_registry.py`** is the check under test. It is read-only
  for this slice; the tests drive its own `matches()`.
* **`sealed_audit_sink.py`** is where a check input comes from in production:
  the gate's audit record, mapped into an 8-field sealed event and appended
  to the forward-seal ledger. That is an *input record* -- the thing a plant
  is allowed to corrupt -- and not a note or a memory.
* **Check-input pinning** (`code_task.py`: `check_inputs`, the
  `check_input_pins` manifest, `DEFAULT_VERIFIER_RULE`) pins *which files* a
  check may read. This slice pins a different thing: *which value* the check
  will see. A pinned file can still be handed a wrong value; the only way to
  show a check can fire is to hand it one and watch it.
* **The sealed / forward-seal ledgers** establish order and integrity of
  events. The evidence ledger here is not a seal: it records what was
  observed and voids it when the check is seen to fail. It uses
  caller-supplied integer sequence numbers and no wall-clock, like the rest
  of the repository's ledgers.

## Open items

These are the questions the source and the code do not settle. They are
recorded rather than answered, because answering them would mean inventing
rules the thread did not state.

1. **Which check scopes the void rule applies to.** The source speaks of "a
   check". This module keys the ledger rows by `check_scope` but the void
   sweep is currently ledger-wide, not per-scope. If one scope misses, does
   an unrelated scope's passes die too? The thread does not say.
2. **How many runs "N" is.** The source says "one of the next N runs". This
   module carries `run_index` on the note but does not bound N or refuse a
   run index outside a declared window.
3. **Whether a catch after a void restores the voided passes.** The source
   says a miss voids the passes back to the last observed catch. It does not
   say a later catch resurrects them. This module leaves them void.
4. **Who holds the commitment.** The source's "posted beforehand" implies a
   public channel. This module's ledger holds the commitment in-process;
   the cross-process publication channel is not implemented.
