# A recorded cancellation must be enforced where the effect happens

**Batch 173, slice `cancellation-gate`.**

## The defect

The runtime can write a cancellation tombstone, can reconstruct the
live tombstone set from the transcript, and the sealed ledger has a
compare-and-swap that refuses a grant covered by a live tombstone.
**None of those three is on the runtime's own tool-call path.**

Measured with a real `AgentRuntime` and a scripted `Write`:

```
record types : ['cancellation', 'session_start', 'user_prompt', 'assistant',
                'tool_result', 'assistant', 'result', 'session_end']
denials      : []
result subtype: success
```

The session said the action was cancelled.  The write happened anyway.

The same defect at the seal layer:

```
ledger.append_grant(grant_id="g1", action="publish", subject="post-42")
  -> sealed, even though the session's live set said blocked=True
ledger.set_tombstones(store.tombstones())
  -> ForwardSealError: action 'g1'/'publish' is cancelled by a live
     tombstone: the seal is refused and no record lands
```

`ForwardSealLedger.set_tombstones` has **no production caller**.  The
only one in the tree is `tests/test_refusal_hold_wiring.py`.
`SessionStore.record_cancellation` and `record_cancellation_lift` have
no production caller either.  So the runtime can *write* a stop and
never *read* it back where the effect happens.

### Why "recorded but not enforced" is the worst of the three states

The runtime writes the cancellation into the transcript.  Slice 15 gave
it one legible rendering; slice 16 put that rendering on the offline
replay page.  A reader sees a stop that was recorded.  The write still
happens.

That is exactly the state the refusal-hold-wiring slice named for
refusals:

> *recorded but not enforced*, which is worse than *not recorded*,
> because the ledger creates the illusion that the refusal was handled.

So the tombstone slice's own open item is the real gap:

> The tombstone is not yet injected into the runtime's own dispatch path
> (the loop's tool-call gate) ... wiring the registry into the loop's
> tool permission gate is the natural next slice

and §7 of its design doc:

> The decision points are the sealed ledger's CAS and the runner's
> `is_blocked` check.

Neither decision point is the runtime's own tool gate, which is where
the runtime's effects actually happen.

## The identity question, and its honest answer

`Tombstone.covers(grant_id, action, subject)`
(`cancellation_tombstone.py:157`) matches on **three** fields:

```python
if grant_id != self.grant_id or action != self.action:
    return False
```

The problem is that **a tool call carries no grant id.**  Measured:

* `PermissionRequestContext` (`permissions.py:628`) has `session_id`,
  `agent`, `depth`, `turn_index`, `workspace`, `mode`, `call_id`,
  `arguments_digest`, `scope_id`, `data` — and **no `grant_id`**.
* `ToolSpec` (`tools/__init__.py:377`) has `name`, `kind`,
  `is_mutating`, `is_delegation`, `needs_workspace` — no grant id.
* The governed runner seals the tool call with `action=spec.name,
  subject=self.config.agent` (`loop.py:3133`) — the **agent** is the
  subject on the tool-call path, and there is no grant in sight.

So the tool-call path's identity vocabulary is `(tool name, agent)`,
while the tombstone's is `(grant id, action, subject)`.  They do not
line up, and the field that cannot be reconciled is the grant id.

### What the alternatives cost

| the gate demands | consequence |
|------------------|-------------|
| an exact grant id | it matches **nothing** — the tombstone's grant id is minted by whatever declared it, and the gate cannot know it |
| an exact grant id, failing closed | it refuses **every tool call in every session that holds any tombstone at all** |
| a subject match alone | a stop for one path would stop every path, and a stop for `publish` would stop nothing that is actually publishable |
| **action + subject, grant id carried** | the two fields the gate can actually derive decide; the grant id is reported, not matched |

The last row is what this slice implements.  It is a **deliberate
coarsening**, and the coarsening is in the safe direction: it can block
a call that a three-field match would have let through, and it cannot
let through a call that any tombstone for that action names.

The grant id is **not** silently ignored.  It is carried into the
refusal message, so the reader sees *which* stop refused the call:

```
Write refused by the permission gate: Write was cancelled by user via
chat and the stop has not been lifted: stop, do not write (grant grant-1)
```

## The fix

### The identity derivation (`sessions.py`)

```python
def canonical_action(tool_name: str) -> str:
    return str(tool_name).strip().casefold()

def canonical_subject(tool_name, payload, *, root=None) -> str:
    ...
```

* the **action** is the canonical tool name, so `Write` and `write` are
  one action — the rule `permissions.canonical_tool_name` already
  exists for, for exactly this reason ("a forbidden action can't slip
  through via spelling variants");
* the **subject** is the call's target: the **workspace-relative path**
  for a file tool (`Read`, `Write`, `Edit`, `LS`, `Grep`), the **host**
  for `Fetch`, and the empty string for every other tool.

The path is **lexically normalized**, which is the runtime's own
convention — `read_file` computes its skill-digest pin name the same
way (`tools/__init__.py:1220`).  So `notes.md`, `./notes.md` and
`sub/../notes.md` are one subject, and a tombstone that names
`notes.md` blocks all three.

### The matching rule (`sessions.cancellation_gate_matches`)

```python
if canonical_action(tombstone_action) != canonical_action(action):
    return False
if not tombstone_subject.strip():
    return True      # an unscoped tombstone covers every subject
if not subject:
    return True      # "an unspecified subject is not evidence of
                     #  being outside the scope"
return tombstone_subject == subject
```

The subject rule is the tombstone's **own** rule, kept verbatim.  The
grant id is the only thing dropped, and the reason is in the
docstring, not only here.

### The live set (`SessionStore.live_tombstones`)

The gate needs the live set, and `SessionStore.tombstones()` re-reads
the whole transcript — O(transcript) **per tool call**, on a file that
grows.  So the live set is cached on the store:

* it is **seeded from the transcript** when the store opens on an
  existing session, so a resumed session enforces the stops it
  inherited;
* it is **updated by `record_cancellation`** and
  `record_cancellation_lift`** as they write, from the very tombstone
  that was written.

So the cache cannot drift from the durable record: the record is
written first, and the cache is updated from the same tombstone.

### The gate (`loop.py`)

The check goes in `_authorize_tool`, which is the **single funnel**:
the serial path (`loop.py:3085`), the parallel path and the delegate
path (`loop.py:4166`) all call it, and the parallel batch authorizes
each call on the main thread before any handler runs.  One insertion
point covers every path.

It sits **after** the payload is final (schema-validated and
hook-rewritten) and **before** the permission gate, so it sees the
arguments the handler would really get.

The refusal uses the **existing** machinery — a `PermissionDecision`
with `source="cancellation"` — so `_refuse_by_gate` books the `denial`
record, fires `PostToolUseFailure`, writes the evidence event and
gives the model a structured denial tool result.  **There is no second
refusal path.**

`"cancellation"` is the one new member of the `DecisionSource`
literal: a stop the principal already gave is not a policy judgement,
and an audit consumer must be able to tell the two apart.

### Fail closed

If the live set cannot be read, the call is **refused**, not allowed,
with the reason carried so a reader can tell "stopped" from "could not
tell".  An unknown state is never a clean read — the same rule
`scope_qualifier.BLOCKING_OUTCOMES` states.

## What was measured

Every number below was measured by running the code.

| property                                        | before | after |
|-------------------------------------------------|--------|-------|
| a stopped `Write` is refused                    | no     | yes   |
| the stopped file is not written                 | no     | yes   |
| the refusal lands as a `denial` record          | no     | yes   |
| the model is told the call was refused          | no     | yes   |
| the refusal names the stop that caused it       | no     | yes   |
| an unrelated tool still runs                    | yes    | yes   |
| a subject-scoped stop blocks that subject       | no     | yes   |
| a subject-scoped stop spares another subject    | no     | yes   |
| a stop for another action blocks nothing        | yes    | yes   |
| the action is matched canonically               | no     | yes   |
| a lifted stop does not block                    | yes    | yes   |
| a resumed session enforces an inherited stop    | no     | yes   |

The mutant probe on `sessions.py`: **21 of 63** killed, up from 10
before the guard was strengthened.  Every site inside this slice's own
code is killed; the remaining survivors are in pre-existing code (the
redaction pass, the chain resume, the byte limits, the transcript
reader).

## The honest ceiling

* **The grant id is not matched.**  That is a real coarsening and it is
  deliberate: the alternative matches nothing, or refuses everything.
  It is stated in the code's docstring, not only here.
* **The gate covers the tool-call path.**  The **durable runner**'s
  re-declaration of pending writes is the tombstone slice's *other*
  open item and is **not** fixed here.  A `PendingWrite` carries
  `(task_id, idx, channel, value, effect_key, task_path)` and **no
  action identity at all**, so wiring it needs a field this slice does
  not add.
* **A tombstone declared for an action the tool registry has no tool
  for is inert at the gate** (`action="publish"` blocks no tool call).
  It is still enforced at the ledger's CAS.  This is worth stating
  because it is the case that would otherwise look like the fix
  "broke publishing" — it did not; there is no `publish` tool.
* **The gate's check is a pre-execution check.**  The ledger's CAS is
  the commit-time check.  The slice does not merge them: the ledger's
  lock cannot cover the tool handler's execution without a lock the
  handler does not take.  The tombstone's own rule — "a check that runs
  ahead of the protected write is a comment, not a control" — is why
  the CAS lives in the ledger's critical section.  This slice puts the
  gate on the path where the runtime's own effects happen, and says so
  rather than claiming the race is closed.
* **A stop declared mid-run** is enforced from the next tool call
  onward.  A call already in flight is not recalled.

## What did not change

* No record type was added or removed.
* `cancellation_tombstone.py` is untouched: the semantics of the
  tombstone, the lift rule and the expiry split are exactly as they
  were.
* The sealed ledger is untouched: its CAS is unchanged, and this slice
  does not add a second enforcement point there.
* **No new module**, so the six pinned module counts (flat 1614,
  installed 1637) do not move.
* No version change, no tag, no release, no push, no merge.
