# The offline replay page must say what a cancellation revoked

**Batch 173, slice `replay-page-legibility`.**

## The defect

`components/northstar-agent-runtime/session_ui.py` builds the runtime's
own offline HTML replay page: a self-contained file with the transcript
in an inert JSON data island and a script that renders it.

That script has its own renderer.  `recordText(record)` walks the
record's `content` blocks and then concatenates **every top-level string
field** (skipping `index`, `ts`, `session_id`, `type`, `content`).

A cancellation record's top-level string fields are its **chain
envelope**: `chain`, `chain_hash`, `digest`, `genesis`, `hlc`, `prev_hash`,
`kind`.  The record's *content* -- the tombstone -- is a **nested**
object, so `recordText` never reaches it.

Measured on a record the runtime itself wrote
(`SessionStore.record_cancellation`), the timeline line was:

```
1794952024881:0 sha256:3249a807f3f9151b22fa51e76c327e0c92bf8c25cf501acc22e696e75555024d permission northstar-audit-chain/2 0dbb3aabb0bb5db182cb561b…
```

and it contained:

| needle               | present |
|----------------------|---------|
| `publish`            | no      |
| `the release`        | no      |
| `user`               | no      |
| `stop, do not publish`| no      |
| `STANDING` / `LIFTED`| no      |
| the record's `chain_hash` value | **yes** |

So the revocation was on the page, and the page said nothing about it.
What it showed instead was the envelope: the digest, the chain name and
the chain hash -- the record's integrity fields, and nothing that
describes the revocation.

## Why it survived the previous slice

Slice 15 (`cancellation-visibility`, commit `50c05bd8`) introduced the
runtime's **one** rendering of a cancellation --
`cancellation_view.describe_cancellation` -- and wired it into the three
read paths that live in Python: `audit_export`, `session_replay` and
`session_view`.

It could not reach this page, because the page's renderer is
**JavaScript**.  The shared rendering is Python; the page is generated
from Python but its script is not.  Its design doc said so plainly, in
the section it called *the honest ceiling*.

That is the drift class recorded in
`b173-read-paths-must-know-what-a-record-means`: *a record type can be
written correctly and still be invisible -- every READ path needs its own
case, not just the writer.*  This page was the read path slice 15 could
not reach.

## The second, deeper defect: the truncation budget

The obvious fix -- paste the shared description into the page -- is not
enough, and measuring it is what forced the second change.

The page's timeline line is a **150-character** preview:

```js
function preview(record) {
  const value = recordText(record);
  return value.length > 150 ? value.slice(0, 147) + "…" : (value || "(no text payload)");
}
```

The shared description's length depends on the **grant id**, and a real
grant id is a uuid -- 36 characters.  Measured:

| grant id     | description length | `STANDING` in the 150-char line? |
|--------------|--------------------|----------------------------------|
| `grant-1`    | 169                | yes                              |
| a uuid       | 204                | **no**                           |

With a realistic grant id, the description's **tail** fell off the end
of the line -- and the tail is where the verdict was.

So the defect was not only "the page shows hashes".  It was also "the
page would truncate away the one word a reader must not miss".  A fix
that only moved the description onto the page would have produced a
page that renders a legible revocation **and silently hides whether the
stop is still standing**.

## The fix

### One rendering, computed in Python

`session_ui._with_descriptions` gives every cancellation record the
shared description and carries it in the payload:

```python
if str(record.get("type", "")) == "cancellation":
    copy = dict(record)
    copy["description"] = describe_cancellation(record)
```

The page's JavaScript then only has to **prefer** it:

```js
const described = record && typeof record.description === "string" ? record.description : "";
if (described) return described;
```

The page does **not** grow a second wording of a cancellation.  A second
wording is a second thing to drift -- which is exactly what happened
here in the first place.

Two details that are easy to get wrong:

* the record is **copied**, not mutated.  A record the runtime wrote is
  an audit boundary; the page must not rewrite it;
* the copy's fallback is **not silent**.  If the renderer ever raised,
  the page would fall back to the hashes -- and a *silent* fallback is
  precisely how a revocation became invisible in the first place.  So
  the failure is shown in the page, as text.

### The verdict comes first

The shared rendering's **order** changed:

```
cancellation - STANDING - publish on the release notes - the stop has not been lifted - declared by user via chat - reason: stop, do not publish - grant=1b4d5e52-72d5-432c-acc3-9dc9bc20553c - kind=permission
```

The state leads, the scope follows immediately, and the bookkeeping
(grant id, kind) trails.  Measured against the 150-character budget with
a uuid grant id, the line keeps:

* `STANDING`,
* the action and the subject,
* the declarer,
* the reason.

Only the grant id and the kind fall off -- and those are the two fields
a reader can look up, not the ones a reader acts on.

This is a change to the **shared** rendering, so it moves slice 15's
three read paths too: the audit feed, the replay frames and
`sessions show` all now lead with the verdict as well.  Their tests
still pass unchanged.

### The page gives a described record a longer line

```js
const budget = record && typeof record.description === "string" ? 300 : 150;
```

A described record gets a 300-character budget; everything else keeps
the 150 it always had.  The order change is what makes the verdict
survive; the budget is what stops the *rest* of the sentence from being
cut for a reader who has a wide window.

### The revocation gets a colour

`.kind.cancellation` now shares the denial's red.  A revocation is a
**withheld authorization** -- the same category as a denial, and slice 15
already said so in the audit feed.  On the page it was the default
blue, i.e. an ordinary informational row.

The detail pane also leads with the shared description, under a
*What was revoked* heading, so the reader who opens a record sees the
sentence before the envelope's hashes.

## What was measured

Every number below was produced by running the page's own JavaScript
under node against a stubbed DOM, with records the runtime wrote.

| property                                        | before | after |
|-------------------------------------------------|--------|-------|
| timeline line names the action                   | no     | yes   |
| timeline line names the subject                  | no     | yes   |
| timeline line names the declarer                 | no     | yes   |
| timeline line shows the reason                   | no     | yes   |
| timeline line distinguishes STANDING / LIFTED     | no     | yes   |
| verdict survives a uuid grant id                 | no     | yes   |
| timeline line contains the record's chain hash   | yes    | no    |
| an ordinary record's rendering                   | unchanged | unchanged |

## The honest ceiling

* The page still shows the chain envelope in the **detail pane** -- the
  hashes are the record's integrity fields, and a detail view is where
  they belong.  Only the *timeline line* is the reader's summary.
* The description says what was revoked; it does not decide whether the
  revocation is currently *enforced*.  The enforcement point is the
  sealed ledger's CAS (`forward_seal_ledger`), not this reader.
* `cancellation_view.REASON_LIMIT` is still declared and still unused.
  It is a real loose end: the reason is not truncated at all, so a very
  long principal reason makes the description long.  It was left alone
  here because changing it would change the shared rendering's output
  for slice 15's three paths, which is a separate decision.

## What did not change

* No record type was added or removed.
* `sessions.py` is untouched: the runtime wrote the record correctly
  before this slice and writes it correctly now.
* The `cancellation_tombstone` semantics are untouched.
* **No new module**, so the six pinned module counts (flat 1614,
  installed 1637) do not move.
* No version change, no tag, no release, no push, no merge.
