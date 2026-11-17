# The session panel's record vocabulary

## The rule

> **The panel's vocabulary is the runtime's vocabulary.**  Every record
> type the runtime writes is a record type the panel knows: it is
> classified as that type, it has a colour, and it is summarised as
> itself.

And, about the panel's errors-only filter:

> **The errors-and-denials-only filter answers a boolean, and it does
> not hide a cancellation.**

## What the panel is

`examples/session-panel/session-panel.html` is an offline viewer over a
session transcript.  It is a single self-contained HTML file: it
parses a `*.jsonl` transcript in the browser, classifies each record by
type, colours it, summarises it, and offers an "errors & denials only"
filter.

It mirrors the runtime's record vocabulary BY HAND: a `RECORD_TYPES`
list, a `TYPE_COLOR` map, and a `summarize` case per record type.

## What was wrong

Commit `695a25b7` (B173 tombstone) added the `cancellation` record type
to the runtime's `RECORD_TYPES` in `sessions.py` and did not add it to
the panel.  The panel therefore rendered the sticky revocation that
says "stop, do not publish" as a raw JSON blob of an unknown type.

Running the panel's real JavaScript against the runtime's real records
found three more defects, all in `isErrorRecord`:

| defect | consequence |
|---|---|
| `isErrorRecord` returned a summary **string** for a checkpoint | a resumable boundary was listed among the errors |
| `isErrorRecord` returned a summary **string** for a postconditions record | the end-of-run verdict was listed among the errors |
| `isErrorRecord` returned `false` for a cancellation | the one record whose whole point is that it must not be missed was **hidden** by the errors-only filter |

A string is truthy, so the first two made the filter treat those
records as errors.  The third made it drop the one record that matters
most.

The repository-level guard `tests/test_observability_examples.py`
already caught the first of these -- the panel's vocabulary had fallen
behind the runtime's -- and it had been **red on this branch** since
commit `695a25b7`.  CI's `documentation` job runs the repository-level
suite, so the branch's CI was failing.

## How the guard measures

The guard does not work from a hand-written list of record shapes.  It

1. **asks the runtime to write the records** -- the runtime's own
   `SessionStore`, its own `Tombstone`, and its own
   `record_cancellation_lift` -- and
2. **feeds those records to the panel's real JavaScript** under node,
   in a sandbox whose DOM is a stub, and reports what the panel does
   with them.

Step 1 matters because the record shapes are exactly what a
hand-written sample list gets wrong:

* a checkpoint's payload is **top-level** (`turns`, `transcript_len`,
  `tool_calls`, `cost_usd`, `denials`), not nested under `data`;
* a postconditions record's verdict is under `data`, with `ok`,
  `passed`, `checked` and `results`;
* a cancellation's payload carries a `tombstone`, a `digest` and a
  `kind`, and a **lifted** cancellation carries a `lift` block as well.

A sample list written by hand would have tested the panel against
shapes the runtime never writes -- which is how a guard can pass while
proving nothing.

Step 2 matters because a marker check can only prove that a string is
present.  Executing the panel proves what the panel **DOES** with each
record type, which is the property that matters: whether it
**classifies** the record as its own type, whether it **colours** it,
whether it **summarises** it, and whether the errors-only filter
**shows** it.

The probe writes one real record of every type, plus a second
cancellation that has been **lifted** -- because a lift is a record
too, and a reader cannot otherwise tell a standing stop from a lifted
one.

## Where node is not installed

The behavioural half is **skipped**, never silently assumed to have
passed.  The vocabulary checks that do not need node -- the panel
declares every runtime record type, and declares no type the runtime
does not write -- run everywhere.

## The fix

The panel's `RECORD_TYPES` gains `cancellation`, `TYPE_COLOR` gives it
`err`, and `summarize` gains a case that renders the tombstone as the
stop it is: what is revoked, on what, by whom, on which channel, why,
and whether the stop was lifted.

`isErrorRecord` is fixed to answer the question it is asked -- "should
the errors-and-denials-only filter show this?" -- with a boolean:

* a checkpoint is a resumable boundary, not an error;
* a postconditions record is an error only when a claim did not hold
  (`data.ok === false`);
* a cancellation is a revocation, so the filter shows it.

## What did not change

* No component's source.  The runtime's `RECORD_TYPES` is untouched.
* No other record type's rendering.
* No version change, no tag, no release, no push, no merge.
