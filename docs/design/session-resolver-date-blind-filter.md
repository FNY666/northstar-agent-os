# The session resolver's date-blind filter

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED in the live tool, with the before/after measured.

## 1. The one-line finding

`b173-resolve-session.py` implements the rule

> a session belongs to slice S iff (1) its **first user message declares**
> S's canary, AND (2) it **starts at or after** S's **last** watch start
> (minus 5 s)

— but rule (2) was implemented by comparing **seconds-of-day**, which
discards the DATE. So a session from ten days EARLIER whose clock time is
later in the day passes a test whose rule is about an INSTANT.

The defect is not in the rule. It is in the implementation of it.

## 2. The code

```python
def _wsec(t):
    """Seconds-of-day from an ISO-8601 timestamp (or None)."""
    try:
        return int(t[11:13]) * 3600 + int(t[14:16]) * 60 + int(t[17:19])
    except Exception:
        return None
```

`t[11:13]`, `t[14:16]`, `t[17:19]` are the hour, minute and second. The
year, month and day (`t[0:10]`) are never read. So `_wsec("2026-11-13T16:05:02Z")`
is `57902` and `_wsec("2026-11-23T04:00:01Z")` is `14401`, and the
comparison `s < w - tolerance` says the 11-13 session is **after** the
11-23 watch start — which is false by ten days.

`candidates()` used `_wsec` for both sides:

```python
ws = watch_start(slug)
w  = _wsec(ws) if ws else None
...
if w is not None and ts:
    s = _wsec(ts)
    if s is not None and s < w - tolerance:
        continue
```

## 3. Why it matters, and the measured blast radius

A slice that is RELAUNCHED gets two sessions carrying its canary: the
original attempt and the relaunch. The resolver is supposed to keep the
relaunch, because the relaunch's watch start is the LAST one in the watch
log and the relaunch is what produced the slice's final commit.

But the relaunches happened in the small hours (the launcher starts them
around 02:20–04:25 UTC), while the ORIGINAL attempts ran in the afternoon
(15:40–16:35 UTC). So the original attempt's clock time is LATER in the
day than the relaunch's watch start, and the date-blind filter admitted
it.

Measured 2026-11-25 over every slice in the batch, **seven** slices are
AMBIGUOUS for exactly this reason. In every one of them the two
candidates differ by a DATE, and the date-aware comparison selects the
session that starts at or after the last watch start:

| slice | last watch start | the WRONG candidate (kept by the date-blind filter) | the RIGHT one |
|---|---|---|---|
| ageofagents | 2026-11-23T03:10:01Z | 8f83ea12 (2026-11-13T16:00:02Z) | ee7b93bc (2026-11-23T03:10:02Z) |
| asinhhc | 2026-11-23T03:35:02Z | 43ca7352 (2026-11-13T16:35:02Z) | 07be0f43 (2026-11-23T03:35:03Z) |
| lightningzero | 2026-11-23T04:00:01Z | ee75584a (2026-11-13T16:05:02Z) | 7ed75d99 (2026-11-23T04:00:02Z) |
| neo-konsi-s2bw | 2026-11-23T04:25:02Z | 00a6cc27 (2026-11-13T16:15:02Z) | 179eb2a0 (2026-11-23T04:25:02Z) |
| outsideloop | 2026-11-23T02:20:01Z | e97b9abb (2026-11-13T16:30:02Z) | 1f562c25 (2026-11-23T02:20:02Z) |
| strands | 2026-11-23T02:45:02Z | 9dffa57e (2026-11-13T15:40:02Z) | 68b5954f (2026-11-23T02:45:03Z) |
| anthropic-effort-scaling | 2026-11-14T01:55:01Z | e0808905 (2026-11-13T21:56:02Z) | a35f0185 (2026-11-14T01:55:02Z) |

The `anthropic-effort-scaling` row is a control: it was already AMBIGUOUS
before this defect was found (the round-6 doc records it as the one slice
that rules (1)+(2) leave ambiguous), and its two candidates differ by a
DATE too — 2026-11-13T21:56:02Z against a 2026-11-14T01:55:01Z watch
start. So the date-blind filter is what made it ambiguous, and the
date-aware filter is what resolves it.

**The cost of the ambiguity was not a wrong verdict — it was NO verdict.**
`b173-accept.sh` treats `AMBIGUOUS` as SKIP, honestly:

```
SKIP REPORT_NUMBERS ambiguous session for canary TBFw0tHO3N1tRUppqG80 -- not guessed
```

So the headline-number cross-check — the one that proves a report's peak
and compaction counts against the session that produced it — did not run
at all for these seven slices. A SKIP is honest, but it is also an
absence of evidence, and the evidence was available.

## 4. The fix

A full-timestamp comparison, one new function, and two call sites:

```python
def _epoch(t):
    """Full UNIX timestamp from an ISO-8601 timestamp (or None)."""
    try:
        import datetime
        return datetime.datetime.fromisoformat(
            str(t).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None
```

`_epoch` replaces `_wsec` in `candidates()` (for the session timestamp) and
for the watch-start timestamp. `_wsec` is kept, with a docstring that says
out loud why it must not be used for this test.

`_epoch` returns `None` for an unparseable timestamp, and the caller
already skips the `None` case (`if s is not None and s < w - tolerance`),
so an unparseable timestamp is treated as "cannot prove it is too early"
and the candidate is admitted — the same conservative behaviour the
seconds-of-day version had.

## 5. Verification

Measured over every slice in the batch, before and after:

* **before**: 7 slices AMBIGUOUS (the table in §3);
* **after**: **0 slices change from a resolved session to a different one,
  and all 7 resolve to a unique session**;
* no slice that was already unique changed its resolution. Verified by
  running the resolver over every taskbook's canary before and after and
  diffing the verdicts: the ONLY differences are AMBIGUOUS -> ONE.

The acceptance script's own verdict, re-run after the fix:

```
PASS REPORT_NUMBERS jsonl=ee7b93bc-3344-421c-b263-6891de012d77.jsonl
PASS REPORT_NUMBERS jsonl=07be0f43-3859-41fe-88dc-bee1bd634797.jsonl
PASS REPORT_NUMBERS jsonl=7ed75d99-a9f8-4217-9526-28161a0edb1f.jsonl
PASS REPORT_NUMBERS jsonl=179eb2a0-8d2c-48d1-9148-86589020c959.jsonl
PASS REPORT_NUMBERS jsonl=1f562c25-e587-4e26-919f-72d9ac87b57d.jsonl
PASS REPORT_NUMBERS jsonl=68b5954f-430b-4dfd-9879-02a3c24454a2.jsonl
PASS REPORT_NUMBERS jsonl=a35f0185-31f8-4b55-9389-26bf486d7304.jsonl
```

## 6. What this does NOT change

* The resolution RULE is untouched. Only the comparison of two instants
  changed, from "their clock times" to "their instants".
* The `AMBIGUOUS -> SKIP` behaviour is untouched. The resolver still never
  guesses; it just has fewer cases where it has to say "I cannot tell".
* The `--latest` tiebreak is untouched and still available.
* No acceptance-script semantics changed, and no verdict flipped for a
  reason other than the session becoming resolvable.

## 7. The general lesson

**A timestamp comparison is only as precise as the fields it reads.**
`_wsec` reads the clock time of a timestamp and is called "seconds-of-day",
which is an honest name — but the RULE it serves ("starts at or after")
is about an instant. The bug is a name/rule mismatch that no amount of
reading the code would make obvious: `_wsec` looks like a time comparison,
and a time comparison *is* what the reader expects to see.

The measure that found it was not reading the code. It was noticing that
three slices were AMBIGUOUS and asking **why**, and then asking **what
would have to be true for a session ten days old to pass a test about
starting after a watch start**. The answer was: the comparison had no
idea what day it was.

## 8. Where the fix lives

The live tool: `/home/muse-newapi/b173-resolve-session.py`.

It is a shared tool — every `b173-accept.sh` reads it — so it is mutated
only when no acceptance run is in flight, and the pre-fix copy is kept at
`/tmp/b173-resolve-session.py.bak-dateblind` for the round.

## 9. Related

* `docs/design/r6-12-session-resolution.md` — the rule this implements, and
  the poison-session defence it defends against.
* `docs/design/baseline-attribution.md` §A-8 — the bench baseline pointer
  move that this window's report-writing work ran into.
