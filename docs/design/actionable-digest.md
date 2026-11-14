# Actionable digest: silent unless the conjunctive fire condition holds

Status: implemented in `components/northstar-agent-runtime/actionable_digest.py`
(tests: `components/northstar-agent-runtime/tests/test_actionable_digest.py`).

This document separates two kinds of claim, and labels every one of them:

* **SOURCE** -- taken from the source post, quoted or paraphrased, and
  marked as such.  Where the source's wording is reproduced it is quoted.
* **NORTHSTAR** -- an extension of this repository.  Not the source's.

## 1. The source

Moltbook, musepalmetto, "PATTERN: silent-unless-actionable alerting"
(`m/tooling`, 2026-11-12, 7 up / 13 comments; full text read 2026-11-14):
<https://www.moltbook.com/post/3572d6d9-2190-45d2-9915-836ba2a1da39>

### 1.1 What Northstar had before this slice

**SOURCE / repository code.** `components/northstar-agent-runtime/alert_trigger_registry.py`
defines two trigger kinds, `kill-switch` and `config-drift`, and each
`AlertTrigger` carries `name`, `kind`, `outcomes`, `detail_fields` and
`enabled`.  The registry answers *what can fire* -- it matches an event's
outcome (or a `config-drift` intent) against the registered triggers.  It
does **not** answer *when to bother a human*: there is no conjunctive
condition, no uncertainty labelling, no false-alarm bookkeeping, and no way
to tell "the monitor was quiet" apart from "the monitor died".

**NORTHSTAR.** This slice adds the missing firing policy as a separate
module.  `alert_trigger_registry.py` is reused **read-only**: the digest
may ask the registry which trigger matches an event and records the name on
the digest item; it never modifies the registry, and the registry's
`enabled` flag is not treated as a firing condition.

### 1.2 The fire condition (SOURCE)

The source's condition is conjunctive.  Its three clauses, in the source's
terms: the listing must be at least ~35% under the verified resale price,
**and** the expected profit at least $75, **and** the listing must look
legitimate.  All three must hold; the source does not offer a disjunctive
relaxation.

The transfer is explicit in the source: the pattern applies to any standing
monitor -- price watches, inbox triage, calendar catchers.

**NORTHSTAR.** The *shape* of the condition is the source's; the field
vocabulary and the thresholds are ours.  See section 2.1.

### 1.3 The uncertainty rule (SOURCE)

If a load-bearing attribute cannot be verified from the available data, the
source fires anyway -- but labels the uncertainty, states both decision
branches, and never asserts the unknown.

The source's instance: a watch listed at $350 against a $400 category
ceiling, where the *model* could not be verified (that particular watch had
no photo access, and the laminate variant is a pass at that price).  The
alert fired labelled *model-unconfirmed*.  The human's next step became
"go look at the label" rather than "decide whether to buy".

**NORTHSTAR.** The label vocabulary ("unknown attribute", "decision
branch") and the refusal of a digest that asserts an unknown as fact are
ours; the rule itself -- fire, label, state both branches -- is the
source's.

### 1.4 The failure modes and the credibility rule (SOURCE)

The source names two ways a monitor loses its principal: a monitor that
narrates gets muted, and a monitor that guesses teaches the principal to
discount every alert, including the true ones.  Its credibility measure is
the **false-alarm rate**, explicitly *not* the hit rate.

**NORTHSTAR.** How the verdict is recorded (`mark_alarm(seq, "false_alarm" |
"true_alarm")`) and the fact that an un-fired or unmarked digest counts
towards the denominator are ours; the choice of the false-alarm rate as
the measure is the source's.

## 2. The module

### 2.1 The fire condition (NORTHSTAR vocabulary, source's shape)

`FireCondition` is a frozen record of three clauses:

| field | meaning | default |
|---|---|---|
| `severity_threshold` | lower bound on the event's severity | `0.7` |
| `impact_floor` | lower bound on the event's impact | `0.5` |
| `requires_legitimate` | the legitimacy/verifiability clause | `True` |

All three must hold for the digest to fire; `FireCondition.evaluate()`
returns `(fires, failed_clauses)` so a suppressed event can say *which*
clause failed.

**NORTHSTAR.** The defaults are Northstar's.  The source's `~35%` and
`$75` are one household's thresholds for one marketplace category and are
**not** copied: severity and impact here are normalized scores in `[0, 1]`,
not money and not a percentage.  The thresholds are configurable per
digest instance.

### 2.2 Event vocabulary (NORTHSTAR)

An event is a mapping with:

* `severity` -- normalized score in `[0, 1]`;
* `impact` -- normalized score in `[0, 1]`;
* `legitimate` -- bool, the legitimacy/verifiability clause;
* `unverifiable_attributes` -- list of load-bearing attributes that could
  not be verified;
* `summary`, `window_id`, `trigger` -- descriptive;
* `branches` -- optional per-attribute `{if_true, if_false}` text;
* `asserted_facts` -- values the caller claims as fact.

**NORTHSTAR.** None of these field names are the source's; they are this
repository's vocabulary for the source's three clauses.

### 2.3 Silence by default (SOURCE rule, NORTHSTAR mechanism)

`ActionableDigest.ingest()` fires only when all three clauses hold.
Everything else is *suppressed*: counted, never emitted, never dropped.
A narrative event -- a pure status update with no severity and no impact --
is always suppressed.  The source's reasoning applies: a monitor that
narrates gets muted.

### 2.4 Uncertainty labelling (SOURCE rule, NORTHSTAR mechanism)

When a fired event carries `unverifiable_attributes`, the digest item is
marked `uncertain`, lists the unknown attributes, and carries one
`DecisionBranch` per unknown attribute with an `if_true` and an `if_false`
statement.  If the caller supplies branch text it is kept verbatim; if not,
a conservative default branch is synthesised.

**Fail-closed.** If an event both lists an attribute as unverifiable *and*
asserts a value for it (`asserted_facts`), the event is refused outright
(`DigestError`) and nothing is emitted or counted.  Writing the unknown as
a fact is the one error this module will not pass on.

### 2.5 Credibility (SOURCE rule, NORTHSTAR mechanism)

`ActionableDigest.credibility()` returns a `Credibility` whose
`false_alarm_rate` is `false_alarms / total_fired`.  The denominator is
everything that fired, including digests that have not yet been marked;
suppressed events never dilute it.  With `total_fired == 0` the rate is
**undefined** (`None`) -- never `0`, never `1`.  This is the source's rule
(false-alarm rate, not hit rate) with an explicit undefined state, because
Northstar's other accounting modules treat "not measured" as distinct from
"measured zero".

### 2.6 Null counting (NORTHSTAR)

This is the frontier transfer note "digest counts the nulls so dead-vs-quiet
is visible" -- a frontier author's note about this pattern, **not** the
source's wording, and not the source's mechanism.

Every window the digest observed gets a `DigestRecord` from
`digest_window(window_id)`, even when zero events were actionable:

* `actionable_count` -- digests emitted in the window (may be 0);
* `suppressed_count` -- events seen and suppressed;
* `last_seq` -- the global sequence number of the last ingested event;
* `window_last_seq` -- the last sequence number seen *in this window*.

The caller makes the liveness judgement: a window with a record is a pipe
that produced a (possibly empty) digest; a window with **no** record
(`record_for(window_id) is None`) is a window the pipe never reached.
Northstar does not raise an alarm on the caller's behalf -- it makes the
distinction observable.

### 2.7 Fail-closed summary

| situation | behaviour |
|---|---|
| event missing `severity`, `impact` or `legitimate` | refused (`DigestError`), not counted |
| event not a mapping | refused |
| severity/impact outside `[0, 1]`, or non-finite | refused |
| unverifiable attribute also asserted as fact | refused, nothing emitted |
| `total_fired == 0` | credibility is `undefined` (`None`) |
| non-actionable event | suppressed and counted -- not an error |
| `mark_alarm` on a seq that never fired | refused |
| `mark_alarm` with an unknown verdict | refused |

## 3. Public API

```
FireCondition(severity_threshold=0.7, impact_floor=0.5, requires_legitimate=True)
FireCondition.evaluate(severity, impact, legitimate) -> (fires, failed_clauses)

ActionableDigest(condition=None, registry=None)
ActionableDigest.ingest(event) -> IngestResult(seq, actionable, reason, item)
ActionableDigest.digest_window(window_id) -> DigestRecord
ActionableDigest.record_for(window_id) -> DigestRecord | None
ActionableDigest.windows() -> tuple[str, ...]
ActionableDigest.mark_alarm(seq, verdict) -> None
ActionableDigest.credibility() -> Credibility
ActionableDigest.fired_items() -> tuple[DigestItem, ...]

DigestEvent.from_mapping(event) -> DigestEvent
DigestError(ValueError)
```

`registry` is the optional read-only trigger registry (see section 1.1).

## 4. The three driven paths

The tests drive the source's instance end to end (`RealPathTests`):

* **Path A -- the unverifiable model.** severity 0.95, impact 0.9,
  legitimate, `model` unverifiable.  Fires, `uncertain` is true,
  `unknown_attributes == ("model",)`, and the two branches read "if the
  model is genuine: go look at the label in person" / "if the model is not
  genuine: drop the candidate, no purchase".  The unknown is never stated
  as a fact.
* **Path B -- one clause short.** severity 0.95, impact 0.9,
  `legitimate=False`.  Suppressed with reason `not_legitimate`; the window
  records `actionable_count == 0` and `suppressed_count == 1`.
* **Path C -- the quiet window.** Two suppressed events in one window.
  `digest_window` still returns a record with `actionable_count == 0`,
  `suppressed_count == 2`, `last_seq == 2` and no items -- the caller sees
  a record and knows the pipe is alive; a window with no record at all
  (`record_for` returns `None`) is the dead-pipe signal.

## 5. What this module does not do

* It does not run a loop, schedule a monitor, or talk to a provider.  It
  observes no live run; every function is pure and deterministic.
* It does not raise an alarm when a window is quiet or missing.  It makes
  the distinction observable; the decision is the caller's.
* It does not judge whether an attribute is "actually" legitimate beyond
  the boolean the caller supplies.
* It does not modify `alert_trigger_registry.py`.

## 6. Source-to-code map

| source element | where it lives | label |
|---|---|---|
| conjunctive fire condition | `FireCondition.evaluate` | SOURCE (shape) / NORTHSTAR (fields, defaults) |
| fire anyway when an attribute is unverifiable | `ActionableDigest._build_item` | SOURCE |
| label the uncertainty | `DigestItem.uncertain`, `DigestItem.unknown_attributes` | SOURCE |
| state both decision branches | `DecisionBranch.if_true` / `.if_false` | SOURCE |
| never assert the unknown | `DigestEvent.from_mapping` refuses `asserted_facts` on an unverifiable attribute | SOURCE |
| credibility = false-alarm rate | `ActionableDigest.credibility` | SOURCE |
| monitors that narrate get muted | narrative events always suppressed | SOURCE |
| price watches / inbox triage / calendar catchers | the `window_id` + event vocabulary | SOURCE (transfer) / NORTHSTAR (mechanism) |
| null counting: dead vs quiet | `digest_window`, `record_for` | NORTHSTAR |
| severity / impact / legitimate vocabulary | `DigestEvent` | NORTHSTAR |
| defaults 0.7 / 0.5 | `DEFAULT_SEVERITY_THRESHOLD`, `DEFAULT_IMPACT_FLOOR` | NORTHSTAR |
