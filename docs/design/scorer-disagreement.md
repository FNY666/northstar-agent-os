# Scorer disagreement: a contested verdict is a verdict

This document describes one slice of Northstar: **multi-scorer disagreement
as a first-class verdict**. When several scorers judge the same case and
they disagree, the case is not averaged into a number and forgotten — the
disagreement itself becomes the verdict (`contested`), and the case is
booked for human review.

The module: `components/northstar-agent-runtime/scorer_disagreement.py`.
The tests: `components/northstar-agent-runtime/tests/test_scorer_disagreement.py`.

---

## 1. The source, and what it does not say

The source is inspect_ai's "Multiple Scorers" page. The excerpt carried by
the slice brief is the source (the upstream page was not crawled for this
slice; the brief's excerpt is what the design is built against). Verbatim
as briefed:

* one Task may carry several scorers, each keeping its own score; a single
  scorer may return a multi-valued score;
* `multi_scorer(scorers, reducer)` aggregates with a reducer — `mode` /
  `majority` / `collect`; `collect` keeps each scorer's original value so
  that inter-rater agreement (e.g. `krippendorff_alpha`) can be computed;
* `cascade()` runs cheapest-first and stops at the first settled scorer;
* the key point: inspect_ai itself only aggregates or preserves scores and
  **never turns "the scorers disagree" into a verdict** — disagreement
  detection is the gap.

**What the source does not contain, and what this slice therefore owns:**

| Thing | Status |
|---|---|
| reducer names `mode` / `majority` / `collect` | **verbatim from the source** |
| `krippendorff_alpha` as the agreement example | **verbatim from the source** |
| `cascade()`, cheapest-first, first-settled-stops | **verbatim from the source** |
| a disagreement metric | **Northstar extension** |
| a disagreement threshold and its value | **Northstar extension** |
| "contested" as a verdict | **Northstar extension** |
| a human-review queue | **Northstar extension** |
| majority-masking detection | **Northstar extension** |
| the exact semantics of `mode` vs `majority` on a tie | **Northstar extension** (see §4.3) |

---

## 2. What Northstar has today (read from the code, not assumed)

### 2.1 `evaluation_harness.py` — one score per case, per run

`components/northstar-agent-runtime/evaluation_harness.py` books exactly
one host-declared scoring per case per run. `EvaluationHarness.score`
(line 442) takes `results` as a list of `(case_id, passed, metric)`
triples; every suite case must be scored **exactly once** — an extra
result for a case is refused (`BadScoreError`, line 470), a missing one is
refused (`MissingCaseError`, line 481), and an unknown one is refused
(`UnknownCaseError`, line 468). `CaseResult` (line 242) has exactly three
data fields: `case_id`, `passed` (a bool), `metric` (a finite float in
[0, 1]).

The word `scorer` occurs **zero times** in that file. There is no
multi-scorer shape, no per-scorer identity, and no disagreement concept
anywhere in it.

**Would today's harness silently average a judge disagreement away?**
Yes — and more sharply than "silently". A second judge cannot be expressed
at all: the second `CaseResult` for the same case is *refused*. A host
that wants a second opinion has to either drop one judge's verdict
(losing the disagreement before it can be seen) or book the second judge
as a separate run/suite (so the two verdicts never meet). There is no
path in which both verdicts coexist and are compared.

### 2.2 `ai_ensemble.py` — a different object entirely

`ai_ensemble.py` has a "disagree"-shaped ledger, but it is **not** a
scorer ledger, and the two must not be confused:

* its object is an **ensemble member** (a system id with declared
  ensemble compositions), not an eval scorer;
* its `agreement` field is a **declared verdict** booked as data
  (`unanimous` / `majority` / `plurality` / `split` / `not-assessed`,
  lines 91–97) — "the host declared it", never "the members really
  disagreed";
* its derived `posture` (`unassembled` → `divided` → `contested` →
  `plural` → `consensus`, lines 106–112) is derived from the *declared
  agreement values* of the ensembles, not from comparing per-case scores;
* it never looks at per-case scores at all.

So `ai_ensemble.py`'s `contested` and this module's `contested` are
different facts about different objects. `ai_ensemble` says "the host
declared these members' agreement to be inconsistent"; this module says
"these scorers' verdicts for this case actually disagree, by a computed
measure". The word `contested` is reused, the meaning is not.

### 2.3 The gap this slice closes

Between them, the two modules leave one hole: **a case that two scorers
judged differently has no representation at all**. There is no place to
put the second verdict, no place to compare the two, no way to say
"the majority said pass but one scorer said fail and we should look at
it". A majority vote, where one exists, is not just lossy — it is
*silently* lossy, because the minority judgement disappears with no
trace and no flag.

---

## 3. The data model

### 3.1 `ScorerVerdict` (frozen dataclass)

    case_id, scorer_id, verdict ("pass" | "fail"), score (float | None), digest

One record = one scorer's declared judgement of one case. Two scorers on
one case are **two records**; registration never overwrites, and the same
scorer registering twice for the same case is refused
(`DuplicateScorerError`) — a silent re-registration would replace a judged
value with no trace.

`verdict` is a Northstar vocabulary: the source says a scorer returns a
*score*, not a pass/fail. Northstar's binary verdicts are what makes
"the minority disagreed with the majority" expressible at all.

`score` is optional and independent of `verdict`: a scorer may declare
`("fail", 0.8)`. The score feeds the auxiliary spread metric.

### 3.2 `Disagreement` (frozen dataclass) — the derived view

    case_id, scorer_count, pass_count, fail_count,
    minority_share: Fraction,          # PRIMARY metric
    score_spread: float | None,        # AUXILIARY metric
    threshold: Fraction,
    exceeded: bool,                    # primary metric vs threshold
    aggregate_verdict: str | None,     # what the reducer said
    aggregate_reducer: str,
    minority_verdict: str | None,      # what the minority said
    masked: bool,                      # aggregate != minority, over threshold
    agreement_alpha: Fraction | None,
    verdicts: tuple[ScorerVerdict, ...],   # the raw values, always kept
    digest

The view carries the raw verdicts inside it, so a derived view is never a
lossy summary: `collect` semantics hold even in the aggregate record.

---

## 4. The rules, pinned

### 4.1 The primary metric: minority share

    minority_share = min(pass_count, fail_count) / (pass_count + fail_count)

An exact `Fraction`, never a float. Unanimity → 0; 3-1 → 1/4; 2-1 → 1/3;
2-2 → 1/2.

### 4.2 The auxiliary metric: score spread

    score_spread = max(scores) - min(scores)

`None` when fewer than two scorers declared a score. It is **never**
mixed into the primary metric — the two answer different questions
("did they split?" vs "how far apart were the numbers?") and a case can
be wide on one and flat on the other. Both are reported side by side, and
there is a test for exactly that divergence in each direction.

### 4.3 The threshold

    DISAGREEMENT_THRESHOLD = Fraction(1, 4)

**This number is a Northstar choice. It is not a number from the source.**
The source names no threshold. The chosen value means: a case is
contested only when *strictly more than* a quarter of the scorers sit on
the minority side. Consequences with binary verdicts:

| split | minority share | contested? | note |
|---|---|---|---|
| 4-0 | 0 | no | unanimous |
| 3-1 | 1/4 | **no** | the documented boundary: equal is *not* over |
| 2-1 | 1/3 | **yes** | aggregate is also recorded as majority-masked |
| 2-2 | 1/2 | **yes** | no majority exists; aggregate is `None` |
| 1-1 | 1/2 | **yes** | no majority exists |
| 1 scorer | 0 | no | a judge cannot disagree with itself |

The threshold is configurable per instance (`ScorerDisagreement(threshold=...)`);
a negative or non-numeric threshold is refused (`BadThresholdError`).

### 4.4 The reducers (names verbatim, semantics ours)

The reducer **names** `mode` / `majority` / `collect` are verbatim from the
source. What each one *means* here is a Northstar decision, chosen so
that the two binary reducers differ exactly where it matters — the tie:

* **majority** (the default): a *strict* majority (more than half) is
  required. On a tie there is no aggregate verdict at all — `None`, and
  the case is contested. A tie is never silently broken.
* **mode**: the most frequent verdict; on a tie the pinned order
  (`pass` before `fail`) decides, and the tie is *flagged* in the
  returned tuple rather than hidden.
* **collect**: no single verdict — the raw values are kept and returned
  by `collect(case_id)`. This is the source's `collect` semantics: keep
  the originals so an agreement coefficient can be computed from them.

The default reducer is `majority`. An unknown reducer is refused
(`BadReducerError`).

### 4.5 The verdict rule

* disagreement **over** the threshold → the case verdict is `contested`
  and the case is booked into the review queue;
* disagreement **within** the threshold → the case verdict is the
  reducer's aggregate verdict, and the aggregate value is recorded.

The review queue is **bookkeeping**: it is an in-memory list of
`ReviewItem` records. Nothing is notified, no reviewer is contacted, no
network or IPC surface exists in the module at all. A review item is a
record that a human *could* pick up.

### 4.6 Majority masking

A case is booked as **masked** when all three hold:

1. the disagreement is over the threshold,
2. an aggregate verdict exists, and
3. the aggregate verdict is the **opposite** of the minority verdict.

"Masked" means: a majority vote would have quietly carried this case, and
the minority judgement — the one that might have been right — would have
disappeared without a trace. Masked cases are listed separately
(`masked_cases()`) and the review item carries the reason
(`majority-masked` vs `disagreement`).

On an exact tie there is no minority, so nothing is masked — there is no
majority to hide anything either.

### 4.7 The agreement coefficient

`agreement_alpha` is a nominal Krippendorff-style coefficient over one
case's scorer verdicts: `Do` is the observed disagreeing-pair share, `De`
the expected disagreement implied by the case's own marginal
distribution, `alpha = 1 - Do/De`. Unanimity → 1; a case with a single
scorer → `None` (nothing to disagree about).

Honest scope: this is a **per-case** coefficient, not a corpus-level
inter-rater reliability; the source's `krippendorff_alpha` is mentioned
only as the example of what `collect` makes possible, and the source's
own metric is not reimplemented here. What matters for this slice is that
the raw values survive so the coefficient **can be recomputed** — and a
test recomputes it from `collect()` and checks it against the value
recorded at adjudication time.

### 4.8 `cascade` — an optional extension, never the default

`run_cascade` implements the source's `cascade()` shape: cheapest-first
order, stop at the first settled scorer. Each scorer entry is
`(scorer_id, cost, fn)`; `fn()` returns `None` (not settled) or
`(verdict, score)`.

**It is an extension, not the default behaviour, and it is not free.**
A cascade that stops early *cannot see a disagreement*: the scorers that
were not run have no verdict, so the disagreement they would have created
does not exist as far as the ledger is concerned. The default path is
that every scorer runs to completion and the disagreement is judged
afterwards — that is the only way the gap the source leaves open can
actually be closed. The cascade exists for hosts who knowingly trade
detection for cost.

---

## 5. The API

    led = ScorerDisagreement(threshold=Fraction(1, 4), reducer="majority")

    led.register(case_id, scorer_id, verdict, score=None) -> ScorerVerdict
    led.disagreement(case_id) -> Disagreement          # pure read
    led.adjudicate(case_id) -> Disagreement            # books review/masked
    led.collect(case_id) -> tuple[ScorerVerdict, ...]  # collect semantics
    led.review_queue() -> tuple[ReviewItem, ...]
    led.masked_cases() -> tuple[str, ...]
    led.case_ids() -> tuple[str, ...]
    led.stats() -> dict
    led.run_cascade(case_id, scorers) -> CascadeResult # optional extension

Module-level pure functions (no state, no I/O):

    minority_share(pass_count, fail_count) -> Fraction
    score_spread(scores) -> float | None
    agreement_alpha(verdicts) -> Fraction | None
    aggregate_verdict(verdicts, reducer) -> (str | None, tie_resolved: bool)

Error taxonomy: `ScorerDisagreementError` (base), `BadCaseIdError`,
`BadScorerIdError`, `BadVerdictError`, `BadScoreError`,
`DuplicateScorerError`, `UnknownCaseError`, `BadThresholdError`,
`BadReducerError`, `AuditKindError`.

---

## 6. Honest scope

* This module books **declared** scorer verdicts and derives arithmetic
  from them. A booked `contested` case is a statement that the declared
  verdicts disagree — it is **not** proof that any judge was right, and
  not proof that the disagreement is meaningful: a flaky judge and a
  broken judge look identical here.
* The threshold is a policy number, not a measured one. 1/4 was chosen
  for this slice; it has not been calibrated against real judge data.
* The review queue sends nothing. There is no notification path, no
  reviewer, no escalation timer.
* `agreement_alpha` is a per-case nominal coefficient, not a corpus
  inter-rater reliability.
* The cascade trades detection for cost and should not be used where the
  disagreement is the point.

---

## 7. Open items

* **Threshold calibration.** 1/4 is a starting point. Real multi-scorer
  runs should be measured (what share of cases does a 3-1 split produce
  in practice?) before the number is treated as anything but a default.
* **A real reduction of `krippendorff_alpha`.** The source names it as
  the thing `collect` makes possible; this slice recomputes a per-case
  nominal coefficient instead. A corpus-level implementation (cases as
  units, scorers as observers) is the honest version and is not written.
* **Wiring into `evaluation_harness.py`.** This slice adds the module and
  its tests only; it does not change the harness. The harness still books
  exactly one score per case per run, so a real deployment would need the
  harness to gain a multi-scorer booking path (a separate slice, and one
  that touches a module this slice is not allowed to change).
* **Review-queue durability.** The queue is in-memory; a restart loses
  it. Pairing with a durable audit writer is the obvious next step.
* **Multi-valued scorer output.** The source notes a single scorer may
  return a multi-valued score; Northstar's `ScorerVerdict` carries one
  verdict and one optional score. A multi-valued verdict vocabulary is
  not modelled.
* **`krippendorff_alpha` naming.** The module implements a per-case
  nominal coefficient under the name `agreement_alpha` and does *not*
  claim it is the source's metric.
