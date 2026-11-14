# Cost per delivery

> Slice: `B173 cost-per-delivery` ·
> Module: `components/northstar-agent-runtime/cost_per_delivery.py` ·
> Tests: `components/northstar-agent-runtime/tests/test_cost_per_delivery.py`

## 1. The rule

A slice's budget is quoted **per verified delivery**, not per attempt:

```
cost_per_verified_delivery = total settled cost / number of verified deliveries
projected_cost_per_delivery(per_attempt_cost, resolution_rate) = per_attempt_cost / resolution_rate
```

The price of an attempt is not the price of a delivery. A model that
resolves 38.8% of tasks costs $6.96 per *rollout*, which is $17.94 per
*resolved task*. Quoting the per-attempt price ranks "cheap but mostly
failing" first, which is the error this design removes: the ranking and the
admission ceiling are both computed on the delivery price.

## 2. Source, and what it is not

**Source.** Real-SWE benchmark, *secondary trade-press writeup*,
2026-09-14, frontier #16:
<https://www.constructionaibrief.com/posts/2026-09-14-real-swe-benchmark-ai-coding-agent-reliability-construction-diy-tools>

Three things about that source must be stated plainly:

1. It is **trade press, not the benchmark paper**. This design does not
   claim to have verified the benchmark itself.
2. The writeup **does not state the task count**. Nothing here depends on
   it, but no absolute cost or task-count claim may be derived from it.
3. The numbers are used here as **formula acceptance anchors only** — the
   arithmetic is checked against them, and no behavioural claim about the
   models is made.

### 2.1 Verbatim numbers from the writeup

Quoted as the source states them:

* Claude Code (Fable 5.1): **38.8% resolution, $6.96 per rollout,
  ~$17.94 per resolved task.**
* Codex CLI (GPT-6 Astra): **33.8%.**
* Gemini 3.8 Flash: **31.2%, $2.50 per rollout, ~$8.01 per resolved task.**
* Failure taxonomy: Grok 4.6's misses are dominated by **missed
  requirements (67.2%)**; Gemini 3.8 Flash by **integration errors (49.1%)**;
  GPT-5.6 Sol by **unverified assumptions (43.3%)**; Fable 5.1 and GPT-6
  Astra **spread evenly (no category above 37%)**.

### 2.2 The source's transfer, verbatim

> "Northstar's slice budgets should be quoted per-verified-delivery, not
> per-run, and the 'cheap model, more retries vs. pricey model, fewer
> retries' trade-off needs completion tracking, which Northstar's sealed
> receipts already enable."

The source states the *transfer* — that budgets should be quoted per
verified delivery, and that completion tracking is what makes the
cheap-vs-pricey trade-off decidable. It does not state any formula.

## 3. The formula, checked against the source's numbers

`cost_per_delivery = per_attempt_cost / resolution_rate`

| Model | per attempt | resolution | computed | source reports |
|---|---|---|---|---|
| Fable 5.1 | $6.96 | 38.8% | $17.9381… | ~$17.94 |
| Gemini 3.8 Flash | $2.50 | 31.2% | $8.0128… | ~$8.01 |

Both reported prices fall out of the formula to better than a cent. The
arithmetic is therefore consistent with the source's two fully-priced
models. **This is a check of the formula against the source's numbers, not
a re-measurement of the benchmark.**

At 38.8% resolution, a delivery costs 1 / 0.388 = 2.577× an attempt.

## 4. What Northstar already had (read, not modified)

The three existing budget modules were read before this slice; none of them
was changed.

* `components/northstar-agent-runtime/budget.py` — prices cost from
  provider usage against a token list-price table
  (`PRICE_TABLE`, `ModelPricing`, `CONSERVATIVE_FALLBACK`) and owns the
  three run ceilings `max_turns` / `max_tool_calls` / `max_budget_usd`
  (class `Budget`, `Budget.reserve`, `Budget.observe`). Settled cost comes
  from `compute_cost(usage, model)`; reservations from
  `estimate_request_cost(request, model)`.
* `components/northstar-agent-runtime/per_call_budget.py` — a per-call
  gate: `PER_CALL_CEILINGS` (model $0.10, tool $0.01, memory $0.001) plus
  the run ceiling, enforced through `PerCallBudget.check_and_charge`, with
  `BudgetExhausted` as the refusal.
* `components/northstar-agent-runtime/failure_budget_combo.py` — turns an
  exhausted budget into an incident: `FailureBudgetBundle`,
  `budget_bundle_from_exhaustion`, `failure_budget_audit_event`,
  `failure_budget_digest`.
* `components/northstar-agent-runtime/forward_seal_ledger.py` — the sealed
  receipt source. `ForwardSealLedger.append(...)` seals an 8-field event
  with triple `sha256:` fingerprints and returns a frozen `SealedEvent`
  carrying `record_hash`; `verify(...)` checks the chain. This is where
  "completion tracking, which Northstar's sealed receipts already enable"
  comes from.

**The gap.** A grep for "deliver" across `budget.py`,
`cost_optimization.py`, `per_call_budget.py` and `failure_budget_combo.py`
returns nothing: all four price *attempts*. None of them has a notion of a
verified delivery, and none of them can rank two models by what a delivery
actually costs.

## 5. Northstar extensions (not from the source)

Everything in this section is ours. The source states the numbers and the
transfer; it does not state any of the following.

### 5.1 A delivery verdict must come from a verification record

`book_attempt(attempt_id, settled_cost_usd, verdict, verdict_source)` books
one attempt and returns a frozen `AttemptRecord`. The verdict is one of
three states — `verified_delivered`, `failed`, `abandoned` — and it is
bookable **only** against a `verdict_source` that names a verification
record: `<kind>:<identifier>`, where the kind is a sealed receipt id
(`sealed-receipt:`, `receipt:`), a test run (`test-run:`), or a content pin
(`sha256:`).

A session's own claim is refused. `verdict_source=""` is refused (no
source at all), and an explicit self-report kind (`self-report:`,
`asserted:`, `claimed:`, …) is refused with its own message, so an
operator can tell "no evidence" from "evidence that was not a verification
record". This is the runtime's own rule — a delivery is what was
*verified*, not what was *asserted* — applied to cost accounting.

### 5.2 Fail-closed admission

`admit(per_attempt_cost, resolution_rate, max_cost_per_delivery)` is the
dispatch gate. The projected delivery price is admitted when it is **at or
below** the ceiling; above the ceiling the dispatch is **refused** — no
dispatch, no booking, no silent pass. A refusal is *data*
(`AdmissionVerdict`, with `admitted=False` and a reason), not an
exception.

A `resolution_rate` of 0 leaves the delivery price undefined (nothing is
ever delivered), so such a slice is refused rather than admitted at an
unknown price.

### 5.3 Undefined is not zero

With zero verified deliveries, `cost_per_verified_delivery()` returns
`None` — undefined. It never returns `0.0` (a false claim of "free
deliveries") and never returns infinity. A caller must handle the
undefined case explicitly; that is the point.

### 5.4 Failure-mode bookkeeping

Each failed attempt carries a `failure_mode` from the source's taxonomy:
`missed_requirement`, `integration_error`, `unverified_assumption`,
`other`. `failure_mode_counts(model)` and `failure_mode_shares(model)`
aggregate them per model.

**Bookkeeping only.** The module never attributes a failure mode to a
model's character and never ranks models by failure mode; it counts what
was observed. The source's own percentages (67.2% / 49.1% / 43.3% / even
spread) are properties of the benchmark's runs, not of this module.

### 5.5 The fail-closed input rules

Every public entry point refuses illegal input with
`CostPerDeliveryError` (a `ValueError`) rather than returning a
plausible-looking number:

* `settled_cost_usd` negative, non-finite, or not a number → refused;
* `resolution_rate` outside `(0, 1]` (0, negative, above 1, NaN, inf) →
  refused; exactly `1.0` is accepted;
* `verdict` outside the three states → refused;
* `verdict_source` missing, malformed, or self-reported → refused;
* a `failure_mode` on a non-failed attempt, or missing on a failed one →
  refused;
* a duplicate `attempt_id` → refused (it would double-count the cost).

## 6. The comparison

`compare(models)` ranks models by `cost_per_delivery`, cheapest first, with
the model name as a deterministic tie-break. It never ranks by
`per_attempt_cost`.

Because the ranking is on the delivery price, a cheap-per-attempt model
with a low resolution rate can and does sort *behind* a pricier model that
delivers more often. That is the point of the transfer: the "cheap model,
more retries vs. pricey model, fewer retries" trade-off is decided on
delivery price, which is what completion tracking makes possible.

## 7. Honest scope

* This module is a **bookkeeping and admission library**. It changes no
  execution loop, talks to no provider, and observes no live run. Every
  function is pure, deterministic and wall-clock-free.
* It does not replace `budget.py`, `per_call_budget.py` or
  `failure_budget_combo.py`; it prices what those modules' spend produced.
  A slice's spend ceiling is still enforced by them; this module decides
  whether a slice is worth dispatching at all, and what it will cost per
  delivery once it is.
* The `resolution_rate` used for a projection is an **input**, expected to
  come from Northstar's own bookkeeping (this module's ledger, or a
  measurement the operator supplies). This module does not measure
  resolution rates by itself.
* The source's numbers are **secondary trade-press figures**; this design
  does not claim the benchmark was verified.
