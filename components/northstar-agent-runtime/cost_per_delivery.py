"""Cost per delivery: quote a slice's budget per *verified delivery*.

What was missing
----------------
Northstar's budget modules all price an *attempt*:

* ``budget.py`` prices cost from provider usage (token list prices) and owns
  the three run ceilings ``max_turns`` / ``max_tool_calls`` /
  ``max_budget_usd``.
* ``per_call_budget.py`` gates a *single* call's estimate (per-call ceiling
  plus the run ceiling), fail-closed before the call happens.
* ``failure_budget_combo.py`` turns an exhausted budget into an incident
  bundle with a digest.

None of them has a notion of a *delivery*: a grep for "deliver" across
``budget.py``, ``cost_optimization.py``, ``per_call_budget.py`` and
``failure_budget_combo.py`` returns nothing.  That matters because the price
of an attempt is not the price of a delivery.  A model that resolves 38.8% of
tasks does not cost $6.96 per delivery; it costs $6.96 per *rollout*, which
at 38.8% resolution is $17.94 per resolved task.  Quoting the cheap-per-attempt
model as the cheap model is exactly the error this module removes: the
comparison is made on cost *per verified delivery*, so a cheap-but-failing
model can and does sort behind a pricey-but-reliable one.

The motivating source numbers (Real-SWE benchmark, secondary trade-press
writeup, 2026-09-14, read in full; **this is trade press, not the benchmark
paper**, and the writeup does not state the task count):

* Claude Code (Fable 5.1): 38.8% resolution, $6.96 per rollout,
  ~$17.94 per resolved task.
* Codex CLI (GPT-6 Astra): 33.8%.
* Gemini 3.8 Flash: 31.2%, $2.50 per rollout, ~$8.01 per resolved task.
* Failure taxonomy: Grok 4.6's misses are dominated by missed requirements
  (67.2%); Gemini 3.8 Flash by integration errors (49.1%); GPT-5.6 Sol by
  unverified assumptions (43.3%); Fable 5.1 and GPT-6 Astra spread evenly
  (no category above 37%).

The core formula ``cost_per_delivery = per_attempt_cost / resolution_rate``
is the arithmetic that reproduces both reported per-resolved-task prices
(6.96 / 0.388 = 17.938 ~ $17.94; 2.50 / 0.312 = 8.013 ~ $8.01).  The source
states the numbers; the formula, the ledger, the admission gate and the
failure taxonomy bookkeeping are **Northstar extensions** (see
``docs/design/cost-per-delivery.md``).

Northstar extensions (not from the source):

* **The delivery verdict comes from a verification record.**  A verdict is
  bookable only with a ``verdict_source`` that names a sealed receipt or a
  test run.  A session's own claim ("I finished the task") is refused: the
  ledger books what was *verified*, not what was *asserted*.
* **The admission gate is fail-closed.**  A projected cost per delivery
  above the ceiling refuses the dispatch -- no dispatch, no booking, no
  silent pass.
* **Undefined is not zero.**  With zero verified deliveries there is no price
  per delivery.  The query returns ``None`` (undefined); it never returns 0
  and never returns infinity.
* **Failure-mode bookkeeping.**  Each failed attempt is tagged with a
  failure mode and the modes are aggregated per model.  The aggregation is
  *bookkeeping only* -- this module never attributes a failure mode to a
  model's character.

Scope: this module is a *bookkeeping and admission* library.  It does not
change any execution loop, does not talk to a provider, and does not observe
a live run.  Every function is pure, deterministic and wall-clock-free.

Fail-closed: every public entry point validates its inputs and raises
:class:`CostPerDeliveryError` (a ``ValueError``) on an illegal argument
rather than returning a plausible-looking number.  An admission *failure* is
not an error -- it is data (:class:`AdmissionVerdict`).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

__all__ = [
    "CostPerDeliveryError",
    "AttemptRecord",
    "AdmissionVerdict",
    "ModelCostQuote",
    "VERDICT_VERIFIED_DELIVERED",
    "VERDICT_FAILED",
    "VERDICT_ABANDONED",
    "VERDICTS",
    "FAILURE_MODE_MISSED_REQUIREMENT",
    "FAILURE_MODE_INTEGRATION_ERROR",
    "FAILURE_MODE_UNVERIFIED_ASSUMPTION",
    "FAILURE_MODE_OTHER",
    "FAILURE_MODES",
    "VERDICT_SOURCE_KINDS",
    "CostPerDeliveryLedger",
    "projected_cost_per_delivery",
    "admit",
    "compare",
]


class CostPerDeliveryError(ValueError):
    """Fail-closed: an illegal argument is refused, never defaulted."""


#: The three delivery verdicts an attempt may carry.
VERDICT_VERIFIED_DELIVERED = "verified_delivered"
VERDICT_FAILED = "failed"
VERDICT_ABANDONED = "abandoned"

#: All bookable verdicts.
VERDICTS: tuple[str, ...] = (
    VERDICT_VERIFIED_DELIVERED,
    VERDICT_FAILED,
    VERDICT_ABANDONED,
)

#: Failure modes, named after the Real-SWE miss taxonomy the source reports.
FAILURE_MODE_MISSED_REQUIREMENT = "missed_requirement"
FAILURE_MODE_INTEGRATION_ERROR = "integration_error"
FAILURE_MODE_UNVERIFIED_ASSUMPTION = "unverified_assumption"
FAILURE_MODE_OTHER = "other"

#: All bookable failure modes.
FAILURE_MODES: tuple[str, ...] = (
    FAILURE_MODE_MISSED_REQUIREMENT,
    FAILURE_MODE_INTEGRATION_ERROR,
    FAILURE_MODE_UNVERIFIED_ASSUMPTION,
    FAILURE_MODE_OTHER,
)

#: The verification-record kinds a ``verdict_source`` may name.  A source is
#: ``<kind>:<identifier>``; the identifier is the receipt id or test-run id.
VERDICT_SOURCE_KINDS: tuple[str, ...] = (
    "sealed-receipt",
    "receipt",
    "test-run",
    "sha256",
)

#: Source kinds that are a session's *self-report* rather than a
#: verification record.  They are refused explicitly, with their own
#: message, so an operator can tell "no evidence" from "evidence was not a
#: verification record".
SELF_REPORTED_SOURCE_KINDS: tuple[str, ...] = (
    "self-report",
    "self_report",
    "self-reported",
    "asserted",
    "claimed",
    "narrative",
    "agent",
)


@dataclass(frozen=True)
class AttemptRecord:
    """One booked attempt (immutable).

    ``verdict_source`` names the verification record that produced
    ``verdict`` -- a sealed receipt id or a test-run id.  ``failure_mode`` is
    set only for :data:`VERDICT_FAILED` attempts.
    """

    attempt_id: str
    settled_cost_usd: float
    verdict: str
    verdict_source: str
    model: str = ""
    failure_mode: str = ""


@dataclass(frozen=True)
class AdmissionVerdict:
    """The admission decision, as data.

    ``admitted`` is the verdict.  A refusal is *not* an exception: it carries
    the numbers that justify it, so a caller can report why the dispatch was
    refused.
    """

    admitted: bool
    projected_cost_per_delivery: float | None
    max_cost_per_delivery: float
    reason: str

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.admitted


@dataclass(frozen=True)
class ModelCostQuote:
    """One model's cost, quoted per verified delivery."""

    model: str
    per_attempt_cost: float
    resolution_rate: float
    cost_per_delivery: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "per_attempt_cost": self.per_attempt_cost,
            "resolution_rate": self.resolution_rate,
            "cost_per_delivery": self.cost_per_delivery,
        }


def _check_text(value: Any, name: str) -> str:
    """Validate a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        raise CostPerDeliveryError(f"{name} must be a non-empty str, got {value!r}")
    return value


def _check_usd(value: Any, name: str) -> float:
    """Validate a settled cost: a finite, non-negative number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CostPerDeliveryError(f"{name} must be a real number, got {value!r}")
    amount = float(value)
    if not math.isfinite(amount):
        raise CostPerDeliveryError(f"{name} must be finite, got {value!r}")
    if amount < 0.0:
        raise CostPerDeliveryError(f"{name} must be >= 0, got {value!r}")
    return amount


def _check_rate(value: Any, name: str) -> float:
    """Validate a resolution rate: a real number strictly inside ``(0, 1]``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CostPerDeliveryError(f"{name} must be a real number, got {value!r}")
    rate = float(value)
    if not math.isfinite(rate):
        raise CostPerDeliveryError(f"{name} must be finite, got {value!r}")
    if not (0.0 < rate <= 1.0):
        raise CostPerDeliveryError(f"{name} must be in (0, 1], got {value!r}")
    return rate


def _check_verdict_source(value: Any, name: str = "verdict_source") -> str:
    """Validate a verification-record reference.

    A verdict source must name a *verification record* -- a sealed receipt
    id, a test-run id, or a content pin -- as ``<kind>:<identifier>``.  A
    missing source is refused (fail-closed): a self-reported delivery is not
    a verified delivery.
    """
    text = _check_text(value, name)
    kind, sep, identifier = text.partition(":")
    if not sep:
        raise CostPerDeliveryError(
            f"{name} must be '<kind>:<identifier>' naming a verification "
            f"record (a sealed receipt id or a test-run id), got {value!r}"
        )
    kind = kind.strip().lower()
    identifier = identifier.strip()
    if kind in SELF_REPORTED_SOURCE_KINDS:
        raise CostPerDeliveryError(
            f"{name} names a self-report ({kind!r}), not a verification "
            f"record; a delivery verdict must come from a sealed receipt or "
            f"a test run"
        )
    if kind not in VERDICT_SOURCE_KINDS:
        raise CostPerDeliveryError(
            f"{name} kind {kind!r} is not a verification-record kind "
            f"{list(VERDICT_SOURCE_KINDS)}"
        )
    if not identifier:
        raise CostPerDeliveryError(f"{name} must carry an identifier after ':'")
    return text


def projected_cost_per_delivery(per_attempt_cost: float, resolution_rate: float) -> float:
    """The cost of one *verified delivery*, projected from an attempt price.

    ``projected = per_attempt_cost / resolution_rate``.

    ``resolution_rate`` must be in ``(0, 1]``: a rate of 0 (nothing ever
    resolves) has no finite projection and a rate above 1 is not a rate.
    Both are refused (fail-closed).
    """
    cost = _check_usd(per_attempt_cost, "per_attempt_cost")
    rate = _check_rate(resolution_rate, "resolution_rate")
    return cost / rate


def admit(
    per_attempt_cost: float,
    resolution_rate: float,
    max_cost_per_delivery: float,
) -> AdmissionVerdict:
    """Fail-closed admission: may this slice be dispatched at this price?

    The projected cost per delivery is admitted when it is at or below
    ``max_cost_per_delivery``.  When it is above, the dispatch is refused --
    no dispatch, no booking, no silent pass.  A refusal is data, not an
    exception.

    A ``resolution_rate`` of 0 has no projection at all (the price of a
    delivery is undefined when nothing is ever delivered), so such a slice
    is refused.
    """
    ceiling = _check_usd(max_cost_per_delivery, "max_cost_per_delivery")
    if isinstance(resolution_rate, bool) or not isinstance(resolution_rate, (int, float)):
        raise CostPerDeliveryError(
            f"resolution_rate must be a real number, got {resolution_rate!r}"
        )
    rate = float(resolution_rate)
    if not math.isfinite(rate):
        raise CostPerDeliveryError(f"resolution_rate must be finite, got {resolution_rate!r}")
    if rate <= 0.0:
        return AdmissionVerdict(
            admitted=False,
            projected_cost_per_delivery=None,
            max_cost_per_delivery=ceiling,
            reason=(
                f"resolution_rate {rate!r} leaves the cost per delivery "
                f"undefined (nothing is ever delivered); refusing to dispatch"
            ),
        )
    projected = projected_cost_per_delivery(per_attempt_cost, rate)
    if projected <= ceiling:
        return AdmissionVerdict(
            admitted=True,
            projected_cost_per_delivery=projected,
            max_cost_per_delivery=ceiling,
            reason=(
                f"projected ${projected:.6f} per delivery is at or below the "
                f"ceiling of ${ceiling:.6f}"
            ),
        )
    return AdmissionVerdict(
        admitted=False,
        projected_cost_per_delivery=projected,
        max_cost_per_delivery=ceiling,
        reason=(
            f"projected ${projected:.6f} per delivery exceeds the ceiling of "
            f"${ceiling:.6f}; refusing to dispatch"
        ),
    )


def compare(models: Iterable[Mapping[str, Any]]) -> list[ModelCostQuote]:
    """Rank models by *cost per verified delivery*, cheapest first.

    Each input mapping carries ``model`` (a name), ``per_attempt_cost`` and
    ``resolution_rate``.  The ranking is on cost per delivery, never on the
    per-attempt price: a cheap-per-attempt model with a low resolution rate
    can sort *behind* a pricier model that delivers more often.
    """
    quotes: list[ModelCostQuote] = []
    for entry in models:
        if not isinstance(entry, Mapping):
            raise CostPerDeliveryError(
                f"each model must be a mapping with model/per_attempt_cost/"
                f"resolution_rate, got {entry!r}"
            )
        if "model" not in entry:
            raise CostPerDeliveryError("each model mapping must carry a 'model' name")
        name = _check_text(entry["model"], "model")
        if "per_attempt_cost" not in entry or "resolution_rate" not in entry:
            raise CostPerDeliveryError(
                f"model {name!r} must carry 'per_attempt_cost' and 'resolution_rate'"
            )
        cost = _check_usd(entry["per_attempt_cost"], "per_attempt_cost")
        rate = _check_rate(entry["resolution_rate"], "resolution_rate")
        quotes.append(
            ModelCostQuote(
                model=name,
                per_attempt_cost=cost,
                resolution_rate=rate,
                cost_per_delivery=cost / rate,
            )
        )
    # Sort by cost per delivery; ties broken by name so the order is total
    # and deterministic.
    quotes.sort(key=lambda q: (q.cost_per_delivery, q.model))
    return quotes


class CostPerDeliveryLedger:
    """Book attempts, quote cost per verified delivery, admit dispatches.

    The ledger is the accounting side of the module: every attempt is booked
    with its settled cost, its delivery verdict and the *verification
    record* that produced the verdict.  The quote side answers "what does one
    verified delivery cost?" -- undefined (not zero, not infinite) while no
    delivery has been verified.

    Example::

        ledger = CostPerDeliveryLedger()
        ledger.book_attempt("a1", 6.96, "verified_delivered",
                            "sealed-receipt:r-1", model="fable-5.1")
        ledger.book_attempt("a2", 6.96, "failed",
                            "test-run:t-2", model="fable-5.1",
                            failure_mode="missed_requirement")
        ledger.cost_per_verified_delivery()  # 13.92
    """

    def __init__(self) -> None:
        self._records: list[AttemptRecord] = []
        self._by_id: dict[str, AttemptRecord] = {}

    # -- booking ---------------------------------------------------------

    def book_attempt(
        self,
        attempt_id: str,
        settled_cost_usd: float,
        verdict: str,
        verdict_source: str,
        *,
        model: str = "",
        failure_mode: str = "",
    ) -> AttemptRecord:
        """Book one attempt and return the frozen record.

        Fail-closed, every one of these refusals:

        * a negative or non-finite ``settled_cost_usd``;
        * a ``verdict`` outside the three bookable verdicts;
        * a missing or non-verification ``verdict_source`` (a session's own
          claim is refused);
        * a ``failure_mode`` on a non-failed attempt, or a missing
          ``failure_mode`` on a failed attempt;
        * a duplicate ``attempt_id``.
        """
        aid = _check_text(attempt_id, "attempt_id")
        if aid in self._by_id:
            raise CostPerDeliveryError(f"attempt_id {aid!r} is already booked")
        cost = _check_usd(settled_cost_usd, "settled_cost_usd")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise CostPerDeliveryError(
                f"verdict must be one of {list(VERDICTS)}, got {verdict!r}"
            )
        source = _check_verdict_source(verdict_source)
        model_name = _check_text(model, "model") if model else ""
        mode = ""
        if verdict == VERDICT_FAILED:
            if not isinstance(failure_mode, str) or failure_mode not in FAILURE_MODES:
                raise CostPerDeliveryError(
                    f"a failed attempt must carry a failure_mode from "
                    f"{list(FAILURE_MODES)}, got {failure_mode!r}"
                )
            mode = failure_mode
        elif failure_mode:
            raise CostPerDeliveryError(
                f"failure_mode is only bookable on a failed attempt, "
                f"got verdict {verdict!r}"
            )
        record = AttemptRecord(
            attempt_id=aid,
            settled_cost_usd=cost,
            verdict=verdict,
            verdict_source=source,
            model=model_name,
            failure_mode=mode,
        )
        self._records.append(record)
        self._by_id[aid] = record
        return record

    # -- reading ---------------------------------------------------------

    @property
    def records(self) -> tuple[AttemptRecord, ...]:
        """Every booked attempt, in booking order."""
        return tuple(self._records)

    def attempts_for(self, model: str) -> tuple[AttemptRecord, ...]:
        """Every booked attempt of one model, in booking order."""
        name = _check_text(model, "model")
        return tuple(r for r in self._records if r.model == name)

    def total_settled_cost_usd(self, model: str | None = None) -> float:
        """Total settled cost, optionally for one model only."""
        records = self._records if model is None else self.attempts_for(model)
        return round(sum(r.settled_cost_usd for r in records), 10)

    def count(self, verdict: str, model: str | None = None) -> int:
        """How many attempts carry ``verdict`` (optionally for one model)."""
        if verdict not in VERDICTS:
            raise CostPerDeliveryError(
                f"verdict must be one of {list(VERDICTS)}, got {verdict!r}"
            )
        records = self._records if model is None else self.attempts_for(model)
        return sum(1 for r in records if r.verdict == verdict)

    def verified_delivery_count(self, model: str | None = None) -> int:
        """How many attempts were verified deliveries."""
        return self.count(VERDICT_VERIFIED_DELIVERED, model)

    def cost_per_verified_delivery(self, model: str | None = None) -> float | None:
        """The price of one verified delivery, or ``None`` when undefined.

        ``total settled cost / number of verified deliveries``.  When no
        delivery has been verified the price per delivery **does not exist**:
        the answer is ``None`` (undefined) -- never ``0.0`` and never
        infinity.  A caller must handle the undefined case explicitly rather
        than be handed a number that looks like a price.
        """
        delivered = self.verified_delivery_count(model)
        if delivered == 0:
            return None
        return self.total_settled_cost_usd(model) / delivered

    def observed_resolution_rate(self, model: str | None = None) -> float | None:
        """The observed share of verified deliveries, or ``None`` if no attempts."""
        records = self._records if model is None else self.attempts_for(model)
        if not records:
            return None
        return self.verified_delivery_count(model) / len(records)

    def failure_mode_counts(self, model: str | None = None) -> dict[str, int]:
        """How many failed attempts carry each failure mode.

        Bookkeeping only: the counts describe what was observed, they do
        not attribute a failure mode to a model's character.
        """
        records = self._records if model is None else self.attempts_for(model)
        counts = {mode: 0 for mode in FAILURE_MODES}
        for record in records:
            if record.verdict == VERDICT_FAILED:
                counts[record.failure_mode] += 1
        return counts

    def failure_mode_shares(self, model: str | None = None) -> dict[str, float]:
        """The share of failed attempts per failure mode (0.0 when none).

        Shares sum to 1.0 when at least one attempt failed, and are all 0.0
        when none did (there is no distribution over an empty set).
        """
        counts = self.failure_mode_counts(model)
        total = sum(counts.values())
        if total == 0:
            return {mode: 0.0 for mode in FAILURE_MODES}
        return {mode: count / total for mode, count in counts.items()}

    def as_dict(self) -> dict[str, Any]:
        """A JSON-friendly view of the ledger."""
        return {
            "attempts": [
                {
                    "attempt_id": r.attempt_id,
                    "settled_cost_usd": r.settled_cost_usd,
                    "verdict": r.verdict,
                    "verdict_source": r.verdict_source,
                    "model": r.model,
                    "failure_mode": r.failure_mode,
                }
                for r in self._records
            ],
            "total_settled_cost_usd": self.total_settled_cost_usd(),
            "verified_deliveries": self.verified_delivery_count(),
            "cost_per_verified_delivery": self.cost_per_verified_delivery(),
        }
