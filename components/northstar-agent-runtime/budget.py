"""Token budgets priced from real per-million rates, with prompt-cache accounting.

Three independent ceilings exist in the runtime: ``max_turns``,
``max_tool_calls``, and ``max_budget_usd``. Each one owns its own
``ResultMessage`` subtype so an operator can tell "the model kept talking" apart
from "the model kept spending". Settled cost comes from provider-reported usage multiplied by the table below;
request reservations use a conservative preflight estimate before provider calls.
"""
from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# Prompt-cache multipliers relative to the model's input price. Reads are an
# order of magnitude cheaper; a cache write costs a 25% premium (5-minute TTL).
CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25

# USD per million tokens. Values are the published list prices for the model
# families the runtime is pointed at; nothing here is a discount or a guess.
PRICE_TABLE: dict[str, "ModelPricing"] = {}


@dataclass(frozen=True)
class ModelPricing:
    """Per-million-token list prices for one model."""

    input_per_mtok: float
    output_per_mtok: float
    source: str = "table"

    @property
    def cache_read_per_mtok(self) -> float:
        return self.input_per_mtok * CACHE_READ_MULTIPLIER

    @property
    def cache_write_per_mtok(self) -> float:
        return self.input_per_mtok * CACHE_WRITE_MULTIPLIER

    def as_dict(self) -> dict[str, float | str]:
        return {
            "input_per_mtok": self.input_per_mtok,
            "output_per_mtok": self.output_per_mtok,
            "cache_read_per_mtok": self.cache_read_per_mtok,
            "cache_write_per_mtok": self.cache_write_per_mtok,
            "source": self.source,
        }


def _register(models: Iterable[str], input_per_mtok: float, output_per_mtok: float) -> None:
    pricing = ModelPricing(input_per_mtok=input_per_mtok, output_per_mtok=output_per_mtok)
    for model in models:
        PRICE_TABLE[model] = pricing


# Claude families (list prices, USD per million tokens).
_register(
    ("claude-opus-4-1", "claude-opus-4-1-20250805", "claude-3-7-sonnet-latest"),
    15.00,
    75.00,
)
_register(
    (
        "claude-sonnet-4-5",
        "claude-sonnet-4-5-20250929",
        "claude-sonnet-4-0",
        "claude-3-5-sonnet-latest",
        "claude-3-5-sonnet-20241022",
    ),
    3.00,
    15.00,
)
_register(
    ("claude-haiku-4-5", "claude-haiku-4-5-20251001", "claude-3-5-haiku-latest"),
    0.80,
    4.00,
)
# Non-Anthropic aliases that hosts do route through this runtime.
_register(("gpt-5", "gpt-5-2025-08-07"), 1.25, 10.00)
_register(("gpt-5-mini", "gpt-5-nano"), 0.25, 2.00)

# Unknown models fall back to the most expensive *known* tier. Over-estimating is
# the conservative direction: a budget ceiling stops spending earlier, it never
# lets a run keep going that the operator meant to stop.
CONSERVATIVE_FALLBACK = ModelPricing(input_per_mtok=15.00, output_per_mtok=75.00, source="conservative_fallback")


def price_for(model: str) -> tuple[ModelPricing, bool]:
    """Return ``(pricing, estimated)`` for a model id.

    Lookup is exact, then by the longest matching family prefix, so a dated model
    id such as ``claude-sonnet-4-5-20250929`` inherits its family price while an
    unrecognised id is priced conservatively and flagged.
    """
    key = (model or "").strip()
    if key in PRICE_TABLE:
        return PRICE_TABLE[key], False
    best_name = ""
    for name in PRICE_TABLE:
        if key.startswith(name) and len(name) > len(best_name):
            best_name = name
    if best_name:
        return PRICE_TABLE[best_name], False
    return CONSERVATIVE_FALLBACK, True


@dataclass(frozen=True)
class CostBreakdown:
    """Itemised cost for one usage report. Components sum to ``total_usd``."""

    model: str = ""
    input_usd: float = 0.0
    output_usd: float = 0.0
    cache_read_usd: float = 0.0
    cache_write_usd: float = 0.0
    pricing_estimated: bool = False
    pricing_source: str = ""
    tokens: int = 0

    @property
    def total_usd(self) -> float:
        return round(
            self.input_usd + self.output_usd + self.cache_read_usd + self.cache_write_usd, 10
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "input_usd": self.input_usd,
            "output_usd": self.output_usd,
            "cache_read_usd": self.cache_read_usd,
            "cache_write_usd": self.cache_write_usd,
            "total_usd": self.total_usd,
            "tokens": self.tokens,
            "pricing_estimated": self.pricing_estimated,
            "pricing_source": self.pricing_source,
        }


class BudgetReservation:
    """One request's conservative preflight hold against a shared run budget."""

    def __init__(self, budget: "Budget", reservation_id: int, amount_usd: float) -> None:
        self._budget = budget
        self._reservation_id = reservation_id
        self.amount_usd = amount_usd
        self._closed = False

    def release(self) -> None:
        """Release a request known not to have reached a billable provider call."""
        self._budget._close_reservation(self, unknown_cost=False)

    def charge_unknown(self) -> None:
        """Keep the reserved amount charged when a failed request may be billable."""
        self._budget._close_reservation(self, unknown_cost=True)


def estimate_request_cost(request: Any, model: str | None = None) -> float:
    """Conservative preflight estimate for a provider request.

    The UTF-8 JSON byte count bounds ordinary byte-oriented tokenizers more
    conservatively than the transcript's display-oriented ``chars/4`` estimate.
    Protocol framing receives additional headroom. This is a budget reservation,
    not an invoice or a formal upper bound for every provider tokenizer.
    """
    pricing, _estimated = price_for(model or getattr(request, "model", ""))
    payload = {
        "system": getattr(request, "system", ""),
        "messages": list(getattr(request, "messages", ()) or ()),
        "tools": list(getattr(request, "tools", ()) or ()),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    messages = payload["messages"]
    tools = payload["tools"]
    input_tokens = len(encoded) + 32 * len(messages) + 64 * len(tools) + 64
    output_tokens = getattr(request, "max_tokens", 0)
    if isinstance(output_tokens, bool) or not isinstance(output_tokens, int) or output_tokens < 0:
        raise ValueError("request.max_tokens must be a non-negative integer")
    # Reserve against the more expensive cache-write rate and do not assume any
    # prompt-cache discount or provider-specific usage normalization.
    input_cost = input_tokens * pricing.cache_write_per_mtok / 1_000_000
    output_cost = output_tokens * pricing.output_per_mtok / 1_000_000
    return math.nextafter(input_cost + output_cost, math.inf)


def compute_cost(usage: Any, model: str) -> CostBreakdown:
    """Price one usage report. Accepts a :class:`Usage` or a mapping."""
    from providers.base import Usage  # local import: keeps budget.py import-cycle free

    value = usage if isinstance(usage, Usage) else Usage.from_mapping(usage)
    pricing, estimated = price_for(model)
    return CostBreakdown(
        model=model,
        input_usd=round(value.input_tokens / 1_000_000 * pricing.input_per_mtok, 10),
        output_usd=round(value.output_tokens / 1_000_000 * pricing.output_per_mtok, 10),
        cache_read_usd=round(value.cache_read_input_tokens / 1_000_000 * pricing.cache_read_per_mtok, 10),
        cache_write_usd=round(value.cache_creation_input_tokens / 1_000_000 * pricing.cache_write_per_mtok, 10),
        pricing_estimated=estimated,
        pricing_source=pricing.source,
        tokens=value.total_tokens,
    )


@dataclass
class Budget:
    """Running cost and usage accumulator with a ceiling check.

    ``observe`` is the only mutation path. Delegation costs are folded into the
    parent by :class:`Budget.observe_child`, so a subagent cannot spend past the
    run it was spawned from.
    """

    max_budget_usd: float | None = None
    total_cost_usd: float = 0.0
    total_usage: Any = field(default_factory=lambda: _zero_usage())
    breakdowns: list[CostBreakdown] = field(default_factory=list)
    pricing_estimated: bool = False
    models: tuple[str, ...] = ()
    unverified_cost_usd: float = 0.0
    reserved_cost_usd: float = 0.0
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)
    _next_reservation_id: int = field(default=1, repr=False, compare=False)
    _reservations: dict[int, float] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.max_budget_usd is not None and (
            isinstance(self.max_budget_usd, bool)
            or not isinstance(self.max_budget_usd, (int, float))
            or not math.isfinite(float(self.max_budget_usd))
            or self.max_budget_usd <= 0
        ):
            raise ValueError("max_budget_usd must be a finite positive number or None")

    def reserve(self, amount_usd: float) -> BudgetReservation | None:
        """Atomically reserve request capacity before a provider attempt.

        Returns ``None`` if committed, unknown, and in-flight spend plus this
        request's envelope would exceed the run ceiling.
        """
        if isinstance(amount_usd, bool) or not isinstance(amount_usd, (int, float)):
            raise ValueError("reservation amount must be a finite non-negative number")
        amount = float(amount_usd)
        if not math.isfinite(amount) or amount < 0:
            raise ValueError("reservation amount must be a finite non-negative number")
        with self._lock:
            if self.max_budget_usd is not None:
                available = self.max_budget_usd - self.total_cost_usd - self.reserved_cost_usd
                if amount > available:
                    return None
            reservation_id = self._next_reservation_id
            self._next_reservation_id += 1
            self._reservations[reservation_id] = amount
            self.reserved_cost_usd = round(self.reserved_cost_usd + amount, 10)
            return BudgetReservation(self, reservation_id, amount)

    def _close_reservation(
        self,
        reservation: BudgetReservation,
        *,
        unknown_cost: bool,
    ) -> None:
        with self._lock:
            if reservation._closed:
                return
            amount = self._reservations.pop(reservation._reservation_id, None)
            reservation._closed = True
            if amount is None:
                return
            self.reserved_cost_usd = round(max(0.0, self.reserved_cost_usd - amount), 10)
            if unknown_cost:
                self.unverified_cost_usd = round(self.unverified_cost_usd + amount, 10)
                # A failed transport may have reached billing. Count its
                # reservation as charged for enforcement and checkpoint carry.
                self.total_cost_usd = round(self.total_cost_usd + amount, 10)
                self.pricing_estimated = True

    def _settle_observation(self, reservation: BudgetReservation | None) -> None:
        if reservation is not None:
            self._close_reservation(reservation, unknown_cost=False)

    def observe(
        self,
        usage: Any,
        model: str,
        *,
        reservation: BudgetReservation | None = None,
    ) -> CostBreakdown:
        breakdown = compute_cost(usage, model)
        with self._lock:
            self._settle_observation(reservation)
            self.breakdowns.append(breakdown)
            self.total_cost_usd = round(self.total_cost_usd + breakdown.total_usd, 10)
            self.total_usage = self.total_usage + _as_usage(usage)
            self.pricing_estimated = self.pricing_estimated or breakdown.pricing_estimated
            if model and model not in self.models:
                self.models = self.models + (model,)
        return breakdown

    def observe_child(self, child: "Budget") -> None:
        """Merge a subagent budget into this one (cost roll-up for governance)."""
        if not isinstance(child, Budget):
            return
        with child._lock:
            child_breakdowns = list(child.breakdowns)
            child_cost = child.total_cost_usd
            child_unverified = child.unverified_cost_usd
            child_usage = child.total_usage
            child_estimated = child.pricing_estimated
            child_models = child.models
        with self._lock:
            self.breakdowns.extend(child_breakdowns)
            self.total_cost_usd = round(self.total_cost_usd + child_cost, 10)
            self.unverified_cost_usd = round(self.unverified_cost_usd + child_unverified, 10)
            self.total_usage = self.total_usage + child_usage
            self.pricing_estimated = self.pricing_estimated or child_estimated
            for model in child_models:
                if model not in self.models:
                    self.models = self.models + (model,)

    @property
    def exhausted(self) -> bool:
        with self._lock:
            if self.max_budget_usd is None:
                return False
            return self.total_cost_usd >= self.max_budget_usd

    def over_limit(self) -> bool:
        """Strictly over, i.e. the ceiling has been breached rather than reached."""
        with self._lock:
            if self.max_budget_usd is None:
                return False
            return self.total_cost_usd > self.max_budget_usd

    def remaining(self) -> float | None:
        with self._lock:
            if self.max_budget_usd is None:
                return None
            return round(max(0.0, self.max_budget_usd - self.total_cost_usd - self.reserved_cost_usd), 10)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "max_budget_usd": self.max_budget_usd,
                "total_cost_usd": self.total_cost_usd,
                "unverified_cost_usd": self.unverified_cost_usd,
                "reserved_cost_usd": self.reserved_cost_usd,
                "remaining_usd": self.remaining(),
                "pricing_estimated": self.pricing_estimated,
                "exhausted": self.exhausted,
            }


def _zero_usage():
    from providers.base import Usage

    return Usage()


def _as_usage(value: Any):
    from providers.base import Usage

    return value if isinstance(value, Usage) else Usage.from_mapping(value)


def describe_pricing(models: Iterable[str]) -> Mapping[str, Any]:
    """Pricing view for the CLI ``--show-pricing`` flag."""
    view: dict[str, Any] = {}
    for model in models:
        pricing, estimated = price_for(model)
        view[model] = {**pricing.as_dict(), "estimated": estimated}
    return view


__all__ = [
    "Budget",
    "CACHE_READ_MULTIPLIER",
    "CACHE_WRITE_MULTIPLIER",
    "CONSERVATIVE_FALLBACK",
    "CostBreakdown",
    "ModelPricing",
    "PRICE_TABLE",
    "compute_cost",
    "describe_pricing",
    "price_for",
]
