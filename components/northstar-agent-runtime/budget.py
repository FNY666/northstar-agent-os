"""Token budgets priced from real per-million rates, with prompt-cache accounting.

Three independent ceilings exist in the runtime: ``max_turns``,
``max_tool_calls``, and ``max_budget_usd``. Each one owns its own
``ResultMessage`` subtype so an operator can tell "the model kept talking" apart
from "the model kept spending". Cost is never derived from a rough character
count: it comes from provider-reported usage multiplied by the table below.
"""
from __future__ import annotations

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

    def observe(self, usage: Any, model: str) -> CostBreakdown:
        breakdown = compute_cost(usage, model)
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
        self.breakdowns.extend(child.breakdowns)
        self.total_cost_usd = round(self.total_cost_usd + child.total_cost_usd, 10)
        self.total_usage = self.total_usage + child.total_usage
        self.pricing_estimated = self.pricing_estimated or child.pricing_estimated
        for model in child.models:
            if model not in self.models:
                self.models = self.models + (model,)

    @property
    def exhausted(self) -> bool:
        if self.max_budget_usd is None:
            return False
        return self.total_cost_usd >= self.max_budget_usd

    def over_limit(self) -> bool:
        """Strictly over, i.e. the ceiling has been breached rather than reached."""
        if self.max_budget_usd is None:
            return False
        return self.total_cost_usd > self.max_budget_usd

    def remaining(self) -> float | None:
        if self.max_budget_usd is None:
            return None
        return round(max(0.0, self.max_budget_usd - self.total_cost_usd), 10)

    def status(self) -> dict[str, Any]:
        return {
            "max_budget_usd": self.max_budget_usd,
            "total_cost_usd": self.total_cost_usd,
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
