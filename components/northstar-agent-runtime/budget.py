"""Cost accounting with real per-million-token pricing.

Pricing rules:

- Known models use their published per-million-token input/output prices.
- Prompt-cache reads are billed at 0.1x the input price.
- Prompt-cache writes are billed at 1.25x the input price.
- ``input_tokens`` is the *non-cached* input; cache read/write tokens are
  priced from the input price independently.
- Unknown models fall back to the most expensive known model (conservative)
  and are flagged ``pricing_estimated=True`` so callers can tell an estimate
  from a real price.
"""
from __future__ import annotations

from dataclasses import dataclass

from providers.base import Usage

CACHE_READ_DISCOUNT = 0.1
CACHE_WRITE_PREMIUM = 1.25

# USD per million tokens: (input, output). Dated model ids match their
# family prefix, so claude-sonnet-4-5-20250929 resolves to claude-sonnet-4-5.
PRICING_PER_MTOK: dict[str, tuple[float, float]] = {
    "claude-opus-4-1": (15.0, 75.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-3-5-haiku": (0.80, 4.00),
}

# Most expensive known model: the conservative fallback for unknown models.
CONSERVATIVE_PRICING: tuple[float, float] = max(PRICING_PER_MTOK.values())


def pricing_for(model: str) -> tuple[float, float, bool]:
    """Return (input_price, output_price, estimated) for a model id."""
    if model in PRICING_PER_MTOK:
        return (*PRICING_PER_MTOK[model], False)
    for key, price in PRICING_PER_MTOK.items():
        if model.startswith(key + "-"):
            return (*price, False)
    return (*CONSERVATIVE_PRICING, True)


@dataclass(frozen=True)
class Cost:
    usd: float
    pricing_estimated: bool = False


def estimate_cost(model: str, usage: Usage) -> Cost:
    input_price, output_price, estimated = pricing_for(model)
    usd = (
        usage.input_tokens * input_price
        + usage.cache_read_input_tokens * input_price * CACHE_READ_DISCOUNT
        + usage.cache_creation_input_tokens * input_price * CACHE_WRITE_PREMIUM
        + usage.output_tokens * output_price
    ) / 1_000_000.0
    # Round to a sub-nanodollar: avoids float dust without losing meaningful precision.
    return Cost(usd=round(usd, 9), pricing_estimated=estimated)


class BudgetTracker:
    """Accumulates spend for one context (one agent loop run).

    A subagent loop records into its own tracker *and* into the shared root
    tracker, so the whole-run total always includes subagent spend.
    """

    def __init__(self) -> None:
        self.total_usd: float = 0.0
        self.usage: Usage = Usage.zero()
        self.pricing_estimated: bool = False
        self.generations: int = 0

    def record(self, model: str, usage: Usage) -> Cost:
        cost = estimate_cost(model, usage)
        self.total_usd = round(self.total_usd + cost.usd, 9)
        self.usage = Usage(
            input_tokens=self.usage.input_tokens + usage.input_tokens,
            output_tokens=self.usage.output_tokens + usage.output_tokens,
            cache_read_input_tokens=self.usage.cache_read_input_tokens + usage.cache_read_input_tokens,
            cache_creation_input_tokens=(
                self.usage.cache_creation_input_tokens + usage.cache_creation_input_tokens
            ),
        )
        self.pricing_estimated = self.pricing_estimated or cost.pricing_estimated
        self.generations += 1
        return cost
