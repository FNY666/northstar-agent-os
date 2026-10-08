"""Tool billing (mock): per-tool call cost ledger, Simulated.

BillingLedger records tool calls against a static cost table
(cost per call, in USD cents of mock money).  Tools without an
explicit entry use a configurable default cost.  Totals can be
computed per tool, across all tools, and per run for invoicing.

What this IS:
* Mock billing ledger with deterministic per-call costs.

What this IS NOT:
* Not real money -- no payment rails, no charges, no currency
  conversion.  The "USD" string is a label, not a settlement.
* Not usage metering -- costs are flat per call.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
TOOL_SYSTEM_17_VERSION = "tool-system-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-17.v1"

#: Currency label (mock; no settlement).
CURRENCY = "USD"


class ToolSystem17Error(Exception):
    """Fail-closed."""


@dataclass
class _CallRecord:
    tool: str
    cost_cents: int
    run_id: Optional[str] = None


@dataclass
class InvoiceLine:
    tool: str
    calls: int
    cost_cents: int


@dataclass
class Invoice:
    run_id: str
    currency: str
    lines: List[InvoiceLine] = field(default_factory=list)
    total_cents: int = 0


class BillingLedger:
    """Mock per-tool billing ledger."""

    def __init__(self, default_cost_cents: int = 0) -> None:
        if default_cost_cents < 0:
            raise ToolSystem17Error("default cost cannot be negative")
        self._costs: Dict[str, int] = {}
        self._default_cost_cents = default_cost_cents
        self._calls: List[_CallRecord] = []

    def set_cost(self, tool: str, cost_cents: int) -> None:
        """Set the mock per-call cost for a tool."""
        if not tool:
            raise ToolSystem17Error("tool required")
        if cost_cents < 0:
            raise ToolSystem17Error("cost cannot be negative")
        self._costs[tool] = cost_cents

    def cost_for(self, tool: str) -> int:
        """Per-call cost in cents (falls back to the default)."""
        return self._costs.get(tool, self._default_cost_cents)

    def record(self, tool: str, run_id: Optional[str] = None) -> int:
        """Record one tool call; returns the mock cost in cents."""
        if not tool:
            raise ToolSystem17Error("tool required")
        cost = self.cost_for(tool)
        self._calls.append(
            _CallRecord(tool=tool, cost_cents=cost, run_id=run_id)
        )
        return cost

    def total_cost(self, tool: str) -> int:
        """Total mock cost in cents for one tool."""
        return sum(c.cost_cents for c in self._calls if c.tool == tool)

    def total_all(self) -> int:
        """Total mock cost in cents across all recorded calls."""
        return sum(c.cost_cents for c in self._calls)

    def call_count(self, tool: Optional[str] = None) -> int:
        if tool is None:
            return len(self._calls)
        return sum(1 for c in self._calls if c.tool == tool)

    def invoice(self, run_id: str) -> Invoice:
        """Aggregate a per-run mock invoice."""
        if not run_id:
            raise ToolSystem17Error("run_id required")
        per_tool: Dict[str, List[int]] = {}
        for call in self._calls:
            if call.run_id == run_id:
                per_tool.setdefault(call.tool, []).append(call.cost_cents)
        lines = [
            InvoiceLine(tool=tool, calls=len(costs), cost_cents=sum(costs))
            for tool, costs in sorted(per_tool.items())
        ]
        total = sum(line.cost_cents for line in lines)
        return Invoice(
            run_id=run_id, currency=CURRENCY, lines=lines, total_cents=total
        )


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    ledger = BillingLedger(default_cost_cents=5)
    ledger.set_cost("search", 10)
    ledger.set_cost("code", 25)
    assert ledger.cost_for("search") == 10
    assert ledger.cost_for("unknown-tool") == 5  # default fallback
    ledger.record("search", run_id="r1")
    ledger.record("search", run_id="r1")
    ledger.record("code", run_id="r1")
    ledger.record("code", run_id="r2")
    assert ledger.total_cost("search") == 20
    assert ledger.total_all() == 20 + 50
    assert ledger.call_count("search") == 2
    inv = ledger.invoice("r1")
    assert inv.currency == CURRENCY == "USD"
    assert inv.total_cents == 20 + 25
    assert {line.tool: line.calls for line in inv.lines} == {
        "code": 1,
        "search": 2,
    }
    empty = ledger.invoice("no-such-run")
    assert empty.total_cents == 0 and empty.lines == []
    try:
        ledger.set_cost("x", -1)
        raise AssertionError("should raise")
    except ToolSystem17Error:
        pass
    assert stdlib_only()
    print("tool_system_17 OK: costs, totals, invoices")


if __name__ == "__main__":
    main()
