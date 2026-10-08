"""Sigma rules: mock detection engine, Simulated.

A Sigma-like rule has detection selections (field -> value or list
of values, with optional modifiers: contains, startswith, endswith)
and a condition over selections: `selection`, `selection and filter`,
`1 of selection*`, `all of them`.

Events are dicts; evaluation returns True on match.

What this IS: log-event detection for audit-trail analysis.

What this IS NOT:
* Not full Sigma spec -- subset only (no aggregations, no near).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_13_VERSION = "monitor-13.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-13.v1"

_MODIFIERS = {"contains", "startswith", "endswith"}


class SigmaError(Exception):
    """Fail-closed."""


def _match_value(field_value: Any, op: str, expected: Any) -> bool:
    actual = "" if field_value is None else str(field_value)
    want = str(expected)
    if op == "eq":
        return actual == want
    if op == "contains":
        return want in actual
    if op == "startswith":
        return actual.startswith(want)
    if op == "endswith":
        return actual.endswith(want)
    raise SigmaError(f"bad modifier {op!r}")


@dataclass(frozen=True)
class Selection:
    """One named selection: field|modifier -> value(s)."""

    name: str
    criteria: Dict[str, Any]  # "Field|modifier" -> value or [values]

    def matches(self, event: Dict[str, Any]) -> bool:
        if not isinstance(event, dict):
            raise SigmaError("event must be dict")
        for key, expected in self.criteria.items():
            parts = key.split("|")
            fname, mod = parts[0], parts[1] if len(parts) > 1 else "eq"
            if mod not in _MODIFIERS and mod != "eq":
                raise SigmaError(f"bad modifier {mod!r}")
            values = expected if isinstance(expected, list) else [expected]
            if not any(_match_value(event.get(fname), mod, v) for v in values):
                return False
        return True


@dataclass
class SigmaRule:
    title: str
    selections: Dict[str, Selection]
    condition: str

    def __post_init__(self) -> None:
        if not self.title:
            raise SigmaError("title required")
        if not self.selections:
            raise SigmaError("at least one selection required")
        if not self.condition or not self.condition.strip():
            raise SigmaError("condition required")

    def matches(self, event: Dict[str, Any]) -> bool:
        hits = {n: s.matches(event) for n, s in self.selections.items()}
        return _eval_condition(self.condition.strip(), hits)


def _eval_condition(cond: str, hits: Dict[str, bool]) -> bool:
    low = cond.lower().strip()
    if low in hits:
        return hits[low]
    if low == "all of them":
        return all(hits.values())
    m = re.fullmatch(r"1 of (\w+)\*", low)
    if m:
        prefix = m.group(1)
        names = [n for n in hits if n.startswith(prefix)]
        if not names:
            raise SigmaError(f"no selections match {prefix}*")
        return any(hits[n] for n in names)
    # boolean expression over selection names
    expr = low
    for name in sorted(hits, key=len, reverse=True):
        expr = re.sub(rf"\b{re.escape(name)}\b", str(hits[name]), expr)
    expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - sandboxed
    except Exception:
        raise SigmaError(f"bad condition {cond!r}")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    """Self-check."""
    rule = SigmaRule(
        title="Deny burst",
        selections={
            "selection": Selection(
                "selection",
                {"EventType": "gate_decision", "Decision|contains": "deny"},
            ),
            "filter": Selection("filter", {"Gate": "authorize"}),
        },
        condition="selection and filter",
    )
    assert rule.matches({"EventType": "gate_decision", "Decision": "deny", "Gate": "authorize"}) is True
    assert rule.matches({"EventType": "gate_decision", "Decision": "allow", "Gate": "authorize"}) is False
    r2 = SigmaRule(
        title="any",
        selections={"sel_a": Selection("sel_a", {"X": "1"}), "sel_b": Selection("sel_b", {"X": "2"})},
        condition="1 of sel_*",
    )
    assert r2.matches({"X": "2"}) is True
    assert r2.matches({"X": "3"}) is False
    try:
        SigmaRule(title="t", selections={}, condition="selection")
        raise AssertionError("should raise")
    except SigmaError:
        pass
    try:
        Selection("s", {"F|bogus": "v"}).matches({"F": "v"})
        raise AssertionError("should raise")
    except SigmaError:
        pass
    assert stdlib_only()
    print("monitor-13 OK: selections, conditions, fail-closed, stdlib")


if __name__ == "__main__":
    main()
