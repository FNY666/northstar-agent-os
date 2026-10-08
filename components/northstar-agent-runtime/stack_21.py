"""Online Stock Span with a price stack. IS: a monotonic decreasing stack of (price, span) pairs. IS NOT: rescanning history on every quote."""

from __future__ import annotations

import ast

VERSION = "stack-21.v1"

def _req_price(price: object) -> int | float:
    if isinstance(price, bool) or not isinstance(price, (int, float)) or price < 0:
        raise ValueError("price must be a non-negative number")
    return price


class StockSpanner:
    """Collect spans of consecutive days at or below today's price."""

    def __init__(self) -> None:
        self._stack: list[tuple[int | float, int]] = []

    def next(self, price: int | float) -> int:
        price = _req_price(price)
        span = 1
        while self._stack and self._stack[-1][0] <= price:
            span += self._stack.pop()[1]
        self._stack.append((price, span))
        return span

def stdlib_only() -> bool:
    """AST-check: no imports outside the allowed stdlib set."""
    import pathlib

    allowed = {"__future__", "ast", "pathlib", "typing"}
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    sp = StockSpanner()
    assert [sp.next(p) for p in [100, 80, 60, 70, 60, 75, 85]] == [1, 1, 1, 2, 1, 4, 6]
    sp2 = StockSpanner()
    assert sp2.next(10) == 1
    assert sp2.next(10) == 2
    try:
        sp2.next(-5)
    except ValueError:
        pass
    else:
        raise AssertionError("negative price must raise ValueError")
    try:
        sp2.next("high")
    except ValueError:
        pass
    else:
        raise AssertionError("non-number must raise ValueError")
    assert stdlib_only()
    print("stack_21 OK")


if __name__ == "__main__":
    main()
