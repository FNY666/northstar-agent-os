"""Final Prices With a Special Discount in a Shop. IS: a monotonic stack finding the next price at most the current one. IS NOT: a nested-loop discount search."""

from __future__ import annotations

import ast

VERSION = "stack-26.v1"

def _req_str(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _req_int_list(values: object, name: str) -> list[int]:
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    for v in values:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{name} must contain only ints")
    return list(values)

def final_prices(prices: list[int]) -> list[int]:
    """Prices minus the next smaller-or-equal price. Fail-closed."""
    ps = _req_int_list(prices, "prices")
    if any(p < 0 for p in ps):
        raise ValueError("prices must be non-negative")
    ans = list(ps)
    stack: list[int] = []
    for i, p in enumerate(ps):
        while stack and ps[stack[-1]] >= p:
            j = stack.pop()
            ans[j] -= p
        stack.append(i)
    return ans

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
    assert final_prices([8, 4, 6, 2, 3]) == [4, 2, 4, 2, 3]
    assert final_prices([1, 2, 3, 4, 5]) == [1, 2, 3, 4, 5]
    assert final_prices([10, 1, 1, 6]) == [9, 0, 1, 6]
    assert final_prices([]) == []
    try:
        final_prices([-1, 2])
    except ValueError:
        pass
    else:
        raise AssertionError("negative price must raise ValueError")
    assert stdlib_only()
    print("stack_26 OK")


if __name__ == "__main__":
    main()
