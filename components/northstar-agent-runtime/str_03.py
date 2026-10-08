"""Rabin-Karp search: rolling-hash multi-pattern friendly search.

Compares hash values of the pattern and each text window with a rolling hash, verifying only on hash match. Extends naturally to many patterns.

What this IS: a real rolling-hash implementation.
What this IS NOT: a cryptographic hash; collisions are resolved by direct compare.
"""

from __future__ import annotations

import ast

#: Module version.
STR_03_VERSION = "str-rabin-karp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-rabin-karp.v1"


class StrError(Exception):
    """Fail-closed."""


def _roll_init(s: str, base: int, mod: int) -> int:
    h = 0
    for ch in s:
        h = (h * base + ord(ch)) % mod
    return h


def rabin_karp_search(text: str, pattern: str, base: int = 256, mod: int = 101) -> list:
    """Return start indices of all occurrences of pattern in text."""
    m, n = len(pattern), len(text)
    if m == 0 or m > n:
        return []
    h = pow(base, m - 1, mod)
    ph = _roll_init(pattern, base, mod)
    th = _roll_init(text[:m], base, mod)
    res = []
    for s in range(n - m + 1):
        if ph == th and text[s:s + m] == pattern:
            res.append(s)
        if s < n - m:
            th = (base * (th - ord(text[s]) * h) + ord(text[s + m])) % mod
    return res


def test_rk_basic():
    assert rabin_karp_search("ABABDABACDABABCABAB", "ABABCABAB") == [10]


def test_rk_overlap():
    assert rabin_karp_search("AAAAA", "AA") == [0, 1, 2, 3]


def test_rk_none():
    assert rabin_karp_search("hello", "world") == []


def test_rk_too_long():
    assert rabin_karp_search("ab", "abc") == []


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_rk_basic()
    test_rk_overlap()
    test_rk_none()
    test_rk_too_long()
    assert stdlib_only()
    print("str-03 OK: rabin-karp")


if __name__ == "__main__":
    main()
