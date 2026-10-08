"""Edit script (operation backtrace)

The concrete operation list turning a into b.

What this IS: a backtrace producing match/sub/ins/del operations.

What this IS NOT:
* distance only -- ed_01 returns just the number.
* an alignment pair -- ed_26 returns gapped strings instead.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

#: Module version.
ED_28_VERSION = "ed-28.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ed-28.v1"


def edit_script(a: str, b: str) -> List[Tuple[str, str, str]]:
    """Operation list transforming a into b.

    Each op is (kind, from_char, to_char) with kind in
    {"match", "sub", "ins", "del"}; "-" marks a gap.
    """
    if not isinstance(a, str) or not isinstance(b, str):
        raise TypeError("inputs must be str")
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1,
                           dp[i - 1][j - 1] + cost)
    ops: List[Tuple[str, str, str]] = []
    i, j = m, n
    while i > 0 or j > 0:
        if i > 0 and j > 0:
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if dp[i][j] == dp[i - 1][j - 1] + cost:
                kind = "match" if cost == 0 else "sub"
                ops.append((kind, a[i - 1], b[j - 1]))
                i -= 1
                j -= 1
                continue
        if i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append(("del", a[i - 1], "-"))
            i -= 1
            continue
        ops.append(("ins", "-", b[j - 1]))
        j -= 1
    ops.reverse()
    return ops


def apply_script(a: str, ops: List[Tuple[str, str, str]]) -> str:
    """Apply an edit script to a (used by the self-check)."""
    out = []
    for kind, fc, tc in ops:
        if kind in ("match", "sub", "ins"):
            out.append(tc)
        elif kind == "del":
            pass
        else:
            raise ValueError("unknown op: " + kind)
    return "".join(out)

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    ops = edit_script("kitten", "sitting")
    assert apply_script("kitten", ops) == "sitting"
    kinds = [k for k, _, _ in ops]
    assert kinds.count("sub") + kinds.count("ins") + kinds.count("del") == 3
    assert all(k == "match" for k, _, _ in edit_script("ab", "ab"))
    assert edit_script("", "ab") == [("ins", "-", "a"), ("ins", "-", "b")]
    try:
        edit_script("a", 2)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError")
    assert stdlib_only()
    print("28-edit-script OK")


if __name__ == "__main__":
    main()
