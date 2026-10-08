"""Integer break (tab-30), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-intbreak.v1"

def integer_break(n: int) -> int:
    if n <= 2: return 1
    dp = [0] * (n + 1)
    dp[1] = 1
    for i in range(2, n + 1):
        best = 0
        for j in range(1, i):
            val = max(j, dp[j]) * max(i - j, dp[i - j])
            if val > best: best = val
        dp[i] = best
    return dp[n]

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True

def main() -> None:
    assert integer_break(2) == 1
    assert integer_break(10) == 36
    assert integer_break(8) == 18
    assert stdlib_only()
    print("tab-intbreak OK")

if __name__ == "__main__": main()
