"""Dice rolls to target (tab-48), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-dice.v1"

def num_rolls(n: int, k: int, target: int) -> int:
    MOD = 10 ** 9 + 7
    dp = [0] * (target + 1)
    dp[0] = 1
    for _ in range(n):
        new = [0] * (target + 1)
        for t in range(1, target + 1):
            total = 0
            for face in range(1, min(k, t) + 1):
                total += dp[t - face]
            new[t] = total % MOD
        dp = new
    return dp[target]

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
    assert num_rolls(1, 6, 3) == 1
    assert num_rolls(2, 6, 7) == 6
    assert num_rolls(2, 5, 10) == 1
    assert stdlib_only()
    print("tab-dice OK")

if __name__ == "__main__": main()
