"""Ones and zeroes (tab-28), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-oneszeroes.v1"

def find_max_form(strs: list, m: int, n: int) -> int:
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for s in strs:
        zeros = s.count("0")
        ones = len(s) - zeros
        for i in range(m, zeros - 1, -1):
            for j in range(n, ones - 1, -1):
                if dp[i - zeros][j - ones] + 1 > dp[i][j]:
                    dp[i][j] = dp[i - zeros][j - ones] + 1
    return dp[m][n]

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
    assert find_max_form(["10", "0001", "111001", "1", "0"], 5, 3) == 4
    assert find_max_form(["10", "0", "1"], 1, 1) == 2
    assert stdlib_only()
    print("tab-oneszeroes OK")

if __name__ == "__main__": main()
