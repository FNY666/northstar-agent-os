"""Decode ways (tab-21), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-decode.v1"

def num_decodings(s: str) -> int:
    if not s or s[0] == "0": return 0
    a, b = 1, 1
    for i in range(1, len(s)):
        cur = 0
        if s[i] != "0": cur += b
        two = int(s[i - 1:i + 1])
        if 10 <= two <= 26: cur += a
        a, b = b, cur
    return b

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
    assert num_decodings("12") == 2
    assert num_decodings("226") == 3
    assert num_decodings("06") == 0
    assert num_decodings("0") == 0
    assert stdlib_only()
    print("tab-decode OK")

if __name__ == "__main__": main()
