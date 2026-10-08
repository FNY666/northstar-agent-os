"""Jump game (tab-22), tabulation DP."""
from __future__ import annotations
import ast
VERSION = "tab-jump.v1"

def can_jump(nums: list) -> bool:
    reach = 0
    for i, x in enumerate(nums):
        if i > reach: return False
        if i + x > reach: reach = i + x
    return True

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
    assert can_jump([2, 3, 1, 1, 4]) is True
    assert can_jump([3, 2, 1, 0, 4]) is False
    assert can_jump([0]) is True
    assert stdlib_only()
    print("tab-jump OK")

if __name__ == "__main__": main()
