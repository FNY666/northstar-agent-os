"""Range Sum Util (D-U-019), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_19.v1"
def range_sum(xs: list, i: int, j: int) -> int:
    return sum(xs[max(0,i):min(len(xs),j)])
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert range_sum([1,2,3,4], 1, 3) == 5
    assert range_sum([], 0, 5) == 0
    assert range_sum([9], 0, 1) == 9
    assert stdlib_only()
    print("aa_19 OK")
if __name__ == "__main__": main()
