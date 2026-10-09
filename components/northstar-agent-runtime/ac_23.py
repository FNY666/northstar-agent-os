"""Next Pow2 Util (D-AC-023), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_23.v1"
def next_pow2(n: int) -> int:
    return 1 << (n - 1).bit_length() if n > 0 else 1
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert next_pow2(5) == 8
    assert next_pow2(8) == 8
    assert next_pow2(1) == 1
    assert stdlib_only()
    print("ac_23 OK")
if __name__ == "__main__": main()
