"""Floor Log2 Util (D-AC-042), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_42.v1"
def floor_log2(n: int) -> int:
    return n.bit_length() - 1 if n > 0 else 0
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
    assert floor_log2(8) == 3
    assert floor_log2(10) == 3
    assert floor_log2(1) == 0
    assert stdlib_only()
    print("ac_42 OK")
if __name__ == "__main__": main()
