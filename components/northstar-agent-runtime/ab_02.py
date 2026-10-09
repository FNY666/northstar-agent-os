"""Linear interpolation (AB-02), Simulated."""
from __future__ import annotations
import ast

VERSION = "lerp.v1"
def lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "math", "base64", "hashlib", "hmac", "urllib", "collections", "itertools", "string", "json", "bisect"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(2, 4, 0) == 2
    assert lerp(2, 4, 1) == 4
    assert stdlib_only()
    print("lerp OK")
if __name__ == "__main__": main()
