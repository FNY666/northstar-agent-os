"""Sigmoid, Simulated."""
from __future__ import annotations
import ast
import math
VERSION = "ag_22.v1"
def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "itertools", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert sigmoid(0) == 0.5
    assert sigmoid(100) > 0.999
    assert sigmoid(-100) < 0.001
    assert stdlib_only()
    print("ag_22 OK")
if __name__ == "__main__": main()
