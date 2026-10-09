"""N-Grams, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_34.v1"
def ngrams(tokens: list, n: int) -> list:
    if n <= 0: raise ValueError("n>0")
    return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]
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
    assert ngrams(["a","b","c"], 2) == [("a","b"),("b","c")]
    assert ngrams(["a"], 1) == [("a",)]
    assert ngrams(["a"], 2) == []
    assert stdlib_only()
    print("ag_34 OK")
if __name__ == "__main__": main()
