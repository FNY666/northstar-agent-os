"""Unigram Precision, Simulated."""
from __future__ import annotations
import ast

VERSION = "ag_37.v1"
def unigram_prec(ref: list, hyp: list) -> float:
    if not hyp: return 0.0
    rc: dict = {}
    for w in ref: rc[w] = rc.get(w, 0) + 1
    hit = sum(1 for w in hyp if rc.get(w, 0) and not rc.__setitem__(w, rc[w]-1))
    return hit / len(hyp)
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
    assert unigram_prec(["a","b"],["a","a"]) == 0.5
    assert unigram_prec(["a"],["a"]) == 1.0
    assert unigram_prec(["a"],[]) == 0.0
    assert stdlib_only()
    print("ag_37 OK")
if __name__ == "__main__": main()
