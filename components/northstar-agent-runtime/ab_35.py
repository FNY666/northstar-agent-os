"""Character frequency (AB-35), Simulated."""
from __future__ import annotations
import ast
import collections
VERSION = "charfreq.v1"
def char_freq(s: str) -> dict:
    return dict(collections.Counter(s))
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
    assert char_freq('aab') == {'a': 2, 'b': 1}
    assert char_freq('') == {}
    assert stdlib_only()
    print("charfreq OK")
if __name__ == "__main__": main()
