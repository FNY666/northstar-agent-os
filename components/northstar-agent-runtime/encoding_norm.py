"""Encoding normalization (D-IN-004), Simulated."""
from __future__ import annotations
import ast
VERSION = "encoding-norm.v1"
def normalize(b: bytes) -> str:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try: return b.decode(enc)
        except: continue
    return b.decode("utf-8", errors="replace")
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
    assert normalize(b"hello") == "hello"
    assert stdlib_only()
    print("encoding-norm OK")
if __name__ == "__main__": main()
