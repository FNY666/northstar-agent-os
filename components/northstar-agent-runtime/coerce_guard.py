"""Type coercion guards (D-IN-029), Simulated."""
from __future__ import annotations
import ast
VERSION = "coerce-guard.v1"
def safe_int(v, default=0) -> int:
    try: return int(v)
    except: return default
def safe_str(v, max_len=1000) -> str:
    s = str(v)
    return s[:max_len]
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
    assert safe_int("123") == 123
    assert safe_int("bad") == 0
    assert stdlib_only()
    print("coerce-guard OK")
if __name__ == "__main__": main()
