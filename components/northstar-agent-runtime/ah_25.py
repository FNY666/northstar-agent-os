"""Safe Float Parse."""
from __future__ import annotations
import ast

VERSION = "ah_25.v1"
def safe_float(s: str, default: float = 0.0) -> float:
    try:
        return float(str(s).strip())
    except (ValueError, TypeError):
        return default
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
    assert safe_float('3.5') == 3.5
    assert safe_float('no') == 0.0
    assert stdlib_only()
    print("ah_25 OK")
if __name__ == "__main__": main()
