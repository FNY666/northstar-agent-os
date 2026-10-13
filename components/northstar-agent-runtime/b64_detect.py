"""Base64 detection (D-IN-009), Simulated."""
from __future__ import annotations
import ast, re
VERSION = "b64-detect.v1"
def is_suspicious_b64(t: str) -> bool:
    if len(t) < 20: return False
    return bool(re.match(r"^[A-Za-z0-9+/=]+$", t) and len(t) % 4 == 0)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert is_suspicious_b64("aGVsbG8gd29ybGQgdGhpcyBpcyBsb25nZXI=")
    assert not is_suspicious_b64("hello")
    assert stdlib_only()
    print("b64-detect OK")
if __name__ == "__main__": main()
