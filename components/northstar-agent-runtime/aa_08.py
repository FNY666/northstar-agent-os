"""Title Case Util (D-U-008), Simulated."""
from __future__ import annotations
import ast
VERSION = "aa_08.v1"
def title_case(s: str) -> str:
    return ' '.join(w[:1].upper() + w[1:] for w in s.split())
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "collections", "hashlib", "hmac", "math", "pathlib", "secrets", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert title_case("hello world") == "Hello World"
    assert title_case("") == ""
    assert title_case("a") == "A"
    assert stdlib_only()
    print("aa_08 OK")
if __name__ == "__main__": main()
