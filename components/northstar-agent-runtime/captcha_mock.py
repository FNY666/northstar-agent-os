"""CAPTCHA mock (D-IN-025), Simulated."""
from __future__ import annotations
import ast
VERSION = "captcha-mock.v1"
def verify(token: str) -> bool: return len(token) > 10
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
    assert verify("valid-token-123")
    assert not verify("short")
    assert stdlib_only()
    print("captcha-mock OK")
if __name__ == "__main__": main()
