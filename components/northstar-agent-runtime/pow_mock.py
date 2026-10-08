"""Proof-of-work mock (D-IN-026), Simulated."""
from __future__ import annotations
import ast, hashlib
VERSION = "pow-mock.v1"
def check_pow(data: str, nonce: str, difficulty: int = 2) -> bool:
    h = hashlib.sha256((data + nonce).encode()).hexdigest()
    return h.startswith("0" * difficulty)
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert stdlib_only()
    print("pow-mock OK")
if __name__ == "__main__": main()
