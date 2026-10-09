"""Prime Check Util (D-AC-016), Simulated."""
from __future__ import annotations
import ast
VERSION = "ac_16.v1"
def is_prime(n: int) -> bool:
    return n > 1 and all(n % i for i in range(2, int(n ** 0.5) + 1))
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "math", "pathlib", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    assert is_prime(7)
    assert is_prime(2)
    assert not is_prime(9)
    assert stdlib_only()
    print("ac_16 OK")
if __name__ == "__main__": main()
