"""Length limits (D-IN-021), Simulated."""
from __future__ import annotations
import ast
VERSION = "len-limit.v1"
def check(t: str, max_len: int = 10000) -> tuple[bool, str]:
    if len(t) > max_len: return False, f"too long {len(t)}"
    return True, "ok"
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
    assert check("hi")[0]
    assert not check("x"*20000)[0]
    assert stdlib_only()
    print("len-limit OK")
if __name__ == "__main__": main()
