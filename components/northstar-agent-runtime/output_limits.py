"""Output length limits (D-OUT-007), Simulated."""
from __future__ import annotations
import ast
VERSION = "output-limits.v1"
class OutputLimiter:
    def __init__(self, max_chars: int = 10000, max_lines: int = 500):
        self.max_chars = max_chars
        self.max_lines = max_lines
    def check(self, text: str) -> tuple[bool, str]:
        if len(text) > self.max_chars:
            return False, f"too long: {len(text)} > {self.max_chars}"
        if text.count("\n") + 1 > self.max_lines:
            return False, "too many lines"
        return True, "ok"
    def truncate(self, text: str) -> str:
        lines = text.split("\n")[:self.max_lines]
        t = "\n".join(lines)
        return t[:self.max_chars]
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
    lim = OutputLimiter(max_chars=10)
    ok, _ = lim.check("12345678901")
    assert ok is False
    assert lim.truncate("12345678901") == "1234567890"
    assert stdlib_only()
    print("output-limits OK")
if __name__ == "__main__": main()
