"""Quota enforcement: daily limits (D-IN-024), Simulated."""
from __future__ import annotations
import ast, time
from typing import Dict
VERSION = "quota-enforce.v1"
class QuotaManager:
    def __init__(self, daily_limit: int = 1000):
        self.daily_limit = daily_limit
        self._usage: Dict[str, Dict[str, int]] = {}
    def _today(self) -> str:
        return time.strftime("%Y-%m-%d")
    def check(self, key: str, cost: int = 1) -> bool:
        today = self._today()
        if key not in self._usage:
            self._usage[key] = {}
        used = self._usage[key].get(today, 0)
        return used + cost <= self.daily_limit
    def consume(self, key: str, cost: int = 1) -> bool:
        if not self.check(key, cost):
            return False
        today = self._today()
        self._usage[key][today] = self._usage[key].get(today, 0) + cost
        return True
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "time", "typing"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed: return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed: return False
    return True
def main() -> None:
    q = QuotaManager(daily_limit=2)
    assert q.consume("u1")
    assert q.consume("u1")
    assert not q.consume("u1")
    assert q.consume("u2")
    assert stdlib_only()
    print("quota-enforce OK")
if __name__ == "__main__": main()
