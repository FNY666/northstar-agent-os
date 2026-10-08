"""DX-21: Test runners (mock), Simulated.

Named suites of canned test cases (pass/fail/skip). `run(name)`
returns a summary with totals and failed case names; an optional
prefix filters case names. Unknown suites and bad outcomes raise.

What this IS: canned suite results with prefix filtering.
What this IS NOT: not a real test runner.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
DX21_TESTRUN_VERSION = "dx-testrun.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-testrun.v1"

#: Known case outcomes.
KNOWN_OUTCOMES = frozenset({"pass", "fail", "skip"})


class TestRunError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TestCase:
    name: str
    outcome: str


@dataclass(frozen=True)
class RunSummary:
    suite: str
    passed: int
    failed: int
    skipped: int
    total: int
    failures: List[str] = field(default_factory=list)


class TestRunner:
    """Canned test-suite runner."""

    def __init__(self) -> None:
        self._suites: Dict[str, List[TestCase]] = {}

    def register_suite(self, name: str, cases: List[TestCase]) -> None:
        if not name or not name.strip():
            raise TestRunError("suite name required")
        if name in self._suites:
            raise TestRunError(f"duplicate suite '{name}'")
        seen = set()
        for c in cases:
            if not c.name:
                raise TestRunError("case name required")
            if c.name in seen:
                raise TestRunError(f"duplicate case '{c.name}'")
            seen.add(c.name)
            if c.outcome not in KNOWN_OUTCOMES:
                raise TestRunError(f"unknown outcome '{c.outcome}'")
        self._suites[name] = list(cases)

    def run(self, name: str, prefix: Optional[str] = None) -> RunSummary:
        if name not in self._suites:
            raise TestRunError(f"unknown suite '{name}'")
        cases = self._suites[name]
        if prefix is not None:
            cases = [c for c in cases if c.name.startswith(prefix)]
        failures = [c.name for c in cases if c.outcome == "fail"]
        return RunSummary(
            suite=name,
            passed=sum(1 for c in cases if c.outcome == "pass"),
            failed=len(failures),
            skipped=sum(1 for c in cases if c.outcome == "skip"),
            total=len(cases),
            failures=failures,
        )

    @property
    def suites(self) -> List[str]:
        return sorted(self._suites)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    runner = TestRunner()
    runner.register_suite("unit", [
        TestCase("test_a", "pass"),
        TestCase("test_b", "fail"),
        TestCase("test_c", "skip"),
        TestCase("db_test", "pass"),
    ])
    s = runner.run("unit")
    assert (s.passed, s.failed, s.skipped, s.total) == (2, 1, 1, 4)
    assert s.failures == ["test_b"]
    s2 = runner.run("unit", prefix="test_")
    assert s2.total == 3 and s2.passed == 1
    try:
        runner.run("nope")
        raise AssertionError("should raise")
    except TestRunError:
        pass
    try:
        runner.register_suite("bad", [TestCase("t", "flaky")])
        raise AssertionError("should raise")
    except TestRunError:
        pass
    assert runner.suites == ["unit"]
    assert stdlib_only()
    print("dx_21 OK: run, prefix filter, summary, validation")


if __name__ == "__main__":
    main()
