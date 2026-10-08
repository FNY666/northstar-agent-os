"""DX-19: Linters (mock), Simulated.

Rule registry: each rule is (rule_id, severity, regex, message).
`lint(text)` returns violations sorted by line. Regexes compile at
registration time; invalid regexes and unknown severities raise.

What this IS: regex-rule linting with an explicit rule catalog.
What this IS NOT: not a real linter.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
DX19_LINTERS_VERSION = "dx-linters.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-linters.v1"

#: Known severities.
KNOWN_SEVERITIES = frozenset({"error", "warning", "info"})


class LintersError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class LintRule:
    rule_id: str
    severity: str
    pattern: str
    message: str


@dataclass(frozen=True)
class LintViolation:
    line: int
    rule_id: str
    severity: str
    message: str


class LintRegistry:
    """Explicit lint-rule catalog."""

    def __init__(self) -> None:
        self._rules: Dict[str, Tuple[LintRule, "re.Pattern[str]"]] = {}

    def register(self, rule: LintRule) -> None:
        if not rule.rule_id or not rule.rule_id.strip():
            raise LintersError("rule_id required")
        if rule.rule_id in self._rules:
            raise LintersError(f"duplicate rule '{rule.rule_id}'")
        if rule.severity not in KNOWN_SEVERITIES:
            raise LintersError(f"unknown severity '{rule.severity}'")
        if not rule.message:
            raise LintersError("message required")
        try:
            compiled = re.compile(rule.pattern)
        except re.error as e:
            raise LintersError(f"bad regex for '{rule.rule_id}': {e}")
        self._rules[rule.rule_id] = (rule, compiled)

    def lint(self, text: str) -> List[LintViolation]:
        if not isinstance(text, str):
            raise LintersError("text must be str")
        violations: List[LintViolation] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            for rule_id in sorted(self._rules):
                rule, rx = self._rules[rule_id]
                if rx.search(line):
                    violations.append(
                        LintViolation(lineno, rule_id, rule.severity, rule.message)
                    )
        return violations

    @property
    def rules(self) -> List[str]:
        return sorted(self._rules)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
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
    reg = LintRegistry()
    reg.register(LintRule("no-todo", "warning", r"\bTODO\b", "TODO left in code"))
    reg.register(LintRule("no-trailing-ws", "info", r" +$", "trailing whitespace"))
    out = reg.lint("x = 1  \n# TODO fix\ny = 2\n")
    assert [(v.line, v.rule_id) for v in out] == [
        (1, "no-trailing-ws"), (2, "no-todo")
    ]
    assert reg.lint("clean = 1\n") == []
    try:
        reg.register(LintRule("bad", "warning", r"(unclosed", "x"))
        raise AssertionError("should raise")
    except LintersError:
        pass
    try:
        reg.register(LintRule("no-todo", "warning", r"x", "dup"))
        raise AssertionError("should raise")
    except LintersError:
        pass
    try:
        reg.register(LintRule("s", "fatal", r"x", "x"))
        raise AssertionError("should raise")
    except LintersError:
        pass
    assert reg.rules == ["no-todo", "no-trailing-ws"]
    assert stdlib_only()
    print("dx_19 OK: lint, ordering, bad-regex/dupe/severity rejected")


if __name__ == "__main__":
    main()
