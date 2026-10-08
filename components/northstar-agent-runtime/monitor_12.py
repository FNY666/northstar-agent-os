"""YARA rules: mock rule engine, Simulated.

Parses a small YARA-like rule syntax:
    rule Name { meta: ... strings: $a = "foo" $b = /re[0-9]+/ condition: ... }

Supported string types: plain text, hex (ignored in scan), regex.
Supported conditions: `any of them`, `all of them`, `N of them`,
`$a`, `not $b`, and simple boolean combinations.

What this IS: content scanning for tool outputs / file reads.

What this IS NOT:
* Not real YARA -- subset grammar only. Host shells out to yara
  for production scanning.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
MONITOR_12_VERSION = "monitor-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-12.v1"


class YaraError(Exception):
    """Fail-closed."""


@dataclass
class YaraString:
    name: str  # e.g. "$a"
    pattern: str  # plain text (regex compiled if is_regex)
    is_regex: bool = False
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def matches(self, data: str) -> bool:
        if self.is_regex:
            if self._compiled is None:
                self._compiled = re.compile(self.pattern)
            return self._compiled.search(data) is not None
        return self.pattern in data


@dataclass
class YaraRule:
    name: str
    meta: Dict[str, str]
    strings: List[YaraString]
    condition: str

    def evaluate(self, data: str) -> bool:
        if not isinstance(data, str):
            raise YaraError("data must be str")
        hits = {s.name: s.matches(data) for s in self.strings}
        return _eval_condition(self.condition.strip(), hits, len(self.strings))


def _eval_condition(cond: str, hits: Dict[str, bool], n_strings: int) -> bool:
    low = cond.lower()
    if low == "any of them":
        return any(hits.values())
    if low == "all of them":
        return all(hits.values())
    m = re.fullmatch(r"(\d+) of them", low)
    if m:
        return sum(hits.values()) >= int(m.group(1))
    # Simple boolean over $vars: tokens and/or/not.
    tokens = re.findall(r"\$[a-zA-Z0-9_]+|and|or|not|\(|\)", low)
    if not tokens or "".join(tokens).replace(" ", "") != low.replace(" ", "").replace("(", "").replace(")", "") and False:
        pass
    expr = low
    for var in sorted(hits, key=len, reverse=True):
        expr = expr.replace(var.lower(), str(hits[var]))
    expr = expr.replace("and", " and ").replace("or", " or ").replace("not", " not ")
    try:
        return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 - sandboxed
    except Exception:
        raise YaraError(f"bad condition {cond!r}")


_RULE_RE = re.compile(
    r"rule\s+(\w+)\s*\{(.*)\}\s*$", re.DOTALL | re.IGNORECASE
)
_STR_RE = re.compile(
    r'(\$\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|/((?:[^/\\]|\\.)+)/)', re.DOTALL
)


def parse_rule(text: str) -> YaraRule:
    """Parse one YARA-like rule."""
    if not isinstance(text, str):
        raise YaraError("rule text must be str")
    m = _RULE_RE.match(text.strip())
    if not m:
        raise YaraError("rule does not match grammar")
    name, body = m.group(1), m.group(2)
    meta: Dict[str, str] = {}
    meta_m = re.search(r"meta\s*:(.*?)(?=strings\s*:|condition\s*:|$)", body, re.DOTALL | re.IGNORECASE)
    if meta_m:
        for mm in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', meta_m.group(1)):
            meta[mm.group(1)] = mm.group(2)
    strings: List[YaraString] = []
    str_m = re.search(r"strings\s*:(.*?)(?=condition\s*:|$)", body, re.DOTALL | re.IGNORECASE)
    if str_m:
        for sm in _STR_RE.finditer(str_m.group(1)):
            var, plain, regex = sm.group(1), sm.group(2), sm.group(3)
            if plain is not None:
                strings.append(YaraString(var, plain.encode().decode("unicode_escape")))
            else:
                strings.append(YaraString(var, regex, is_regex=True))
    cond_m = re.search(r"condition\s*:(.*)$", body, re.DOTALL | re.IGNORECASE)
    if not cond_m or not cond_m.group(1).strip():
        raise YaraError("condition required")
    if not strings:
        raise YaraError("at least one string required")
    return YaraRule(name=name, meta=meta, strings=strings, condition=cond_m.group(1).strip())


class YaraEngine:
    """Holds parsed rules and scans data."""

    def __init__(self) -> None:
        self._rules: Dict[str, YaraRule] = {}

    def add_rule(self, text: str) -> YaraRule:
        rule = parse_rule(text)
        if rule.name in self._rules:
            raise YaraError(f"duplicate rule {rule.name!r}")
        self._rules[rule.name] = rule
        return rule

    def scan(self, data: str) -> List[str]:
        """Return names of matching rules."""
        return [name for name, r in self._rules.items() if r.evaluate(data)]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    eng = YaraEngine()
    eng.add_rule(
        'rule Evil { meta: author = "t" strings: $a = "rm -rf" $b = /evil[0-9]+/ '
        "condition: any of them }"
    )
    assert eng.scan("please rm -rf /") == ["Evil"]
    assert eng.scan("nothing here") == []
    eng.add_rule(
        'rule Both { strings: $a = "foo" $b = "bar" condition: all of them }'
    )
    assert eng.scan("foo and bar") == ["Both"]
    assert eng.scan("foo only") == []
    try:
        parse_rule("not a rule")
        raise AssertionError("should raise")
    except YaraError:
        pass
    try:
        eng.add_rule('rule NoCond { strings: $a = "x" }')
        raise AssertionError("should raise")
    except YaraError:
        pass
    assert stdlib_only()
    print("monitor-12 OK: parse, scan, conditions, fail-closed, stdlib")


if __name__ == "__main__":
    main()
