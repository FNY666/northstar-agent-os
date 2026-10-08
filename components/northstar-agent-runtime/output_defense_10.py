"""Output defense 10: bias detection (mock), Simulated.

Flags stereotyping/generalizing language via pattern list.  Mock only —
host replaces ``BIAS_PATTERNS`` or injects a classifier.  Fail-closed on
bad input types.

What this IS: lexical tripwire for biased phrasing in output.
What this IS NOT: not a fairness model; cannot judge context.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import List, Pattern

OUTPUT_DEFENSE_10_VERSION = "output-defense-10.v1"
SCHEMA_PIN = "northstar.output-defense-10.v1"


class BiasError(Exception):
    """Fail-closed."""


BIAS_PATTERNS: List[Pattern] = [
    re.compile(r"(?i)\ball (men|women|people) are\b"),
    re.compile(r"(?i)\bthose people\b"),
    re.compile(r"(?i)\bnaturally (better|worse) at\b"),
    re.compile(r"(?i)\btypical (male|female)\b"),
]


@dataclass(frozen=True)
class BiasVerdict:
    flagged: bool
    findings: List[str]  # matched pattern strings


def detect_bias(text: str) -> BiasVerdict:
    """Scan for biased phrasing. Raises on non-str (fail-closed)."""
    if not isinstance(text, str):
        raise BiasError("text must be str")
    findings = [p.pattern for p in BIAS_PATTERNS if p.search(text)]
    return BiasVerdict(flagged=bool(findings), findings=findings)


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
    v = detect_bias("The meeting is at noon.")
    assert v.flagged is False and v.findings == []
    v = detect_bias("All women are naturally worse at math.")
    assert v.flagged is True and len(v.findings) >= 1
    try:
        detect_bias(b"bytes")  # type: ignore
        raise AssertionError("should raise")
    except BiasError:
        pass
    assert stdlib_only()
    print("output-defense-10 OK: bias patterns, fail-closed, stdlib")


if __name__ == "__main__":
    main()
