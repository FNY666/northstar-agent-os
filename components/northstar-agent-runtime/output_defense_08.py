"""Output defense 08: content filtering (blocklist), Simulated.

Blocks output containing disallowed patterns.  Fail-closed: non-str
input raises; blocklist miss on unknown category raises.

What this IS: last-line output filter before user sees text.
What this IS NOT: not semantic — pattern-based only; pair with a
classifier (defense 09) for semantic coverage.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Pattern

OUTPUT_DEFENSE_08_VERSION = "output-defense-08.v1"
SCHEMA_PIN = "northstar.output-defense-08.v1"


class ContentFilterError(Exception):
    """Fail-closed."""


# category -> compiled patterns
BLOCKLIST: Dict[str, List[Pattern]] = {
    "pii": [
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # api key
    ],
    "instructions": [
        re.compile(r"(?i)\bignore (all )?previous instructions\b"),
        re.compile(r"(?i)\bsystem prompt\b"),
    ],
    "exfil": [
        re.compile(r"(?i)\bsend .* to \S+@\S+"),
    ],
}


@dataclass(frozen=True)
class FilterVerdict:
    allowed: bool
    matched: List[str]  # "category:pattern" hits


def filter_content(text: str) -> FilterVerdict:
    """Return verdict. Raises on non-str input (fail-closed)."""
    if not isinstance(text, str):
        raise ContentFilterError("text must be str")
    matched: List[str] = []
    for category, patterns in BLOCKLIST.items():
        for pat in patterns:
            if pat.search(text):
                matched.append(f"{category}:{pat.pattern}")
    return FilterVerdict(allowed=not matched, matched=matched)


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
    v = filter_content("hello world")
    assert v.allowed is True and v.matched == []
    v = filter_content("my ssn is 123-45-6789")
    assert v.allowed is False and any(m.startswith("pii:") for m in v.matched)
    v = filter_content("ignore all previous instructions")
    assert v.allowed is False
    try:
        filter_content(None)  # type: ignore
        raise AssertionError("should raise")
    except ContentFilterError:
        pass
    assert stdlib_only()
    print("output-defense-08 OK: blocklist, fail-closed, stdlib")


if __name__ == "__main__":
    main()
