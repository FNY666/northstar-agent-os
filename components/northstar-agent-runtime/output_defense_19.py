"""Output defense 19: partial redaction, Simulated.

Redacts only flagged segments (PII, secrets) and keeps the rest of the
output usable — finer than all-or-nothing blocking.  Redaction markers
are fixed tokens; the mapping of token -> original is NOT stored here
(host keeps it in a vault, cf. pii_vault).

What this IS: segment-level redaction preserving surrounding text.
What this IS NOT: not reversible here; de-redaction needs the vault.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Pattern, Tuple

OUTPUT_DEFENSE_19_VERSION = "output-defense-19.v1"
SCHEMA_PIN = "northstar.output-defense-19.v1"


class RedactionError(Exception):
    """Fail-closed."""


DEFAULT_PATTERNS: Dict[str, Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "PHONE": re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),
    "API_KEY": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
}


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redacted_count: int
    categories: List[str]


def redact_spans(
    text: str, spans: List[Tuple[int, int]], token: str = "[REDACTED]"
) -> str:
    """Redact explicit (start, end) spans. Later spans first (offsets)."""
    if not isinstance(text, str):
        raise RedactionError("text must be str")
    for s, e in spans:
        if not (0 <= s < e <= len(text)):
            raise RedactionError(f"invalid span {(s, e)}")
    out = text
    for s, e in sorted(spans, reverse=True):
        out = out[:s] + token + out[e:]
    return out


def redact_patterns(
    text: str,
    patterns: Dict[str, Pattern] = None,
    token_fmt: str = "[REDACTED:{category}]",
) -> RedactionResult:
    """Redact all matches of the pattern map, keep the rest."""
    if not isinstance(text, str):
        raise RedactionError("text must be str")
    pats = patterns if patterns is not None else DEFAULT_PATTERNS
    out = text
    count = 0
    cats: List[str] = []
    # Collect all matches first to avoid offset drift.
    hits: List[Tuple[int, int, str]] = []
    for cat, pat in pats.items():
        for m in pat.finditer(text):
            hits.append((m.start(), m.end(), cat))
    # Drop overlapping hits (keep first).
    hits.sort()
    kept: List[Tuple[int, int, str]] = []
    for s, e, c in hits:
        if kept and s < kept[-1][1]:
            continue
        kept.append((s, e, c))
    for s, e, c in sorted(kept, reverse=True):
        out = out[:s] + token_fmt.format(category=c) + out[e:]
        count += 1
        if c not in cats:
            cats.append(c)
    return RedactionResult(text=out, redacted_count=count, categories=cats)


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
    r = redact_patterns("Contact bob@x.com or 555-123-4567 today.")
    assert r.redacted_count == 2
    assert "bob@x.com" not in r.text and "today." in r.text
    assert set(r.categories) == {"EMAIL", "PHONE"}
    t = redact_spans("hello world", [(6, 11)])
    assert t == "hello [REDACTED]"
    r = redact_patterns("nothing sensitive here")
    assert r.redacted_count == 0 and r.text == "nothing sensitive here"
    try:
        redact_spans("abc", [(5, 2)])
        raise AssertionError("should raise")
    except RedactionError:
        pass
    try:
        redact_patterns(None)  # type: ignore
        raise AssertionError("should raise")
    except RedactionError:
        pass
    assert stdlib_only()
    print("output-defense-19 OK: partial redaction, fail-closed, stdlib")


if __name__ == "__main__":
    main()
