"""Output defense 20: summarization guard, Simulated.

Bounds summaries: max characters and max compression ratio vs the
source.  Over-long or suspiciously short summaries are rejected or
truncated (host chooses mode).  Guards against summary-as-exfiltration
(dump source verbatim) and summary-as-attack (hide payload).

What this IS: length/ratio policy for generated summaries.
What this IS NOT: not a content judge; pair with output scanning.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

OUTPUT_DEFENSE_20_VERSION = "output-defense-20.v1"
SCHEMA_PIN = "northstar.output-defense-20.v1"


class SummaryGuardError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SummaryVerdict:
    ok: bool
    text: str  # possibly truncated
    reason: str
    ratio: float  # len(summary)/len(source)


def guard_summary(
    summary: str,
    source: str,
    *,
    max_chars: int = 2000,
    max_ratio: float = 0.5,
    min_ratio: float = 0.01,
    mode: str = "truncate",
) -> SummaryVerdict:
    """Check summary bounds. mode: 'truncate' or 'reject'."""
    if not isinstance(summary, str) or not isinstance(source, str):
        raise SummaryGuardError("summary and source must be str")
    if mode not in ("truncate", "reject"):
        raise SummaryGuardError("mode must be truncate|reject")
    if max_chars <= 0 or not 0 < max_ratio <= 1 or not 0 <= min_ratio < max_ratio:
        raise SummaryGuardError("invalid bounds")
    ratio = (len(summary) / len(source)) if source else 0.0
    if len(summary) > max_chars:
        if mode == "reject":
            return SummaryVerdict(False, summary, "exceeds max_chars", ratio)
        cut = summary[:max_chars].rsplit(" ", 1)[0]
        return SummaryVerdict(True, cut + "…", "truncated to max_chars", ratio)
    if ratio > max_ratio:
        return SummaryVerdict(
            False, summary,
            f"ratio {ratio:.2f} > max {max_ratio} (possible verbatim dump)",
            ratio,
        )
    if ratio < min_ratio and source:
        return SummaryVerdict(
            False, summary,
            f"ratio {ratio:.3f} < min {min_ratio} (suspiciously short)",
            ratio,
        )
    return SummaryVerdict(True, summary, "within bounds", ratio)


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
    src = "word " * 1000  # 5000 chars
    v = guard_summary("a reasonable summary of the document content here " * 5, src)
    assert v.ok is True
    v = guard_summary("x " * 2000, src, max_chars=100, mode="truncate")
    assert v.ok is True and len(v.text) <= 104
    v = guard_summary("x " * 2000, src, max_chars=100, mode="reject")
    assert v.ok is False and "max_chars" in v.reason
    src2 = "word " * 100  # 500 chars, under max_chars
    v = guard_summary(src2, src2)  # verbatim dump
    assert v.ok is False and "verbatim" in v.reason
    v = guard_summary("tiny", src)
    assert v.ok is False and "short" in v.reason
    try:
        guard_summary(None, src)  # type: ignore
        raise AssertionError("should raise")
    except SummaryGuardError:
        pass
    assert stdlib_only()
    print("output-defense-20 OK: summary bounds, fail-closed, stdlib")


if __name__ == "__main__":
    main()
