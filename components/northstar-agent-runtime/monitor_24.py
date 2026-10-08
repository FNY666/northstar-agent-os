"""Brand monitoring: mock typosquat/lookalike detection, Simulated.

Scores candidate domains against known brand domains:
- exact second-level domain on a different TLD -> variant
- levenshtein(sld) <= 2 -> lookalike
- punycode (xn--) or suspicious TLD or hyphen-stuffing -> suspicious

The host supplies candidates (mock registrar/cert feed).

What this IS: stdlib string-similarity heuristics.

What this IS NOT:
* Not live feed monitoring.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import FrozenSet, List, Set, Tuple

#: Module version.
MONITOR_24_VERSION = "monitor-24.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-24.v1"

_SUSP_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "zip", "mov",
})


class BrandError(Exception):
    """Fail-closed."""


def levenshtein(a: str, b: str) -> int:
    """Edit distance (stdlib DP)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _split(domain: str) -> Tuple[str, str]:
    parts = domain.lower().strip().split(".")
    if len(parts) < 2 or any(not p for p in parts):
        raise BrandError(f"bad domain {domain!r}")
    return parts[-2], parts[-1]


@dataclass(frozen=True)
class BrandVerdict:
    domain: str
    verdict: str  # clean | variant | lookalike | suspicious
    score: int  # 0-100
    reasons: Tuple[str, ...]


class BrandMonitor:
    """Typosquat detector (mock)."""

    def __init__(
        self,
        brands: List[str],
        suspicious_tlds: FrozenSet[str] = _SUSP_TLDS,
        lookalike_distance: int = 2,
    ) -> None:
        if not brands:
            raise BrandError("brands required")
        if lookalike_distance < 0:
            raise BrandError("lookalike_distance must be >= 0")
        self._brands: List[Tuple[str, str]] = []
        for b in brands:
            sld, tld = _split(b)
            self._brands.append((sld, tld))
        self._susp_tlds = set(suspicious_tlds)
        self._dist = lookalike_distance

    def check(self, domain: str) -> BrandVerdict:
        if not domain or not isinstance(domain, str):
            raise BrandError("domain required")
        sld, tld = _split(domain)
        reasons: List[str] = []
        score = 0
        verdict = "clean"
        for bsld, btld in self._brands:
            if sld == bsld and tld != btld:
                verdict, score = "variant", max(score, 60)
                reasons.append(f"brand sld on different tld .{tld}")
            elif sld != bsld and levenshtein(sld, bsld) <= self._dist:
                verdict = "lookalike"
                score = max(score, 80)
                reasons.append(f"lookalike of {bsld} (d<={self._dist})")
        if sld.startswith("xn--") or tld.startswith("xn--"):
            verdict = "suspicious" if verdict == "clean" else verdict
            score = max(score, 70)
            reasons.append("punycode")
        if tld in self._susp_tlds:
            score = max(score, 50 if verdict == "clean" else score)
            if verdict == "clean":
                verdict = "suspicious"
            reasons.append(f"suspicious tld .{tld}")
        if sld.count("-") >= 3:
            score = max(score, 55 if verdict == "clean" else score)
            if verdict == "clean":
                verdict = "suspicious"
            reasons.append("hyphen stuffing")
        return BrandVerdict(domain, verdict, min(100, score), tuple(reasons))


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    bm = BrandMonitor(["google.com", "acme.com"])
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    v = bm.check("google.org")
    assert v.verdict == "variant" and v.score == 60
    v = bm.check("googel.com")
    assert v.verdict == "lookalike" and v.score == 80
    v = bm.check("xn--googl-9ta.com")
    assert "punycode" in v.reasons
    v = bm.check("acme-login.tk")
    assert v.verdict == "suspicious" and "suspicious tld .tk" in v.reasons
    v = bm.check("totally-unrelated.example")
    assert v.verdict == "clean" and v.score == 0
    for bad in (
        lambda: BrandMonitor([]),
        lambda: bm.check(""),
        lambda: bm.check("nodot"),
        lambda: bm.check("a..b"),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except BrandError:
            pass
    assert stdlib_only()
    print("monitor-24 OK: variant, lookalike, punycode, tld, fail-closed, stdlib")


if __name__ == "__main__":
    main()
