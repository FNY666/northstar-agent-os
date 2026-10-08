"""obs_18: Real user monitoring web vitals (mock data format), Simulated.

RUMCollector stores caller-supplied page-view samples of web-vitals-like
metrics (LCP ms, INP ms, CLS score) per page and summarizes them with
p50/p75/p95 of LCP plus the share of views meeting the "good"
thresholds (LCP < 2500 ms, INP < 200 ms, CLS < 0.1).  Mock: no browser
telemetry is captured; all samples are injected by the caller.

Fail-closed: negative timings or unknown pages raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

OBS18_VERSION = "obs-18.v1"
SCHEMA_PIN = "northstar.obs-18.v1"

GOOD_LCP_MS = 2500.0
GOOD_INP_MS = 200.0
GOOD_CLS = 0.1


class Obs18Error(Exception):
    """Fail-closed."""


def _percentile(sorted_vals: List[float], pct: float) -> float:
    """Linear-interpolation percentile on pre-sorted values."""
    if not sorted_vals:
        raise Obs18Error("no values for percentile")
    if pct < 0 or pct > 100:
        raise Obs18Error("pct must be in [0, 100]")
    rank = pct / 100.0 * (len(sorted_vals) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = rank - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def _check_metric(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Obs18Error(f"{name} must be a number")
    v = float(value)
    if v < 0:
        raise Obs18Error(f"{name} must be non-negative")
    return v


class RUMCollector:
    """Stores mock RUM page-view samples and summarizes web vitals."""

    def __init__(self) -> None:
        self._samples: Dict[str, List[Tuple[float, float, float]]] = {}

    def record_page_view(self, page: str, lcp_ms: float, inp_ms: float, cls: float) -> None:
        """Record one page view's vitals.  Rejects negative timings."""
        if not isinstance(page, str) or not page.strip():
            raise Obs18Error("page must be non-empty str")
        lcp = _check_metric("lcp_ms", lcp_ms)
        inp = _check_metric("inp_ms", inp_ms)
        c = _check_metric("cls", cls)
        self._samples.setdefault(page.strip(), []).append((lcp, inp, c))

    def vitals_summary(self, page: str) -> Dict:
        """Summarize vitals for a page: LCP p50/p75/p95, % good, count."""
        if not isinstance(page, str) or not page.strip():
            raise Obs18Error("page must be non-empty str")
        samples = self._samples.get(page.strip())
        if not samples:
            raise Obs18Error(f"no samples for page '{page}'")
        n = len(samples)
        lcps = sorted(s[0] for s in samples)
        good_lcp = sum(1 for s in samples if s[0] < GOOD_LCP_MS)
        good_inp = sum(1 for s in samples if s[1] < GOOD_INP_MS)
        good_cls = sum(1 for s in samples if s[2] < GOOD_CLS)
        good_all = sum(
            1
            for s in samples
            if s[0] < GOOD_LCP_MS and s[1] < GOOD_INP_MS and s[2] < GOOD_CLS
        )
        return {
            "schema": SCHEMA_PIN,
            "page": page.strip(),
            "count": n,
            "lcp_p50": _percentile(lcps, 50),
            "lcp_p75": _percentile(lcps, 75),
            "lcp_p95": _percentile(lcps, 95),
            "good_pct": {
                "lcp": 100.0 * good_lcp / n,
                "inp": 100.0 * good_inp / n,
                "cls": 100.0 * good_cls / n,
            },
            "overall_good_pct": 100.0 * good_all / n,
        }


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    rum = RUMCollector()
    rum.record_page_view("/home", 1200.0, 80.0, 0.02)
    rum.record_page_view("/home", 2600.0, 90.0, 0.05)
    rum.record_page_view("/home", 2400.0, 300.0, 0.02)
    s = rum.vitals_summary("/home")
    assert s["count"] == 3
    assert s["lcp_p50"] == 2400.0
    assert abs(s["good_pct"]["lcp"] - 200.0 / 3) < 1e-9
    assert abs(s["overall_good_pct"] - 100.0 / 3) < 1e-9
    try:
        rum.record_page_view("/home", -1.0, 80.0, 0.02)
        raise AssertionError("should raise")
    except Obs18Error:
        pass
    try:
        rum.vitals_summary("/missing")
        raise AssertionError("should raise")
    except Obs18Error:
        pass
    try:
        rum.record_page_view("", 1.0, 1.0, 0.0)
        raise AssertionError("should raise")
    except Obs18Error:
        pass
    assert stdlib_only()
    print("obs_18 OK")


if __name__ == "__main__":
    main()
