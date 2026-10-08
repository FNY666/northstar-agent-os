"""obs_19: Synthetic monitoring checks (mock data format), Simulated.

SyntheticCheck runs an ordered script of steps against mock transports:
each step is (label, callable) and each callable returns (ok,
latency_ms).  Steps execute in order and the run stops at the first
failed step; the result carries per-step outcomes, the overall verdict,
and total latency.  Mock: no network traffic happens; transports are
caller-supplied callables returning canned results.

Fail-closed: empty labels, non-callable steps, or malformed transport
results raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Any, Callable, Dict, List, Tuple

OBS19_VERSION = "obs-19.v1"
SCHEMA_PIN = "northstar.obs-19.v1"

Step = Tuple[str, Callable[[], Tuple[bool, float]]]


class Obs19Error(Exception):
    """Fail-closed."""


def _check_result(label: str, out: Any) -> Tuple[bool, float]:
    if not isinstance(out, (list, tuple)) or len(out) != 2:
        raise Obs19Error(f"step '{label}' must return (ok, latency_ms)")
    ok, latency = out
    if not isinstance(ok, bool):
        raise Obs19Error(f"step '{label}' ok must be bool")
    if isinstance(latency, bool) or not isinstance(latency, (int, float)):
        raise Obs19Error(f"step '{label}' latency_ms must be a number")
    latency_f = float(latency)
    if latency_f < 0:
        raise Obs19Error(f"step '{label}' latency_ms must be non-negative")
    return ok, latency_f


class SyntheticCheck:
    """Ordered script of mock synthetic monitoring steps."""

    def __init__(self, name: str, steps: List[Step]) -> None:
        if not isinstance(name, str) or not name.strip():
            raise Obs19Error("name must be non-empty str")
        if not isinstance(steps, list) or not steps:
            raise Obs19Error("steps must be non-empty list")
        cleaned: List[Step] = []
        for step in steps:
            if not isinstance(step, (list, tuple)) or len(step) != 2:
                raise Obs19Error("each step must be (label, callable)")
            label, fn = step
            if not isinstance(label, str) or not label.strip():
                raise Obs19Error("step labels must be non-empty str")
            if not callable(fn):
                raise Obs19Error(f"step '{label}' must be callable")
            cleaned.append((label.strip(), fn))
        self._name = name.strip()
        self._steps = cleaned

    @property
    def name(self) -> str:
        return self._name

    def run(self) -> Dict:
        """Execute steps in order; stop at the first failure."""
        step_results: List[Dict] = []
        total_latency = 0.0
        failed_step: str = ""
        for label, fn in self._steps:
            try:
                out = fn()
            except Exception as exc:
                step_results.append(
                    {
                        "label": label,
                        "ok": False,
                        "latency_ms": 0.0,
                        "error": str(exc),
                    }
                )
                failed_step = label
                break
            ok, latency = _check_result(label, out)
            step_results.append(
                {"label": label, "ok": ok, "latency_ms": latency}
            )
            total_latency += latency
            if not ok:
                failed_step = label
                break
        return {
            "schema": SCHEMA_PIN,
            "name": self._name,
            "ok": not failed_step,
            "failed_step": failed_step or None,
            "steps": step_results,
            "total_latency_ms": total_latency,
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
    c = SyntheticCheck(
        "homepage",
        [
            ("dns", lambda: (True, 12.5)),
            ("tls", lambda: (True, 40.0)),
            ("http", lambda: (True, 120.0)),
        ],
    )
    r = c.run()
    assert r["ok"] is True and r["failed_step"] is None
    assert r["total_latency_ms"] == 172.5
    assert len(r["steps"]) == 3

    c2 = SyntheticCheck(
        "api",
        [
            ("dns", lambda: (True, 10.0)),
            ("auth", lambda: (False, 50.0)),
            ("query", lambda: (True, 30.0)),
        ],
    )
    r2 = c2.run()
    assert r2["ok"] is False and r2["failed_step"] == "auth"
    assert len(r2["steps"]) == 2 and r2["total_latency_ms"] == 60.0

    try:
        SyntheticCheck("x", [("", lambda: (True, 1.0))])
        raise AssertionError("should raise")
    except Obs19Error:
        pass
    try:
        SyntheticCheck("", [("a", lambda: (True, 1.0))])
        raise AssertionError("should raise")
    except Obs19Error:
        pass
    try:
        SyntheticCheck("x", [("a", "not-callable")]).run()
        raise AssertionError("should raise")
    except Obs19Error:
        pass
    assert stdlib_only()
    print("obs_19 OK")


if __name__ == "__main__":
    main()
