"""obs_12: Exemplars (mock), Simulated.

Exemplars attach a trace ID to a metric observation, linking metrics
to traces.  Mock: in-memory store, no exporter.

Fail-closed: invalid inputs raise.
Stdlib only.
"""

from __future__ import annotations

import ast
import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

OBS12_VERSION = "obs-12.v1"
SCHEMA_PIN = "northstar.obs-12.v1"


class Obs12Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Exemplar:
    trace_id: str
    value: float
    timestamp: float


class ExemplarStore:
    """Mock exemplar store per metric name."""

    def __init__(self, max_per_metric: int = 10) -> None:
        if not isinstance(max_per_metric, int) or max_per_metric < 1:
            raise Obs12Error("max must be positive int")
        self._max = max_per_metric
        self._store: Dict[str, List[Exemplar]] = {}

    def add(self, metric: str, trace_id: str, value: float) -> None:
        if not isinstance(metric, str) or not metric:
            raise Obs12Error("metric must be non-empty str")
        if not isinstance(trace_id, str) or not trace_id:
            raise Obs12Error("trace_id must be non-empty str")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise Obs12Error("value must be numeric")
        if not math.isfinite(value):
            raise Obs12Error("value must be finite")
        lst = self._store.setdefault(metric, [])
        lst.append(Exemplar(trace_id, float(value), time.time()))
        # Keep only the most recent.
        if len(lst) > self._max:
            del lst[0 : len(lst) - self._max]

    def get(self, metric: str) -> List[Exemplar]:
        if not isinstance(metric, str):
            raise Obs12Error("metric must be str")
        return list(self._store.get(metric, []))


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "math", "pathlib", "time", "typing"}
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
    st = ExemplarStore(max_per_metric=2)
    st.add("latency", "t1", 12.5)
    st.add("latency", "t2", 13.5)
    st.add("latency", "t3", 14.5)  # evicts t1
    ex = st.get("latency")
    assert len(ex) == 2 and ex[0].trace_id == "t2"
    assert st.get("missing") == []
    try:
        st.add("", "t", 1.0)
        raise AssertionError("should raise")
    except Obs12Error:
        pass
    assert stdlib_only()
    print("obs_12 OK")


if __name__ == "__main__":
    main()
