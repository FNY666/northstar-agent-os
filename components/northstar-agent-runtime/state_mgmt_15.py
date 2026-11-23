"""State 15: hybrid logical clocks (mock), Simulated.

HLC = (wall_time_ms, logical, node_id).
- tick(): if wall > last.wall: (wall, 0); else (last.wall, last.logical+1)
- receive(remote): l = max(local, remote); standard HLC merge
- Bounded drift: if wall clock jumps more than max_drift_ms ahead of
  the last timestamp, fail-closed (clock anomaly).

Gives wall-clock-ish ordering plus logical causality within the same
millisecond.

Fail-closed: drift beyond max_drift_ms, malformed stamps raise.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable

MODULE_VERSION = "state-mgmt-15.v1"
SCHEMA_PIN = "northstar.state-mgmt-15.v1"


class HLCError(Exception):
    pass


@dataclass(frozen=True)
class HLCStamp:
    wall: int      # ms
    logical: int
    node: str

    def __post_init__(self):
        if not isinstance(self.wall, int) or isinstance(self.wall, bool) or self.wall < 0:
            raise HLCError("wall must be non-negative int")
        if not isinstance(self.logical, int) or isinstance(self.logical, bool) or self.logical < 0:
            raise HLCError("logical must be non-negative int")
        if not self.node:
            raise HLCError("node required")


class HybridClock:
    def __init__(
        self,
        node_id: str,
        now_ms: Callable[[], int],
        *,
        max_drift_ms: int = 60_000,
    ) -> None:
        if not node_id:
            raise HLCError("node_id required")
        if not callable(now_ms):
            raise HLCError("now_ms must be callable")
        self.node_id = node_id
        self._now = now_ms
        self._max_drift = max_drift_ms
        self._last = HLCStamp(0, 0, node_id)

    def tick(self) -> HLCStamp:
        wall = self._now()
        self._check_drift(wall)
        last = self._last
        if wall > last.wall:
            nxt = HLCStamp(wall, 0, self.node_id)
        else:
            nxt = HLCStamp(last.wall, last.logical + 1, self.node_id)
        self._last = nxt
        return nxt

    def receive(self, remote: HLCStamp) -> HLCStamp:
        if not isinstance(remote, HLCStamp):
            raise HLCError("remote must be HLCStamp")
        wall = self._now()
        self._check_drift(wall)
        last = self._last
        w = max(wall, last.wall, remote.wall)
        if w == wall and wall > last.wall and wall > remote.wall:
            nxt = HLCStamp(w, 0, self.node_id)
        elif w == last.wall == remote.wall:
            nxt = HLCStamp(w, max(last.logical, remote.logical) + 1, self.node_id)
        elif w == last.wall:
            nxt = HLCStamp(w, last.logical + 1, self.node_id)
        elif w == remote.wall:
            nxt = HLCStamp(w, remote.logical + 1, self.node_id)
        else:  # w == wall > both
            nxt = HLCStamp(w, 0, self.node_id)
        self._last = nxt
        return nxt

    def _check_drift(self, wall: int) -> None:
        if self._last.wall == 0:
            return  # uninitialized: nothing to compare against
        if wall - self._last.wall > self._max_drift:
            raise HLCError(
                f"clock drift {wall - self._last.wall}ms > {self._max_drift}ms"
            )

    @staticmethod
    def order(a: HLCStamp, b: HLCStamp) -> int:
        ka = (a.wall, a.logical, a.node)
        kb = (b.wall, b.logical, b.node)
        if ka == kb:
            return 0
        return -1 if ka < kb else 1


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
    now = [1000]
    c = HybridClock("n1", lambda: now[0])
    s1 = c.tick()
    assert (s1.wall, s1.logical) == (1000, 0)
    s2 = c.tick()  # same ms -> logical bumps
    assert (s2.wall, s2.logical) == (1000, 1)
    now[0] = 2000
    s3 = c.tick()
    assert (s3.wall, s3.logical) == (2000, 0)
    # Receive merges.
    other = HLCStamp(2000, 5, "n2")
    s4 = c.receive(other)
    assert s4.wall == 2000 and s4.logical == 6
    # Order is total.
    assert HybridClock.order(s1, s4) == -1
    assert HybridClock.order(s4, s4) == 0
    # Drift -> fail-closed.
    now[0] = 1000 + 61_000 + 2000
    try:
        c.tick()
        raise AssertionError("should raise")
    except HLCError:
        pass
    assert stdlib_only()
    print("state_mgmt_15 OK: HLC tick/receive/order, drift guard, fail-closed")


if __name__ == "__main__":
    main()
