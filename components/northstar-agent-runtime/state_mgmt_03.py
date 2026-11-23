"""State 03: differential snapshots, Simulated.

Keep periodic full snapshots plus diffs since the last snapshot.
snapshot_every(k): full state at multiples of k, diffs otherwise.

Reconstruct: load nearest full snapshot, apply diffs forward.

Fail-closed: missing snapshot or gap in diff sequence raises.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

MODULE_VERSION = "state-mgmt-03.v1"
SCHEMA_PIN = "northstar.state-mgmt-03.v1"

import importlib.util as _ilu
import sys as _sys
from pathlib import Path as _Path

def _load_diff_mod():
    p = _Path(__file__).resolve().parent / "state_mgmt_02.py"
    spec = _ilu.spec_from_file_location("sm02_snap", str(p))
    m = _ilu.module_from_spec(spec)
    _sys.modules["sm02_snap"] = m
    spec.loader.exec_module(m)
    return m

_sm02 = _load_diff_mod()


class SnapshotError(Exception):
    pass


@dataclass
class SnapshotLog:
    snapshot_every: int = 5
    full: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    diffs: List[Tuple[int, List[Any]]] = field(default_factory=list)
    seq: int = 0

    def __post_init__(self):
        if self.snapshot_every < 1:
            raise SnapshotError("snapshot_every must be >= 1")

    def append(self, state: Dict[str, Any]) -> None:
        if not isinstance(state, dict):
            raise SnapshotError("state must be dict")
        self.seq += 1
        if self.seq % self.snapshot_every == 0:
            import copy
            self.full[self.seq] = copy.deepcopy(state)
        else:
            base = self.reconstruct(self.seq - 1) if self.seq > 1 else {}
            self.diffs.append((self.seq, _sm02.diff(base, state)))

    def reconstruct(self, seq: int) -> Dict[str, Any]:
        if seq < 1 or seq > self.seq:
            raise SnapshotError(f"seq {seq} out of range")
        # Nearest full snapshot at or before seq.
        snap_seqs = [s for s in self.full if s <= seq]
        if snap_seqs:
            import copy
            state = copy.deepcopy(self.full[max(snap_seqs)])
            start = max(snap_seqs)
        else:
            state = {}
            start = 0
        # Apply diffs in order, checking for gaps.
        expected = start + 1
        for dseq, ds in self.diffs:
            if dseq < expected:
                continue
            if dseq > seq:
                break
            if dseq != expected:
                raise SnapshotError(f"gap at seq {expected}")
            state = _sm02.apply(state, ds)
            expected += 1
            if expected > seq:
                break
        if expected - 1 < seq and not snap_seqs and not self.diffs:
            raise SnapshotError("no data")
        return state


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "copy", "dataclasses", "importlib", "pathlib", "sys", "typing"}
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
    log = SnapshotLog(snapshot_every=3)
    states = [{"n": i} for i in range(1, 8)]
    for s in states:
        log.append(s)
    for i, s in enumerate(states, start=1):
        assert log.reconstruct(i) == s, f"seq {i}"
    # Full snapshots at 3 and 6.
    assert 3 in log.full and 6 in log.full
    # Out of range
    try:
        log.reconstruct(99)
        raise AssertionError("should raise")
    except SnapshotError:
        pass
    assert stdlib_only()
    print("state_mgmt_03 OK: snapshots + diffs, reconstruct, fail-closed")


if __name__ == "__main__":
    main()
