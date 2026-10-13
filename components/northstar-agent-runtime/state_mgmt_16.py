"""State 16: distributed snapshots (mock), Simulated.

Coordinator-driven global snapshot across simulated nodes:
- coordinator.broadcast_snapshot() tells every node to record local state
- each node returns a SnapshotRecord (node, seq, state digest)
- coordinator verifies quorum: all expected nodes replied, digests well-formed

Mock: no real network; nodes are in-process objects implementing the
snapshot interface.  Models the protocol + failure semantics, not the
wire format.

Fail-closed: missing node replies, duplicate records, or malformed
digests raise.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Mapping, Sequence, Set


MODULE_VERSION = "state-mgmt-16.v1"
SCHEMA_PIN = "northstar.state-mgmt-16.v1"


class SnapshotError(Exception):
    pass


@dataclass(frozen=True)
class SnapshotRecord:
    node: str
    seq: int
    digest: str  # "sha256:<hex>"

    def __post_init__(self):
        if not self.node:
            raise SnapshotError("node required")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 0:
            raise SnapshotError("seq must be non-negative int")
        if not (self.digest.startswith("sha256:") and len(self.digest) == 71):
            raise SnapshotError("malformed digest")


def digest_state(state: Mapping[str, object]) -> str:
    """Deterministic digest of a JSON-serializable state mapping."""
    try:
        blob = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    except (TypeError, ValueError) as e:
        raise SnapshotError(f"state not JSON-serializable: {e}") from e
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class MockNode:
    """In-process stand-in for a distributed node."""

    def __init__(self, node_id: str, state: Mapping[str, object] | None = None,
                 fail: bool = False) -> None:
        if not node_id:
            raise SnapshotError("node_id required")
        self.node_id = node_id
        self._state = dict(state or {})
        self.fail = fail
        self.seq = 0

    def take_snapshot(self) -> SnapshotRecord:
        if self.fail:
            raise SnapshotError(f"node {self.node_id} unreachable")
        self.seq += 1
        return SnapshotRecord(self.node_id, self.seq, digest_state(self._state))


class SnapshotCoordinator:
    """Drives a global snapshot and checks quorum completeness."""

    def __init__(self, expected_nodes: Sequence[str]) -> None:
        if not expected_nodes:
            raise SnapshotError("expected_nodes required")
        if len(set(expected_nodes)) != len(expected_nodes):
            raise SnapshotError("duplicate expected nodes")
        self.expected: Set[str] = set(expected_nodes)

    def run(self, nodes: Sequence[MockNode]) -> Dict[str, SnapshotRecord]:
        records: Dict[str, SnapshotRecord] = {}
        for node in nodes:
            if node.node_id in records:
                raise SnapshotError(f"duplicate record for {node.node_id}")
            records[node.node_id] = node.take_snapshot()
        missing = self.expected - set(records)
        if missing:
            raise SnapshotError(f"missing replies from: {sorted(missing)}")
        extra = set(records) - self.expected
        if extra:
            raise SnapshotError(f"unexpected replies from: {sorted(extra)}")
        return records


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
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
    n1, n2 = MockNode("a", {"x": 1}), MockNode("b", {"y": [1, 2]})
    coord = SnapshotCoordinator(["a", "b"])
    recs = coord.run([n1, n2])
    assert set(recs) == {"a", "b"}
    assert recs["a"].digest == digest_state({"x": 1})
    # Missing node -> fail-closed.
    try:
        coord.run([n1])
        raise AssertionError("should raise")
    except SnapshotError:
        pass
    # Failing node -> fail-closed.
    bad = MockNode("b", fail=True)
    try:
        coord.run([n1, bad])
        raise AssertionError("should raise")
    except SnapshotError:
        pass
    # Malformed digest rejected at construction.
    try:
        SnapshotRecord("a", 1, "bogus")
        raise AssertionError("should raise")
    except SnapshotError:
        pass
    assert stdlib_only()
    print("state_mgmt_16 OK: coordinator quorum, digests, fail-closed")


if __name__ == "__main__":
    main()
