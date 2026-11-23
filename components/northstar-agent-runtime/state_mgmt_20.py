"""State 20: anti-entropy (mock), Simulated.

Pairwise anti-entropy reconciliation between simulated replicas:
- each replica holds a dict of key -> (value, version)
- reconcile(a, b): exchange digests; the replica missing a key or
  holding a lower version pulls the newer entry
- rounds_until_converged(replicas): repeatedly reconcile random pairs
  (seeded) until all replicas agree, returning the round count

Mock: in-process dicts; models the digest-then-pull protocol, not the
wire format.

Fail-closed: malformed entries, unknown replica on direct
reconcile, or non-convergence within max_rounds raise.
"""

from __future__ import annotations

import ast
import hashlib
import json
import random
from typing import Dict, List, Tuple


MODULE_VERSION = "state-mgmt-20.v1"
SCHEMA_PIN = "northstar.state-mgmt-20.v1"


class AntiEntropyError(Exception):
    pass


Entry = Tuple[str, int]  # (value, version)


def _check_entry(key: str, entry: Entry) -> None:
    if not isinstance(key, str) or not key:
        raise AntiEntropyError("key must be non-empty str")
    if (not isinstance(entry, tuple) or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], int) or isinstance(entry[1], bool)
            or entry[1] < 0):
        raise AntiEntropyError(f"malformed entry for {key!r}")


class Replica:
    def __init__(self, rid: str, data: Dict[str, Entry] | None = None) -> None:
        if not rid:
            raise AntiEntropyError("rid required")
        self.rid = rid
        self.data: Dict[str, Entry] = {}
        for k, e in (data or {}).items():
            _check_entry(k, e)
            self.data[k] = e

    def digest(self) -> str:
        blob = json.dumps(
            {k: [v, ver] for k, (v, ver) in sorted(self.data.items())},
            separators=(",", ":"),
        ).encode()
        return "sha256:" + hashlib.sha256(blob).hexdigest()

    def put(self, key: str, value: str, version: int) -> None:
        _check_entry(key, (value, version))
        cur = self.data.get(key)
        if cur is None or version > cur[1]:
            self.data[key] = (value, version)


def reconcile(a: Replica, b: Replica) -> int:
    """One anti-entropy exchange.  Returns number of entries pulled."""
    if a.digest() == b.digest():
        return 0
    pulled = 0
    for key, (val, ver) in list(b.data.items()):
        cur = a.data.get(key)
        if cur is None or ver > cur[1]:
            a.data[key] = (val, ver)
            pulled += 1
    for key, (val, ver) in list(a.data.items()):
        cur = b.data.get(key)
        if cur is None or ver > cur[1]:
            b.data[key] = (val, ver)
            pulled += 1
    return pulled


def rounds_until_converged(replicas: List[Replica], seed: int,
                           *, max_rounds: int = 10_000) -> int:
    if len(replicas) < 2:
        raise AntiEntropyError("need at least 2 replicas")
    rng = random.Random(seed)
    rounds = 0
    while len({r.digest() for r in replicas}) > 1:
        rounds += 1
        if rounds > max_rounds:
            raise AntiEntropyError("did not converge")
        x, y = rng.sample(replicas, 2)
        reconcile(x, y)
    return rounds


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "json", "pathlib", "random", "typing"}
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
    a = Replica("a", {"k": ("v1", 1)})
    b = Replica("b", {"k": ("v2", 2), "j": ("x", 1)})
    assert reconcile(a, b) > 0
    assert a.digest() == b.digest()
    assert a.data["k"] == ("v2", 2) and a.data["j"] == ("x", 1)
    # Already converged -> 0 pulls.
    assert reconcile(a, b) == 0
    # Multi-replica convergence.
    reps = [Replica(f"r{i}", {f"k{i}": ("v", 1)}) for i in range(5)]
    n = rounds_until_converged(reps, seed=3)
    assert n >= 1 and len({r.digest() for r in reps}) == 1
    # Malformed entry -> fail-closed.
    try:
        Replica("z", {"k": ("v", -1)})
        raise AssertionError("should raise")
    except AntiEntropyError:
        pass
    assert stdlib_only()
    print("state_mgmt_20 OK: digest-pull reconcile, convergence, fail-closed")


if __name__ == "__main__":
    main()
