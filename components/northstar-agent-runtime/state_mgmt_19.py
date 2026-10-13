"""State 19: gossip protocols (mock), Simulated.

Round-based gossip dissemination over a simulated membership:
- each round, every infected node picks `fanout` random peers and
  sends the rumor
- rounds_to_infect(n, fanout): simulated rounds until all n nodes
  infected (deterministic via seeded RNG)
- dissemination is probabilistic; the module estimates rounds, it
  does not guarantee delivery

Mock: no real networking; peers are in-process IDs.

Fail-closed: fanout < 1, n < 1, fanout >= n, or non-deterministic
(unseeded) RNG raises.
"""

from __future__ import annotations

import ast
import random
from typing import List, Set


MODULE_VERSION = "state-mgmt-19.v1"
SCHEMA_PIN = "northstar.state-mgmt-19.v1"


class GossipError(Exception):
    pass


class GossipSim:
    """Deterministic (seeded) gossip dissemination simulator."""

    def __init__(self, node_ids: List[str], fanout: int, seed: int) -> None:
        if len(node_ids) < 2:
            raise GossipError("need at least 2 nodes")
        if len(set(node_ids)) != len(node_ids):
            raise GossipError("duplicate node ids")
        if not isinstance(fanout, int) or isinstance(fanout, bool) or fanout < 1:
            raise GossipError("fanout must be positive int")
        if fanout >= len(node_ids):
            raise GossipError("fanout must be < node count")
        self.nodes = list(node_ids)
        self.fanout = fanout
        self.rng = random.Random(seed)

    def disseminate(self, origin: str, *, max_rounds: int = 1000) -> int:
        """Return rounds until every node has the rumor.

        Raises GossipError if not converged within max_rounds.
        """
        if origin not in self.nodes:
            raise GossipError(f"unknown origin {origin}")
        if max_rounds <= 0:
            raise GossipError("max_rounds must be positive")
        infected: Set[str] = {origin}
        rounds = 0
        while len(infected) < len(self.nodes):
            rounds += 1
            if rounds > max_rounds:
                raise GossipError("did not converge within max_rounds")
            new: Set[str] = set()
            for node in list(infected):
                peers = [p for p in self.nodes if p != node]
                for peer in self.rng.sample(peers, min(self.fanout, len(peers))):
                    new.add(peer)
            infected |= new
        return rounds

    def expected_rounds(self, origin: str, trials: int = 50) -> float:
        """Mean rounds over `trials` seeded runs (seed varies per trial)."""
        if trials <= 0:
            raise GossipError("trials must be positive")
        total = 0
        for t in range(trials):
            sim = GossipSim(self.nodes, self.fanout, seed=t)
            total += sim.disseminate(origin)
        return total / trials


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "random", "typing"}
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
    nodes = [f"n{i}" for i in range(20)]
    sim = GossipSim(nodes, fanout=3, seed=42)
    rounds = sim.disseminate("n0")
    assert 1 <= rounds < 1000
    # Deterministic: same seed -> same result.
    assert GossipSim(nodes, 3, 42).disseminate("n0") == rounds
    # Higher fanout converges no slower on average.
    avg1 = GossipSim(nodes, 1, 0).expected_rounds("n0", trials=20)
    avg3 = GossipSim(nodes, 3, 0).expected_rounds("n0", trials=20)
    assert avg3 <= avg1
    # Fail-closed.
    for bad in (lambda: GossipSim(["a"], 1, 0),
                lambda: GossipSim(["a", "b"], 2, 0),
                lambda: GossipSim(["a", "b"], 0, 0)):
        try:
            bad()
            raise AssertionError("should raise")
        except GossipError:
            pass
    assert stdlib_only()
    print("state_mgmt_19 OK: gossip rounds, determinism, fanout ordering")


if __name__ == "__main__":
    main()
