"""Tests for routing_engine: A*/Dijkstra shortest paths as bookkeeping."""

import ast
import unittest
from fractions import Fraction
from pathlib import Path

from routing_engine import (
    AUDIT_SCHEMA,
    ROUTING_ENGINE_VERSION,
    SCHEMA_PIN,
    BadCostError,
    BadSpeedError,
    DuplicateEdgeError,
    DuplicateNodeError,
    EtaEstimate,
    NoPathError,
    RouteRecord,
    RoutingEngine,
    RoutingError,
    SelfLoopError,
    SeqOrderError,
    UnknownEdgeError,
    UnknownNodeError,
    main,
    routing_engine_audit_event,
)


def _graph():
    """Diamond: s -> a -> t (cost 2), s -> b -> t (cost 2), s -> t (cost 5)."""
    eng = RoutingEngine()
    seq = 0

    def nxt():
        nonlocal seq
        seq += 1
        return seq

    for n in ("s", "a", "b", "t"):
        eng.add_node(n, nxt())
    eng.add_edge("s", "a", 1, nxt())
    eng.add_edge("a", "t", 1, nxt())
    eng.add_edge("s", "b", 1, nxt())
    eng.add_edge("b", "t", 1, nxt())
    eng.add_edge("s", "t", 5, nxt())
    return eng, nxt


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(ROUTING_ENGINE_VERSION, "routing-engine.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.routing-engine.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        src = (Path(__file__).parent.parent / "routing_engine.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib", "heapq", "json", "math", "threading", "dataclasses",
            "fractions", "typing", "__future__", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_frozen_records(self):
        eng, nxt = _graph()
        r = eng.route("s", "t", nxt())
        with self.assertRaises(Exception):
            r.path = ("x",)  # type: ignore[misc]
        e = eng.eta("s", "t", nxt(), 2)
        with self.assertRaises(Exception):
            e.duration = Fraction(9, 1)  # type: ignore[misc]


class TestNodesEdges(unittest.TestCase):
    def test_add_node_roundtrip(self):
        eng = RoutingEngine()
        self.assertEqual(eng.add_node("n1", 1), "n1")
        self.assertEqual(eng.nodes(), ("n1",))
        self.assertEqual(eng.node_count(), 1)

    def test_add_node_duplicate_refused(self):
        eng = RoutingEngine()
        eng.add_node("n1", 1)
        with self.assertRaises(DuplicateNodeError):
            eng.add_node("n1", 2)

    def test_add_node_bad_ids(self):
        eng = RoutingEngine()
        with self.assertRaises(ValueError):
            eng.add_node("", 1)
        with self.assertRaises(TypeError):
            eng.add_node(123, 1)  # type: ignore[arg-type]

    def test_add_node_bad_coords(self):
        eng = RoutingEngine()
        with self.assertRaises(ValueError):
            eng.add_node("n1", 1, coords=(1.0, float("nan")))
        with self.assertRaises(ValueError):
            eng.add_node("n1", 1, coords=(1.0,))  # type: ignore[arg-type]

    def test_add_edge_happy(self):
        eng, nxt = _graph()
        self.assertEqual(eng.edge_count(), 5)
        self.assertIn(("s", "a", 1), eng.edges())

    def test_add_edge_unknown_node(self):
        eng, nxt = _graph()
        with self.assertRaises(UnknownNodeError):
            eng.add_edge("s", "ghost", 1, nxt())
        with self.assertRaises(UnknownNodeError):
            eng.add_edge("ghost", "s", 1, nxt())

    def test_add_edge_cost_refusals(self):
        eng, nxt = _graph()
        eng.add_node("x", nxt())
        eng.add_node("y", nxt())
        for bad in (-1, -0.5, float("nan"), float("inf"), True, "3", None):
            with self.assertRaises(BadCostError, msg=repr(bad)):
                eng.add_edge("x", "y", bad, nxt())
                nxt()

    def test_add_edge_self_loop_refused(self):
        eng, nxt = _graph()
        with self.assertRaises(SelfLoopError):
            eng.add_edge("s", "s", 1, nxt())

    def test_add_edge_duplicate_refused(self):
        eng, nxt = _graph()
        with self.assertRaises(DuplicateEdgeError):
            eng.add_edge("s", "a", 1, nxt())

    def test_remove_edge(self):
        eng, nxt = _graph()
        eng.remove_edge("s", "t", nxt())
        self.assertEqual(eng.edge_count(), 4)
        with self.assertRaises(UnknownEdgeError):
            eng.remove_edge("s", "t", nxt())

    def test_remove_node_drops_incident_edges(self):
        eng, nxt = _graph()
        removed = eng.remove_node("b", nxt())
        self.assertEqual(removed, 2)  # s->b, b->t
        self.assertEqual(eng.edge_count(), 3)
        with self.assertRaises(UnknownNodeError):
            eng.remove_node("b", nxt())

    def test_neighbors(self):
        eng, _ = _graph()
        self.assertEqual(eng.neighbors("s"), ("a", "b", "t"))
        with self.assertRaises(UnknownNodeError):
            eng.neighbors("ghost")

    def test_seq_monotonicity(self):
        eng = RoutingEngine()
        eng.add_node("n1", 5)
        with self.assertRaises(SeqOrderError):
            eng.add_node("n2", 5)
        with self.assertRaises(SeqOrderError):
            eng.add_node("n2", 3)
        with self.assertRaises(TypeError):
            eng.add_node("n2", True)  # type: ignore[arg-type]
        eng.add_node("n2", 6)  # strictly increasing works


class TestRouting(unittest.TestCase):
    def test_shortest_path_picked(self):
        eng, nxt = _graph()
        r = eng.route("s", "t", nxt())
        self.assertIsInstance(r, RouteRecord)
        self.assertEqual(r.total_cost, 2)
        self.assertEqual(r.hops, 2)
        self.assertTrue(r.path[0] == "s" and r.path[-1] == "t")

    def test_tie_break_deterministic(self):
        # Two equal-cost paths s->a->t and s->b->t: must always pick the
        # same one (lexicographic tie-break), never flap.
        first = None
        for _ in range(3):
            eng, nxt = _graph()
            r = eng.route("s", "t", nxt())
            if first is None:
                first = r.path
            self.assertEqual(r.path, first)
        self.assertEqual(first, ("s", "a", "t"))

    def test_self_route_zero_cost(self):
        eng, nxt = _graph()
        r = eng.route("s", "s", nxt())
        self.assertEqual(r.path, ("s",))
        self.assertEqual(r.total_cost, 0)
        self.assertEqual(r.hops, 0)

    def test_unreachable_raises_no_path(self):
        eng, nxt = _graph()
        eng.add_node("iso", nxt())
        with self.assertRaises(NoPathError):
            eng.route("s", "iso", nxt())
        with self.assertRaises(NoPathError):
            eng.route("iso", "s", nxt())

    def test_unknown_node_raises(self):
        eng, nxt = _graph()
        with self.assertRaises(UnknownNodeError):
            eng.route("s", "ghost", nxt())
        with self.assertRaises(UnknownNodeError):
            eng.route("ghost", "s", nxt())

    def test_directed_edges_respected(self):
        eng = RoutingEngine()
        seq = 0

        def nxt2():
            nonlocal seq
            seq += 1
            return seq

        eng.add_node("u", nxt2())
        eng.add_node("v", nxt2())
        eng.add_edge("u", "v", 1, nxt2())
        self.assertEqual(eng.route("u", "v", nxt2()).path, ("u", "v"))
        with self.assertRaises(NoPathError):
            eng.route("v", "u", nxt2())

    def test_float_costs(self):
        eng = RoutingEngine()
        seq = 0

        def nxt2():
            nonlocal seq
            seq += 1
            return seq

        eng.add_node("u", nxt2())
        eng.add_node("v", nxt2())
        eng.add_node("w", nxt2())
        eng.add_edge("u", "v", 0.5, nxt2())
        eng.add_edge("v", "w", 0.5, nxt2())
        eng.add_edge("u", "w", 2.0, nxt2())
        r = eng.route("u", "w", nxt2())
        self.assertEqual(r.path, ("u", "v", "w"))
        self.assertAlmostEqual(r.total_cost, 1.0)

    def test_route_digest_deterministic(self):
        eng1, nxt1 = _graph()
        eng2, nxt2 = _graph()
        r1 = eng1.route("s", "t", nxt1())
        r2 = eng2.route("s", "t", nxt2())
        self.assertEqual(r1.digest, r2.digest)
        self.assertTrue(r1.digest.startswith("sha256:"))
        # Different route -> different digest.
        eng1.remove_edge("s", "a", nxt1())
        r3 = eng1.route("s", "t", nxt1())
        self.assertNotEqual(r1.digest, r3.digest)


class TestHeuristicMode(unittest.TestCase):
    def _coord_graph(self, diag_cost):
        eng = RoutingEngine()
        seq = 0

        def nxt():
            nonlocal seq
            seq += 1
            return seq

        for n, xy in {
            "a": (0.0, 0.0), "b": (1.0, 0.0),
            "c": (1.0, 1.0), "d": (0.0, 1.0),
        }.items():
            eng.add_node(n, nxt(), coords=xy)
        for u, v in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")]:
            eng.add_edge(u, v, 1, nxt())
            eng.add_edge(v, u, 1, nxt())
        eng.add_edge("a", "c", diag_cost, nxt())
        eng.add_edge("c", "a", diag_cost, nxt())
        return eng, nxt

    def test_astar_when_bound_holds(self):
        # Diagonal costs 2 >= sqrt(2): Euclidean bound holds -> A*.
        eng, nxt = self._coord_graph(2)
        r = eng.route("a", "c", nxt())
        self.assertEqual(r.heuristic, "astar")
        self.assertEqual(r.path, ("a", "c"))
        self.assertEqual(r.total_cost, 2)

    def test_dijkstra_fallback_on_bound_violation(self):
        # Diagonal costs 1.0 < sqrt(2): bound violated -> Dijkstra,
        # still optimal (1.0 beats the 2-cost ring path).
        eng, nxt = self._coord_graph(1.0)
        r = eng.route("a", "c", nxt())
        self.assertEqual(r.heuristic, "dijkstra")
        self.assertEqual(r.path, ("a", "c"))
        self.assertEqual(r.total_cost, 1.0)

    def test_dijkstra_without_coords(self):
        eng, nxt = _graph()  # no coords anywhere
        r = eng.route("s", "t", nxt())
        self.assertEqual(r.heuristic, "dijkstra")
        self.assertEqual(r.total_cost, 2)


class TestDistanceEta(unittest.TestCase):
    def test_distance_matches_route(self):
        eng, nxt = _graph()
        self.assertEqual(eng.distance("s", "t", nxt()), 2)
        self.assertEqual(eng.distance("s", "s", nxt()), 0)

    def test_distance_unreachable_raises(self):
        eng, nxt = _graph()
        eng.add_node("iso", nxt())
        with self.assertRaises(NoPathError):
            eng.distance("s", "iso", nxt())

    def test_eta_exact_fraction(self):
        eng, nxt = _graph()
        e = eng.eta("s", "t", nxt(), 3)
        self.assertIsInstance(e, EtaEstimate)
        self.assertEqual(e.distance, 2)
        self.assertEqual(e.speed, 3)
        self.assertEqual(e.duration, Fraction(2, 3))
        self.assertEqual(e.route_digest, eng.route("s", "t", nxt()).digest)

    def test_eta_float_speed_exact(self):
        eng, nxt = _graph()
        e = eng.eta("s", "t", nxt(), 0.5)
        self.assertEqual(e.duration, Fraction(4, 1))  # 2 / 0.5 exactly

    def test_eta_bad_speed_refused(self):
        eng, nxt = _graph()
        for bad in (0, -1, -2.5, float("nan"), float("inf"), True, "fast", None):
            with self.assertRaises(BadSpeedError, msg=repr(bad)):
                eng.eta("s", "t", nxt(), bad)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        eng, nxt = _graph()
        ev = routing_engine_audit_event("routed", eng, 7, {"src": "s", "dst": "t"})
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["event"], "routing-engine.routed")
        self.assertEqual(ev["node_count"], 4)
        self.assertEqual(ev["edge_count"], 5)
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["detail"], {"src": "s", "dst": "t"})
        ev2 = routing_engine_audit_event("node-added", eng, 0)
        self.assertNotIn("detail", ev2)

    def test_audit_bad_kind(self):
        eng, _ = _graph()
        with self.assertRaises(ValueError):
            routing_engine_audit_event("launched", eng, 1)

    def test_audit_bad_seq(self):
        eng, _ = _graph()
        with self.assertRaises(ValueError):
            routing_engine_audit_event("routed", eng, -1)
        with self.assertRaises(ValueError):
            routing_engine_audit_event("routed", eng, True)

    def test_main_self_check(self):
        self.assertIsNone(main())


if __name__ == "__main__":
    unittest.main()
