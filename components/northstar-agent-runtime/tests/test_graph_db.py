"""Tests for graph_db: property-graph nodes/edges/traversal/shortest paths."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db import (
    GraphDB, NodeRecord, EdgeRecord, TraversalReport, PathResult,
    GraphError, DuplicateNodeError, UnknownNodeError, DuplicateEdgeError,
    GraphValidationError, GRAPH_DB_VERSION, GRAPH_DB_SCHEMA,
    graph_db_audit_event,
)


class TestAddNode(unittest.TestCase):
    def setUp(self):
        self.g = GraphDB()

    def test_version_and_schema_pins(self):
        self.assertEqual(GRAPH_DB_VERSION, "graph-db.v1")
        self.assertEqual(GRAPH_DB_SCHEMA, "northstar.graph-db.v1")

    def test_add_node_roundtrip(self):
        rec = self.g.add_node("a", 1, labels=["city"], properties={"pop": 100})
        self.assertIsInstance(rec, NodeRecord)
        self.assertEqual(rec.node_id, "a")
        self.assertEqual(rec.labels, ("city",))
        self.assertEqual(dict(rec.properties), {"pop": 100})
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, GRAPH_DB_VERSION)
        self.assertEqual(rec.schema, GRAPH_DB_SCHEMA)

    def test_labels_sorted_deterministic(self):
        rec = self.g.add_node("a", 1, labels=["z", "a", "m"])
        self.assertEqual(rec.labels, ("a", "m", "z"))

    def test_duplicate_node_refused(self):
        self.g.add_node("a", 1)
        with self.assertRaises(DuplicateNodeError):
            self.g.add_node("a", 2)

    def test_node_digest_deterministic(self):
        r1 = GraphDB().add_node("a", 1, labels=["x"], properties={"p": 1})
        r2 = GraphDB().add_node("a", 1, labels=["x"], properties={"p": 1})
        self.assertEqual(r1.digest, r2.digest)

    def test_node_digest_content_sensitive(self):
        r1 = GraphDB().add_node("a", 1, properties={"p": 1})
        r2 = GraphDB().add_node("a", 1, properties={"p": 2})
        self.assertNotEqual(r1.digest, r2.digest)

    def test_add_node_validation(self):
        for bad in ("", 123, None, True):
            with self.assertRaises(GraphValidationError):
                self.g.add_node(bad, 1)
        for bad_seq in (-1, True, "1", None):
            with self.assertRaises(GraphValidationError):
                self.g.add_node("x", bad_seq)
        with self.assertRaises(GraphValidationError):
            self.g.add_node("x", 1, properties={"p": float("nan")})
        with self.assertRaises(GraphValidationError):
            self.g.add_node("x", 1, properties={"p": 2**54})
        with self.assertRaises(GraphValidationError):
            self.g.add_node("x", 1, properties={"p": b"bytes"})
        with self.assertRaises(GraphValidationError):
            self.g.add_node("x", 1, labels=["ok", ""])

    def test_node_lookup(self):
        rec = self.g.add_node("a", 1)
        self.assertEqual(self.g.node("a"), rec)
        with self.assertRaises(UnknownNodeError):
            self.g.node("missing")

    def test_node_record_frozen(self):
        rec = self.g.add_node("a", 1)
        with self.assertRaises(Exception):
            rec.node_id = "b"  # type: ignore[misc]


class TestAddEdge(unittest.TestCase):
    def setUp(self):
        self.g = GraphDB()
        self.g.add_node("a", 1)
        self.g.add_node("b", 2)
        self.g.add_node("c", 3)

    def test_add_edge_roundtrip(self):
        rec = self.g.add_edge("a", "b", "KNOWS", 4, {"since": 2020})
        self.assertIsInstance(rec, EdgeRecord)
        self.assertEqual(rec.src, "a")
        self.assertEqual(rec.dst, "b")
        self.assertEqual(rec.edge_type, "KNOWS")
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_edge_unknown_nodes_refused(self):
        with self.assertRaises(UnknownNodeError):
            self.g.add_edge("a", "ghost", "KNOWS", 4)
        with self.assertRaises(UnknownNodeError):
            self.g.add_edge("ghost", "a", "KNOWS", 4)

    def test_parallel_edge_refused(self):
        self.g.add_edge("a", "b", "KNOWS", 4)
        with self.assertRaises(DuplicateEdgeError):
            self.g.add_edge("a", "b", "KNOWS", 5)

    def test_same_pair_different_type_ok(self):
        self.g.add_edge("a", "b", "KNOWS", 4)
        rec = self.g.add_edge("a", "b", "LIKES", 5)
        self.assertEqual(rec.edge_type, "LIKES")

    def test_self_loop_allowed(self):
        rec = self.g.add_edge("a", "a", "SELF", 4)
        self.assertEqual(rec.src, rec.dst)

    def test_edge_validation(self):
        with self.assertRaises(GraphValidationError):
            self.g.add_edge("a", "b", "", 4)
        with self.assertRaises(GraphValidationError):
            self.g.add_edge("a", "b", "KNOWS", -1)
        with self.assertRaises(GraphValidationError):
            self.g.add_edge("a", "b", "KNOWS", 4, {"p": float("inf")})

    def test_edge_lookup(self):
        rec = self.g.add_edge("a", "b", "KNOWS", 4)
        self.assertEqual(self.g.edge(rec.edge_id), rec)
        with self.assertRaises(GraphError):
            self.g.edge("no-such-edge")

    def test_neighbors(self):
        self.g.add_edge("a", "b", "KNOWS", 4)
        self.g.add_edge("a", "c", "LIKES", 5)
        self.g.add_edge("b", "c", "KNOWS", 6)
        nbrs = self.g.neighbors("a")
        self.assertEqual(len(nbrs), 2)
        filtered = self.g.neighbors("a", edge_types=["KNOWS"])
        self.assertEqual(len(filtered), 1)
        with self.assertRaises(UnknownNodeError):
            self.g.neighbors("ghost")


class TestTraversal(unittest.TestCase):
    def setUp(self):
        self.g = GraphDB()
        self.g.add_node("a", 1, labels=["root"])
        self.g.add_node("b", 2, labels=["mid"])
        self.g.add_node("c", 3, labels=["leaf"])
        self.g.add_node("d", 4, labels=["leaf"])
        self.g.add_edge("a", "b", "ROAD", 5)
        self.g.add_edge("b", "c", "ROAD", 6)
        self.g.add_edge("b", "d", "RAIL", 7)
        self.g.add_edge("a", "d", "RAIL", 8)

    def test_bfs_visit_order(self):
        rep = self.g.traverse("a", 9)
        self.assertIsInstance(rep, TraversalReport)
        ids = [v.node_id for v in rep.visits]
        self.assertEqual(ids[0], "a")
        self.assertEqual(set(ids), {"a", "b", "c", "d"})
        depths = {v.node_id: v.depth for v in rep.visits}
        self.assertEqual(depths["a"], 0)
        self.assertEqual(depths["b"], 1)
        self.assertEqual(depths["c"], 2)
        # bfs: d reachable directly from a, so depth 1
        self.assertEqual(depths["d"], 1)

    def test_bfs_deterministic(self):
        r1 = self.g.traverse("a", 9)
        r2 = self.g.traverse("a", 9)
        self.assertEqual(r1.digest, r2.digest)
        self.assertEqual([v.node_id for v in r1.visits],
                         [v.node_id for v in r2.visits])

    def test_dfs_visits_all(self):
        rep = self.g.traverse("a", 9, mode="dfs")
        ids = [v.node_id for v in rep.visits]
        self.assertEqual(ids[0], "a")
        self.assertEqual(set(ids), {"a", "b", "c", "d"})

    def test_max_depth(self):
        rep = self.g.traverse("a", 9, max_depth=1)
        depths = {v.node_id: v.depth for v in rep.visits}
        self.assertNotIn("c", depths)
        self.assertEqual(set(depths), {"a", "b", "d"})

    def test_edge_type_filter(self):
        rep = self.g.traverse("a", 9, edge_types=["RAIL"])
        ids = {v.node_id for v in rep.visits}
        self.assertEqual(ids, {"a", "d"})

    def test_label_filter(self):
        rep = self.g.traverse("a", 9, label_filter=["leaf"])
        ids = {v.node_id for v in rep.visits}
        self.assertEqual(ids, {"a", "c", "d"})

    def test_traverse_validation(self):
        with self.assertRaises(GraphValidationError):
            self.g.traverse("a", 9, mode="random")
        with self.assertRaises(GraphValidationError):
            self.g.traverse("a", 9, max_depth=-1)
        with self.assertRaises(UnknownNodeError):
            self.g.traverse("ghost", 9)
        with self.assertRaises(GraphValidationError):
            self.g.traverse("a", -1)

    def test_traversal_report_frozen_and_shape(self):
        rep = self.g.traverse("a", 9)
        with self.assertRaises(Exception):
            rep.start = "x"  # type: ignore[misc]
        self.assertTrue(rep.digest.startswith("sha256:"))
        d = rep.as_dict()
        self.assertEqual(d["start"], "a")
        self.assertEqual(d["mode"], "bfs")
        self.assertEqual(len(d["visits"]), 4)


class TestShortestPath(unittest.TestCase):
    def setUp(self):
        self.g = GraphDB()
        for nid in ("a", "b", "c", "d", "z"):
            self.g.add_node(nid, 1)
        self.g.add_edge("a", "b", "ROAD", 2, {"km": 5.0})
        self.g.add_edge("b", "c", "ROAD", 3, {"km": 7.0})
        self.g.add_edge("a", "c", "RAIL", 4, {"km": 20.0})
        self.g.add_edge("c", "d", "ROAD", 5, {"km": 3.0})

    def test_uniform_shortest(self):
        path = self.g.shortest_path("a", "d", 6)
        self.assertIsInstance(path, PathResult)
        self.assertEqual(path.node_path, ("a", "c", "d"))
        self.assertEqual(path.total_cost, 2.0)
        self.assertEqual(len(path.edge_path), 2)

    def test_weighted_shortest(self):
        path = self.g.shortest_path("a", "c", 6, weight_property="km")
        self.assertEqual(path.node_path, ("a", "b", "c"))
        self.assertAlmostEqual(path.total_cost, 12.0)

    def test_self_path(self):
        path = self.g.shortest_path("a", "a", 6)
        self.assertEqual(path.node_path, ("a",))
        self.assertEqual(path.edge_path, ())
        self.assertEqual(path.total_cost, 0.0)

    def test_disconnected_refused(self):
        with self.assertRaises(GraphError):
            self.g.shortest_path("a", "z", 6)

    def test_unknown_nodes_refused(self):
        with self.assertRaises(UnknownNodeError):
            self.g.shortest_path("a", "ghost", 6)
        with self.assertRaises(UnknownNodeError):
            self.g.shortest_path("ghost", "a", 6)

    def test_missing_weight_refused(self):
        g = GraphDB()
        g.add_node("x", 1)
        g.add_node("y", 2)
        g.add_edge("x", "y", "ROAD", 3)  # no km property
        with self.assertRaises(GraphValidationError):
            g.shortest_path("x", "y", 4, weight_property="km")

    def test_negative_weight_refused(self):
        g = GraphDB()
        g.add_node("x", 1)
        g.add_node("y", 2)
        g.add_edge("x", "y", "ROAD", 3, {"km": -1})
        with self.assertRaises(GraphValidationError):
            g.shortest_path("x", "y", 4, weight_property="km")

    def test_edge_type_filter_path(self):
        path = self.g.shortest_path("a", "c", 6, edge_types=["RAIL"])
        self.assertEqual(path.node_path, ("a", "c"))
        self.assertEqual(path.total_cost, 1.0)

    def test_path_deterministic_digest(self):
        p1 = self.g.shortest_path("a", "d", 6)
        p2 = self.g.shortest_path("a", "d", 6)
        self.assertEqual(p1.digest, p2.digest)
        self.assertTrue(p1.digest.startswith("sha256:"))

    def test_path_validation(self):
        with self.assertRaises(GraphValidationError):
            self.g.shortest_path("a", "d", -1)
        with self.assertRaises(GraphValidationError):
            self.g.shortest_path("a", "d", 6, weight_property="")


class TestViewsAndAudit(unittest.TestCase):
    def setUp(self):
        self.g = GraphDB()
        self.g.add_node("b", 1)
        self.g.add_node("a", 2)
        self.g.add_edge("a", "b", "E", 3)

    def test_counts_and_ids(self):
        self.assertEqual(self.g.node_count(), 2)
        self.assertEqual(self.g.edge_count(), 1)
        self.assertEqual(self.g.node_ids(), ["a", "b"])

    def test_audit_event_shapes(self):
        for kind in ("node-added", "edge-added", "traversed", "path-found", "rejected"):
            ev = graph_db_audit_event(kind, 1, digest="sha256:abc")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["schema"], GRAPH_DB_SCHEMA)
            self.assertEqual(ev["version"], GRAPH_DB_VERSION)
        ev = graph_db_audit_event("node-added", 1)
        self.assertNotIn("digest", ev)
        with self.assertRaises(GraphValidationError):
            graph_db_audit_event("bogus", 1)
        with self.assertRaises(GraphValidationError):
            graph_db_audit_event("node-added", -1)
        with self.assertRaises(GraphValidationError):
            graph_db_audit_event("node-added", 1, digest="not-a-pin")

    def test_properties_copy_isolation(self):
        props = {"p": 1, "nested": [1, 2]}
        self.g.add_node("n", 10, properties=props)
        props["p"] = 999
        props["nested"].append(3)
        self.assertEqual(dict(self.g.node("n").properties), {"p": 1, "nested": [1, 2]})


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import graph_db
        self.assertIsNone(graph_db.main())


if __name__ == "__main__":
    unittest.main()
