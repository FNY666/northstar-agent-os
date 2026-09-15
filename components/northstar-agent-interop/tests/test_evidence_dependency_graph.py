"""Tests for deterministic evidence dependency graphs and witnesses."""
from __future__ import annotations

import unittest

from evidence_dependency_graph import (
    ClaimDependency,
    DependencyGraphError,
    DependencyGraphWitness,
    DependencyProjection,
    EvidenceDependencyGraph,
    GraphWitnessVerdict,
    make_dependency_graph,
    make_graph_witness,
    project_dependencies,
    verify_graph_witness,
)
from evidence_state_projection import ClaimProjection, SCHEMA as PROJECTION_SCHEMA

D = lambda char: "sha256:" + char * 64


def direct(claim, *, state="supported", reason=(), unverified=()):
    if state == "unknown":
        return ClaimProjection(PROJECTION_SCHEMA, claim, state, False, (), (), (), tuple(sorted(reason)), tuple(sorted(unverified)))
    return ClaimProjection(
        PROJECTION_SCHEMA, claim, state, state == "supported",
        (D("c"),), (D("d"),), (D("e"),) if state == "conflicted" else (),
        tuple(sorted(reason)), tuple(sorted(unverified)),
    )


def graph(*nodes):
    return make_dependency_graph(nodes)


class GraphSchemaTests(unittest.TestCase):
    def test_graph_normalizes_node_and_edge_order(self):
        first = graph(
            ClaimDependency(D("b"), (D("a"),)),
            ClaimDependency(D("a"), ()),
        )
        self.assertEqual([node.claim_digest for node in first.nodes], [D("a"), D("b")])
        self.assertEqual(EvidenceDependencyGraph.from_dict(first.to_dict()), first)
        self.assertTrue(first.graph_digest.startswith("sha256:"))

    def test_duplicate_nodes_edges_self_dependencies_and_cycles_fail_closed(self):
        with self.assertRaises(DependencyGraphError):
            graph(ClaimDependency(D("a"), ()), ClaimDependency(D("a"), ()))
        with self.assertRaises(DependencyGraphError):
            graph(ClaimDependency(D("a"), (D("b"), D("b"))), ClaimDependency(D("b"), ()))
        with self.assertRaises(DependencyGraphError):
            graph(ClaimDependency(D("a"), (D("a"),)))
        with self.assertRaises(DependencyGraphError):
            graph(ClaimDependency(D("a"), (D("b"),)), ClaimDependency(D("b"), (D("a"),)))
        with self.assertRaises(DependencyGraphError):
            graph(ClaimDependency(D("a"), (D("b"),)))

    def test_graph_wire_form_is_strict(self):
        item = graph(ClaimDependency(D("a"), ()))
        with self.assertRaises(DependencyGraphError):
            EvidenceDependencyGraph.from_dict({**item.to_dict(), "extra": True})
        with self.assertRaises(DependencyGraphError):
            EvidenceDependencyGraph.from_dict({})


class DependencyProjectionTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = D("a"), D("b"), D("c")
        self.graph = graph(
            ClaimDependency(self.c, (self.a, self.b)),
            ClaimDependency(self.a, ()),
            ClaimDependency(self.b, ()),
        )

    def project(self, values):
        return project_dependencies(self.graph, values)

    def test_supported_dependencies_remain_supported_without_authorization(self):
        result = self.project({self.a: direct(self.a), self.b: direct(self.b), self.c: direct(self.c)})
        projected = result[self.c]
        self.assertEqual(projected.state, "supported")
        self.assertFalse(projected.actionable)
        self.assertEqual(projected.requires, (self.a, self.b))

    def test_blocked_prerequisite_propagates_blocked(self):
        result = self.project({
            self.a: direct(self.a, state="conflicted", reason=("root_mismatch",)),
            self.b: direct(self.b), self.c: direct(self.c),
        })
        projected = result[self.c]
        self.assertEqual(projected.state, "blocked")
        self.assertIn(self.a, projected.blocked_dependencies)
        self.assertIn("blocked_dependency:conflicted", projected.reasons)
        self.assertFalse(projected.actionable)

    def test_unknown_or_missing_prerequisite_propagates_unknown(self):
        unknown = self.project({
            self.a: direct(self.a, state="unknown", reason=("no_evidence",)),
            self.b: direct(self.b), self.c: direct(self.c),
        })[self.c]
        self.assertEqual(unknown.state, "unknown")
        self.assertIn(self.a, unknown.unknown_dependencies)

        missing = self.project({self.a: direct(self.a), self.c: direct(self.c)})[self.c]
        self.assertEqual(missing.state, "unknown")
        self.assertIn(self.b, missing.unknown_dependencies)
        self.assertIn("missing_direct_projection", missing.reasons)

    def test_direct_negative_state_dominates_dependencies(self):
        for state in ("conflicted", "insufficient", "unverifiable"):
            result = self.project({
                self.a: direct(self.a), self.b: direct(self.b),
                self.c: direct(self.c, state=state, reason=(state + "_reason",)),
            })[self.c]
            self.assertEqual(result.state, state)
            self.assertFalse(result.actionable)
            self.assertIn("direct_state:" + state, result.reasons)

    def test_direct_projection_unverified_is_preserved_through_dependency(self):
        result = self.project({
            self.a: direct(self.a, unverified=("same-key",)),
            self.b: direct(self.b), self.c: direct(self.c),
        })[self.c]
        self.assertEqual(result.state, "supported")
        self.assertIn("same-key", result.unverified)

    def test_projection_wire_is_strict(self):
        result = self.project({self.a: direct(self.a), self.b: direct(self.b), self.c: direct(self.c)})[self.c]
        self.assertEqual(DependencyProjection.from_dict(result.to_dict()), result)
        with self.assertRaises(DependencyGraphError):
            DependencyProjection.from_dict({**result.to_dict(), "extra": True})


class GraphWitnessTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = D("a"), D("b")
        self.graph = graph(ClaimDependency(self.b, (self.a,)), ClaimDependency(self.a, ()))
        self.direct = {self.a: direct(self.a, unverified=("same-key",)), self.b: direct(self.b)}
        self.witness = make_graph_witness(self.graph, self.direct)

    def test_witness_replays_all_graph_projections(self):
        verdict = verify_graph_witness(
            self.witness, self.graph, self.direct,
            expected_digest=self.witness.witness_digest,
        )
        self.assertIsInstance(verdict, GraphWitnessVerdict)
        self.assertEqual(verdict.state, "graph-witness-verified")
        self.assertFalse(verdict.actionable)
        self.assertIn("same-key", verdict.unverified)

    def test_missing_external_pin_is_explicit(self):
        verdict = verify_graph_witness(self.witness, self.graph, self.direct)
        self.assertEqual(verdict.state, "graph-witness-verified-unpinned")
        self.assertIn("graph_witness_digest_unpinned", verdict.unverified)

    def test_graph_direct_projection_state_or_digest_substitution_is_rejected(self):
        with self.assertRaises(DependencyGraphError):
            verify_graph_witness(
                self.witness, graph(ClaimDependency(self.a, ()), ClaimDependency(self.b, ())),
                self.direct, expected_digest=self.witness.witness_digest,
            )
        with self.assertRaises(DependencyGraphError):
            verify_graph_witness(
                self.witness, self.graph,
                {self.a: direct(self.a, state="insufficient"), self.b: direct(self.b)},
                expected_digest=self.witness.witness_digest,
            )
        forged = DependencyGraphWitness(
            self.witness.schema_version, self.witness.graph,
            self.witness.graph_digest, self.witness.direct_projections,
            self.witness.projections, "sha256:" + "f" * 64,
        )
        with self.assertRaises(DependencyGraphError):
            verify_graph_witness(forged, self.graph, self.direct,
                                 expected_digest=self.witness.witness_digest)


if __name__ == "__main__":
    unittest.main()
