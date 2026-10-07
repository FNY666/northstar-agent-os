"""Tests for the artifact-graph lineage / diagnosis / integrity probe corpus.

The artifact graph is the audit-trail shape from the reasoning research:
diagnose by artifacts, not by the final score. These tests pin the corpus
shape (10 attack probes across 3 families, 3 benign controls) and the
lineage / diagnosis / integrity detector semantics.
"""

import unittest

import artifact_graph_probes as agp

EXPECTED_PROBE_NAMES = (
    # lineage-forgery
    "lineage-parent-swap",
    "lineage-fabricated-intermediate",
    "lineage-missing-parent-claim",
    "lineage-cycle-injection",
    # graph-diagnosis
    "diagnosis-decoy-cause",
    "diagnosis-pruned-branch",
    "diagnosis-merged-graphs",
    # artifact-integrity
    "integrity-content-edit",
    "integrity-metadata-edit",
    "integrity-reexport-fresh-graph",
)

EXPECTED_BENIGN_NAMES = (
    "benign-reproducible-rebuild",
    "benign-attested-prune",
    "benign-multi-parent-merge",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)


def _content(tag: str) -> str:
    from canonical_json import jcs_sha256_hex

    return "sha256:" + jcs_sha256_hex({"bytes": tag})


def _node(artifact_id, content_tag="c", parents=(), producer="pipeline", kind="model"):
    return agp.build_node(
        artifact_id,
        _content(content_tag),
        parents,
        producer,
        kind,
        provenance_domain="run-1",
    )


def _chain_graph(n: int = 3) -> tuple[agp.ArtifactGraph, list[agp.ArtifactNode]]:
    graph = agp.ArtifactGraph()
    nodes: list[agp.ArtifactNode] = []
    parents: tuple[str, ...] = ()
    for i in range(n):
        node = _node(f"artifact-{i}", content_tag=f"content-{i}", parents=parents)
        graph.add_node(node)
        nodes.append(node)
        parents = (node.digest,)
    return graph, nodes


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names(self):
        self.assertEqual(agp.probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self):
        self.assertEqual(agp.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_no_name_collisions(self):
        names = [*agp.probe_names(), *agp.benign_names()]
        self.assertEqual(len(names), len(set(names)))

    def test_required_keys(self):
        for probe in (*agp.ARTIFACT_GRAPH_PROBES, *agp.ARTIFACT_GRAPH_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{probe['probe']} missing {key}")

    def test_expected_values(self):
        for name, expected in agp.expected_outcomes().items():
            if name in agp.benign_names():
                self.assertEqual(expected, "allow")
            else:
                self.assertEqual(expected, "deny")

    def test_deny_side_keyword(self):
        for probe in agp.ARTIFACT_GRAPH_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} gate_interaction names no deny-side check",
            )

    def test_probes_by_family(self):
        self.assertEqual(len(agp.probes_by_family("lineage-forgery")), 4)
        self.assertEqual(len(agp.probes_by_family("graph-diagnosis")), 3)
        self.assertEqual(len(agp.probes_by_family("artifact-integrity")), 3)

    def test_probe_by_name_unknown_fails_closed(self):
        with self.assertRaises(KeyError):
            agp.probe_by_name("no-such-probe")

    def test_version_pinned(self):
        self.assertEqual(agp.ARTIFACT_GRAPH_VERSION, "artifact-graph.v1")


class NodeSemanticsTests(unittest.TestCase):
    def test_build_verify_round_trip(self):
        node = _node("a")
        self.assertTrue(agp.verify_node(node))

    def test_content_edit_breaks_verify(self):
        node = _node("a", content_tag="original")
        forged = agp.ArtifactNode(
            artifact_id=node.artifact_id,
            content_digest=_content("edited"),
            parent_digests=node.parent_digests,
            producer=node.producer,
            kind=node.kind,
            provenance_domain=node.provenance_domain,
            digest=node.digest,  # stale digest
        )
        self.assertFalse(agp.verify_node(forged))

    def test_metadata_edit_breaks_verify(self):
        node = _node("a", producer="trusted-pipeline")
        relabeled = agp.ArtifactNode(
            artifact_id=node.artifact_id,
            content_digest=node.content_digest,
            parent_digests=node.parent_digests,
            producer="approved-pipeline",  # relabeled, bytes untouched
            kind=node.kind,
            provenance_domain=node.provenance_domain,
            digest=node.digest,
        )
        # The label rides inside the digest body: relabeling is editing.
        self.assertFalse(agp.verify_node(relabeled))

    def test_bad_digest_format_rejected(self):
        with self.assertRaises(ValueError):
            agp.build_node("a", "not-a-digest", (), "p", "k", "d")

    def test_graph_rejects_unverifiable_node(self):
        node = _node("a")
        bad = agp.ArtifactNode(
            artifact_id=node.artifact_id,
            content_digest=node.content_digest,
            parent_digests=node.parent_digests,
            producer=node.producer,
            kind=node.kind,
            provenance_domain=node.provenance_domain,
            digest="sha256:" + "f" * 64,
        )
        graph = agp.ArtifactGraph()
        with self.assertRaises(ValueError):
            graph.add_node(bad)
        self.assertEqual(len(graph), 0)

    def test_graph_rejects_duplicate(self):
        graph = agp.ArtifactGraph()
        node = _node("a")
        graph.add_node(node)
        with self.assertRaises(ValueError):
            graph.add_node(node)


class IntegrityTests(unittest.TestCase):
    def test_clean_graph_verifies(self):
        graph, _ = _chain_graph(4)
        ok, findings = agp.verify_graph_integrity(graph)
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_missing_parent_is_finding_not_crash(self):
        graph = agp.ArtifactGraph()
        orphan = _node("orphan", parents=("sha256:" + "a" * 64,))
        graph.add_node(orphan)  # accepted: the record is evidence of pruning
        ok, findings = agp.verify_graph_integrity(graph)
        self.assertFalse(ok)
        kinds = [f["kind"] for f in findings]
        self.assertIn("missing_parent", kinds)

    def test_cycle_detected(self):
        # A true digest cycle is infeasible to build honestly: a node's
        # digest seals its parent links, so X<->Y would need a hash
        # fixpoint. The cycle detector therefore guards the *import*
        # path (graphs assembled from name-based links elsewhere). We
        # model that by injecting a malformed pair directly -- add_node
        # would (correctly) reject them for bad digests.
        graph = agp.ArtifactGraph()
        dx, dy = "sha256:" + "d" * 64, "sha256:" + "e" * 64
        x = agp.ArtifactNode("x", _content("x"), (dy,), "p", "k", "dom", dx)
        y = agp.ArtifactNode("y", _content("y"), (dx,), "p", "k", "dom", dy)
        graph._nodes[dx] = x
        graph._nodes[dy] = y
        ok, findings = agp.verify_graph_integrity(graph)
        self.assertFalse(ok)
        kinds = [f["kind"] for f in findings]
        self.assertIn("cycle", kinds)

    def test_diamond_is_not_a_cycle(self):
        graph = agp.ArtifactGraph()
        root = _node("root")
        graph.add_node(root)
        left = _node("left", parents=(root.digest,))
        right = _node("right", parents=(root.digest,))
        graph.add_node(left)
        graph.add_node(right)
        child = _node("child", parents=(left.digest, right.digest))
        graph.add_node(child)
        ok, findings = agp.verify_graph_integrity(graph)
        self.assertTrue(ok, findings)


class LineageWalkTests(unittest.TestCase):
    def test_walk_returns_ancestors_oldest_last(self):
        graph, nodes = _chain_graph(3)
        ancestors = agp.lineage_walk(graph, nodes[2].digest)
        self.assertEqual(ancestors, (nodes[1].digest, nodes[0].digest))

    def test_walk_diamond_visits_shared_once(self):
        graph = agp.ArtifactGraph()
        root = _node("root")
        graph.add_node(root)
        left = _node("left", parents=(root.digest,))
        right = _node("right", parents=(root.digest,))
        graph.add_node(left)
        graph.add_node(right)
        child = _node("child", parents=(left.digest, right.digest))
        graph.add_node(child)
        ancestors = agp.lineage_walk(graph, child.digest)
        self.assertEqual(len(ancestors), 3)
        self.assertEqual(len(set(ancestors)), 3)  # root visited once

    def test_walk_stops_at_cycle(self):
        # Same malformed-import setup as test_cycle_detected: the walk
        # must terminate on cyclic input instead of looping forever.
        graph = agp.ArtifactGraph()
        dx, dy = "sha256:" + "d" * 64, "sha256:" + "e" * 64
        x = agp.ArtifactNode("x", _content("x"), (dy,), "p", "k", "dom", dx)
        y = agp.ArtifactNode("y", _content("y"), (dx,), "p", "k", "dom", dy)
        graph._nodes[dx] = x
        graph._nodes[dy] = y
        ancestors = agp.lineage_walk(graph, dx)
        # Terminates (the assertion is that we get here at all) and
        # visits each cyclic node at most once.
        self.assertIsInstance(ancestors, tuple)
        self.assertEqual(len(ancestors), len(set(ancestors)))


class DiagnosisTests(unittest.TestCase):
    def test_diagnose_excludes_off_lineage_decoy(self):
        graph, nodes = _chain_graph(3)
        decoy = _node("decoy", parents=())  # outside the outcome's lineage
        graph.add_node(decoy)
        suspects, _ = agp.diagnose(graph, nodes[2].digest)
        self.assertNotIn(decoy.digest, suspects)
        self.assertEqual(set(suspects), {nodes[0].digest, nodes[1].digest})

    def test_diagnose_returns_suspect_set_not_verdict(self):
        graph, nodes = _chain_graph(3)
        suspects, _ = agp.diagnose(graph, nodes[2].digest)
        # A tuple of candidates -- never a single "the cause" string.
        self.assertIsInstance(suspects, tuple)
        self.assertGreater(len(suspects), 1)

    def test_diagnose_pruned_branch_surfaces_finding(self):
        graph = agp.ArtifactGraph()
        orphan = _node("orphan", parents=("sha256:" + "b" * 64,))
        graph.add_node(orphan)
        child = _node("child", parents=(orphan.digest,))
        graph.add_node(child)
        suspects, findings = agp.diagnose(graph, child.digest)
        kinds = [f["kind"] for f in findings]
        self.assertIn("missing_parent", kinds)
        self.assertIn(orphan.digest, suspects)

    def test_diagnose_unknown_outcome_fails_closed(self):
        graph, _ = _chain_graph(2)
        suspects, findings = agp.diagnose(graph, "sha256:" + "c" * 64)
        self.assertEqual(suspects, ())
        self.assertEqual(findings[0]["kind"], "unknown_outcome")

    def test_diagnose_keeps_provenance_domain(self):
        graph = agp.ArtifactGraph()
        clean = agp.build_node(
            "clean", _content("c"), (), "pipeline", "dataset", "run-clean"
        )
        dirty = agp.build_node(
            "dirty", _content("d"), (), "pipeline", "dataset", "run-dirty"
        )
        graph.add_node(clean)
        graph.add_node(dirty)
        merged = agp.build_node(
            "merged",
            _content("m"),
            (clean.digest, dirty.digest),
            "pipeline",
            "dataset",
            "run-merged",
        )
        graph.add_node(merged)
        suspects, _ = agp.diagnose(graph, merged.digest)
        domains = {
            graph.get(d).provenance_domain for d in suspects if graph.get(d)
        }
        self.assertEqual(domains, {"run-clean", "run-dirty"})


class HeadDigestTests(unittest.TestCase):
    def test_head_digest_stable(self):
        graph, _ = _chain_graph(3)
        self.assertEqual(agp.graph_head_digest(graph), agp.graph_head_digest(graph))

    def test_head_digest_changes_on_add(self):
        graph, nodes = _chain_graph(2)
        before = agp.graph_head_digest(graph)
        extra = _node("extra", parents=(nodes[1].digest,))
        graph.add_node(extra)
        self.assertNotEqual(before, agp.graph_head_digest(graph))

    def test_head_digest_order_independent(self):
        g1, n1 = _chain_graph(2)
        g2 = agp.ArtifactGraph()
        for node in reversed(n1):
            g2.add_node(node)
        self.assertEqual(agp.graph_head_digest(g1), agp.graph_head_digest(g2))


if __name__ == "__main__":
    unittest.main()
