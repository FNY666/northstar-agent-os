"""Tests for the self-referential-trust probe corpus and detectors.

An agent's own outputs are never independent evidence: a claim whose
support graph contains no external node is self-grounded no matter how
many hops deep the chain runs. These tests pin the corpus shape (10
attack probes across 3 families, 3 benign controls) and the
self-grounding / citation-cycle / confidence-bootstrap / dangling-ref
detector semantics.
"""

import unittest

import self_referential_trust_probes as srt

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


def _claim(node_id, agent, refs=(), confidence=None, basis=()):
    return srt.build_node(
        node_id,
        "claim",
        agent_id=agent,
        refs=refs,
        asserted_confidence=confidence,
        confidence_basis=basis,
    )


def _external(node_id):
    return srt.build_node(node_id, "external")


class CorpusShapeTests(unittest.TestCase):
    def test_version_pinned(self):
        self.assertEqual(
            srt.SELF_REFERENTIAL_TRUST_VERSION, "self-referential-trust.v1"
        )

    def test_probe_count(self):
        attack = [p for p in srt.SELF_REFERENTIAL_TRUST_PROBES if p["expected"] == "deny"]
        benign = [p for p in srt.SELF_REFERENTIAL_TRUST_PROBES if p["expected"] == "allow"]
        self.assertEqual(len(attack), 10)
        self.assertEqual(len(benign), 3)

    def test_required_keys(self):
        for probe in srt.SELF_REFERENTIAL_TRUST_PROBES:
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])
                self.assertTrue(probe[key], probe["probe"])

    def test_probe_names_unique(self):
        names = srt.probe_names()
        self.assertEqual(len(names), len(set(names)))

    def test_families(self):
        families = {p["family"] for p in srt.SELF_REFERENTIAL_TRUST_PROBES}
        self.assertEqual(
            families, {"self-citation", "own-output-evidence", "trust-bootstrap"}
        )

    def test_deny_side_keywords_in_attack_interactions(self):
        for probe in srt.SELF_REFERENTIAL_TRUST_PROBES:
            if probe["expected"] != "deny":
                continue
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_expected_outcomes_complete(self):
        outcomes = srt.expected_outcomes()
        self.assertEqual(len(outcomes), len(srt.SELF_REFERENTIAL_TRUST_PROBES))
        self.assertTrue(all(v in ("deny", "allow") for v in outcomes.values()))

    def test_probe_by_name_round_trip(self):
        for name in srt.probe_names():
            self.assertEqual(srt.probe_by_name(name)["probe"], name)
        with self.assertRaises(KeyError):
            srt.probe_by_name("no-such-probe")

    def test_source_lists_all_probes(self):
        listed = list(srt.SELF_REFERENTIAL_TRUST_SOURCE["probes"]) + list(
            srt.SELF_REFERENTIAL_TRUST_SOURCE["benign"]
        )
        self.assertEqual(set(listed), set(srt.probe_names()))


class NodeValidationTests(unittest.TestCase):
    def test_claim_requires_agent(self):
        with self.assertRaises(srt.SelfReferentialTrustError):
            srt.build_node("c1", "claim")

    def test_external_must_not_name_agent(self):
        with self.assertRaises(srt.SelfReferentialTrustError):
            srt.build_node("e1", "external", agent_id="agent-a")

    def test_unknown_kind_rejected(self):
        with self.assertRaises(srt.SelfReferentialTrustError):
            srt.build_node("x1", "rumor", agent_id="agent-a")

    def test_confidence_bounds_enforced(self):
        with self.assertRaises(srt.SelfReferentialTrustError):
            _claim("c1", "agent-a", confidence=1.5)
        with self.assertRaises(srt.SelfReferentialTrustError):
            _claim("c1", "agent-a", confidence=True)

    def test_node_digest_round_trip(self):
        node = _claim("c1", "agent-a", confidence=0.7)
        digest = node.digest()
        self.assertTrue(digest.startswith("sha256:"))
        self.assertTrue(srt.verify_node_digest(node, digest))
        self.assertFalse(srt.verify_node_digest(node, digest[:-2] + "00"))

    def test_duplicate_node_id_rejected(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("c1", "agent-a"))
        with self.assertRaises(srt.SelfReferentialTrustError):
            graph.add(_claim("c1", "agent-a"))

    def test_unknown_node_lookup_raises(self):
        graph = srt.EvidenceGraph()
        with self.assertRaises(srt.SelfReferentialTrustError):
            graph.get("missing")


class SelfGroundingTests(unittest.TestCase):
    def test_single_self_cite_is_self_grounded(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("summary", "agent-a"))
        graph.add(_claim("clearance", "agent-a", refs=("summary",)))
        finding = graph.detect_self_grounding("clearance")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "self-grounded")
        self.assertTrue(finding.verify_digest())

    def test_two_hop_own_chain_is_self_grounded(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("draft", "agent-a"))
        graph.add(_claim("report", "agent-a", refs=("draft",)))
        graph.add(_claim("decision", "agent-a", refs=("report",)))
        finding = graph.detect_self_grounding("decision")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "self-grounded")

    def test_external_support_breaks_self_grounding(self):
        graph = srt.EvidenceGraph()
        graph.add(_external("measurement"))
        graph.add(_claim("summary", "agent-a"))
        graph.add(
            _claim("clearance", "agent-a", refs=("summary", "measurement"))
        )
        self.assertIsNone(graph.detect_self_grounding("clearance"))

    def test_unsupported_claim_is_self_grounded(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("bare", "agent-a"))
        finding = graph.detect_self_grounding("bare")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "self-grounded")


class CitationCycleTests(unittest.TestCase):
    def test_direct_cycle_detected(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("a", "agent-a", refs=("b",)))
        graph.add(_claim("b", "agent-a", refs=("a",)))
        finding = graph.detect_citation_cycle("a")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "citation-cycle")

    def test_no_cycle_no_finding(self):
        graph = srt.EvidenceGraph()
        graph.add(_external("measurement"))
        graph.add(_claim("c", "agent-a", refs=("measurement",)))
        self.assertIsNone(graph.detect_citation_cycle("c"))


class ConfidenceBootstrapTests(unittest.TestCase):
    def test_carried_forward_confidence_is_bootstrap(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("old", "agent-a", confidence=0.9))
        graph.add(
            _claim("new", "agent-a", confidence=0.9, basis=("old",))
        )
        finding = graph.detect_confidence_bootstrap("new")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "confidence-bootstrap")

    def test_externally_anchored_confidence_passes(self):
        graph = srt.EvidenceGraph()
        graph.add(_external("calibration-study"))
        graph.add(
            _claim("new", "agent-a", confidence=0.9, basis=("calibration-study",))
        )
        self.assertIsNone(graph.detect_confidence_bootstrap("new"))

    def test_no_basis_no_finding(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("solo", "agent-a", confidence=0.5))
        self.assertIsNone(graph.detect_confidence_bootstrap("solo"))


class DanglingReferenceTests(unittest.TestCase):
    def test_dangling_ref_is_a_finding(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("c1", "agent-a", refs=("never-recorded",)))
        finding = graph.detect_dangling_reference("c1")
        self.assertIsNotNone(finding)
        self.assertEqual(finding.finding, "dangling-reference")
        self.assertTrue(finding.verify_digest())

    def test_resolved_refs_no_finding(self):
        graph = srt.EvidenceGraph()
        graph.add(_external("measurement"))
        graph.add(_claim("c1", "agent-a", refs=("measurement",)))
        self.assertIsNone(graph.detect_dangling_reference("c1"))


class FindingsAggregationTests(unittest.TestCase):
    def test_findings_stable_order_and_digest_pinned(self):
        graph = srt.EvidenceGraph()
        graph.add(_claim("a", "agent-a", refs=("b",), confidence=0.8, basis=("b",)))
        graph.add(_claim("b", "agent-a", refs=("a",), confidence=0.8))
        findings = graph.findings("a")
        kinds = [f.finding for f in findings]
        # Stable detector order: dangling, cycle, self-grounded, bootstrap.
        self.assertEqual(
            kinds, ["citation-cycle", "self-grounded", "confidence-bootstrap"]
        )
        for finding in findings:
            self.assertTrue(finding.verify_digest())

    def test_benign_control_scenario_clean(self):
        # benign-own-output-with-external-anchor: own output as a step,
        # external measurement as the ground.
        graph = srt.EvidenceGraph()
        graph.add(_external("lab-measurement"))
        graph.add(_claim("summary", "agent-a"))
        graph.add(
            _claim(
                "decision",
                "agent-a",
                refs=("summary", "lab-measurement"),
                confidence=0.85,
                basis=("lab-measurement",),
            )
        )
        self.assertEqual(graph.findings("decision"), [])


if __name__ == "__main__":
    unittest.main()
