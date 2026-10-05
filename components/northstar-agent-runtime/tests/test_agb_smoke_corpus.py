"""AGB smoke corpus: 30 synthetic probes wired into the metrics track."""
from __future__ import annotations

import unittest

import support  # noqa: F401

from agb_smoke_corpus import AGB_SMOKE_SPECS, AGB_SOURCE, describe
from governance_bench import METRIC_CORPUS, run_metric_corpus


class AgbSmokeSpecsTests(unittest.TestCase):
    def test_thirty_specs_six_categories_five_sectors(self):
        self.assertEqual(len(AGB_SMOKE_SPECS), 30)
        cats = {s["payload"]["agb_category"] for s in AGB_SMOKE_SPECS}
        sectors = {s["payload"]["agb_sector"] for s in AGB_SMOKE_SPECS}
        self.assertEqual(len(cats), 6)
        self.assertEqual(len(sectors), 5)

    def test_ids_unique_and_traceable(self):
        ids = [s["id"] for s in AGB_SMOKE_SPECS]
        self.assertEqual(len(set(ids)), 30)
        for s in AGB_SMOKE_SPECS:
            cat = s["payload"]["agb_category"]
            sector = s["payload"]["agb_sector"]
            self.assertEqual(s["id"], f"agb.{cat}.{sector}")
            self.assertEqual(
                s["payload"]["agb_template_id"], f"agb.en.{cat}.{sector}"
            )

    def test_every_spec_carries_attribution(self):
        self.assertEqual(AGB_SOURCE["license"], "MIT")
        self.assertTrue(AGB_SOURCE["synthetic"])
        self.assertIn("agentguardbench", AGB_SOURCE["repo"])

    def test_no_mock_agent_or_baseline_scores(self):
        blob = repr(AGB_SMOKE_SPECS).lower()
        self.assertNotIn("mockagent", blob)
        self.assertNotIn("injection_markers", blob)

    def test_benign_controls_are_allow_anchors(self):
        benign = [s for s in AGB_SMOKE_SPECS
                  if s["payload"]["agb_category"] == "benign_control"]
        self.assertEqual(len(benign), 5)
        for s in benign:
            self.assertTrue(s["expect_allowed"])

    def test_attack_shapes_are_deny_anchors(self):
        attacks = [s for s in AGB_SMOKE_SPECS
                   if s["payload"]["agb_category"] != "benign_control"]
        self.assertEqual(len(attacks), 25)
        for s in attacks:
            self.assertFalse(s["expect_allowed"])


class AgbSmokeCorpusWiredTests(unittest.TestCase):
    def test_probes_present_in_metric_corpus(self):
        agb = [p for p in METRIC_CORPUS if p.id.startswith("agb.")]
        self.assertEqual(len(agb), 30)
        self.assertEqual({p.family for p in agb}, {"agb-smoke"})

    def test_no_mismatches_against_gate(self):
        summary = run_metric_corpus()
        bad = [m for m in summary["mismatches"]
               if m["probe_id"].startswith("agb.")]
        self.assertEqual(bad, [])

    def test_describe_manifest(self):
        manifest = describe()
        self.assertEqual(manifest["n_probes"], 30)
        self.assertEqual(len(manifest["ids"]), 30)


if __name__ == "__main__":
    unittest.main()
