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


class CategoryPayloadContractTests(unittest.TestCase):
    """Each attack category's payload must CARRY the scenario it names.

    WHY THIS CLASS EXISTS (measured 2026-11-25)
    --------------------------------------------
    The mutant census scores `agb_smoke_corpus.py` at **0/2**: both of
    its mutants SURVIVE, and they are the two category dispatch
    comparisons in `_build_specs`:

        if category == "tool_misuse":        -> the payload's
                                                 `recipients`/`draft_approved`
        if category == "privilege_abuse":    -> the payload's
                                                 `requester_role`

    The corpus DID carry the right values -- `recipients: "external"`,
    `draft_approved: False`, `requester_role: "analyst_read_only"` --
    but no test asserted them.  The suite checked the COUNT of specs,
    their IDS, their ATTRIBUTION, and their allow/deny anchors, and none
    of that can see whether the payload says what the category means.

    That is the §31 rule again: **a guard needs a crafted input**, and
    here the thing that needed the input was the ASSERTION.  A corpus
    whose payloads are wrong still passes every other test in the file,
    because the wrong payload is still a payload, still has the right
    number of keys, and still carries the right id.

    So these tests assert the CONTRACT between a category and the
    scenario fields it must carry -- which is the only thing the two
    comparisons in `_build_specs` decide.
    """

    def _by_category(self, category):
        return [
            s for s in AGB_SMOKE_SPECS
            if s["payload"]["agb_category"] == category
        ]

    def test_tool_misuse_specs_carry_the_external_draft_scenario(self):
        # A tool-misuse probe is "an unreviewed draft to all external
        # recipients".  If the payload drops those two fields, the probe
        # is a SendEmail with no scenario attached -- and it still
        # counts as a tool_misuse spec to every other test in the file.
        specs = self._by_category("tool_misuse")
        self.assertEqual(len(specs), 5)
        for s in specs:
            payload = s["payload"]
            self.assertEqual(
                payload.get("recipients"), "external",
                f"{s['id']} lost the external-recipients scenario",
            )
            self.assertIs(
                payload.get("draft_approved"), False,
                f"{s['id']} lost the unreviewed-draft scenario",
            )

    def test_privilege_abuse_specs_carry_the_read_only_requester(self):
        # A privilege-abuse probe is "a read-only role reaching for a
        # destructive tool".  The `requester_role` field is what makes
        # it that probe rather than a bare DeleteRecord.
        specs = self._by_category("privilege_abuse")
        self.assertEqual(len(specs), 5)
        for s in specs:
            self.assertEqual(
                s["payload"].get("requester_role"), "analyst_read_only",
                f"{s['id']} lost the read-only-requester scenario",
            )

    def test_the_scenario_fields_belong_to_no_other_category(self):
        # The other side of the same contract: the scenario fields are
        # CATEGORY-SPECIFIC.  If the `tool_misuse` branch fired for
        # every category, then every spec would carry `recipients`, and
        # the corpus would claim a dozen or so exfiltration probes it
        # does not have.
        for category in (
            "prompt_injection", "privacy_leakage", "memory_safety",
            "benign_control",
        ):
            for s in self._by_category(category):
                payload = s["payload"]
                self.assertNotIn(
                    "recipients", payload,
                    f"{s['id']} carries a tool-misuse scenario it does not own",
                )
                self.assertNotIn(
                    "draft_approved", payload,
                    f"{s['id']} carries a tool-misuse scenario it does not own",
                )
                self.assertNotIn(
                    "requester_role", payload,
                    f"{s['id']} carries a privilege-abuse scenario it does not own",
                )
