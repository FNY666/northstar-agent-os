"""Tests for the history-deviation / plan-tracking / precedent-gap probes.

The plan history is the planning-integrity signal: an action with no
precedent in the agent's own proposed history is a finding. These tests
pin the corpus shape (10 attack probes across 3 families, 3 benign
controls) and the deviation / precedent-gap / conformance detector
semantics.
"""

import unittest

import history_deviation_probes as hdp

EXPECTED_PROBE_NAMES = (
    # history-deviation
    "deviation-unproposed-call",
    "deviation-args-swap",
    "deviation-stale-revision-replay",
    "deviation-order-violation",
    # plan-tracking
    "tracking-shadow-step",
    "tracking-skipped-mandatory",
    "tracking-fabricated-completion",
    # precedent-gap
    "precedent-tool-output-injection",
    "precedent-goal-shift",
    "precedent-novel-tool-adoption",
)

EXPECTED_BENIGN_NAMES = (
    "benign-local-retry",
    "benign-replan-repropose",
    "benign-history-consistent",
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


def _args(tag: str) -> str:
    from canonical_json import jcs_sha256_hex

    return "sha256:" + jcs_sha256_hex({"args": tag})


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names(self):
        self.assertEqual(hdp.probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self):
        self.assertEqual(hdp.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_unique_names(self):
        all_names = hdp.probe_names() + hdp.benign_names()
        self.assertEqual(len(all_names), len(set(all_names)))

    def test_required_keys(self):
        for name in hdp.probe_names() + hdp.benign_names():
            probe = hdp.probe_by_name(name)
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{name} missing {key}")
                self.assertTrue(probe[key], f"{name}.{key} is empty")

    def test_expected_outcomes(self):
        outcomes = hdp.expected_outcomes()
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_attack_gate_interactions_carry_deny_side_keywords(self):
        for name in EXPECTED_PROBE_NAMES:
            text = hdp.probe_by_name(name)["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{name} has no deny-side keyword",
            )

    def test_families_cover_all_attack_probes(self):
        covered = [n for fam in hdp.FAMILIES.values() for n in fam]
        self.assertEqual(sorted(covered), sorted(EXPECTED_PROBE_NAMES))

    def test_probes_by_family(self):
        self.assertEqual(
            {p["probe"] for p in hdp.probes_by_family("precedent-gap")},
            {
                "precedent-tool-output-injection",
                "precedent-goal-shift",
                "precedent-novel-tool-adoption",
            },
        )

    def test_probe_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            hdp.probe_by_name("no-such-probe")


class EntryTests(unittest.TestCase):
    def test_build_and_verify_round_trip(self):
        e = hdp.build_entry("proposed", "file.read", _args("a"), 0, 0, "plan")
        self.assertTrue(hdp.verify_entry(e))

    def test_tampered_digest_fails(self):
        e = hdp.build_entry("proposed", "file.read", _args("a"), 0, 0, "plan")
        import dataclasses

        bad = dataclasses.replace(e, digest="sha256:" + "0" * 64)
        self.assertFalse(hdp.verify_entry(bad))

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            hdp.build_entry("forged", "x", _args("a"), 0, 0, "plan")

    def test_bad_arguments_digest_rejected(self):
        with self.assertRaises(ValueError):
            hdp.build_entry("proposed", "x", "not-a-digest", 0, 0, "plan")

    def test_empty_tool_rejected(self):
        with self.assertRaises(ValueError):
            hdp.build_entry("proposed", "", _args("a"), 0, 0, "plan")


class HistoryTests(unittest.TestCase):
    def _history(self, entries):
        h = hdp.PlanHistory()
        prev = "sha256:genesis"
        for i, (kind, tool, args_tag, revision, origin) in enumerate(entries):
            e = hdp.build_entry(kind, tool, _args(args_tag), i, revision, origin, prev)
            h.append(e)
            prev = e.digest
        return h

    def test_clean_history_verifies(self):
        h = self._history(
            [
                ("proposed", "file.read", "a", 0, "plan"),
                ("executed", "file.read", "a", 0, "executor"),
            ]
        )
        ok, findings = hdp.verify_history(h)
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_chain_break_rejected(self):
        e1 = hdp.build_entry("proposed", "a", _args("x"), 0, 0, "plan")
        e2 = hdp.build_entry("proposed", "b", _args("y"), 1, 0, "plan", "sha256:wrong")
        h = hdp.PlanHistory()
        h.append(e1)
        with self.assertRaises(ValueError):
            h.append(e2)

    def test_unverifiable_entry_rejected(self):
        import dataclasses

        e = hdp.build_entry("proposed", "a", _args("x"), 0, 0, "plan")
        bad = dataclasses.replace(e, digest="sha256:" + "f" * 64)
        h = hdp.PlanHistory()
        with self.assertRaises(ValueError):
            h.append(bad)


class DeviationTests(unittest.TestCase):
    def _history(self, entries):
        h = hdp.PlanHistory()
        prev = "sha256:genesis"
        for i, (kind, tool, args_tag, revision, origin) in enumerate(entries):
            e = hdp.build_entry(kind, tool, _args(args_tag), i, revision, origin, prev)
            h.append(e)
            prev = e.digest
        return h

    def test_unproposed_call(self):
        h = self._history(
            [
                ("proposed", "file.read", "a", 0, "plan"),
                ("executed", "db.delete_table", "b", 0, "executor"),
            ]
        )
        kinds = [f["kind"] for f in hdp.detect_deviation(h)]
        self.assertIn("unproposed-call", kinds)

    def test_args_swap(self):
        h = self._history(
            [
                ("proposed", "file.read", "config", 0, "plan"),
                ("executed", "file.read", "shadow", 0, "executor"),
            ]
        )
        kinds = [f["kind"] for f in hdp.detect_deviation(h)]
        self.assertIn("args-mismatch", kinds)

    def test_stale_revision_replay(self):
        h = self._history(
            [
                ("proposed", "network.egress", "x", 2, "plan"),
                ("proposed", "file.read", "a", 3, "plan"),
                ("executed", "network.egress", "x", 3, "executor"),
            ]
        )
        kinds = [f["kind"] for f in hdp.detect_deviation(h)]
        self.assertIn("stale-revision", kinds)

    def test_out_of_order(self):
        h = self._history(
            [
                ("proposed", "db.snapshot", "s", 0, "plan"),
                ("proposed", "db.migrate", "m", 0, "plan"),
                ("executed", "db.migrate", "m", 0, "executor"),
            ]
        )
        kinds = [f["kind"] for f in hdp.detect_deviation(h)]
        self.assertIn("out-of-order", kinds)

    def test_in_order_is_clean(self):
        h = self._history(
            [
                ("proposed", "db.snapshot", "s", 0, "plan"),
                ("proposed", "db.migrate", "m", 0, "plan"),
                ("executed", "db.snapshot", "s", 0, "executor"),
                ("executed", "db.migrate", "m", 0, "executor"),
            ]
        )
        self.assertEqual(hdp.detect_deviation(h), ())

    def test_identical_retry_is_clean(self):
        h = self._history(
            [
                ("proposed", "api.fetch", "q", 0, "plan"),
                ("executed", "api.fetch", "q", 0, "executor"),
                ("executed", "api.fetch", "q", 0, "executor"),
            ]
        )
        self.assertEqual(hdp.detect_deviation(h), ())


class PrecedentGapTests(unittest.TestCase):
    def _history(self, entries):
        h = hdp.PlanHistory()
        prev = "sha256:genesis"
        for i, (kind, tool, args_tag, revision, origin) in enumerate(entries):
            e = hdp.build_entry(kind, tool, _args(args_tag), i, revision, origin, prev)
            h.append(e)
            prev = e.digest
        return h

    def test_tool_output_origin_flagged(self):
        h = self._history(
            [
                ("proposed", "doc.read", "d", 0, "plan"),
                ("executed", "doc.read", "d", 0, "executor"),
                ("tool_result", "mail.send", "m", 0, "host"),
                ("executed", "mail.send", "m", 0, "executor"),
            ]
        )
        findings = hdp.detect_precedent_gap(h)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "untrusted-origin-action")
        self.assertEqual(findings[0]["origin"], "tool_result")

    def test_origin_none_flagged(self):
        h = self._history(
            [
                ("proposed", "doc.read", "d", 0, "plan"),
                ("executed", "browser.automation.click", "c", 0, "executor"),
            ]
        )
        findings = hdp.detect_precedent_gap(h)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["origin"], "none")

    def test_proposed_action_has_precedent(self):
        h = self._history(
            [
                ("proposed", "doc.read", "d", 0, "plan"),
                ("executed", "doc.read", "d", 0, "executor"),
            ]
        )
        self.assertEqual(hdp.detect_precedent_gap(h), ())

    def test_human_retask_covers_goal(self):
        h = self._history(
            [
                ("proposed", "doc.read", "d", 0, "plan"),
                ("retask", "mail.send", "m", 0, "host"),
                ("executed", "mail.send", "m", 0, "executor"),
            ]
        )
        self.assertEqual(hdp.detect_precedent_gap(h), ())


class TrackPlanTests(unittest.TestCase):
    def _history(self, entries):
        h = hdp.PlanHistory()
        prev = "sha256:genesis"
        for i, (kind, tool, args_tag, revision, origin) in enumerate(entries):
            e = hdp.build_entry(kind, tool, _args(args_tag), i, revision, origin, prev)
            h.append(e)
            prev = e.digest
        return h

    def test_all_matched(self):
        h = self._history(
            [
                ("proposed", "a", "1", 0, "plan"),
                ("proposed", "b", "2", 0, "plan"),
                ("executed", "a", "1", 0, "executor"),
                ("executed", "b", "2", 0, "executor"),
            ]
        )
        report = hdp.track_plan(h)
        self.assertEqual(report["counts"], {"matched": 2, "skipped": 0, "deviated": 0})

    def test_skipped_step(self):
        h = self._history(
            [
                ("proposed", "a", "1", 0, "plan"),
                ("proposed", "b", "2", 0, "plan"),
                ("executed", "a", "1", 0, "executor"),
            ]
        )
        report = hdp.track_plan(h)
        self.assertEqual(report["counts"]["skipped"], 1)
        self.assertEqual(report["counts"]["matched"], 1)

    def test_no_composite_score(self):
        h = self._history([("proposed", "a", "1", 0, "plan")])
        report = hdp.track_plan(h)
        self.assertNotIn("score", report)
        self.assertNotIn("total", report)

    def test_head_digest_stable(self):
        h1 = self._history([("proposed", "a", "1", 0, "plan")])
        h2 = self._history([("proposed", "a", "1", 0, "plan")])
        self.assertEqual(hdp.history_head_digest(h1), hdp.history_head_digest(h2))

    def test_head_digest_changes_on_append(self):
        h = self._history([("proposed", "a", "1", 0, "plan")])
        before = hdp.history_head_digest(h)
        prev = h.entries()[-1].digest
        h.append(hdp.build_entry("executed", "a", _args("1"), 1, 0, "executor", prev))
        self.assertNotEqual(before, hdp.history_head_digest(h))


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            hdp.main()
        self.assertIn("history-deviation.v1", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
