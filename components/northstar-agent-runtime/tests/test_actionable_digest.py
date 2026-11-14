"""Tests for the actionable digest: silent unless the fire condition holds.

The rule under test (from the source, musepalmetto's "PATTERN:
silent-unless-actionable alerting", 2026-11-12): the fire condition is
conjunctive -- severity AND impact AND legitimacy, all three, or nothing.
An unverifiable load-bearing attribute does *not* stop the alert; it
labels it and states both decision branches.  Credibility is the
false-alarm rate, not the hit rate.

The null-counting behaviour (every observed window gets a record) is a
Northstar extension, marked as such in the design doc.
"""
from __future__ import annotations

import unittest

from actionable_digest import (
    ActionableDigest,
    DigestError,
    FireCondition,
    DEFAULT_IMPACT_FLOOR,
    DEFAULT_SEVERITY_THRESHOLD,
)


def event(**overrides):
    """A well-formed actionable event; override one field per test."""
    base = {
        "severity": 0.9,
        "impact": 0.8,
        "legitimate": True,
        "summary": "listing under verified resale",
        "window_id": "w1",
    }
    base.update(overrides)
    return base


class ConjunctiveFireConditionTests(unittest.TestCase):
    """The fire condition is a conjunction: all three clauses or nothing."""

    def test_all_three_clauses_hold_fires(self):
        digest = ActionableDigest()
        result = digest.ingest(event())
        self.assertTrue(result.actionable)
        self.assertEqual(result.reason, "fired")
        self.assertIsNotNone(result.item)

    def test_missing_severity_clause_suppresses(self):
        digest = ActionableDigest()
        result = digest.ingest(event(severity=0.1))
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "severity_below_threshold")
        self.assertIsNone(result.item)

    def test_missing_impact_clause_suppresses(self):
        digest = ActionableDigest()
        result = digest.ingest(event(impact=0.1))
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "impact_below_floor")
        self.assertIsNone(result.item)

    def test_missing_legitimacy_clause_suppresses(self):
        digest = ActionableDigest()
        result = digest.ingest(event(legitimate=False))
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "not_legitimate")
        self.assertIsNone(result.item)

    def test_threshold_is_inclusive_at_the_boundary(self):
        digest = ActionableDigest(FireCondition(severity_threshold=0.9, impact_floor=0.8))
        result = digest.ingest(event(severity=0.9, impact=0.8))
        self.assertTrue(result.actionable)

    def test_evaluate_names_every_failed_clause(self):
        condition = FireCondition()
        fires, failed = condition.evaluate(0.1, 0.1, False)
        self.assertFalse(fires)
        self.assertEqual(set(failed), {"severity_below_threshold",
                                       "impact_below_floor", "not_legitimate"})

    def test_defaults_are_northstar_defaults_not_the_source_numbers(self):
        condition = FireCondition()
        self.assertEqual(condition.severity_threshold, DEFAULT_SEVERITY_THRESHOLD)
        self.assertEqual(condition.impact_floor, DEFAULT_IMPACT_FLOOR)
        # The source's ~35% under resale / $75 profit are household numbers
        # and are not copied into the thresholds.
        self.assertNotEqual(condition.severity_threshold, 0.35)
        self.assertNotEqual(condition.impact_floor, 75)

    def test_condition_rejects_non_finite_threshold(self):
        with self.assertRaises(DigestError):
            FireCondition(severity_threshold=float("nan"))
        with self.assertRaises(DigestError):
            FireCondition(impact_floor=float("inf"))


class UncertaintyLabelingTests(unittest.TestCase):
    """Fire anyway, label the uncertainty, state both branches."""

    def test_unverifiable_attribute_still_fires_and_is_marked_uncertain(self):
        digest = ActionableDigest()
        result = digest.ingest(event(unverifiable_attributes=["model"]))
        self.assertTrue(result.actionable)
        self.assertTrue(result.item.uncertain)
        self.assertEqual(result.item.unknown_attributes, ("model",))

    def test_both_decision_branches_are_stated(self):
        digest = ActionableDigest()
        result = digest.ingest(event(unverifiable_attributes=["model"]))
        branches = {b.attribute: b for b in result.item.branches}
        self.assertIn("model", branches)
        self.assertTrue(branches["model"].if_true)
        self.assertTrue(branches["model"].if_false)
        self.assertNotEqual(branches["model"].if_true, branches["model"].if_false)

    def test_caller_supplied_branches_are_kept_verbatim(self):
        digest = ActionableDigest()
        result = digest.ingest(event(
            unverifiable_attributes=["model"],
            branches={"model": {"if_true": "go look at the label in person",
                                "if_false": "drop it, no purchase"}}))
        branch = result.item.branches[0]
        self.assertEqual(branch.if_true, "go look at the label in person")
        self.assertEqual(branch.if_false, "drop it, no purchase")
        self.assertFalse(branch.synthetic)

    def test_unknown_is_never_asserted_as_fact(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest(event(unverifiable_attributes=["model"],
                                asserted_facts={"model": "laminate"}))
        self.assertEqual(digest.fired_items(), ())

    def test_a_clean_event_is_not_marked_uncertain(self):
        digest = ActionableDigest()
        result = digest.ingest(event())
        self.assertFalse(result.item.uncertain)
        self.assertEqual(result.item.unknown_attributes, ())
        self.assertEqual(result.item.branches, ())


class CredibilityTests(unittest.TestCase):
    """Credibility is the false-alarm rate, not the hit rate."""

    def test_false_alarm_rate_is_false_alarms_over_total_fired(self):
        digest = ActionableDigest()
        for _ in range(4):
            digest.ingest(event())
        fired = [item.seq for item in digest.fired_items()]
        digest.mark_alarm(fired[0], "false_alarm")
        digest.mark_alarm(fired[1], "false_alarm")
        digest.mark_alarm(fired[2], "true_alarm")
        digest.mark_alarm(fired[3], "true_alarm")
        credibility = digest.credibility()
        self.assertEqual(credibility.total_fired, 4)
        self.assertEqual(credibility.false_alarms, 2)
        self.assertEqual(credibility.true_alarms, 2)
        self.assertAlmostEqual(credibility.false_alarm_rate, 0.5)

    def test_rate_is_not_the_hit_rate(self):
        """Two false alarms out of four fired is a 0.5 false-alarm rate and
        a 0.5 hit rate -- the two differ in general, so check the sign of
        the relation, not just the number."""
        digest = ActionableDigest()
        for _ in range(4):
            digest.ingest(event())
        fired = [item.seq for item in digest.fired_items()]
        digest.mark_alarm(fired[0], "false_alarm")
        digest.mark_alarm(fired[1], "false_alarm")
        digest.mark_alarm(fired[2], "false_alarm")
        digest.mark_alarm(fired[3], "true_alarm")
        credibility = digest.credibility()
        hit_rate = credibility.true_alarms / credibility.total_fired
        self.assertAlmostEqual(credibility.false_alarm_rate, 0.75)
        self.assertAlmostEqual(hit_rate, 0.25)
        self.assertNotAlmostEqual(credibility.false_alarm_rate, hit_rate)

    def test_total_fired_zero_is_undefined_not_zero_and_not_one(self):
        digest = ActionableDigest()
        credibility = digest.credibility()
        self.assertEqual(credibility.total_fired, 0)
        self.assertIsNone(credibility.false_alarm_rate)
        self.assertTrue(credibility.undefined)
        self.assertNotEqual(credibility.false_alarm_rate, 0)
        self.assertNotEqual(credibility.false_alarm_rate, 1)

    def test_suppressed_events_do_not_dilute_the_rate(self):
        digest = ActionableDigest()
        digest.ingest(event(legitimate=False))
        digest.ingest(event())
        fired = [item.seq for item in digest.fired_items()]
        digest.mark_alarm(fired[0], "false_alarm")
        credibility = digest.credibility()
        self.assertEqual(credibility.total_fired, 1)
        self.assertAlmostEqual(credibility.false_alarm_rate, 1.0)

    def test_marking_an_unfired_seq_is_refused(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.mark_alarm(999, "false_alarm")

    def test_unknown_verdict_is_refused(self):
        digest = ActionableDigest()
        digest.ingest(event())
        fired = [item.seq for item in digest.fired_items()]
        with self.assertRaises(DigestError):
            digest.mark_alarm(fired[0], "maybe")


class NullCountingTests(unittest.TestCase):
    """Northstar extension: every observed window leaves a record."""

    def test_quiet_window_still_produces_a_record(self):
        digest = ActionableDigest()
        digest.ingest(event(legitimate=False))
        record = digest.digest_window("w1")
        self.assertEqual(record.window_id, "w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertGreater(record.suppressed_count, 0)
        self.assertEqual(record.last_seq, 1)
        self.assertEqual(record.items, ())

    def test_record_means_alive_and_absence_means_dead(self):
        digest = ActionableDigest()
        digest.ingest(event())
        alive = digest.record_for("w1")
        self.assertIsNotNone(alive)
        self.assertEqual(alive.actionable_count, 1)
        dead = digest.record_for("never-seen")
        self.assertIsNone(dead)

    def test_unseen_window_record_is_empty_but_present(self):
        digest = ActionableDigest()
        record = digest.digest_window("never-seen")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 0)
        self.assertEqual(record.items, ())

    def test_last_seq_tracks_the_last_ingested_event(self):
        digest = ActionableDigest()
        digest.ingest(event(window_id="w1"))
        digest.ingest(event(window_id="w1", legitimate=False))
        record = digest.digest_window("w1")
        self.assertEqual(record.last_seq, 2)
        self.assertEqual(record.window_last_seq, 2)
        self.assertEqual(record.actionable_count, 1)
        self.assertEqual(record.suppressed_count, 1)

    def test_windows_are_counted_separately(self):
        digest = ActionableDigest()
        digest.ingest(event(window_id="w1"))
        digest.ingest(event(window_id="w2", legitimate=False))
        self.assertEqual(digest.digest_window("w1").actionable_count, 1)
        self.assertEqual(digest.digest_window("w2").actionable_count, 0)
        self.assertEqual(digest.digest_window("w2").suppressed_count, 1)
        self.assertEqual(set(digest.windows()), {"w1", "w2"})


class SilenceAndFailClosedTests(unittest.TestCase):
    """Default silence; malformed events are refused, not guessed."""

    def test_narrative_event_is_always_suppressed(self):
        digest = ActionableDigest()
        result = digest.ingest({"narrative": True, "summary": "watcher started",
                                "window_id": "w1"})
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "narrative_event")
        self.assertEqual(digest.digest_window("w1").actionable_count, 0)

    def test_status_kind_event_is_always_suppressed(self):
        digest = ActionableDigest()
        result = digest.ingest({"kind": "status", "summary": "still running",
                                "window_id": "w1"})
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "narrative_event")

    def test_narrative_event_is_counted_not_lost(self):
        digest = ActionableDigest()
        digest.ingest({"narrative": True, "summary": "heartbeat", "window_id": "w1"})
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 1)

    def test_missing_severity_is_refused(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest({"impact": 0.8, "legitimate": True})
        self.assertEqual(digest.fired_items(), ())

    def test_missing_impact_is_refused(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest({"severity": 0.9, "legitimate": True})

    def test_missing_legitimate_is_refused(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest({"severity": 0.9, "impact": 0.8})

    def test_refused_event_is_not_counted(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest({"impact": 0.8, "legitimate": True, "window_id": "w1"})
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 0)

    def test_out_of_range_severity_is_refused(self):
        digest = ActionableDigest()
        with self.assertRaises(DigestError):
            digest.ingest(event(severity=1.5))

    def test_default_silence_leaves_nothing_to_show(self):
        digest = ActionableDigest()
        digest.ingest(event(severity=0.2, impact=0.1))
        digest.ingest(event(legitimate=False))
        digest.ingest({"narrative": True, "summary": "tick", "window_id": "w1"})
        self.assertEqual(digest.fired_items(), ())
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 3)


class RealPathTests(unittest.TestCase):
    """The three paths from the source's instance, driven end to end."""

    def test_path_a_unverifiable_model_still_fires_labelled_with_both_branches(self):
        """The source's instance: a $350 listing against a $400 ceiling with
        the model unverifiable.  The alert fires, labelled model-unconfirmed,
        and the human's next step is a check, not a decision."""
        digest = ActionableDigest()
        result = digest.ingest({
            "severity": 0.95,
            "impact": 0.9,
            "legitimate": True,
            "unverifiable_attributes": ["model"],
            "summary": "Takamine 350 vs 400 ceiling, 45% under verified resale",
            "window_id": "w1",
            "branches": {
                "model": {
                    "if_true": "if the model is genuine: go look at the label in person",
                    "if_false": "if the model is not genuine: drop the candidate, no purchase",
                },
            },
        })
        self.assertTrue(result.actionable)
        item = result.item
        self.assertTrue(item.uncertain)
        self.assertEqual(item.unknown_attributes, ("model",))
        branch = item.branches[0]
        self.assertIn("look at the label", branch.if_true)
        self.assertIn("no purchase", branch.if_false)
        # The unknown is never stated as a fact.
        self.assertNotIn("model", item.as_dict().get("asserted_facts", {}))
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 1)
        self.assertEqual(record.suppressed_count, 0)

    def test_path_b_one_missing_clause_suppresses_and_is_counted(self):
        digest = ActionableDigest()
        result = digest.ingest({
            "severity": 0.95,
            "impact": 0.9,
            "legitimate": False,
            "summary": "listing looks illegitimate",
            "window_id": "w1",
        })
        self.assertFalse(result.actionable)
        self.assertEqual(result.reason, "not_legitimate")
        self.assertIsNone(result.item)
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 1)

    def test_path_c_empty_window_still_yields_a_record(self):
        digest = ActionableDigest()
        digest.ingest({"severity": 0.95, "impact": 0.9, "legitimate": False,
                       "summary": "not legitimate", "window_id": "w1"})
        digest.ingest({"severity": 0.2, "impact": 0.9, "legitimate": True,
                       "summary": "low severity", "window_id": "w1"})
        record = digest.digest_window("w1")
        self.assertEqual(record.actionable_count, 0)
        self.assertEqual(record.suppressed_count, 2)
        self.assertEqual(record.last_seq, 2)
        self.assertEqual(record.items, ())
        # The record's presence is what tells the caller the pipe is alive.
        self.assertIsNotNone(digest.record_for("w1"))

    def test_no_record_at_all_is_the_dead_pipe_signal(self):
        digest = ActionableDigest()
        digest.ingest(event(window_id="w1"))
        self.assertIsNone(digest.record_for("w2"))
