"""Targeted tests for the personalization engine."""

import ast
import os
import unittest

from personalization import (
    PERSONALIZATION_VERSION,
    PERSONALIZATION_SCHEMA,
    EVENTS,
    OPERATORS,
    BadEventError,
    BadRuleError,
    BadVariantError,
    DuplicateExperimentError,
    DuplicateSegmentError,
    Personalization,
    PersonalizationError,
    SeqOrderError,
    UnknownExperimentError,
    UnknownSegmentError,
    personalization_audit_event,
)

_MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "personalization.py")


def _engine_with_basics():
    engine = Personalization()
    engine.define_segment(
        "pro", "Pro plan", 1, rules=[("plan", "eq", "pro")]
    )
    engine.define_experiment(
        "exp-1", "Experiment one", 2,
        variants=[("a", 60), ("b", 40)],
    )
    return engine


class VersionPinsTest(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(PERSONALIZATION_VERSION, "personalization.v1")
        self.assertEqual(PERSONALIZATION_SCHEMA, "northstar.personalization.v1")

    def test_vocabularies_pinned(self):
        self.assertIn("eq", OPERATORS)
        self.assertIn("contains", OPERATORS)
        self.assertIn("conversion", EVENTS)
        self.assertIn("purchase", EVENTS)


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        with open(_MODULE_PATH, encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        allowed = {
            "hashlib", "json", "threading", "dataclasses", "typing",
            "__future__", "os", "sys",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class DefineSegmentTest(unittest.TestCase):
    def test_define_segment_roundtrip(self):
        engine = Personalization()
        record = engine.define_segment(
            "new", "New users", 1,
            rules=[("signup_days_ago", "lte", 7)],
            description="recent signups",
        )
        self.assertTrue(record.verify())
        self.assertEqual(engine.segment_record("new").digest, record.digest)
        self.assertEqual(engine.segment_ids(), ("new",))

    def test_define_segment_duplicate_refused(self):
        engine = _engine_with_basics()
        with self.assertRaises(DuplicateSegmentError):
            engine.define_segment("pro", "Pro again", 3)

    def test_define_segment_bad_rules_refused(self):
        engine = Personalization()
        with self.assertRaises(BadRuleError):
            engine.define_segment("x", "X", 1, rules=[("plan", "bogus-op", "pro")])
        with self.assertRaises(BadRuleError):
            engine.define_segment("y", "Y", 2, rules=[("plan", "in", [])])
        with self.assertRaises(PersonalizationError):
            engine.define_segment("", "Empty", 3)


class DefineExperimentTest(unittest.TestCase):
    def test_define_experiment_roundtrip(self):
        engine = Personalization()
        record = engine.define_experiment(
            "e2", "Two variants", 1, variants=[("control", 70), ("v2", 30)]
        )
        self.assertTrue(record.verify())
        self.assertEqual(engine.experiment_ids(), ("e2",))

    def test_define_experiment_bad_weights_refused(self):
        engine = Personalization()
        with self.assertRaises(BadVariantError):
            engine.define_experiment(
                "bad", "Bad", 1, variants=[("a", 60), ("b", 30)]
            )
        with self.assertRaises(BadVariantError):
            engine.define_experiment(
                "dup", "Dup", 2, variants=[("a", 50), ("a", 50)]
            )


class SegmentMatchTest(unittest.TestCase):
    def test_segment_matches_and_misses(self):
        engine = _engine_with_basics()
        hit = engine.segment("u1", 3, {"plan": "pro"})
        self.assertTrue(hit.verify())
        self.assertEqual(hit.segment_ids, ("pro",))
        miss = engine.segment("u2", 4, {"plan": "free"})
        self.assertEqual(miss.segment_ids, ())
        # Missing attribute: fail-closed non-match, not an exception.
        unknown = engine.segment("u3", 5, {})
        self.assertEqual(unknown.segment_ids, ())

    def test_segment_lookups(self):
        engine = _engine_with_basics()
        with self.assertRaises(UnknownSegmentError):
            engine.segment_record("nope")


class VariantTest(unittest.TestCase):
    def test_variant_stable_and_idempotent(self):
        engine = _engine_with_basics()
        first = engine.variant("u1", "exp-1", 3)
        self.assertTrue(first.verify())
        self.assertIn(first.variant_id, ("a", "b"))
        second = engine.variant("u1", "exp-1", 4)
        self.assertIs(second, first)  # stable, no new record
        other = engine.variant("u2", "exp-1", 5)
        self.assertIn(other.variant_id, ("a", "b"))

    def test_variant_unknown_experiment(self):
        engine = _engine_with_basics()
        with self.assertRaises(UnknownExperimentError):
            engine.variant("u1", "nope", 3)


class TrackTest(unittest.TestCase):
    def test_track_roundtrip(self):
        engine = _engine_with_basics()
        evt = engine.track(
            "u1", "conversion", 3, value=42,
            segment_id="pro", experiment_id="exp-1", variant_id="a",
        )
        self.assertTrue(evt.verify())
        self.assertEqual(len(engine.events()), 1)

    def test_track_bad_inputs_refused(self):
        engine = _engine_with_basics()
        with self.assertRaises(BadEventError):
            engine.track("u1", "unknown-event", 3)
        with self.assertRaises(UnknownSegmentError):
            engine.track("u1", "click", 4, segment_id="nope")
        with self.assertRaises(BadEventError):
            engine.track("u1", "click", 5, variant_id="a")  # no experiment


class SeqAndAuditTest(unittest.TestCase):
    def test_seq_strictly_increasing(self):
        engine = _engine_with_basics()
        engine.segment("u1", 3, {"plan": "pro"})
        with self.assertRaises(SeqOrderError):
            engine.segment("u1", 3, {"plan": "pro"})
        with self.assertRaises(SeqOrderError):
            engine.track("u1", "click", 2)

    def test_audit_shapes(self):
        engine = _engine_with_basics()
        engine.segment("u1", 3, {"plan": "pro"})
        kinds = [e["kind"] for e in engine.audit_log()]
        self.assertIn("personalization.segment-defined", kinds)
        self.assertIn("personalization.segment-assigned", kinds)
        for event in engine.audit_log():
            self.assertEqual(event["schema"], "audit.ndjson/1")
        with self.assertRaises(PersonalizationError):
            personalization_audit_event("bogus", 1)


class MainTest(unittest.TestCase):
    def test_main_runs(self):
        import personalization as module

        module.main()


if __name__ == "__main__":
    unittest.main()
