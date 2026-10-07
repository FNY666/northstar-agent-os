"""Tests for cep_engine: deterministic complex-event pattern matching."""

import unittest

from cep_engine import (
    CEP_ENGINE_SCHEMA,
    CEP_ENGINE_VERSION,
    CEPEngine,
    CEPEngineError,
    DuplicatePatternError,
    EventError,
    Pattern,
    PatternError,
    PatternMatch,
    UnknownPatternError,
)


def _events(*type_seq_pairs):
    return [{"seq": seq, "type": t} for t, seq in type_seq_pairs]


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CEP_ENGINE_VERSION, "cep-engine.v1")

    def test_schema_pin(self):
        self.assertEqual(CEP_ENGINE_SCHEMA, "northstar.cep-engine.v1")


class DefinePatternTests(unittest.TestCase):
    def test_define_happy_path(self):
        engine = CEPEngine()
        pattern = engine.define_pattern("p", ["a", "b"])
        self.assertIsInstance(pattern, Pattern)
        self.assertEqual(pattern.name, "p")
        self.assertEqual(pattern.stage_count, 2)
        self.assertIsNone(pattern.max_span)
        self.assertTrue(pattern.digest.startswith("sha256:"))

    def test_define_callable_stage(self):
        engine = CEPEngine()
        engine.define_pattern("p", [lambda e: e.get("type") == "a"])
        self.assertEqual(engine.patterns(), ("p",))

    def test_define_attr_mapping_stage(self):
        engine = CEPEngine()
        engine.define_pattern("p", [{"type": "a", "k": 1}])
        self.assertEqual(engine.pattern("p").stage_count, 1)

    def test_define_duplicate_refused(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        with self.assertRaises(DuplicatePatternError):
            engine.define_pattern("p", ["b"])

    def test_define_empty_name(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern("", ["a"])

    def test_define_non_str_name(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern(123, ["a"])

    def test_define_empty_stages(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern("p", [])

    def test_define_bad_stage_type(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern("p", ["a", 42])

    def test_define_stages_must_be_sequence(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern("p", {"a": 1})

    def test_define_empty_str_stage(self):
        engine = CEPEngine()
        with self.assertRaises(PatternError):
            engine.define_pattern("p", [""])

    def test_pattern_frozen(self):
        engine = CEPEngine()
        pattern = engine.define_pattern("p", ["a"])
        with self.assertRaises(Exception):
            pattern.name = "q"

    def test_pattern_as_dict(self):
        engine = CEPEngine()
        pattern = engine.define_pattern("p", ["a", "b"])
        d = pattern.as_dict()
        self.assertEqual(d["schema"], CEP_ENGINE_SCHEMA)
        self.assertEqual(d["version"], CEP_ENGINE_VERSION)
        self.assertEqual(d["stage_count"], 2)

    def test_unknown_pattern_lookup(self):
        engine = CEPEngine()
        with self.assertRaises(UnknownPatternError):
            engine.pattern("nope")


class WithinTests(unittest.TestCase):
    def test_within_sets_bound(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        pattern = engine.within("p", 10)
        self.assertEqual(pattern.max_span, 10)

    def test_within_clears_with_none(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        engine.within("p", 10)
        pattern = engine.within("p", None)
        self.assertIsNone(pattern.max_span)

    def test_within_zero_allowed(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        self.assertEqual(engine.within("p", 0).max_span, 0)

    def test_within_unknown_pattern(self):
        engine = CEPEngine()
        with self.assertRaises(UnknownPatternError):
            engine.within("nope", 10)

    def test_within_negative_refused(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        with self.assertRaises(PatternError):
            engine.within("p", -1)

    def test_within_bool_refused(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        with self.assertRaises(PatternError):
            engine.within("p", True)

    def test_within_non_int_refused(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        with self.assertRaises(PatternError):
            engine.within("p", "10")


class MatchTests(unittest.TestCase):
    def test_match_two_stage(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        matches = engine.match("p", _events(("a", 1), ("b", 2)))
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertIsInstance(match, PatternMatch)
        self.assertEqual(match.event_seqs, (1, 2))
        self.assertEqual(match.start_seq, 1)
        self.assertEqual(match.end_seq, 2)
        self.assertEqual(match.span, 0 + 1)
        self.assertEqual(match.pattern, "p")
        self.assertTrue(match.digest.startswith("sha256:"))
        self.assertEqual(len(match.event_digests), 2)

    def test_match_skips_noise(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("a", 1), ("x", 2), ("y", 3), ("b", 4))
        matches = engine.match("p", events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_seqs, (1, 4))
        self.assertEqual(matches[0].span, 3)

    def test_match_earliest_completion(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("a", 1), ("b", 2), ("b", 3))
        matches = engine.match("p", events)
        self.assertEqual(matches[0].event_seqs, (1, 2))

    def test_match_second_occurrence_found(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("a", 1), ("b", 2), ("a", 3), ("b", 4))
        matches = engine.match("p", events)
        self.assertEqual([m.event_seqs for m in matches], [(1, 2), (3, 4)])

    def test_match_first_stage_anchored_no_duplicates(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("x", 1), ("a", 2), ("b", 3))
        matches = engine.match("p", events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_seqs, (2, 3))

    def test_match_callable_stage(self):
        engine = CEPEngine()
        engine.define_pattern("p", [lambda e: e.get("n", 0) > 5, "b"])
        events = [
            {"seq": 1, "n": 10, "type": "z"},
            {"seq": 2, "type": "b"},
        ]
        matches = engine.match("p", events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_seqs, (1, 2))

    def test_match_predicate_must_return_bool(self):
        engine = CEPEngine()
        engine.define_pattern("p", [lambda e: "yes"])
        with self.assertRaises(PatternError):
            engine.match("p", _events(("a", 1)))

    def test_match_attr_mapping_stage(self):
        engine = CEPEngine()
        engine.define_pattern("p", [{"type": "a", "k": 1}])
        events = [
            {"seq": 1, "type": "a", "k": 2},
            {"seq": 2, "type": "a", "k": 1},
        ]
        matches = engine.match("p", events)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].event_seqs, (2,))

    def test_match_within_bound_enforced(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        engine.within("p", 5)
        events = _events(("a", 1), ("b", 100))
        matches = engine.match("p", events)
        self.assertEqual(matches, ())

    def test_match_within_boundary_inclusive(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        engine.within("p", 5)
        events = _events(("a", 1), ("b", 6))
        matches = engine.match("p", events)
        self.assertEqual(len(matches), 1)

    def test_match_three_stages(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b", "c"])
        events = _events(("a", 1), ("b", 2), ("c", 3))
        matches = engine.match("p", events)
        self.assertEqual(matches[0].event_seqs, (1, 2, 3))

    def test_match_incomplete_returns_nothing(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b", "c"])
        events = _events(("a", 1), ("b", 2))
        self.assertEqual(engine.match("p", events), ())

    def test_match_empty_events(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        self.assertEqual(engine.match("p", []), ())

    def test_match_unknown_pattern(self):
        engine = CEPEngine()
        with self.assertRaises(UnknownPatternError):
            engine.match("nope", _events(("a", 1)))

    def test_match_deterministic(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("a", 1), ("b", 2), ("a", 3), ("b", 4))
        first = engine.match("p", events)
        second = engine.match("p", events)
        self.assertEqual(
            [m.as_dict() for m in first], [m.as_dict() for m in second]
        )

    def test_match_digest_deterministic(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a", "b"])
        events = _events(("a", 1), ("b", 2))
        self.assertEqual(
            engine.match("p", events)[0].digest,
            engine.match("p", events)[0].digest,
        )

    def test_match_frozen(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        match = engine.match("p", _events(("a", 1)))[0]
        with self.assertRaises(Exception):
            match.span = 99

    def test_match_as_dict_shape(self):
        engine = CEPEngine()
        engine.define_pattern("p", ["a"])
        d = engine.match("p", _events(("a", 1)))[0].as_dict()
        self.assertEqual(d["schema"], CEP_ENGINE_SCHEMA)
        self.assertEqual(d["event_seqs"], [1])


class EventValidationTests(unittest.TestCase):
    def setUp(self):
        self.engine = CEPEngine()
        self.engine.define_pattern("p", ["a"])

    def test_non_mapping_event_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", ["a"])

    def test_missing_seq_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", [{"type": "a"}])

    def test_bool_seq_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", [{"seq": True, "type": "a"}])

    def test_negative_seq_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", [{"seq": -1, "type": "a"}])

    def test_unordered_seqs_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", _events(("a", 2), ("a", 1)))

    def test_duplicate_seqs_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", _events(("a", 1), ("a", 1)))

    def test_non_sequence_events_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", {"seq": 1, "type": "a"})

    def test_non_pinnable_payload_refused(self):
        with self.assertRaises(EventError):
            self.engine.match("p", [{"seq": 1, "type": "a", "x": float("nan")}])


class AuditEventTests(unittest.TestCase):
    def test_audit_shapes(self):
        engine = CEPEngine()
        event = engine.cep_audit_event("pattern-defined", 0, pattern="p")
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["kind"], "cep-engine.pattern-defined")
        self.assertEqual(event["module"], CEP_ENGINE_SCHEMA)
        self.assertEqual(event["version"], CEP_ENGINE_VERSION)
        self.assertEqual(event["seq"], 0)
        self.assertEqual(event["pattern"], "p")

    def test_audit_all_kinds(self):
        engine = CEPEngine()
        for kind in ("pattern-defined", "within-set", "matched", "scan-complete"):
            event = engine.cep_audit_event(kind, 1)
            self.assertEqual(event["kind"], f"cep-engine.{kind}")

    def test_audit_bad_kind(self):
        engine = CEPEngine()
        with self.assertRaises(ValueError):
            engine.cep_audit_event("bogus", 1)

    def test_audit_bad_seq(self):
        engine = CEPEngine()
        with self.assertRaises(ValueError):
            engine.cep_audit_event("matched", -1)
        with self.assertRaises(ValueError):
            engine.cep_audit_event("matched", True)


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        import cep_engine

        cep_engine.main()


class StdlibOnlyTests(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            Path(__file__).parent.parent.joinpath("cep_engine.py").read_text()
        )
        allowed = {"__future__", "hashlib", "json", "math", "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


if __name__ == "__main__":
    unittest.main()
