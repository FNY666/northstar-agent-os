"""Tests for formal_verif (explicit-state model checking interface)."""

import unittest

from formal_verif import (
    FORMAL_VERIF_SCHEMA,
    FORMAL_VERIF_VERSION,
    MAX_STATES,
    FormalSpec,
    InvariantReport,
    ModelResult,
    SpecError,
    SpecRecord,
    StateVar,
    formal_verif_audit_event,
)


def _counter_spec():
    """x counts 0 -> 1 -> 2, then deadlocks. 3 states, 2 transitions."""
    return FormalSpec(
        "counter",
        [StateVar("x", (0, 1, 2))],
        lambda s: s["x"] == 0,
        lambda s: [{"x": s["x"] + 1}] if s["x"] < 2 else [],
    )


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FORMAL_VERIF_VERSION, "formal-verif.v1")

    def test_schema_pin(self):
        self.assertEqual(FORMAL_VERIF_SCHEMA, "northstar.formal-verif.v1")


class TestStateVar(unittest.TestCase):
    def test_ok(self):
        v = StateVar("x", (0, 1))
        self.assertEqual(v.name, "x")
        self.assertEqual(v.domain, (0, 1))

    def test_empty_name_rejected(self):
        with self.assertRaises(SpecError):
            StateVar("", (0, 1))

    def test_non_str_name_rejected(self):
        with self.assertRaises(SpecError):
            StateVar(1, (0, 1))

    def test_empty_domain_rejected(self):
        with self.assertRaises(SpecError):
            StateVar("x", ())

    def test_duplicate_domain_values_rejected(self):
        with self.assertRaises(SpecError):
            StateVar("x", (0, 0))

    def test_bool_domain_value_rejected(self):
        with self.assertRaises(SpecError):
            StateVar("x", (True, False))

    def test_unhashable_domain_value_rejected(self):
        with self.assertRaises(SpecError):
            StateVar("x", ([1],))


class TestFormalSpecConstruction(unittest.TestCase):
    def test_ok(self):
        FormalSpec("s", [StateVar("x", (0,))], lambda s: True, lambda s: [])

    def test_empty_spec_name_rejected(self):
        with self.assertRaises(SpecError):
            FormalSpec("", [StateVar("x", (0,))], lambda s: True, lambda s: [])

    def test_empty_variables_rejected(self):
        with self.assertRaises(SpecError):
            FormalSpec("s", [], lambda s: True, lambda s: [])

    def test_duplicate_var_names_rejected(self):
        with self.assertRaises(SpecError):
            FormalSpec(
                "s",
                [StateVar("x", (0,)), StateVar("x", (1,))],
                lambda s: True,
                lambda s: [],
            )

    def test_non_callable_init_rejected(self):
        with self.assertRaises(SpecError):
            FormalSpec("s", [StateVar("x", (0,))], "init", lambda s: [])

    def test_non_callable_next_rejected(self):
        with self.assertRaises(SpecError):
            FormalSpec("s", [StateVar("x", (0,))], lambda s: True, "next")


class TestSpecRecord(unittest.TestCase):
    def test_spec_record_shape(self):
        rec = _counter_spec().spec()
        self.assertIsInstance(rec, SpecRecord)
        self.assertEqual(rec.spec_name, "counter")
        self.assertTrue(rec.structural_digest.startswith("sha256:"))
        self.assertEqual(len(rec.structural_digest), len("sha256:") + 64)

    def test_digest_changes_with_shape(self):
        a = _counter_spec().spec().structural_digest
        b = FormalSpec(
            "counter",
            [StateVar("x", (0, 1, 2, 3))],
            lambda s: s["x"] == 0,
            lambda s: [],
        ).spec().structural_digest
        self.assertNotEqual(a, b)

    def test_digest_deterministic(self):
        a = _counter_spec().spec().structural_digest
        b = _counter_spec().spec().structural_digest
        self.assertEqual(a, b)

    def test_as_dict_pins(self):
        d = _counter_spec().spec().as_dict()
        self.assertEqual(d["version"], FORMAL_VERIF_VERSION)
        self.assertEqual(d["schema"], FORMAL_VERIF_SCHEMA)


class TestInvariants(unittest.TestCase):
    def test_add_and_list(self):
        spec = _counter_spec()
        spec.add_invariant("x-small", lambda s: s["x"] < 10)
        rec = spec.spec()
        self.assertEqual(rec.invariant_names, ("x-small",))

    def test_duplicate_invariant_rejected(self):
        spec = _counter_spec()
        spec.add_invariant("i", lambda s: True)
        with self.assertRaises(SpecError):
            spec.add_invariant("i", lambda s: True)

    def test_non_callable_rejected(self):
        spec = _counter_spec()
        with self.assertRaises(SpecError):
            spec.add_invariant("i", "not-callable")

    def test_unknown_invariant_check_rejected(self):
        with self.assertRaises(SpecError):
            _counter_spec().check_invariant("nope")


class TestModel(unittest.TestCase):
    def test_counter_model(self):
        result = _counter_spec().model()
        self.assertIsInstance(result, ModelResult)
        self.assertEqual(result.state_count, 3)
        self.assertEqual(result.transition_count, 2)
        self.assertEqual(result.diameter, 2)
        self.assertFalse(result.truncated)

    def test_deadlock_detected(self):
        result = _counter_spec().model()
        self.assertEqual(len(result.deadlock_states), 1)
        last = dict(result.deadlock_states[0])
        self.assertEqual(last["x"], 2)

    def test_no_deadlock_model(self):
        spec = FormalSpec(
            "loop",
            [StateVar("x", (0, 1))],
            lambda s: s["x"] == 0,
            lambda s: [{"x": 1 - s["x"]}],
        )
        result = spec.model()
        self.assertEqual(len(result.deadlock_states), 0)
        self.assertEqual(result.diameter, 1)

    def test_truncation_flag(self):
        result = _counter_spec().model(max_states=1)
        self.assertTrue(result.truncated)
        self.assertEqual(result.state_count, 1)

    def test_bad_max_states_rejected(self):
        with self.assertRaises(SpecError):
            _counter_spec().model(max_states=0)
        with self.assertRaises(SpecError):
            _counter_spec().model(max_states=True)

    def test_successor_out_of_domain_rejected(self):
        spec = FormalSpec(
            "badnext",
            [StateVar("x", (0, 1))],
            lambda s: s["x"] == 0,
            lambda s: [{"x": 99}],
        )
        with self.assertRaises(SpecError):
            spec.model()

    def test_successor_partial_state_rejected(self):
        spec = FormalSpec(
            "partial",
            [StateVar("x", (0, 1)), StateVar("y", (0, 1))],
            lambda s: True,
            lambda s: [{"x": 0}],
        )
        with self.assertRaises(SpecError):
            spec.model()

    def test_empty_init_rejected(self):
        spec = FormalSpec(
            "noinit",
            [StateVar("x", (0, 1))],
            lambda s: False,
            lambda s: [],
        )
        with self.assertRaises(SpecError):
            spec.model()

    def test_non_bool_init_rejected(self):
        spec = FormalSpec(
            "badinit",
            [StateVar("x", (0, 1))],
            lambda s: 1,
            lambda s: [],
        )
        with self.assertRaises(SpecError):
            spec.model()

    def test_model_result_as_dict(self):
        d = _counter_spec().model().as_dict()
        self.assertEqual(d["version"], FORMAL_VERIF_VERSION)
        self.assertEqual(d["schema"], FORMAL_VERIF_SCHEMA)
        self.assertEqual(d["state_count"], 3)


class TestCheckInvariant(unittest.TestCase):
    def test_holds(self):
        spec = _counter_spec()
        spec.add_invariant("x-le-2", lambda s: s["x"] <= 2)
        report = spec.check_invariant("x-le-2")
        self.assertIsInstance(report, InvariantReport)
        self.assertTrue(report.holds)
        self.assertIsNone(report.counterexample)
        self.assertEqual(report.states_checked, 3)

    def test_violated_with_counterexample(self):
        spec = _counter_spec()
        spec.add_invariant("x-lt-2", lambda s: s["x"] < 2)
        report = spec.check_invariant("x-lt-2")
        self.assertFalse(report.holds)
        self.assertIsNotNone(report.counterexample)
        trace = report.counterexample
        self.assertEqual(len(trace), 3)
        self.assertEqual(dict(trace[0])["x"], 0)
        self.assertEqual(dict(trace[-1])["x"], 2)
        # Trace is a valid chain of transitions.
        for prev, nxt in zip(trace, trace[1:]):
            self.assertIn(nxt, [tuple(sorted(n.items())) for n in [{"x": dict(prev)["x"] + 1}]])

    def test_non_bool_predicate_rejected(self):
        spec = _counter_spec()
        spec.add_invariant("i", lambda s: 1)
        with self.assertRaises(SpecError):
            spec.check_invariant("i")

    def test_report_as_dict_pins(self):
        spec = _counter_spec()
        spec.add_invariant("i", lambda s: True)
        d = spec.check_invariant("i").as_dict()
        self.assertEqual(d["version"], FORMAL_VERIF_VERSION)
        self.assertEqual(d["schema"], FORMAL_VERIF_SCHEMA)
        self.assertIsNone(d["counterexample_length"])

    def test_truncated_flag_propagates(self):
        spec = _counter_spec()
        spec.add_invariant("i", lambda s: True)
        report = spec.check_invariant("i", max_states=1)
        self.assertTrue(report.truncated)


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        ev = formal_verif_audit_event("modeled", "counter", 7, state_count=3)
        self.assertEqual(ev["event"], "formal-verif")
        self.assertEqual(ev["kind"], "modeled")
        self.assertEqual(ev["spec_name"], "counter")
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["fields"]["state_count"], 3)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            formal_verif_audit_event("nope", "counter", 1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(SpecError):
            formal_verif_audit_event("modeled", "counter", True)


if __name__ == "__main__":
    unittest.main()
