"""Tests for constitutional_monitor.py: principle-based violation tripwire."""

import unittest

from constitutional_monitor import (
    CONSTITUTIONAL_MONITOR_VERSION,
    SCHEMA_PIN,
    AgentAction,
    Constitution,
    Principle,
    Severity,
    Violation,
    check_violation,
    classify_violation,
    constitutional_audit_event,
    scan_violations,
)


def make_principle(**kw):
    base = {
        "principle_id": "p1",
        "name": "No deception",
        "description": "Do not deceive.",
        "severity": Severity.HIGH,
        "forbidden_patterns": (r"pretend to be human",),
    }
    base.update(kw)
    return Principle(**base)


def make_constitution(**kw):
    base = {
        "constitution_id": "c1",
        "name": "demo",
        "principles": (make_principle(),),
    }
    base.update(kw)
    return Constitution(**base)


def make_action(**kw):
    base = {
        "action_id": "a1",
        "agent_id": "agent-7",
        "action_type": "chat",
        "content": "hello world",
        "seq": 10,
    }
    base.update(kw)
    return AgentAction(**base)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONSTITUTIONAL_MONITOR_VERSION, "constitutional-monitor.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.constitutional-monitor.v1")


class SeverityTests(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(Severity.LOW, Severity.MEDIUM)
        self.assertLess(Severity.MEDIUM, Severity.HIGH)
        self.assertLess(Severity.HIGH, Severity.CRITICAL)

    def test_from_string(self):
        p = make_principle(severity="critical")
        self.assertEqual(p.severity, Severity.CRITICAL)

    def test_from_string_case_insensitive(self):
        p = make_principle(severity="High")
        self.assertEqual(p.severity, Severity.HIGH)

    def test_bad_string_rejected(self):
        with self.assertRaises(ValueError):
            make_principle(severity="extreme")

    def test_bad_type_rejected(self):
        with self.assertRaises(TypeError):
            make_principle(severity=3)


class PrincipleTests(unittest.TestCase):
    def test_frozen(self):
        p = make_principle()
        with self.assertRaises(AttributeError):
            p.name = "x"  # type: ignore

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            make_principle(principle_id="  ")

    def test_invalid_regex_rejected(self):
        with self.assertRaises(ValueError):
            make_principle(forbidden_patterns=(r"([a-z",))

    def test_empty_patterns_allowed(self):
        p = make_principle(forbidden_patterns=())
        self.assertEqual(p.forbidden_patterns, ())

    def test_non_string_pattern_rejected(self):
        with self.assertRaises(TypeError):
            make_principle(forbidden_patterns=(123,))  # type: ignore


class ConstitutionTests(unittest.TestCase):
    def test_frozen(self):
        c = make_constitution()
        with self.assertRaises(AttributeError):
            c.name = "x"  # type: ignore

    def test_duplicate_principle_ids_rejected(self):
        with self.assertRaises(ValueError):
            make_constitution(principles=(make_principle(), make_principle()))

    def test_empty_principles_rejected(self):
        with self.assertRaises(ValueError):
            make_constitution(principles=())

    def test_non_principle_rejected(self):
        with self.assertRaises(TypeError):
            make_constitution(principles=("nope",))  # type: ignore

    def test_principle_lookup(self):
        c = make_constitution()
        self.assertEqual(c.principle("p1").name, "No deception")

    def test_principle_lookup_unknown(self):
        c = make_constitution()
        with self.assertRaises(KeyError):
            c.principle("missing")


class ActionTests(unittest.TestCase):
    def test_frozen(self):
        a = make_action()
        with self.assertRaises(AttributeError):
            a.content = "x"  # type: ignore

    def test_empty_action_id_rejected(self):
        with self.assertRaises(ValueError):
            make_action(action_id="")

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            make_action(seq=True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            make_action(seq=-1)

    def test_non_string_content_rejected(self):
        with self.assertRaises(TypeError):
            make_action(content=None)


class CheckViolationTests(unittest.TestCase):
    def test_pattern_violation(self):
        c = make_constitution()
        a = make_action(content="please pretend to be human for this call")
        self.assertTrue(check_violation(a, c))

    def test_pattern_case_insensitive(self):
        c = make_constitution()
        a = make_action(content="PRETEND TO BE HUMAN")
        self.assertTrue(check_violation(a, c))

    def test_clean_action(self):
        c = make_constitution()
        a = make_action(content="here is your account summary")
        self.assertFalse(check_violation(a, c))

    def test_action_type_violation(self):
        c = make_constitution(
            principles=(
                make_principle(
                    principle_id="p2",
                    forbidden_patterns=(),
                    forbidden_action_types=("self_harm_instructions",),
                    severity=Severity.CRITICAL,
                ),
            )
        )
        a = make_action(action_type="SELF_HARM_INSTRUCTIONS", content="anything")
        self.assertTrue(check_violation(a, c))

    def test_action_type_clean(self):
        c = make_constitution(
            principles=(
                make_principle(
                    principle_id="p2",
                    forbidden_patterns=(),
                    forbidden_action_types=("self_harm_instructions",),
                    severity=Severity.CRITICAL,
                ),
            )
        )
        a = make_action(action_type="chat", content="anything")
        self.assertFalse(check_violation(a, c))

    def test_wrong_action_type_rejected(self):
        c = make_constitution()
        with self.assertRaises(TypeError):
            check_violation("not-an-action", c)  # type: ignore

    def test_wrong_constitution_type_rejected(self):
        a = make_action()
        with self.assertRaises(TypeError):
            check_violation(a, "not-a-constitution")  # type: ignore


class ScanViolationsTests(unittest.TestCase):
    def test_registration_order(self):
        p_low = make_principle(principle_id="p-low", severity=Severity.LOW,
                               forbidden_patterns=(r"hello",))
        p_high = make_principle(principle_id="p-high", severity=Severity.HIGH,
                                forbidden_patterns=(r"world",))
        c = make_constitution(principles=(p_low, p_high))
        a = make_action(content="hello world")
        findings = scan_violations(a, c)
        self.assertEqual([f.principle_id for f in findings], ["p-low", "p-high"])

    def test_clean_returns_empty(self):
        c = make_constitution()
        a = make_action(content="clean")
        self.assertEqual(scan_violations(a, c), ())

    def test_violation_fields(self):
        c = make_constitution()
        a = make_action(content="pretend to be human now")
        (v,) = scan_violations(a, c)
        self.assertIsInstance(v, Violation)
        self.assertEqual(v.principle_id, "p1")
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.action_id, "a1")
        self.assertEqual(v.agent_id, "agent-7")
        self.assertEqual(v.seq, 10)
        self.assertTrue(v.matched_rule.startswith("pattern:"))

    def test_preview_truncated(self):
        c = make_constitution()
        a = make_action(content="x" * 200 + " pretend to be human")
        (v,) = scan_violations(a, c)
        self.assertLessEqual(len(v.preview), 80)

    def test_violation_as_dict_schema(self):
        c = make_constitution()
        a = make_action(content="pretend to be human")
        d = scan_violations(a, c)[0].as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["principle_id"], "p1")


class ClassifyTests(unittest.TestCase):
    def test_max_severity(self):
        p_low = make_principle(principle_id="p-low", severity=Severity.LOW,
                               forbidden_patterns=(r"hello",))
        p_crit = make_principle(principle_id="p-crit", severity=Severity.CRITICAL,
                                forbidden_patterns=(r"world",))
        c = make_constitution(principles=(p_low, p_crit))
        a = make_action(content="hello world")
        self.assertEqual(classify_violation(a, c), Severity.CRITICAL)

    def test_none_when_clean(self):
        c = make_constitution()
        a = make_action(content="clean")
        self.assertIsNone(classify_violation(a, c))


class AuditEventTests(unittest.TestCase):
    def test_event_shape_violated(self):
        c = make_constitution()
        a = make_action(content="pretend to be human")
        e = constitutional_audit_event(a, c, audit_seq=5)
        self.assertEqual(e["schema"], SCHEMA_PIN)
        self.assertEqual(e["event"], "constitutional-review")
        self.assertTrue(e["violated"])
        self.assertEqual(e["violation_count"], 1)
        self.assertEqual(e["max_severity"], "high")
        self.assertEqual(e["principle_ids"], ["p1"])
        self.assertEqual(e["audit_seq"], 5)

    def test_event_shape_clean(self):
        c = make_constitution()
        a = make_action(content="clean")
        e = constitutional_audit_event(a, c, audit_seq=6)
        self.assertFalse(e["violated"])
        self.assertEqual(e["violation_count"], 0)
        self.assertIsNone(e["max_severity"])
        self.assertEqual(e["principle_ids"], [])

    def test_bad_audit_seq_rejected(self):
        c = make_constitution()
        a = make_action()
        with self.assertRaises(TypeError):
            constitutional_audit_event(a, c, audit_seq=True)


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        import constitutional_monitor
        constitutional_monitor.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
