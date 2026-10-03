"""Tests for provenance_taint (eighty-eighth batch, Guardians absorption)."""

import unittest

from provenance_taint import (
    AutomatonEngine,
    AutomatonState,
    AutomatonTransition,
    BudgetEnforcer,
    GateDecision,
    ProvenanceTaintGate,
    SecurityAutomaton,
    TaintRule,
    TaintTracker,
    TaintedValue,
    ToolTaintSpec,
    expr_names,
    find_tainted,
    gate_audit_event,
    safe_eval,
)


def _mail_policy():
    """The paper's demo: fetch_mail -> send_email taint + automaton."""
    specs = {
        "fetch_mail": ToolTaintSpec(
            name="fetch_mail", source_labels=("secret", "pii")
        ),
        "send_email": ToolTaintSpec(
            name="send_email", sink_params=("body", "to")
        ),
        "redact": ToolTaintSpec(
            name="redact", sanitizes=("mail_to_body",)
        ),
        "summarize": ToolTaintSpec(name="summarize"),
    }
    rules = [
        TaintRule(
            name="mail_to_body",
            source_tool="fetch_mail",
            source_labels=("secret", "pii"),
            sink_tool="send_email",
            sink_param="body",
        ),
    ]
    exfil_automaton = SecurityAutomaton(
        name="no_send_after_fetch",
        states=(
            AutomatonState("clean"),
            AutomatonState("saw_fetch"),
            AutomatonState("exfiltrated", is_error=True),
        ),
        initial_state="clean",
        transitions=(
            AutomatonTransition("clean", "fetch_mail", "saw_fetch"),
            AutomatonTransition("saw_fetch", "redact", "clean"),
            AutomatonTransition("saw_fetch", "send_email", "exfiltrated"),
        ),
    )
    return specs, rules, exfil_automaton


def _tainted_mail(tracker):
    return tracker.produce("fetch_mail", "INBOX: salary $200k, SSN 123-45-6789")


class TestSafeEval(unittest.TestCase):
    def test_literals_and_names(self):
        # '+' is not in the allowlist: must raise
        with self.assertRaises(ValueError):
            safe_eval("1 + 1", {})
        self.assertTrue(safe_eval("x == 'a'", {"x": "a"}))
        self.assertTrue(safe_eval("x != 'b' and y", {"x": "a", "y": True}))
        self.assertTrue(safe_eval("'@x' in to", {"to": "a@x"}))
        self.assertEqual(safe_eval("len(items)", {"items": [1, 2]}), 2)

    def test_disallowed_raises(self):
        for expr in (
            "__import__('os')",
            "f(x)",
            "[x for x in y]",
            "x.attr",
            "{'a': 1}",
            "lambda: 1",
        ):
            with self.assertRaises(ValueError, msg=expr):
                safe_eval(expr, {"x": 1, "y": [1], "f": len})

    def test_undefined_name_raises(self):
        with self.assertRaises(ValueError):
            safe_eval("nope == 1", {})

    def test_expr_names(self):
        self.assertEqual(expr_names("to == 'a' and len(x) > 1"), {"to", "x"})


class TestTaintConjunction(unittest.TestCase):
    def setUp(self):
        specs, rules, _ = _mail_policy()
        self.tracker = TaintTracker(specs, rules)

    def test_label_and_provenance_fires(self):
        mail = _tainted_mail(self.tracker)
        d = self.tracker.check_sink("send_email", {"body": mail, "to": "x"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "taint")
        self.assertIn("fetch_mail", d.reason)

    def test_label_without_provenance_does_not_fire(self):
        # Same labels, but the value did NOT come from fetch_mail: no fire.
        # This is the Guardians provenance check beating label-only taint.
        impostor = TaintedValue(
            raw="salary $200k",
            labels={"secret"},
            provenance={"unrelated_tool"},
            source_tool="unrelated_tool",
        )
        d = self.tracker.check_sink("send_email", {"body": impostor})
        self.assertTrue(d.allowed)

    def test_unlabeled_value_passes(self):
        d = self.tracker.check_sink(
            "send_email", {"body": TaintedValue(raw="hello")}
        )
        self.assertTrue(d.allowed)

    def test_nested_tainted_value_found(self):
        mail = _tainted_mail(self.tracker)
        d = self.tracker.check_sink(
            "send_email", {"body": {"parts": [mail]}, "to": "x"}
        )
        self.assertFalse(d.allowed)

    def test_sanitizer_marks_value(self):
        mail = _tainted_mail(self.tracker)
        clean = self.tracker.apply_sanitizers("redact", mail)
        self.assertIn("mail_to_body", clean.sanitized_for)
        d = self.tracker.check_sink("send_email", {"body": clean})
        self.assertTrue(d.allowed)

    def test_missing_spec_with_tainted_input_denies(self):
        tracker = TaintTracker({}, [
            TaintRule(
                name="any_to_mystery",
                source_tool="fetch_mail",
                source_labels=("secret",),
                sink_tool="mystery_tool",
                sink_param="*",
            )
        ])
        mail = TaintedValue(
            raw="x", labels={"secret"}, provenance={"fetch_mail"}
        )
        d = tracker.check_sink("mystery_tool", {"q": mail})
        self.assertFalse(d.allowed)
        self.assertIn("no taint spec", d.reason)

    def test_missing_spec_without_taint_allows(self):
        tracker = TaintTracker({}, [])
        d = tracker.check_sink("mystery_tool", {"q": "plain"})
        self.assertTrue(d.allowed)

    def test_derive_unions_labels_and_provenance(self):
        mail = _tainted_mail(self.tracker)
        derived = self.tracker.derive("summarize", "summary", {"m": mail})
        self.assertEqual(derived.labels, {"secret", "pii"})
        self.assertEqual(derived.provenance, {"summarize", "fetch_mail"})

    def test_conditional_rule_excuses_on_concrete_false(self):
        # Guardians' condition semantics: the condition describes when the
        # dangerous flow *holds*. Condition True -> fires; False -> excused.
        rule = TaintRule(
            name="cond",
            source_tool="fetch_mail",
            source_labels=("secret",),
            sink_tool="send_email",
            sink_param="body",
            condition="domain == 'external.example'",
        )
        tracker = TaintTracker(
            {"fetch_mail": ToolTaintSpec("fetch_mail", ("secret",)),
             "send_email": ToolTaintSpec("send_email", ("body",))},
            [rule],
        )
        mail = tracker.produce("fetch_mail", "data")
        d = tracker.check_sink(
            "send_email", {"body": mail, "domain": "internal.example"}
        )
        self.assertTrue(d.allowed)

    def test_conditional_rule_fires_on_symbolic(self):
        rule = TaintRule(
            name="cond",
            source_tool="fetch_mail",
            source_labels=("secret",),
            sink_tool="send_email",
            sink_param="body",
            condition="domain == 'internal.example'",
        )
        tracker = TaintTracker(
            {"fetch_mail": ToolTaintSpec("fetch_mail", ("secret",)),
             "send_email": ToolTaintSpec("send_email", ("body",))},
            [rule],
        )
        mail = tracker.produce("fetch_mail", "data")
        # 'domain' unknown -> symbolic -> rule applies conservatively.
        d = tracker.check_sink("send_email", {"body": mail})
        self.assertFalse(d.allowed)


class TestAutomatonEngine(unittest.TestCase):
    def setUp(self):
        _, _, automaton = _mail_policy()
        self.engine = AutomatonEngine([automaton])

    def test_send_after_fetch_denied(self):
        self.assertTrue(self.engine.observe("fetch_mail", {}).allowed)
        d = self.engine.observe("send_email", {"to": "a"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "automaton")
        self.assertIn("exfiltrated", d.reason)

    def test_redact_between_allows(self):
        self.engine.observe("fetch_mail", {})
        self.assertTrue(self.engine.observe("redact", {}).allowed)
        self.assertTrue(self.engine.observe("send_email", {"to": "a"}).allowed)

    def test_session_halted_after_violation(self):
        self.engine.observe("fetch_mail", {})
        self.engine.observe("send_email", {"to": "a"})
        d = self.engine.observe("summarize", {})
        self.assertFalse(d.allowed)
        self.assertIn("already in error state", d.reason)

    def test_unrelated_tool_keeps_state(self):
        self.assertTrue(self.engine.observe("summarize", {}).allowed)
        self.assertEqual(self.engine.states()["no_send_after_fetch"], ("clean",))

    def test_unparseable_condition_fires_fail_closed(self):
        automaton = SecurityAutomaton(
            name="strict",
            states=(AutomatonState("s0"), AutomatonState("bad", is_error=True)),
            initial_state="s0",
            transitions=(
                AutomatonTransition("s0", "tool_a", "bad",
                                    condition="(((unparseable"),
            ),
        )
        engine = AutomatonEngine([automaton])
        d = engine.observe("tool_a", {})
        self.assertFalse(d.allowed)
        self.assertIn("bad", d.reason)

    def test_symbolic_condition_fires_fail_closed(self):
        automaton = SecurityAutomaton(
            name="strict",
            states=(AutomatonState("s0"), AutomatonState("bad", is_error=True)),
            initial_state="s0",
            transitions=(
                AutomatonTransition("s0", "tool_a", "bad",
                                    condition="flag == 'yes'"),
            ),
        )
        engine = AutomatonEngine([automaton])
        # 'flag' not provided -> symbolic -> assume fires -> deny.
        d = engine.observe("tool_a", {})
        self.assertFalse(d.allowed)

    def test_concrete_false_condition_does_not_fire(self):
        automaton = SecurityAutomaton(
            name="lenient",
            states=(AutomatonState("s0"), AutomatonState("bad", is_error=True)),
            initial_state="s0",
            transitions=(
                AutomatonTransition("s0", "tool_a", "bad",
                                    condition="flag == 'yes'"),
            ),
        )
        engine = AutomatonEngine([automaton])
        d = engine.observe("tool_a", {"flag": "no"})
        self.assertTrue(d.allowed)
        self.assertEqual(engine.states()["lenient"], ("s0",))


class TestBudgetEnforcer(unittest.TestCase):
    def test_cap_enforced(self):
        b = BudgetEnforcer({"send_email": 2})
        self.assertTrue(b.check("send_email").allowed)
        b.record("send_email")
        self.assertTrue(b.check("send_email").allowed)
        b.record("send_email")
        d = b.check("send_email")
        self.assertFalse(d.allowed)
        self.assertIn("budget exceeded", d.reason)

    def test_tools_independent(self):
        b = BudgetEnforcer({"a": 1})
        b.record("a")
        self.assertFalse(b.check("a").allowed)
        self.assertTrue(b.check("b").allowed)  # unlisted: no cap

    def test_malformed_limit_fails_closed(self):
        for bad in (-1, True, "3", 2.5, None):
            b = BudgetEnforcer({"a": bad})
            d = b.check("a")
            self.assertFalse(d.allowed, msg=f"limit={bad!r}")
            self.assertIn("malformed", d.reason)

    def test_zero_cap_denies_immediately(self):
        b = BudgetEnforcer({"a": 0})
        self.assertFalse(b.check("a").allowed)


class TestCombinedGate(unittest.TestCase):
    def setUp(self):
        specs, rules, automaton = _mail_policy()
        self.gate = ProvenanceTaintGate(
            TaintTracker(specs, rules),
            AutomatonEngine([automaton]),
            BudgetEnforcer({"send_email": 10}),
        )

    def test_first_deny_wins_budget_first(self):
        gate = ProvenanceTaintGate(
            TaintTracker(*_mail_policy()[:2]),
            AutomatonEngine([_mail_policy()[2]]),
            BudgetEnforcer({"send_email": 0}),
        )
        d = gate.evaluate("send_email", {"body": "x"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "budget")

    def test_tainted_send_denied_by_taint(self):
        # Automaton would also deny, but budget passes and automaton is
        # checked first; use a fresh engine on clean state with taint only.
        specs, rules, _ = _mail_policy()
        gate = ProvenanceTaintGate(TaintTracker(specs, rules))
        mail = gate.tracker.produce("fetch_mail", "secret data")
        d = gate.evaluate("send_email", {"body": mail})
        self.assertFalse(d.allowed)
        self.assertEqual(d.check, "taint")

    def test_produce_result_wraps_and_sanitizes(self):
        specs, rules, _ = _mail_policy()
        gate = ProvenanceTaintGate(TaintTracker(specs, rules))
        mail = gate.tracker.produce("fetch_mail", "secret data")
        out = gate.produce_result("redact", "REDACTED", {"m": mail})
        self.assertEqual(out.labels, {"secret", "pii"})
        self.assertIn("mail_to_body", out.sanitized_for)

    def test_clean_flow_allows(self):
        d = self.gate.evaluate("summarize", {"q": "hello"})
        self.assertTrue(d.allowed)
        self.assertEqual(d.check, "taint")  # last check ran, all passed


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        d = GateDecision(False, "budget exceeded", "budget", {"used": 3})
        ev = gate_audit_event(d, "send_email", call_id="c1")
        self.assertEqual(ev["event"], "provenance_taint.decision")
        self.assertEqual(ev["tool"], "send_email")
        self.assertEqual(ev["call_id"], "c1")
        self.assertFalse(ev["allowed"])
        self.assertEqual(ev["check"], "budget")

    def test_find_tainted(self):
        v = TaintedValue(raw=1, labels={"a"})
        found = find_tainted({"x": [v, "plain"], "y": "plain2"})
        self.assertEqual(found, [v])


if __name__ == "__main__":
    unittest.main()
