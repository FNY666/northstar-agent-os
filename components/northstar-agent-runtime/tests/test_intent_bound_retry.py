"""Tests for the intent-bounded retry gate (``intent_bound_retry``).

The gate is the third layer of Northstar's retry story: ``retry_config``
sets the budget, the hook decides the trigger, ``idempotency_manager`` stops
the same operation being applied twice, and this gate answers the remaining
question -- is *this* attempt still worth spending against the original
intent?

The tests below drive real paths through the module, not a mock of it: a
retry that would have succeeded is still refused when the deadline has
passed (the source's "send a notification before 5pm" example), a retry is
refused when the precondition's premise is gone, and a side-effecting action
with no declared intent bound is refused fail-closed.
"""
import unittest

from intent_bound_retry import (
    INTENT_BOUND_RETRY_VERSION,
    SCHEMA_PIN,
    IntentCheck,
    RetryDecision,
    gate,
    should_retry,
)


class _Clock:
    """A movable clock, so the 5pm example is driven by real epoch seconds."""

    def __init__(self, now: float) -> None:
        self.now = float(now)

    def __call__(self) -> float:
        return self.now


class IntentBoundRetryGateTests(unittest.TestCase):
    """The gate's own rules: deadline, precondition, and fail-closed."""

    def test_allows_retry_when_declaration_is_live_and_precondition_holds(self):
        """(a) deadline not passed + precondition true -> the retry is allowed."""
        check = IntentCheck(
            intent="read the build log",
            deadline=1_000.0,
            precondition=lambda: True,
            created_at=900.0,
        )
        decision, reason = gate(check, now=950.0)
        self.assertIs(decision, RetryDecision.ALLOW)
        self.assertIn("read the build log", reason)

    def test_denies_retry_after_deadline_even_though_the_tool_would_succeed(self):
        """(b) the source's 5pm example: past the deadline, no retry.

        The tool here would succeed -- the *call* is fine. The intent is not:
        "send a notification before 5pm" cannot be served after 5pm, so the
        retry must not happen.
        """
        five_pm = 17 * 3600.0
        check = IntentCheck(
            intent="send a notification before 5pm",
            deadline=five_pm,
            created_at=five_pm - 300.0,
        )
        tool_would_succeed = True
        self.assertTrue(tool_would_succeed)

        decision, reason = gate(check, now=five_pm + 300.0)
        self.assertIs(decision, RetryDecision.DENY_DEADLINE)
        self.assertIn("deadline", reason)
        self.assertIn("send a notification before 5pm", reason)
        self.assertFalse(
            should_retry(check, now=five_pm + 300.0),
            "a retry past the deadline must be refused even when it would succeed",
        )

    def test_denies_retry_when_precondition_is_false_though_deadline_is_live(self):
        """(c) deadline not passed but the precondition is false -> refuse."""
        check = IntentCheck(
            intent="notify the on-call engineer",
            deadline=1_000.0,
            precondition=lambda: False,
            created_at=900.0,
        )
        decision, reason = gate(check, now=950.0)
        self.assertIs(decision, RetryDecision.DENY_PRECONDITION)
        self.assertIn("precondition", reason)
        self.assertFalse(should_retry(check, now=950.0))

    def test_deadline_wins_when_both_conditions_are_broken(self):
        """Both broken -> DENY_DEADLINE: the deadline is the hard boundary."""
        check = IntentCheck(
            intent="notify the on-call engineer",
            deadline=500.0,
            precondition=lambda: False,
            created_at=400.0,
        )
        decision, reason = gate(check, now=600.0)
        self.assertIs(decision, RetryDecision.DENY_DEADLINE)
        self.assertIn("deadline", reason)

    def test_denies_retry_without_intent_check_when_the_action_has_side_effects(self):
        """(d) no intent check + side effects -> DENY_NO_INTENT (fail closed)."""
        decision, reason = gate(None, now=950.0, has_side_effects=True)
        self.assertIs(decision, RetryDecision.DENY_NO_INTENT)
        self.assertIn("no intent check", reason)
        self.assertFalse(
            should_retry(None, now=950.0, has_side_effects=True),
            "a side-effecting retry with no intent bound must be refused",
        )

    def test_explicit_allow_unbounded_permits_a_retry_without_intent_check(self):
        """(e) allow_unbounded=True -> allowed, and the reason says so."""
        decision, reason = gate(
            None, now=950.0, has_side_effects=True, allow_unbounded=True
        )
        self.assertIs(decision, RetryDecision.ALLOW)
        self.assertIn("explicitly allowed", reason)
        self.assertTrue(
            should_retry(
                None, now=950.0, has_side_effects=True, allow_unbounded=True
            )
        )

    def test_deadline_equal_to_now_counts_as_expired(self):
        """(f) boundary: deadline == now is expired (fail closed)."""
        check = IntentCheck(
            intent="send a notification before 5pm",
            deadline=1_000.0,
            created_at=900.0,
        )
        decision, reason = gate(check, now=1_000.0)
        self.assertIs(decision, RetryDecision.DENY_DEADLINE)
        self.assertIn("deadline", reason)
        self.assertFalse(should_retry(check, now=1_000.0))

    def test_precondition_is_reevaluated_on_every_gate_call(self):
        """The premise is re-read at gate time, never cached at creation."""
        alive = {"value": True}
        check = IntentCheck(
            intent="retry the write while the lock is free",
            deadline=1_000.0,
            precondition=lambda: alive["value"],
            created_at=900.0,
        )
        self.assertIs(gate(check, now=910.0)[0], RetryDecision.ALLOW)

        # The world changed after the check was created.
        alive["value"] = False
        decision, reason = gate(check, now=920.0)
        self.assertIs(decision, RetryDecision.DENY_PRECONDITION)
        self.assertIn("precondition", reason)

        # And it can come back.
        alive["value"] = True
        self.assertIs(gate(check, now=930.0)[0], RetryDecision.ALLOW)

    def test_should_retry_is_true_only_on_allow(self):
        """should_retry mirrors gate() exactly, whatever the decision."""
        live = IntentCheck(intent="ok", deadline=1_000.0, precondition=lambda: True)
        expired = IntentCheck(intent="late", deadline=500.0)
        broken = IntentCheck(intent="stale", deadline=1_000.0, precondition=lambda: False)

        self.assertTrue(should_retry(live, now=900.0))
        self.assertFalse(should_retry(expired, now=900.0))
        self.assertFalse(should_retry(broken, now=900.0))
        self.assertFalse(should_retry(None, now=900.0))
        self.assertTrue(
            should_retry(None, now=900.0, allow_unbounded=True),
        )

    def test_attempt_number_does_not_change_the_gate_decision(self):
        """The attempt budget lives in retry_config; the gate ignores attempt."""
        check = IntentCheck(
            intent="notify the on-call engineer",
            deadline=1_000.0,
            precondition=lambda: True,
            created_at=900.0,
        )
        for attempt in range(5):
            self.assertTrue(
                should_retry(check, now=950.0, attempt=attempt),
                "attempt number must not take part in the gate decision",
            )
            self.assertIs(gate(check, 950.0)[0], RetryDecision.ALLOW)

        expired = IntentCheck(intent="late", deadline=500.0)
        for attempt in range(5):
            self.assertFalse(
                should_retry(expired, now=900.0, attempt=attempt),
                "a high attempt count must not resurrect an expired intent",
            )


class IntentBoundRetryEdgeTests(unittest.TestCase):
    """Edges around the gate: side-effect-free calls, state, broken premises."""

    def test_side_effect_free_action_without_intent_check_is_allowed(self):
        """No side effects and no intent check -> nothing to gate, allowed."""
        decision, reason = gate(None, now=950.0, has_side_effects=False)
        self.assertIs(decision, RetryDecision.ALLOW)
        self.assertIn("no intent check", reason)

    def test_precondition_receives_the_call_state(self):
        """The precondition is evaluated against the caller's state."""
        check = IntentCheck(
            intent="retry the upload while the token is live",
            deadline=1_000.0,
            precondition=lambda state: state.get("token_live", False),
            created_at=900.0,
        )
        self.assertIs(
            gate(check, now=910.0, state={"token_live": True})[0],
            RetryDecision.ALLOW,
        )
        decision, reason = gate(check, now=910.0, state={"token_live": False})
        self.assertIs(decision, RetryDecision.DENY_PRECONDITION)
        self.assertIn("precondition", reason)

    def test_a_raising_precondition_is_treated_as_false(self):
        """An unevaluable premise does not license an attempt (fail closed)."""
        def broken() -> bool:
            raise RuntimeError("precondition probe exploded")

        check = IntentCheck(
            intent="retry the write while the lock is free",
            deadline=1_000.0,
            precondition=broken,
            created_at=900.0,
        )
        decision, _reason = gate(check, now=910.0)
        self.assertIs(decision, RetryDecision.DENY_PRECONDITION)
        self.assertFalse(should_retry(check, now=910.0))

    def test_deadline_is_absolute_not_relative(self):
        """A deadline far in the future stays open; it is epoch seconds."""
        check = IntentCheck(
            intent="send a notification before 5pm",
            deadline=17 * 3600.0,
            created_at=16 * 3600.0,
        )
        self.assertIs(gate(check, now=16 * 3600.0 + 1.0)[0], RetryDecision.ALLOW)
        self.assertIs(
            gate(check, now=17 * 3600.0 + 1.0)[0], RetryDecision.DENY_DEADLINE
        )

    def test_intent_check_serializes_without_the_callable(self):
        """The check is recordable as data; the callable is not serialized."""
        check = IntentCheck(
            intent="read the build log",
            deadline=1_000.0,
            precondition=lambda: True,
            created_at=900.0,
        )
        payload = check.as_dict()
        self.assertEqual(payload["schema"], SCHEMA_PIN)
        self.assertEqual(payload["intent"], "read the build log")
        self.assertEqual(payload["deadline"], 1_000.0)
        self.assertTrue(payload["has_precondition"])
        self.assertEqual(payload["created_at"], 900.0)
        self.assertNotIn("precondition", payload)
        self.assertEqual(INTENT_BOUND_RETRY_VERSION, "intent-bound-retry.v1")

    def test_the_four_decisions_are_distinct(self):
        """Every refusal reason is distinguishable."""
        values = [decision.value for decision in RetryDecision]
        self.assertEqual(len(values), len(set(values)))
        self.assertEqual(
            sorted(values),
            ["allow", "deny_deadline", "deny_no_intent", "deny_precondition"],
        )
        self.assertTrue(RetryDecision.ALLOW.allowed)
        for decision in RetryDecision:
            if decision is not RetryDecision.ALLOW:
                self.assertFalse(decision.allowed)


class PreconditionGuardSecondHalfTests(unittest.TestCase):
    """The `retT@157` guard: a precondition that is ABSENT.

    `_evaluate_precondition` has one constant return that is a real
    decision, not a default: when there is NO precondition, the
    premise is vacuously satisfied and the answer is True.  The planted
    fault flips that `return True` to `return False`.

    The intent-bound-retry slice's own suite exercised the *other*
    returns of the same function -- a precondition that holds, one that
    is false, one that raises -- but never the ABSENT case, so the
    constant was never read and the fault SURVIVED.

    With `return True -> return False`, a gate declared with no
    precondition would refuse every retry: an unevaluable premise is
    not the same as an unsatisfied one, and the two must not collapse.
    """

    def test_an_absent_precondition_is_satisfied(self):
        """The `retT@157` guard, taken one way.

        No precondition means no premise to violate, so the answer is
        True.
        """
        from intent_bound_retry import _evaluate_precondition

        self.assertIs(_evaluate_precondition(None, {"call": "state"}), True)

    def test_an_absent_precondition_is_satisfied_for_any_state(self):
        """The `retT@157` guard, independent of the state.

        The absence of a precondition does not depend on the state, so
        the answer must not either.
        """
        from intent_bound_retry import _evaluate_precondition

        self.assertIs(_evaluate_precondition(None, None), True)
        self.assertIs(_evaluate_precondition(None, 0), True)
        self.assertIs(_evaluate_precondition(None, ""), True)

    def test_a_precondition_that_holds_is_satisfied(self):
        """The control: the other returns still agree."""
        from intent_bound_retry import _evaluate_precondition

        self.assertIs(_evaluate_precondition(lambda state: True, {}), True)

    def test_a_precondition_that_is_false_is_not_satisfied(self):
        """The other side of the same function, so the two are not
        conflated: a FALSE precondition must still be False."""
        from intent_bound_retry import _evaluate_precondition

        self.assertIs(_evaluate_precondition(lambda state: False, {}), False)

    def test_a_precondition_that_raises_is_not_satisfied(self):
        """The fail-closed case: an unevaluable premise is False.

        This is the distinction the mutant erases.  An absent
        precondition is not an unevaluable one -- absence means there
        was never a premise to evaluate.
        """
        from intent_bound_retry import _evaluate_precondition

        def raising(state):
            raise RuntimeError("boom")

        self.assertIs(_evaluate_precondition(raising, {}), False)


if __name__ == "__main__":
    unittest.main()
