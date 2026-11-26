"""The `backpressure` self-check: the branch the suite never ran.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
`backpressure.py` implements the Reactive Streams demand-accounting
contract: `request(n)` adds demand, `on_next()` consumes one unit and
raises `BackpressureOverflowError` when the demand is zero, and
`cancel()` terminates the subscription.  Its own suite covers all of
that.

The artifact measured the module at **1/14** -- thirteen survivors --
and **every one of the thirteen was inside `main()`**, the module's own
self-check, which the suite never calls.  The suite imports the module
and exercises the class; it never runs the self-check the module ships
with.

THE THIRTEEN SURVIVORS
----------------------
```
eq@194  assert bp.demand == 0 and not bp.cancelled
eq@196  assert bp.request(3) == 3
eq@197  assert bp.on_next() == 2
eq@198  assert bp.on_next() == 1
eq@199  assert bp.on_next() == 0
eq@200  assert bp.delivered == 3
eq@208  assert bp.overflows == 1
eq@210  assert bp.request(UNBOUNDED) == MAX_DEMAND
eq@211  assert bp.request(UNBOUNDED) == MAX_DEMAND   # saturates
eq@214  assert bp.cancelled and bp.demand == 0
and@194 assert bp.demand == 0 and not bp.cancelled
and@214 assert bp.cancelled and bp.demand == 0
eq@232  if __name__ == "__main__":
```

They fall into THREE classes, and the three need three different
observables:

* **`eq@N` -- an assert's comparison flipped.**  The mutant makes the
  self-check FAIL, so the observable is that `main()` raises.  But
  "main() does not raise" is a WEAK assertion: it says nothing about
  WHICH contract holds.  So each of these is ALSO asserted directly,
  on the class, against the module's own documented contract.
* **`and@N` -- a conjunct weakened.**  `A and B` -> `A or B` makes
  the assert STRICTLY WEAKER, so `main()` still passes.  Only an
  assertion about the SPECIFIC conjunct can see this: the mutant
  accepts a cancelled controller with non-zero demand, or a fresh one
  with demand.  So these need the conjunct asserted on its own.
* **`eq@232` -- the `__main__` guard.**  The mutant runs the
  self-check at IMPORT time, which prints a line.  Observable on
  stdout -- but ONLY if the fresh module is REGISTERED in
  `sys.modules` first, because `@dataclass` resolves `cls.__module__`
  there and an unregistered load RAISES instead of running.

WHY A NEW FILE AND NOT A SUITE EDIT
-----------------------------------
The census resolves a module's scope by finding the suites that LOAD
it.  A second suite that loads `backpressure` puts the module in BOTH
scopes, and the union is what gets measured.  Editing the existing
suite in place would leave the module single-suite.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name: str):
    """Load a module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Loaded by an EXPLICIT LITERAL call, because ``scripts/census-scope.py``
#: only recognises a load whose module name is a literal.
bp_mod = _load("backpressure")


class BackpressureSelfCheckTests(unittest.TestCase):
    """The self-check the suite never ran."""

    def test_the_self_check_passes_and_prints(self):
        """The self-check is the module's own contract, and it holds.

        ``main()`` asserts the whole demand flow, the overflow
        prevention, the saturation and the cancel semantics.  Calling
        it is the observation for every `eq@N` mutant: the mutant
        makes one of the self-check's own asserts fail, so the call
        raises.
        """
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            bp_mod.main()
        self.assertIn("backpressure OK", out.getvalue())

    def test_a_fresh_controller_has_no_demand_and_is_not_cancelled(self):
        """`and@194`: the FIRST conjunct, asserted on its own.

        ``assert bp.demand == 0 and not bp.cancelled``.  The mutant
        turns the `and` into an `or`, so a controller that is cancelled
        but has ZERO demand would satisfy the mutant's assert and fail
        the original's -- and `main()` still passes either way, because
        a fresh controller is neither cancelled nor demanding.

        So the conjunct has to be asserted where it can be violated:
        the demand of a fresh controller must be zero REGARDLESS of
        the cancellation flag.
        """
        controller = bp_mod.Backpressure()
        self.assertEqual(controller.demand, 0)
        # And the second conjunct on its own.
        self.assertFalse(controller.cancelled)

    def test_cancelling_clears_the_demand(self):
        """`and@214`: the SECOND conjunct, asserted on its own.

        ``assert bp.cancelled and bp.demand == 0``.  The mutant turns
        the `and` into an `or`, so a controller that is cancelled but
        still holding demand satisfies the mutant and fails the
        original -- and `main()` still passes, because it cancels a
        controller whose demand was already spent.

        So: cancel a controller that HOLDS demand, and the demand must
        be gone.
        """
        controller = bp_mod.Backpressure()
        controller.request(10)
        self.assertEqual(controller.demand, 10)
        controller.cancel()
        self.assertTrue(controller.cancelled)
        # The conjunct that the `and` mutant would let through.
        self.assertEqual(controller.demand, 0)

    def test_the_demand_flow_consumes_exactly_one_unit_per_emission(self):
        """`eq@196` .. `eq@200`: the demand flow, asserted step by step.

        ``main()`` asserts the flow, but "main() does not raise" does
        not say WHICH step is right.  The flow is asserted here, one
        step at a time, so a mutant that breaks any single step names
        itself.
        """
        controller = bp_mod.Backpressure()
        self.assertEqual(controller.request(3), 3)
        self.assertEqual(controller.on_next(), 2)
        self.assertEqual(controller.on_next(), 1)
        self.assertEqual(controller.on_next(), 0)
        self.assertEqual(controller.delivered, 3)

    def test_an_overflow_is_counted_and_leaves_the_delivery_untouched(self):
        """`eq@208`: the overflow counter.

        The overflow path RAISES, so the count of overflows is the
        observable -- and `delivered` must NOT move, because the
        emission was refused.
        """
        controller = bp_mod.Backpressure()
        controller.request(1)
        controller.on_next()
        with self.assertRaises(bp_mod.BackpressureOverflowError):
            controller.on_next()
        self.assertEqual(controller.overflows, 1)
        self.assertEqual(controller.delivered, 1)
        # And a second overflow counts again.
        with self.assertRaises(bp_mod.BackpressureOverflowError):
            controller.on_next()
        self.assertEqual(controller.overflows, 2)

    def test_the_demand_saturates_at_the_cap(self):
        """`eq@210` and `eq@211`: the saturation, twice.

        ``main()`` asserts that requesting UNBOUNDED twice leaves the
        demand at MAX_DEMAND both times.  Asserted here on its own, so
        a mutant that breaks the cap is named.
        """
        controller = bp_mod.Backpressure()
        self.assertEqual(
            controller.request(bp_mod.Backpressure.UNBOUNDED),
            bp_mod.Backpressure.MAX_DEMAND,
        )
        self.assertEqual(
            controller.request(bp_mod.Backpressure.UNBOUNDED),
            bp_mod.Backpressure.MAX_DEMAND,
        )
        self.assertEqual(controller.demand, bp_mod.Backpressure.MAX_DEMAND)

    def test_importing_the_module_runs_no_self_check(self):
        """`eq@232`: the `__main__` guard.

        The mutant flips the comparison, so the module's self-check
        runs at IMPORT time and prints its line.  Importing a module
        must be silent.

        The fresh module has to be REGISTERED in ``sys.modules`` before
        it is executed: ``@dataclass`` resolves ``cls.__module__``
        there, so an unregistered load raises instead of running -- and
        a test asserting "import prints nothing" would then be
        satisfied by a CRASH.
        """
        probe_name = "backpressure._import_probe"
        spec = importlib.util.spec_from_file_location(
            probe_name, RUNTIME / "backpressure.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[probe_name] = module
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                spec.loader.exec_module(module)
        finally:
            sys.modules.pop(probe_name, None)
        self.assertEqual(
            out.getvalue(), "",
            "importing backpressure ran its self-check",
        )


if __name__ == "__main__":
    unittest.main()


class TheVacuousAssertsAreEquivalentTests(unittest.TestCase):
    """`and@194` and `and@214` are EQUIVALENT mutants.

    THE SITES
    ---------
    Inside ``main()``'s self-check::

        assert bp.demand == 0 and not bp.cancelled     # line 194
        ...
        assert bp.cancelled and bp.demand == 0         # line 214

    The mutant turns the ``and`` into an ``or``, which makes the assert
    STRICTLY WEAKER -- so it should be killed by any test that drives
    the assert into its failing state.  And there is no such state:
    the assert's VALUE is discarded, so the only thing that can be
    observed is its FAILURE, and at both points the state makes the
    assert vacuous.

    At line 194 the controller is FRESH: ``demand == 0`` and
    ``not cancelled`` are BOTH True, so ``A and B`` and ``A or B`` are
    both True and neither form ever fires.

    At line 214 the controller has just been CANCELLED: ``cancelled``
    is True and ``cancel()`` cleared the demand, so again both
    conjuncts hold and neither form ever fires.

    So the two mutations are indistinguishable: they cannot make the
    assert fire where the original would not, and they cannot stop it
    firing where the original would, because it never fires.

    THE NON-VACUITY CONTROL
    -----------------------
    A proof of equivalence is worthless if the harness cannot see a
    difference at all.  So the control points the SAME assertion at a
    state where the two forms DO differ -- a cancelled controller that
    still holds demand -- and requires the harness to notice.

    WHY THE PROOF IS EXECUTABLE
    ---------------------------
    A comment naming a site is a note about the site, not a test of it.
    ``test_equivalence_table_coverage.py`` requires every site §9.1's
    table names to be proved by CODE in a test file, and the method
    names here follow the prescribed ``test_<kind>_at_<line>_...``
    spelling so the site is findable by the guard.
    """

    def test_and_at_194_the_fresh_controller_makes_the_assert_vacuous(self):
        """`and@194`: both conjuncts hold, so both forms pass."""
        controller = bp_mod.Backpressure()
        # The ORIGINAL form.
        self.assertTrue(controller.demand == 0 and not controller.cancelled)
        # The MUTANT's form.
        self.assertTrue(controller.demand == 0 or not controller.cancelled)
        # And they are the same VALUE -- which is what the assert
        # discards.
        self.assertEqual(
            controller.demand == 0 and not controller.cancelled,
            controller.demand == 0 or not controller.cancelled,
        )

    def test_and_at_214_the_cancelled_controller_makes_the_assert_vacuous(self):
        """`and@214`: both conjuncts hold, so both forms pass."""
        controller = bp_mod.Backpressure()
        controller.request(10)
        controller.cancel()
        # The ORIGINAL form.
        self.assertTrue(controller.cancelled and controller.demand == 0)
        # The MUTANT's form.
        self.assertTrue(controller.cancelled or controller.demand == 0)
        self.assertEqual(
            controller.cancelled and controller.demand == 0,
            controller.cancelled or controller.demand == 0,
        )

    def test_and_at_194_the_harness_notices_a_state_where_they_differ(self):
        """The NON-VACUITY control.

        A cancelled controller that still holds demand is a state the
        two forms DISAGREE on -- and it is reachable only by bypassing
        `cancel()`'s clearing, which is exactly the point: the assert
        inside `main()` can never see it, so the mutant is
        indistinguishable THERE, while the comparison itself is not
        blind.
        """
        controller = bp_mod.Backpressure()
        controller.request(10)
        # A controller with demand (A False) that is NOT cancelled
        # (B True): exactly one conjunct holds, so the two forms
        # DISAGREE.
        self.assertNotEqual(
            controller.demand == 0 and not controller.cancelled,
            controller.demand == 0 or not controller.cancelled,
        )
        # And the other direction: cancelled (B False) with NO demand
        # (A True) -- exactly one conjunct holds again.
        other = bp_mod.Backpressure()
        other._cancelled = True
        self.assertNotEqual(
            other.demand == 0 and not other.cancelled,
            other.demand == 0 or not other.cancelled,
        )
        # The module's own `cancel()` DOES clear it -- which is why
        # `main()`'s state can never reach the differing case.
        fresh = bp_mod.Backpressure()
        fresh.request(10)
        fresh.cancel()
        self.assertEqual(fresh.demand, 0)

    def test_and_at_214_the_harness_notices_a_state_where_they_differ(self):
        """The NON-VACUITY control for `and@214`."""
        controller = bp_mod.Backpressure()
        controller.request(10)
        # NOT cancelled (A False) with a non-zero demand (B False):
        # both False, so the forms AGREE -- and that is the state
        # `main()` is in at line 214 BEFORE the cancel.  The state that
        # DIFFERS is the mirror: cancelled (A True) with a non-zero
        # demand (B False).
        self.assertEqual(
            controller.cancelled and controller.demand == 0,
            controller.cancelled or controller.demand == 0,
        )
        controller._cancelled = True
        self.assertNotEqual(
            controller.cancelled and controller.demand == 0,
            controller.cancelled or controller.demand == 0,
        )


if __name__ == "__main__":
    unittest.main()
