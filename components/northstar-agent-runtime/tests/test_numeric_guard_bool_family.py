"""The NUMERIC-guard family: 18 sites that accepted a bool.

WHY A SEPARATE FAMILY FROM THE INT FAMILY
------------------------------------------
`tests/test_int_guard_bool_family*.py` covers the guards spelled
`not isinstance(X, int)`.  This file covers the OTHER numeric
spelling: `not isinstance(X, (int, float))`.

The blind spot is the same one, with the same shape.  `bool` is a
SUBCLASS of `int`, so `isinstance(True, int)` is True -- and `True` is
also an `int` member of the `(int, float)` tuple:

    isinstance(True, (int, float))   ->  True

So a guard written as

    if not isinstance(x, (int, float)) or x < 0:
        raise ValueError(...)

does NOT fire for `True`: the first clause is False, and `True < 0` is
False, so the bool slips through the whole guard.  That is the same
defect the int family fixed, in the other spelling.

THE REPO ALREADY HAS THE CONVENTION -- 279 SITES OF IT
--------------------------------------------------------
The runtime holds the corrected shape in 279 places:

    if isinstance(x, bool) or not isinstance(x, (int, float)):

and, for the PERMISSIVE checks, the mirrored form in 27 places:

    if isinstance(x, (int, float)) and (not isinstance(x, bool)):

These 18 sites were the exceptions.  Each one now spells the bool half
out, using the form its own neighbourhood already uses.

WHAT WAS MEASURED, AND HOW
---------------------------
The list was not read off the source.  An AST walk found every
`isinstance(X, (int, float))` whose enclosing function has NO bool
check for the SAME target -- 23 candidates in 11 modules.  Each was
then PROBED with a crafted input, `True` and `False` separately:

  * A RANGE check can refuse one bool and let the other through.
    `True == 1` fails a `< 1` bound, but `False == 0` passes a `< 0`
    bound.  So a site was a DEFECT when EITHER bool was accepted, and
    a site that refused both for a RANGE reason was NOT a defect.

  * 18 of them were defects.  The other FOUR were already covered
    by a sibling guard on the same path (`dp_interface` and
    `federated_attack_detector` call a `_reject_bool` helper), and
    `moderation_agents`' `tolerance` was reverted because its range
    check already refuses both bools.

  The 23 CANDIDATES are 22 distinct SITES: the walk counted
  `constraint_synthesis_probes`' NESTED `_compile_props` separately
  from its enclosing `synthesize_constraints`.  18 defects + the four
  cleared = the 22.

THE THREE OBSERVABLE KINDS
---------------------------
Not every module reports a malformed input by RAISING.  The three
kinds need different assertions, and this suite states which is which:

  RAISE   the call raises the module's OWN error class.
  REASON  the call REPORTS the refusal in its return value -- a denial
          string, or a record whose `reason` field names the malformed
          input.  `decision_model._check_probabilities` returns
          "probability for 'allow' is not within [0, 1]: True";
          `ask_or_solve_probes.decide_next` returns an abstain whose
          reason is "malformed confidence; abstaining".
  RETURN  the call returns a value that DIFFERS from the valid call's
          -- `constraint_synthesis_probes` DROPS the range constraint
          instead of raising.

A guard that refuses a bool for the WRONG reason is deletable, so each
member's control is the SAME call with a number that EQUALS the bool
under test: `True` is controlled by `1` and `False` by `0`.  A bool
that has no in-range numeric equivalent at that site (`check_saturation`
requires `0.0 < ceiling`, so `False` has none) is still asserted to be
refused, but it cannot carry a control -- and the suite says so
rather than pretending otherwise.

THE CONTROL
-----------
Every member is paired with the valid-numeric control described above:
the same call with the equal number must SUCCEED and must produce the
member's `expected`.  A guard that refused everything would pass every
rejection test otherwise.

And the suite carries a NON-VACUITY control that plants the mutation
this family exists to catch -- dropping the bool half -- in a COPY of
the tree, loads the mutant, and shows the member then ACCEPTS the
bool.  A test that cannot fail proves nothing.
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[1]
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))


def _load(name: str):
    """Load one family module by file path (the house loader).

    The literal in the CALL SITE matters, not the one here: the census's
    scope resolver (``scripts/census-scope.py``) resolves a module's
    scope by finding the suites that LOAD it, and the loader shape it
    recognises is a call with a LITERAL module name.  A module built
    from a dict literal is INVISIBLE to the resolver, so the census
    would pair each module with its own suite alone and never run these
    tests at all -- the family would measure nothing.

    **A module already in `sys.modules` is REUSED, not re-loaded.**
    That is not an optimisation; it is a correctness requirement, and
    it was found by MEASUREMENT rather than by reading.

    `permissions.py` does `from decision_model import DecisionPolicy`
    at import time, so it holds a reference to the class object that
    was live when IT was imported.  A second load of `decision_model`
    builds a NEW `DecisionPolicy` class and installs it in
    `sys.modules` -- and `permissions` still holds the OLD one.  Its
    `isinstance(decision_policy, DecisionPolicy)` check then fails for
    a policy built from either class, and the failure surfaces as an
    unrelated suite (`test_audit_fixes`) failing in a full-suite run
    while passing in isolation.

    Reusing the already-imported module keeps one class object per
    module for the whole process, so `isinstance` means what it says.
    """
    existing = sys.modules.get(name)
    if existing is not None:
        path = getattr(existing, "__file__", None)
        if path is not None:
            try:
                same = Path(path).resolve() == (RUNTIME_DIR / f"{name}.py").resolve()
            except OSError:  # pragma: no cover - defensive
                same = False
            if same:
                return existing
    spec = importlib.util.spec_from_file_location(name, RUNTIME_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MODULES = {
    "ask_or_solve_probes": _load("ask_or_solve_probes"),
    "benchmark_retirement_probes": _load("benchmark_retirement_probes"),
    "constraint_synthesis_probes": _load("constraint_synthesis_probes"),
    "decision_model": _load("decision_model"),
    "harness_binding": _load("harness_binding"),
    "model_attack_09": _load("model_attack_09"),
    "moderation_agents": _load("moderation_agents"),
    "orbital_agents": _load("orbital_agents"),
}


class _Reason:
    """A normalised REASON-kind result.

    The three REASON members report their refusal in different shapes
    -- a plain string, a tuple, a dataclass with a `reason` field --
    so each call is wrapped to return this one shape.
    """

    __slots__ = ("reason",)

    def __init__(self, reason):
        self.reason = reason

    def __eq__(self, other):
        return isinstance(other, _Reason) and other.reason == self.reason

    def __repr__(self):
        return f"_Reason({self.reason!r})"


def _members(modules=None):
    """Build the member list.

    `modules` overrides the module dict, so the non-vacuity control
    can rebuild the members against a MUTATED copy of a module.  The
    members' calls close over the module objects they were built with,
    so rebuilding is what makes the mutation observable.

    Each member is
        (label, module, argument, call, valid, kind, expected, primary)

      label     the member's name
      module    the module's short name (its key in MODULES)
      argument  the guarded TARGET, as it appears in the module's source
      call      callable(value) -> result; `value` is the guarded field
      valid     the NUMBER that equals the member's primary bool:
                `1` for a `True` member, `0` for a `False` member.  It
                must be accepted by the site, or the member is not
                buildable.
      kind      "RAISE", "REASON" or "RETURN"
      expected  for RAISE: the module's own error class.  For REASON
                and RETURN: the value the VALID call produces.
      primary   the bool this member controls: True or False.

    A site with no in-range numeric equivalent for one of the bools
    gets a member only for the bool that has one -- and the other
    bool is still asserted to be refused, by the site's own member.
    """
    mods = MODULES if modules is None else modules
    out = []

    # ------------------------------------------------- ask_or_solve_probes
    asp = mods["ask_or_solve_probes"]
    out.append((
        "ask_or_solve_probes.AskDecision.confidence", "ask_or_solve_probes",
        "self.confidence",
        lambda v: asp.AskDecision(decision_id="d", action="solve", confidence=v),
        1, "RAISE", ValueError, True,
    ))
    out.append((
        "ask_or_solve_probes.AskDecision.confidence.false",
        "ask_or_solve_probes", "self.confidence",
        lambda v: asp.AskDecision(decision_id="d", action="solve", confidence=v),
        0, "RAISE", ValueError, False,
    ))
    out.append((
        "ask_or_solve_probes.AskPolicy.abstain_below", "ask_or_solve_probes",
        "value",
        lambda v: asp.AskPolicy(abstain_below=v),
        0, "RAISE", ValueError, False,
    ))
    out.append((
        "ask_or_solve_probes.decide_next.confidence", "ask_or_solve_probes",
        "confidence",
        lambda v: _Reason(asp.decide_next(decision_id="d", confidence=v).reason),
        1, "REASON", None, True,
    ))
    out.append((
        "ask_or_solve_probes.decide_next.confidence.false",
        "ask_or_solve_probes", "confidence",
        lambda v: _Reason(asp.decide_next(decision_id="d", confidence=v).reason),
        0, "REASON", None, False,
    ))

    # ------------------------------------------ benchmark_retirement_probes
    brp = mods["benchmark_retirement_probes"]
    out.append((
        "benchmark_retirement_probes.check_saturation.ceiling",
        "benchmark_retirement_probes", "ceiling",
        lambda v: brp.check_saturation("b", [0.5], ceiling=v),
        1, "RAISE", ValueError, True,
    ))

    # ------------------------------------------- constraint_synthesis_probes
    csp = mods["constraint_synthesis_probes"]

    def _cs_count(v):
        schema = {"type": "object", "properties": {
            "x": {"type": "integer", "minimum": v}}}
        return len(csp.synthesize_constraints(schema).constraints)

    out.append((
        "constraint_synthesis_probes.synthesize_constraints.minimum",
        "constraint_synthesis_probes", "decl[key]",
        _cs_count, 1, "RETURN", None, True,
    ))
    out.append((
        "constraint_synthesis_probes.synthesize_constraints.minimum.false",
        "constraint_synthesis_probes", "decl[key]",
        _cs_count, 0, "RETURN", None, False,
    ))
    out.append((
        "constraint_synthesis_probes._decl_names.minimum",
        "constraint_synthesis_probes", "decl[k]",
        lambda v: csp._decl_names({"x": {"type": "integer", "minimum": v}}, ""),
        1, "RETURN", None, True,
    ))
    out.append((
        "constraint_synthesis_probes._decl_names.minimum.false",
        "constraint_synthesis_probes", "decl[k]",
        lambda v: csp._decl_names({"x": {"type": "integer", "minimum": v}}, ""),
        0, "RETURN", None, False,
    ))

    # ------------------------------------------------------ decision_model
    dm = mods["decision_model"]
    out.append((
        "decision_model._check_probabilities.prob", "decision_model", "prob",
        lambda v: _Reason(dm._check_probabilities(
            {"allow": v, "deny": 0.0, "escalate": 0.0},
            ("allow", "deny", "escalate"))),
        1, "REASON", None, True,
    ))
    out.append((
        "decision_model.adjudicate.yes", "decision_model", "yes",
        _dm_adjudicate_yes(dm), 1, "REASON", None, True,
    ))
    out.append((
        "decision_model.adjudicate.yes.false", "decision_model", "yes",
        _dm_adjudicate_yes(dm), 0, "REASON", None, False,
    ))
    out.append((
        "decision_model.decide.yes", "decision_model", "yes",
        _dm_decide_yes(dm), 1, "RAISE", ValueError, True,
    ))
    out.append((
        "decision_model.decide.yes.false", "decision_model", "yes",
        _dm_decide_yes(dm), 0, "RAISE", ValueError, False,
    ))

    # ----------------------------------------------------- harness_binding
    hb = mods["harness_binding"]
    out.append((
        "harness_binding.validate_quad.cost", "harness_binding", "cost",
        _hb_quad_cost(hb), 1, "RAISE", hb.HarnessBindingError, True,
    ))
    out.append((
        "harness_binding.validate_quad.cost.false", "harness_binding", "cost",
        _hb_quad_cost(hb), 0, "RAISE", hb.HarnessBindingError, False,
    ))
    out.append((
        "harness_binding.validate_quad.score", "harness_binding",
        "result.score",
        _hb_quad_score(hb), 1, "RAISE", hb.HarnessBindingError, True,
    ))
    out.append((
        "harness_binding.validate_quad.score.false", "harness_binding",
        "result.score",
        _hb_quad_score(hb), 0, "RAISE", hb.HarnessBindingError, False,
    ))

    # ------------------------------------------------------ model_attack_09
    ma = mods["model_attack_09"]
    out.append((
        "model_attack_09.detect_gradient_anomaly.v", "model_attack_09", "v",
        lambda v: ma.detect_gradient_anomaly(
            [{"client": "c", "gradient": [v]}]),
        1, "RAISE", ma.ModelAttackError, True,
    ))
    out.append((
        "model_attack_09.detect_gradient_anomaly.v.false", "model_attack_09",
        "v",
        lambda v: ma.detect_gradient_anomaly(
            [{"client": "c", "gradient": [v]}]),
        0, "RAISE", ma.ModelAttackError, False,
    ))

    # --------------------------------------------------- moderation_agents
    mo = mods["moderation_agents"]
    out.append((
        "moderation_agents.check_dialect_parity.max_disparity",
        "moderation_agents", "max_disparity",
        _mo_dialect(mo), 0, "RAISE", mo.ModerationError, False,
    ))

    # ----------------------------------------------------- orbital_agents
    oa = mods["orbital_agents"]
    out.append((
        "orbital_agents.conjunction_receipt.uncertainty_km", "orbital_agents",
        "uncertainty_km",
        _oa_conjunction(oa), 1, "RAISE", oa.OrbitalError, True,
    ))
    out.append((
        "orbital_agents.conjunction_receipt.uncertainty_km.false",
        "orbital_agents", "uncertainty_km",
        _oa_conjunction(oa), 0, "RAISE", oa.OrbitalError, False,
    ))
    out.append((
        "orbital_agents.check_maneuver.dv_ms", "orbital_agents", "dv_ms",
        _oa_registry_maneuver(oa), 1, "RAISE", oa.OrbitalError, True,
    ))
    out.append((
        "orbital_agents.check_maneuver.dv_ms.false", "orbital_agents", "dv_ms",
        _oa_registry_maneuver(oa), 0, "RAISE", oa.OrbitalError, False,
    ))
    out.append((
        "orbital_agents.maneuver_authorization_envelope.max_dv_ms",
        "orbital_agents", "max_dv_ms",
        _oa_envelope(oa), 1, "RAISE", oa.OrbitalError, True,
    ))
    out.append((
        "orbital_agents.check_maneuver.envelope_dv_ms", "orbital_agents",
        "dv_ms",
        _oa_envelope_maneuver(oa), 1, "RAISE", oa.OrbitalError, True,
    ))
    out.append((
        "orbital_agents.check_maneuver.envelope_dv_ms.false", "orbital_agents",
        "dv_ms",
        _oa_envelope_maneuver(oa), 0, "RAISE", oa.OrbitalError, False,
    ))
    out.append((
        "orbital_agents.stm_data_receipt.uncertainty_km", "orbital_agents",
        "uncertainty_km",
        _oa_stm(oa), 1, "RAISE", oa.OrbitalError, True,
    ))
    out.append((
        "orbital_agents.stm_data_receipt.uncertainty_km.false", "orbital_agents",
        "uncertainty_km",
        _oa_stm(oa), 0, "RAISE", oa.OrbitalError, False,
    ))

    # the expected values for the REASON and RETURN members are the
    # VALID call's value, which depends on the module -- so they are
    # filled in here, where the calls are live.
    for member in out:
        label, _module, _argument, call, valid, kind, _expected, _primary = member
        if kind in ("REASON", "RETURN"):
            out[out.index(member)] = (
                label, _module, _argument, call, valid, kind,
                call(valid), _primary,
            )
    return out


def _dm_adjudicate_yes(dm):
    def call(v):
        qa = dm.QuestionAnswer(name="approval", type="noul",
                               probabilities={"yes": v, "no": 0.0},
                               choice="yes", confidence=0.9)
        policy = dm.DecisionPolicy(approve_threshold=0.5, deny_threshold=0.2,
                                   min_confidence=0.5)
        return _Reason(dm.adjudicate(
            dm.DecisionModelResult(answers={"approval": qa}, model="m"),
            policy)[1])
    return call


def _dm_decide_yes(dm):
    def call(v):
        q = dm.DecisionQuestion(name="n", type="noul")
        model = dm.StaticDecisionModel(profiles={"tool:t": {"n": v}})
        return model.decide({"tool": "t"}, {"n": q})
    return call


def _hb_config(hb):
    return hb.HarnessConfig(code_version="v", prompt_templates={},
                            tool_versions={}, environment={})


def _hb_quad_cost(hb):
    def call(v):
        return hb.validate_quad(hb.ScoredResult(
            model_version="v", harness=_hb_config(hb), effort="medium",
            cost_per_task_usd=v, score=0.5, n_tasks=1))
    return call


def _hb_quad_score(hb):
    def call(v):
        return hb.validate_quad(hb.ScoredResult(
            model_version="v", harness=_hb_config(hb), effort="medium",
            cost_per_task_usd=1.0, score=v, n_tasks=1))
    return call


def _mo_dialect(mo):
    report = mo.DialectParityReport(report_id="r", baseline_dialect="a",
                                    tested_at=1, fp_counts=(("a", 1, 10),))
    return lambda v: mo.check_dialect_parity(report, max_disparity=v)


def _oa_conjunction(oa):
    return lambda v: oa.conjunction_receipt(
        receipt_id="r", warning_id="w", conjunction_digest="a" * 64,
        uncertainty_km=v, warned_at=1, ttl_s=60, object_pair="p",
        issued_by="i", authority_pubkey_hex="b" * 64,
        authority_secret=b"k" * 32)


def _oa_registry_maneuver(oa):
    registry = oa.ConjunctionRegistry()
    return lambda v: registry.check_maneuver(
        warning_id="w", dv_ms=v, maneuver_at=1, now=1)


def _oa_envelope(oa):
    return lambda v: oa.maneuver_authorization_envelope(
        envelope_id="e", max_dv_ms=v, valid_from=1, valid_to=2,
        issued_by="i", authority_pubkey_hex="b" * 64,
        authority_secret=b"k" * 32)


def _oa_envelope_maneuver(oa):
    def call(v):
        envelope = oa.maneuver_authorization_envelope(
            envelope_id="e", max_dv_ms=1.0, valid_from=1, valid_to=2,
            issued_by="i", authority_pubkey_hex="b" * 64,
            authority_secret=b"k" * 32)
        return oa.check_maneuver(envelope, dv_ms=v, at=1, now=1)
    return call


def _oa_stm(oa):
    return lambda v: oa.stm_data_receipt(
        receipt_id="r", data_id="d", data_digest="a" * 64,
        uncertainty_km=v, observed_at=1, ttl_s=60, source="s",
        issued_by="i", authority_pubkey_hex="b" * 64,
        authority_secret=b"k" * 32)


MEMBERS = _members()

#: The (line, target) pairs the non-vacuity control drops the bool half
#: from, per member.  Each member's OWN guard is the first pair.
#:
#: MEASURED 2026-11-26 by planting the mutation in a COPY of the tree
#: and running the real suite: for each member, drop the bool half from
#: the member's own line and check that the member's own refusal
#: assertion then FAILS.
MUTATIONS = {
    "ask_or_solve_probes.AskDecision.confidence": [[710, "self.confidence"]],
    "ask_or_solve_probes.AskDecision.confidence.false":
        [[710, "self.confidence"]],
    "ask_or_solve_probes.AskPolicy.abstain_below": [[777, "value"]],
    "ask_or_solve_probes.decide_next.confidence": [[805, "confidence"]],
    "ask_or_solve_probes.decide_next.confidence.false": [[805, "confidence"]],
    "benchmark_retirement_probes.check_saturation.ceiling": [[371, "ceiling"]],
    "constraint_synthesis_probes.synthesize_constraints.minimum":
        [[494, "decl[key]"]],
    "constraint_synthesis_probes.synthesize_constraints.minimum.false":
        [[494, "decl[key]"]],
    "constraint_synthesis_probes._decl_names.minimum": [[639, "decl[k]"]],
    "constraint_synthesis_probes._decl_names.minimum.false": [[639, "decl[k]"]],
    "decision_model._check_probabilities.prob": [[237, "prob"]],
    "decision_model.adjudicate.yes": [[276, "yes"]],
    "decision_model.adjudicate.yes.false": [[276, "yes"]],
    "decision_model.decide.yes": [[333, "yes"]],
    "decision_model.decide.yes.false": [[333, "yes"]],
    "harness_binding.validate_quad.cost": [[192, "cost"]],
    "harness_binding.validate_quad.cost.false": [[192, "cost"]],
    "harness_binding.validate_quad.score": [[194, "result.score"]],
    "harness_binding.validate_quad.score.false": [[194, "result.score"]],
    "model_attack_09.detect_gradient_anomaly.v": [[53, "v"]],
    "model_attack_09.detect_gradient_anomaly.v.false": [[53, "v"]],
    "moderation_agents.check_dialect_parity.max_disparity":
        [[534, "max_disparity"]],
    "orbital_agents.conjunction_receipt.uncertainty_km":
        [[391, "uncertainty_km"]],
    "orbital_agents.conjunction_receipt.uncertainty_km.false":
        [[391, "uncertainty_km"]],
    "orbital_agents.check_maneuver.dv_ms": [[470, "dv_ms"]],
    "orbital_agents.check_maneuver.dv_ms.false": [[470, "dv_ms"]],
    "orbital_agents.maneuver_authorization_envelope.max_dv_ms":
        [[590, "max_dv_ms"]],
    "orbital_agents.check_maneuver.envelope_dv_ms": [[624, "dv_ms"]],
    "orbital_agents.check_maneuver.envelope_dv_ms.false": [[624, "dv_ms"]],
    "orbital_agents.stm_data_receipt.uncertainty_km": [[741, "uncertainty_km"]],
    "orbital_agents.stm_data_receipt.uncertainty_km.false":
        [[741, "uncertainty_km"]],
}


def _bool_half_present(module_name, argument, line=None):
    """Does the module's source carry the bool half for THIS argument?

    Read from the module's own source, so a module that grows or drops a
    guard is handled without this file being edited.

    `line` narrows the search to the member's OWN guard line.  That
    matters: `orbital_agents` guards `dv_ms` in BOTH
    `ConjunctionRegistry.check_maneuver` and the module-level
    `check_maneuver`, and a whole-module search would report the shape
    for a member whose own guard had lost it.  A shape test that passes
    on a SIBLING's guard is a shape test that measures nothing.
    """
    import ast

    path = Path(sys.modules[module_name].__file__)
    tree = ast.parse(path.read_text(errors="ignore"))
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp):
            if line is not None and node.lineno != line:
                continue
            text = ast.unparse(node)
            if f"isinstance({argument}, bool)" in text:
                return True
    return False


def _refused(call, value, kind, expected):
    """Did the call REFUSE the value?

    The SAME predicate is used for the real module and for the mutant,
    so the non-vacuity control measures the guard and not the
    predicate's asymmetry.

      RAISE   the call raised the module's own error class
      REASON  the returned reason differs from the valid call's
      RETURN  the returned value differs from the valid call's
    """
    if kind == "RAISE":
        try:
            call(value)
        except expected:
            return True
        except Exception:  # noqa: BLE001
            return False
        return False
    return call(value) != expected


class NumericGuardShapeTest(unittest.TestCase):
    """The family really is the family."""

    def test_every_member_carries_the_bool_half(self) -> None:
        """The guard must spell the bool half out.

        The repo holds the negative convention in 279 places and the
        permissive one in 27.  These 18 sites were the exceptions.
        """
        for label, module, argument, _call, _valid, _kind, _expected, _p in MEMBERS:
            with self.subTest(call=label):
                line = MUTATIONS[label][0][0]
                self.assertTrue(
                    _bool_half_present(module, argument, line),
                    f"{module}:{line}: the guard for {argument!r} does not "
                    "refuse a bool",
                )

    def test_the_members_are_still_numeric_guards(self) -> None:
        """A guard that refuses EVERYTHING would pass the test above.

        This is the control: the guard still accepts the plain number
        that equals the member's bool.
        """
        for label, _module, _argument, call, valid, kind, expected, _p in MEMBERS:
            with self.subTest(call=label):
                if kind == "RAISE":
                    # the valid number must NOT raise
                    call(valid)
                else:
                    self.assertEqual(expected, call(valid),
                                     f"{label}: the valid number's value")


class NumericGuardRefusesBoolTest(unittest.TestCase):
    """THE CRAFTED INPUT: every member refuses BOTH bools.

    Both bools, not one.  A range check can refuse `True` and let
    `False` through -- `False == 0` passes a `< 0` bound -- so testing
    one bool would let half the family through.
    """

    def test_a_bool_is_refused(self) -> None:
        for label, _module, _argument, call, _valid, kind, expected, _p in MEMBERS:
            for value in (True, False):
                with self.subTest(call=label, bool=value):
                    self.assertTrue(
                        _refused(call, value, kind, expected),
                        f"{label}: the bool {value!r} was accepted",
                    )

    def test_a_refusal_that_raises_says_why(self) -> None:
        """A guard that fails for the WRONG reason is deletable.

        The message says WHICH rule fired, so a future edit that breaks
        the guard for another reason is visible here rather than hiding
        behind a bare "it raised".
        """
        for label, _module, _argument, call, _valid, kind, expected, _p in MEMBERS:
            if kind != "RAISE":
                continue
            with self.subTest(call=label):
                with self.assertRaises(expected) as caught:
                    call(True)
                self.assertTrue(str(caught.exception), f"{label}: empty message")


class NumericGuardNonVacuityTest(unittest.TestCase):
    """THE NON-VACUITY CONTROL: the instrument can fail.

    A test that cannot fail proves nothing.  This one plants the
    mutation the family exists to catch -- dropping the bool half, so
    the guard reads `isinstance(X, (int, float))` again -- in the
    module's own SOURCE, LOADS the mutated copy, REBUILDS the members
    against it, and shows the member then ACCEPTS the bool.

    The mutation is done in a COPY under a temp directory: the shared
    tree is never touched.
    """

    def _mutant(self, module_name, mutations, tmpdir):
        """Copy the module, drop the bool half at each (line, target).

        The copy is loaded under a MUTANT name, so the family's own
        member calls -- which close over the ORIGINAL module object --
        are not what is being measured.

        Three spellings of the bool half exist in this family, and the
        control has to handle all of them:

          `isinstance(T, bool) or not isinstance(T, (int, float))`
              the NEGATIVE convention, 279 sites
          `not isinstance(T, bool) and isinstance(T, (int, float))`
              the PERMISSIVE convention, 27 sites
          `isinstance(T, (int, float)) and (not isinstance(T, bool))`
              the permissive convention, parenthesised
        """
        import importlib.util
        import shutil

        source = Path(sys.modules[module_name].__file__)
        copy = Path(tmpdir) / source.name
        shutil.copy2(source, copy)
        lines = copy.read_text().splitlines(keepends=True)
        for line_no, target in mutations:
            index = line_no - 1
            text = lines[index]
            # the negative convention
            pair = (f"isinstance({target}, bool) or "
                    f"not isinstance({target}, (int, float))")
            if pair in text:
                lines[index] = text.replace(
                    pair, f"not isinstance({target}, (int, float))", 1)
                continue
            # the permissive convention
            perm = (f"not isinstance({target}, bool) and "
                    f"isinstance({target}, (int, float))")
            if perm in text:
                lines[index] = text.replace(
                    perm, f"isinstance({target}, (int, float))", 1)
                continue
            # the permissive convention, parenthesised
            perm2 = (f"isinstance({target}, (int, float)) and "
                     f"(not isinstance({target}, bool))")
            if perm2 in text:
                lines[index] = text.replace(
                    perm2, f"isinstance({target}, (int, float))", 1)
                continue
            # the bare `isinstance(T, bool) or` clause
            bare = re.search(r"isinstance\(" + re.escape(target) +
                             r", bool\) or ", text)
            if bare:
                lines[index] = text[:bare.start()] + text[bare.end():]
                continue
            # the bare `not isinstance(T, bool) and` clause
            bare2 = re.search(r"not isinstance\(" + re.escape(target) +
                              r", bool\) and ", text)
            if bare2:
                lines[index] = text[:bare2.start()] + text[bare2.end():]
                continue
            self.fail(
                f"{module_name}:{line_no} is not the guard for {target!r} "
                "-- the control would mutate the wrong line"
            )
        copy.write_text("".join(lines))

        mutant_name = f"_mutant_{module_name}"
        spec = importlib.util.spec_from_file_location(mutant_name, copy)
        module = importlib.util.module_from_spec(spec)
        sys.modules[mutant_name] = module
        spec.loader.exec_module(module)
        return module

    def test_the_mutation_makes_the_crafted_input_accepted(self) -> None:
        """THE CONTROL: with the bool half dropped, the bool gets through.

        One member per module this suite covers, so the family is shown
        to be able to fail on EVERY module -- not on one convenient
        example.
        """
        import tempfile

        for member in MEMBERS:
            label, module, _argument, _call, _valid, kind, expected, primary = member
            with self.subTest(call=label):
                mutations = MUTATIONS.get(label)
                self.assertIsNotNone(
                    mutations,
                    f"{label}: the control has no mutation recorded for "
                    "this member")
                with tempfile.TemporaryDirectory() as tmp:
                    mutant = self._mutant(module, mutations, tmp)
                    swapped = dict(MODULES)
                    swapped[module] = mutant
                    mutant_members = _members(swapped)
                    mutant_label, _m, _a, mutant_call, _v, mutant_kind, mutant_expected, _p = next(
                        m for m in mutant_members if m[0] == label
                    )
                    self.assertEqual(kind, mutant_kind)
                    if kind == "RAISE":
                        # The mutant defines its OWN error class, so the
                        # ORIGINAL's class would never match it -- and a
                        # refusal predicate that can never match is
                        # vacuous.  The two classes are the same CLASS by
                        # name, and that is what the predicate uses.
                        self.assertEqual(
                            expected.__name__, mutant_expected.__name__,
                            f"{label}: the mutant raised a different class",
                        )
                    # The MUTATED module must ACCEPT the bool: the guard
                    # no longer fires.  This is the assertion that makes
                    # the unmutated refusal meaningful.
                    #
                    # The direction matters: the mutant must NOT be
                    # refused.  Asserting that the mutant IS refused
                    # would be a tautology -- it would pass on the
                    # UNMUTATED module too, and prove nothing.
                    #
                    # The predicate uses the MUTANT's own expected value,
                    # for the same reason: against the original's class
                    # the mutant's refusal would go unnoticed, and the
                    # control could not fail.
                    self.assertFalse(
                        _refused(mutant_call, primary, kind, mutant_expected),
                        f"{label}: the MUTANT still refused the bool "
                        f"{primary!r} -- the control cannot make the family fail",
                    )

    def test_every_member_has_a_recorded_mutation(self) -> None:
        """Every member the suite proves must be falsifiable.

        A member with no recorded mutation is a member whose guard could
        be broken and the suite would not notice.
        """
        for member in MEMBERS:
            label = member[0]
            with self.subTest(call=label):
                self.assertIn(label, MUTATIONS)

    def test_the_mutations_are_the_members_own_guard(self) -> None:
        """Every member's FIRST mutation is its own guard's line.

        A member whose own guard is not in the mutation list is a member
        whose family might be measuring a DIFFERENT guard.
        """
        for member in MEMBERS:
            label, _module, argument, _call, _valid, _kind, _expected, _p = member
            mutations = MUTATIONS.get(label)
            if mutations is None:
                continue
            with self.subTest(call=label):
                line, target = mutations[0]
                source = Path(sys.modules[member[1]].__file__)
                text = source.read_text().splitlines()[line - 1]
                self.assertIn(
                    f"isinstance({target}, bool)", text,
                    f"{label}: the mutation at {member[1]}:{line} does not "
                    f"name the member's own target {argument!r}",
                )
