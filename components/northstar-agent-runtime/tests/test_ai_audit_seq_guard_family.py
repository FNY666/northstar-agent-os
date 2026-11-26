"""The `ai_*` audit-event seq-guard family: ONE blind spot, 162 copies.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
162 of the runtime's `ai_*` modules expose a function whose second
positional parameter is a sequence number, guarded by ONE template:

    def <module>_audit_event(kind, seq, ...):
        if kind not in <KINDS>:
            raise AuditKindError(...)
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError('seq must be an int')
        ...

Every one of the 162 modules has its OWN suite.  Those suites call the
audit-event builder with a GOOD seq -- an `int` -- and assert that the
row comes back.  When they test the seq guard at all, they test it with
a NEGATIVE int.

**A GUARD WHOSE WHOLE JOB IS TO REJECT, TESTED ONLY ON THE ACCEPTING
SIDE IS NOT TESTED.**  The seq guard's rejection is what the `bool`
half is for, and no suite in the family passes a `bool`.

THE DISCRIMINATOR IS A bool, NOT A NEGATIVE
-------------------------------------------
`bool` is a subclass of `int` in Python, so `isinstance(True, int)` is
`True`.  The guard therefore needs TWO halves to refuse a bool:

    isinstance(seq, bool) or not isinstance(seq, int)

The first half refuses the bool; the second half refuses a string or a
float.  Mutating the `or` to an `and` (the census's `or -> and` mutant)
turns the guard into

    isinstance(seq, bool) and not isinstance(seq, int)

which is FALSE for a bool (`not isinstance(True, int)` is `False`), so
the mutant ACCEPTS `True`.  A negative int still trips the mutant --
`isinstance(-1, bool)` is `False`, so the whole `and` is `False` -- so
**a test that only passes a negative int cannot see this mutant at
all.**  The crafted input has to be a bool.

THE OBSERVABLE IS THE EXCEPTION TYPE
------------------------------------
The original raises the module's OWN error class (`SeqOrderError`, and
in one module `BadSeqError`).  Under the mutant, no exception is raised
at all: the row is returned with `seq=True` in it.  A test that
asserted "it raised something" would still be a valid test here, but
the test that says what the module actually does -- "it raises
`SeqOrderError`, not `AttributeError`, and not nothing" -- is the one
that pins the behaviour.  The error class is DERIVED FROM EACH MODULE'S
OWN SOURCE, because the family is not uniform: one member raises
`BadSeqError` where the other 161 raise `SeqOrderError`.

THE KIND IS DERIVED FROM EACH MODULE'S OWN SOURCE
-------------------------------------------------
To reach the seq guard at all, the call must survive the KIND check
first, so the test needs a valid kind.  The kinds live in a per-module
constant -- `AUDIT_KINDS` (93 members), `EMIT_KINDS` (67), or
`_AUDIT_KINDS` (2) -- and the constant's NAME is read from the guard's
own source.  A hardcoded kind would be a claim about the module that
the module does not make, and the test would then be asserting against
a rule the module does not enforce.

TWO MEMBERS TAKE A REQUIRED `details` DICT
-------------------------------------------
`ai_ethics_monitoring` and `ai_pentesting` declare
`audit_event(kind, seq, details)` with a REQUIRED third parameter.  The
suite passes an empty dict for them.  The third parameter is read from
the signature, so a member that grows or drops it is handled without a
hand-maintained list.

THE CONTROL
-----------
Every rejection case is paired with an acceptance case on the SAME
module: a good `int` seq must produce a row.  A guard that refused
everything would pass every rejection test; only the pair tells "the
guard refuses a bool" from "the guard refuses everything".

A NOTE ON SCOPE
---------------
The 162 are the modules whose audit-event function STRUCTURALLY matches
this template: the function's name ends in `_audit_event`, its second
parameter is named `seq`, and its body carries a `bool`/`int`
discriminating guard on that parameter.  The suite asserts the family's
PREMISE -- that every member really has that shape -- so a module that
leaves the family is caught rather than silently carried by the cases.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name: str):
    """Load one family module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Every family module, loaded by an EXPLICIT LITERAL call.
#:
#: The literal matters.  ``scripts/census-scope.py`` resolves a module's
#: scope by finding the suites that LOAD it, and the loader shape it
#: recognises is a call with a literal module name.  A list built by a
#: loop is INVISIBLE to the resolver, so the census would pair each
#: module with its own suite alone and never run these tests at all.
MODULES = {
    "ai_accident": _load("ai_accident"),
    "ai_accountability": _load("ai_accountability"),
    "ai_accountability_incident": _load("ai_accountability_incident"),
    "ai_accountability_mitigation": _load("ai_accountability_mitigation"),
    "ai_accountability_monitoring": _load("ai_accountability_monitoring"),
    "ai_accountability_remediation": _load("ai_accountability_remediation"),
    "ai_accountability_risk": _load("ai_accountability_risk"),
    "ai_accountability_testing": _load("ai_accountability_testing"),
    "ai_accountability_threat": _load("ai_accountability_threat"),
    "ai_accountability_validation": _load("ai_accountability_validation"),
    "ai_accountability_verification": _load("ai_accountability_verification"),
    "ai_accountability_vulnerability": _load("ai_accountability_vulnerability"),
    "ai_act": _load("ai_act"),
    "ai_adversarial": _load("ai_adversarial"),
    "ai_alignment": _load("ai_alignment"),
    "ai_attack": _load("ai_attack"),
    "ai_audit": _load("ai_audit"),
    "ai_benchmarking": _load("ai_benchmarking"),
    "ai_bias": _load("ai_bias"),
    "ai_calibration": _load("ai_calibration"),
    "ai_charter": _load("ai_charter"),
    "ai_compliance": _load("ai_compliance"),
    "ai_compliance_incident": _load("ai_compliance_incident"),
    "ai_compliance_mitigation": _load("ai_compliance_mitigation"),
    "ai_compliance_monitoring": _load("ai_compliance_monitoring"),
    "ai_compliance_remediation": _load("ai_compliance_remediation"),
    "ai_compliance_risk": _load("ai_compliance_risk"),
    "ai_compliance_testing": _load("ai_compliance_testing"),
    "ai_compliance_threat": _load("ai_compliance_threat"),
    "ai_compliance_validation": _load("ai_compliance_validation"),
    "ai_compliance_verification": _load("ai_compliance_verification"),
    "ai_compliance_vulnerability": _load("ai_compliance_vulnerability"),
    "ai_concept": _load("ai_concept"),
    "ai_containment": _load("ai_containment"),
    "ai_contestability_incident": _load("ai_contestability_incident"),
    "ai_contestability_mitigation": _load("ai_contestability_mitigation"),
    "ai_contestability_monitoring": _load("ai_contestability_monitoring"),
    "ai_contestability_remediation": _load("ai_contestability_remediation"),
    "ai_contestability_risk": _load("ai_contestability_risk"),
    "ai_contestability_testing": _load("ai_contestability_testing"),
    "ai_contestability_threat": _load("ai_contestability_threat"),
    "ai_contestability_validation": _load("ai_contestability_validation"),
    "ai_contestability_verification": _load("ai_contestability_verification"),
    "ai_contestability_vulnerability": _load("ai_contestability_vulnerability"),
    "ai_counterfactual": _load("ai_counterfactual"),
    "ai_defense": _load("ai_defense"),
    "ai_detection": _load("ai_detection"),
    "ai_distillation": _load("ai_distillation"),
    "ai_distribution_shift": _load("ai_distribution_shift"),
    "ai_ensemble": _load("ai_ensemble"),
    "ai_ethics_incident": _load("ai_ethics_incident"),
    "ai_ethics_mitigation": _load("ai_ethics_mitigation"),
    "ai_ethics_monitoring": _load("ai_ethics_monitoring"),
    "ai_ethics_remediation": _load("ai_ethics_remediation"),
    "ai_ethics_risk": _load("ai_ethics_risk"),
    "ai_ethics_testing": _load("ai_ethics_testing"),
    "ai_ethics_threat": _load("ai_ethics_threat"),
    "ai_ethics_validation": _load("ai_ethics_validation"),
    "ai_ethics_verification": _load("ai_ethics_verification"),
    "ai_ethics_vulnerability": _load("ai_ethics_vulnerability"),
    "ai_evaluation": _load("ai_evaluation"),
    "ai_explainability": _load("ai_explainability"),
    "ai_exploit": _load("ai_exploit"),
    "ai_failure": _load("ai_failure"),
    "ai_fairness_incident": _load("ai_fairness_incident"),
    "ai_fairness_mitigation": _load("ai_fairness_mitigation"),
    "ai_fairness_monitoring": _load("ai_fairness_monitoring"),
    "ai_fairness_remediation": _load("ai_fairness_remediation"),
    "ai_fairness_risk": _load("ai_fairness_risk"),
    "ai_fairness_testing": _load("ai_fairness_testing"),
    "ai_fairness_threat": _load("ai_fairness_threat"),
    "ai_fairness_validation": _load("ai_fairness_validation"),
    "ai_fairness_verification": _load("ai_fairness_verification"),
    "ai_fairness_vulnerability": _load("ai_fairness_vulnerability"),
    "ai_feature": _load("ai_feature"),
    "ai_fuzzing": _load("ai_fuzzing"),
    "ai_gating": _load("ai_gating"),
    "ai_harm": _load("ai_harm"),
    "ai_incident": _load("ai_incident"),
    "ai_isolation": _load("ai_isolation"),
    "ai_mechanistic": _load("ai_mechanistic"),
    "ai_mitigation": _load("ai_mitigation"),
    "ai_monitoring": _load("ai_monitoring"),
    "ai_ood_detection": _load("ai_ood_detection"),
    "ai_oversight_incident": _load("ai_oversight_incident"),
    "ai_oversight_mitigation": _load("ai_oversight_mitigation"),
    "ai_oversight_monitoring": _load("ai_oversight_monitoring"),
    "ai_oversight_remediation": _load("ai_oversight_remediation"),
    "ai_oversight_risk": _load("ai_oversight_risk"),
    "ai_oversight_testing": _load("ai_oversight_testing"),
    "ai_oversight_threat": _load("ai_oversight_threat"),
    "ai_oversight_validation": _load("ai_oversight_validation"),
    "ai_oversight_verification": _load("ai_oversight_verification"),
    "ai_oversight_vulnerability": _load("ai_oversight_vulnerability"),
    "ai_pentesting": _load("ai_pentesting"),
    "ai_prevention": _load("ai_prevention"),
    "ai_privacy": _load("ai_privacy"),
    "ai_probing": _load("ai_probing"),
    "ai_pruning": _load("ai_pruning"),
    "ai_quarantine": _load("ai_quarantine"),
    "ai_recovery": _load("ai_recovery"),
    "ai_redress": _load("ai_redress"),
    "ai_redteaming": _load("ai_redteaming"),
    "ai_remediation": _load("ai_remediation"),
    "ai_resilience": _load("ai_resilience"),
    "ai_risk": _load("ai_risk"),
    "ai_robustness": _load("ai_robustness"),
    "ai_robustness_incident": _load("ai_robustness_incident"),
    "ai_robustness_mitigation": _load("ai_robustness_mitigation"),
    "ai_robustness_monitoring": _load("ai_robustness_monitoring"),
    "ai_robustness_remediation": _load("ai_robustness_remediation"),
    "ai_robustness_risk": _load("ai_robustness_risk"),
    "ai_robustness_testing": _load("ai_robustness_testing"),
    "ai_robustness_threat": _load("ai_robustness_threat"),
    "ai_robustness_validation": _load("ai_robustness_validation"),
    "ai_robustness_verification": _load("ai_robustness_verification"),
    "ai_robustness_vulnerability": _load("ai_robustness_vulnerability"),
    "ai_safety": _load("ai_safety"),
    "ai_safety_incident": _load("ai_safety_incident"),
    "ai_safety_mitigation": _load("ai_safety_mitigation"),
    "ai_safety_monitoring": _load("ai_safety_monitoring"),
    "ai_safety_remediation": _load("ai_safety_remediation"),
    "ai_safety_risk": _load("ai_safety_risk"),
    "ai_safety_testing": _load("ai_safety_testing"),
    "ai_safety_threat": _load("ai_safety_threat"),
    "ai_safety_validation": _load("ai_safety_validation"),
    "ai_safety_verification": _load("ai_safety_verification"),
    "ai_safety_vulnerability": _load("ai_safety_vulnerability"),
    "ai_saliency": _load("ai_saliency"),
    "ai_sandbox": _load("ai_sandbox"),
    "ai_security": _load("ai_security"),
    "ai_stress_testing": _load("ai_stress_testing"),
    "ai_surveillance": _load("ai_surveillance"),
    "ai_testing": _load("ai_testing"),
    "ai_threat": _load("ai_threat"),
    "ai_throttling": _load("ai_throttling"),
    "ai_traceability_incident": _load("ai_traceability_incident"),
    "ai_traceability_mitigation": _load("ai_traceability_mitigation"),
    "ai_traceability_monitoring": _load("ai_traceability_monitoring"),
    "ai_traceability_remediation": _load("ai_traceability_remediation"),
    "ai_traceability_risk": _load("ai_traceability_risk"),
    "ai_traceability_testing": _load("ai_traceability_testing"),
    "ai_traceability_threat": _load("ai_traceability_threat"),
    "ai_traceability_validation": _load("ai_traceability_validation"),
    "ai_traceability_verification": _load("ai_traceability_verification"),
    "ai_traceability_vulnerability": _load("ai_traceability_vulnerability"),
    "ai_transparency": _load("ai_transparency"),
    "ai_transparency_incident": _load("ai_transparency_incident"),
    "ai_transparency_mitigation": _load("ai_transparency_mitigation"),
    "ai_transparency_monitoring": _load("ai_transparency_monitoring"),
    "ai_transparency_remediation": _load("ai_transparency_remediation"),
    "ai_transparency_risk": _load("ai_transparency_risk"),
    "ai_transparency_testing": _load("ai_transparency_testing"),
    "ai_transparency_threat": _load("ai_transparency_threat"),
    "ai_transparency_validation": _load("ai_transparency_validation"),
    "ai_transparency_verification": _load("ai_transparency_verification"),
    "ai_transparency_vulnerability": _load("ai_transparency_vulnerability"),
    "ai_uncertainty": _load("ai_uncertainty"),
    "ai_validation": _load("ai_validation"),
    "ai_verification": _load("ai_verification"),
    "ai_visualization": _load("ai_visualization"),
    "ai_vulnerability": _load("ai_vulnerability"),
}


def _audit_fn(name: str):
    """The module's audit-event function, or None."""
    module = MODULES[name]
    for attr in vars(module).values():
        if callable(attr) and getattr(attr, "__name__", "") == f"{name}_audit_event":
            return attr
    return None


def _guard_node(name: str):
    """The `BoolOp` that discriminates the seq guard, or None."""
    module = MODULES[name]
    fn = _audit_fn(name)
    if fn is None:
        return None
    tree = ast.parse(Path(fn.__code__.co_filename).read_text(errors="ignore"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == fn.__name__
        ):
            for inner in ast.walk(node):
                if isinstance(inner, ast.BoolOp):
                    text = ast.unparse(inner)
                    if "isinstance(seq, bool)" in text and "int" in text:
                        return inner
    return None


def _error_class(name: str):
    """The error class the seq branch raises, read from the module's source."""
    module = MODULES[name]
    fn = _audit_fn(name)
    tree = ast.parse(Path(fn.__code__.co_filename).read_text(errors="ignore"))
    node = None
    for candidate in ast.walk(tree):
        if isinstance(candidate, ast.FunctionDef) and candidate.name == fn.__name__:
            node = candidate
            break
    # the raise that sits in the seq branch's body
    for statement in ast.walk(node):
        if isinstance(statement, ast.If) and isinstance(statement.test, ast.BoolOp):
            text = ast.unparse(statement.test)
            if "isinstance(seq, bool)" not in text:
                continue
            for inner in ast.walk(statement):
                if isinstance(inner, ast.Raise) and isinstance(inner.exc, ast.Call):
                    func = inner.exc.func
                    if isinstance(func, ast.Name):
                        return getattr(module, func.id)
    return None


def _kind(name: str):
    """A valid audit kind, read from the module's own kind constant."""
    module = MODULES[name]
    fn = _audit_fn(name)
    tree = ast.parse(Path(fn.__code__.co_filename).read_text(errors="ignore"))
    node = None
    for candidate in ast.walk(tree):
        if isinstance(candidate, ast.FunctionDef) and candidate.name == fn.__name__:
            node = candidate
            break
    # the kind check compares the parameter against a module constant
    const = None
    for statement in ast.walk(node):
        if isinstance(statement, ast.If) and isinstance(statement.test, ast.Compare):
            for comparator in statement.test.comparators:
                if isinstance(comparator, ast.Name):
                    const = comparator.id
                    break
        if const:
            break
    assert const is not None, f"{name}: no kind constant found"
    for top in tree.body:
        if isinstance(top, ast.Assign):
            for target in top.targets:
                if isinstance(target, ast.Name) and target.id == const:
                    value = top.value
                    if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
                        for element in value.elts:
                            if isinstance(element, ast.Constant) and isinstance(
                                element.value, str
                            ):
                                return element.value
                    if isinstance(value, ast.Dict):
                        for key in value.keys:
                            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                return key.value
    raise AssertionError(f"{name}: kind constant {const} has no string member")


def _extra_args(name: str):
    """The extra POSITIONAL arguments the audit function requires.

    Two members declare ``audit_event(kind, seq, details)`` with a
    required third parameter.  The parameter is read from the
    signature, so the list is not hand-maintained.
    """
    fn = _audit_fn(name)
    args = fn.__code__.co_varnames[: fn.__code__.co_argcount]
    return [{"details": {}}] if len(args) > 2 else []


class AiAuditEventSeqGuardFamilyTest(unittest.TestCase):
    """The family really is the family, and every member refuses a bool."""

    def test_the_family_members_really_carry_the_seq_guard(self) -> None:
        for name in MODULES:
            with self.subTest(module=name):
                fn = _audit_fn(name)
                self.assertIsNotNone(fn, f"{name} has no {name}_audit_event")
                node = _guard_node(name)
                self.assertIsNotNone(
                    node,
                    f"{name} has no bool/int seq guard in {name}_audit_event",
                )
                text = ast.unparse(node)
                self.assertIn("isinstance(seq, bool)", text)
                self.assertIn("int", text)

    def test_a_bool_seq_is_refused_with_the_modules_own_error(self) -> None:
        """THE CRAFTED INPUT.

        `True` is an `int` in Python, so only the `bool` half of the
        guard refuses it.  Under the `or -> and` mutant the guard
        accepts `True` and returns a row carrying `seq=True`.
        """
        for name in MODULES:
            with self.subTest(module=name):
                fn = _audit_fn(name)
                error = _error_class(name)
                self.assertIsNotNone(error, f"{name}: no seq error class")
                with self.assertRaises(error):
                    fn(_kind(name), True, *_extra_args(name))

    def test_a_good_seq_is_accepted(self) -> None:
        """THE CONTROL.

        Paired with the rejection above on the SAME module: a guard that
        refused everything would pass every rejection test.  This is the
        case that says the guard accepts a plain int.
        """
        for name in MODULES:
            with self.subTest(module=name):
                fn = _audit_fn(name)
                row = fn(_kind(name), 1, *_extra_args(name))
                self.assertIsInstance(row, dict)
                self.assertEqual(row["seq"], 1)
                self.assertNotIsInstance(row["seq"], bool)

    def test_a_negative_seq_is_refused_where_the_guard_says_so(self) -> None:
        """The second half of the guard, on the modules that carry it.

        Fourteen members add a `seq < 0` (or `seq <= 0`) clause.  For
        those the negative case is refused; for the rest a negative int
        is a legal seq and the module must accept it.  The clause is
        read from the module's own source, so the test never asserts a
        rule the module does not enforce.
        """
        for name in MODULES:
            with self.subTest(module=name):
                fn = _audit_fn(name)
                node = _guard_node(name)
                text = ast.unparse(node)
                error = _error_class(name)
                if "<" in text:
                    with self.assertRaises(error):
                        fn(_kind(name), -1, *_extra_args(name))
                else:
                    row = fn(_kind(name), -1, *_extra_args(name))
                    self.assertEqual(row["seq"], -1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
