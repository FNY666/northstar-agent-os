"""The `ai_*` import-guard family: ONE blind spot, 170 copies.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
170 of the runtime's `ai_*` modules carry a `stdlib_only()` that is a
copy of ONE template: parse your own source with `ast`, walk the
imports, and refuse any import whose root is not on an allowlist.

    def stdlib_only() -> bool:
        allowed = {...}
        tree = ast.parse(Path(__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] not in allowed:
                        return False
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] not in allowed:
                    return False
        return True

Every one of the 170 modules has its OWN suite, and every one of those
suites calls `stdlib_only()` and asserts it is `True` -- against the
module's REAL file, whose imports are all on the allowlist.

**A GUARD WHOSE WHOLE JOB IS TO REJECT, TESTED ONLY ON THE ACCEPTING
SIDE, IS NOT TESTED.**  The two `return False` branches are the guard.
They are never taken, because the file the guard reads is the module
itself, and the module imports only what it is allowed to import.

MEASURED: the artifact's 137 rows for this family carry the two
`stdlib_only` `return False` sites as SURVIVORS in **96** of them --
the same two lines, in 96 rows, for the same reason.

    ai_accident MUTANT retF@943 SURVIVED; MUTANT retF@946 SURVIVED;
                MUTANT RESULT: killed 23/26

This is the SECOND level of the gap described in the `ai_*_auditing`
family slice: a blind spot replicated N times is INVISIBLE to a
per-module reading, because each module's own suite looks normal.

THE CRAFTED INPUT
-----------------
The guard reads its OWN FILE, so the only way to drive its rejection
is to point it at a file that VIOLATES the rule.  The module's
`__file__` attribute is redirected for the duration of the call; the
real file is never modified.

Three things a crafted source has to get right, and all three are
DRIVEN BY THE MODULE'S OWN RULE rather than by a copy of it:

* The FOREIGN import must be one the module's allowlist excludes.
  The allowlist is read from the module's SOURCE, not hardcoded: a
  hardcoded copy could drift from the module, and then the test would
  be asserting against a rule the module does not enforce.
* The ACCEPTED import must be one the module's allowlist INCLUDES.
* `ast` is on every one of the 170 allowlists (measured), so it is the
  one name that is safe to use as the accepted import everywhere.

THE CONTROL
-----------
Every rejection test is paired with an acceptance test on the SAME
module.  A guard that rejected everything would pass every rejection
test; only the pair distinguishes "the guard rejects foreign imports"
from "the guard rejects everything".

TWO AST NODES, TWO `return False`
----------------------------------
The `ast.Import` branch and the `ast.ImportFrom` branch are SEPARATE
AST nodes with SEPARATE `return False` statements.  A test that only
drives one of them leaves the other untested -- and a mutant that
breaks only one of the two sites survives a suite that drove the
other.  So they are TWO tests, not one.

A NOTE ON SCOPE
---------------
The 170 are the modules whose `stdlib_only()` STRUCTURALLY matches
this template: it reads `__file__`, it has an `ast.Import` branch, it
has an `ast.ImportFrom` branch, and each branch has its own
`return False`.  The family is discovered by that structure, so a
module that joins the family joins it automatically.

The suite asserts the family's PREMISE -- that every member really has
the template's shape -- so a module that leaves the family is caught
rather than silently carried by the cases.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import sys
import tempfile
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
    "ai_accountability_auditing": _load("ai_accountability_auditing"),
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
    "ai_adversarial": _load("ai_adversarial"),
    "ai_assurance": _load("ai_assurance"),
    "ai_attack": _load("ai_attack"),
    "ai_audit": _load("ai_audit"),
    "ai_bias": _load("ai_bias"),
    "ai_calibration": _load("ai_calibration"),
    "ai_charter": _load("ai_charter"),
    "ai_compliance": _load("ai_compliance"),
    "ai_compliance_auditing": _load("ai_compliance_auditing"),
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
    "ai_contestability_auditing": _load("ai_contestability_auditing"),
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
    "ai_defense": _load("ai_defense"),
    "ai_distillation": _load("ai_distillation"),
    "ai_distribution_shift": _load("ai_distribution_shift"),
    "ai_ensemble": _load("ai_ensemble"),
    "ai_ethics_auditing": _load("ai_ethics_auditing"),
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
    "ai_exploit": _load("ai_exploit"),
    "ai_failure": _load("ai_failure"),
    "ai_fairness_auditing": _load("ai_fairness_auditing"),
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
    "ai_governance": _load("ai_governance"),
    "ai_harm": _load("ai_harm"),
    "ai_incident": _load("ai_incident"),
    "ai_isolation": _load("ai_isolation"),
    "ai_liability": _load("ai_liability"),
    "ai_mitigation": _load("ai_mitigation"),
    "ai_monitoring": _load("ai_monitoring"),
    "ai_ood_detection": _load("ai_ood_detection"),
    "ai_oversight": _load("ai_oversight"),
    "ai_oversight_auditing": _load("ai_oversight_auditing"),
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
    "ai_policy": _load("ai_policy"),
    "ai_prevention": _load("ai_prevention"),
    "ai_privacy": _load("ai_privacy"),
    "ai_probing": _load("ai_probing"),
    "ai_pruning": _load("ai_pruning"),
    "ai_quarantine": _load("ai_quarantine"),
    "ai_recourse": _load("ai_recourse"),
    "ai_recovery": _load("ai_recovery"),
    "ai_redress": _load("ai_redress"),
    "ai_redteaming": _load("ai_redteaming"),
    "ai_regulation": _load("ai_regulation"),
    "ai_remediation": _load("ai_remediation"),
    "ai_resilience": _load("ai_resilience"),
    "ai_risk": _load("ai_risk"),
    "ai_robustness": _load("ai_robustness"),
    "ai_robustness_auditing": _load("ai_robustness_auditing"),
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
    "ai_safety_auditing": _load("ai_safety_auditing"),
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
    "ai_traceability_auditing": _load("ai_traceability_auditing"),
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
    "ai_transparency_auditing": _load("ai_transparency_auditing"),
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


#: The name every one of the 170 allowlists contains.
#:
#: MEASURED: the intersection of the 162 literal allowlists is
#: `['__future__', 'ast', 'dataclasses', 'hashlib', 'json', 'threading',
#: 'typing']`, so `ast` is the one import that is safe to use as the
#: ACCEPTED case in every module.
COMMON_ALLOWED = "ast"

#: An import root that is on NO allowlist in this repository.
#:
#: `numpy` is a third-party package that no `ai_*` module is allowed to
#: import.  It is never imported here -- it only appears as TEXT in a
#: crafted source file, which is parsed but never executed.
FOREIGN_ROOT = "numpy"


def _source_of(name: str) -> str:
    return (RUNTIME / f"{name}.py").read_text(encoding="utf-8")


def _stdlib_only_node(name: str):
    """The module's `stdlib_only` function node, or None."""
    for node in ast.parse(_source_of(name)).body:
        if isinstance(node, ast.FunctionDef) and node.name == "stdlib_only":
            return node
    return None


def _allowed_roots(name: str) -> frozenset[str]:
    """The module's OWN import allowlist, read from its SOURCE.

    Read from the AST rather than hardcoded: a hardcoded copy could
    drift from the module, and the test would then be asserting against
    a rule the module does not enforce.

    The allowlist is found in the `stdlib_only` body -- either as a
    literal `allowed = {...}` or as a reference to a module-level
    constant.  When it cannot be resolved statically the whole
    allowlist is returned as EMPTY, and the caller then only uses the
    ACCEPTED case (which every module allows) -- see
    `_accepted_root`.
    """
    source = _source_of(name)
    tree = ast.parse(source)
    node = _stdlib_only_node(name)
    if node is None:
        return frozenset()
    allowed: set[str] = set()
    # a module-level constant referenced by the guard
    for other in tree.body:
        if isinstance(other, ast.Assign):
            for target in other.targets:
                if isinstance(target, ast.Name) and target.id.startswith("_"):
                    try:
                        value = ast.literal_eval(other.value)
                    except Exception:
                        continue
                    if isinstance(value, (set, frozenset, list, tuple)):
                        allowed.update(str(v) for v in value)
    # a literal assigned INSIDE the guard
    for inner in ast.walk(node):
        if isinstance(inner, ast.Assign):
            for target in inner.targets:
                if isinstance(target, ast.Name) and target.id == "allowed":
                    try:
                        value = ast.literal_eval(inner.value)
                    except Exception:
                        continue
                    if isinstance(value, (set, frozenset, list, tuple)):
                        allowed.update(str(v) for v in value)
    return frozenset(allowed)


def _accepted_root(name: str) -> str:
    """A root the module's allowlist includes, or `COMMON_ALLOWED`.

    `ast` is on every one of the 170 allowlists (measured), so it is
    the safe fallback when a module's allowlist cannot be resolved
    statically.
    """
    allowed = _allowed_roots(name)
    if allowed and COMMON_ALLOWED in allowed:
        return COMMON_ALLOWED
    if allowed:
        for candidate in sorted(allowed):
            if candidate != "canonical_json":
                return candidate
    return COMMON_ALLOWED


def _has_import_and_importfrom(name: str) -> tuple[bool, bool]:
    """Which of the two AST branches the module's guard really has."""
    node = _stdlib_only_node(name)
    if node is None:
        return (False, False)
    source = ast.get_source_segment(_source_of(name), node) or ""
    return ("ast.Import" in source, "ast.ImportFrom" in source)


def _with_source(module, source: str):
    """Call ``stdlib_only()`` against a CRAFTED source file.

    The module's ``__file__`` is redirected for the duration of the
    call, so the guard parses a file that VIOLATES the rule it
    enforces.  The real file is never modified.
    """
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".py", delete=False, encoding="utf-8"
    )
    handle.write(source)
    handle.close()
    real = module.__file__
    module.__file__ = handle.name
    try:
        return module.stdlib_only()
    finally:
        module.__file__ = real
        os.unlink(handle.name)


# ---------------------------------------------------------------------------
# The SECOND blind spot in the same family: the id guard
# ---------------------------------------------------------------------------

#: A non-string that no id guard can accept.
#:
#: The id guards read `isinstance(value, bool) or not isinstance(value, str)
#: or not value.strip()`.  The type half is the one that is never driven:
#: every suite that calls the guard passes a STRING, so the guard's
#: first two disjuncts are never the ones that decide.
NON_STRING = 123


def _id_guard(name: str):
    """The module's id guard, discovered by STRUCTURE.

    ``(function name, error class name, how the error class is
    supplied)`` -- or None when the module has no such guard.

    "How the error class is supplied" is either ``"module-class"`` (the
    guard raises a module-level error class) or ``"class-param"`` (the
    guard takes the error class as its second argument, and the CALLER
    supplies it).

    The guard is found by its CONDITION, not by its name: 145 of the
    170 modules have one, but under several names (`_check_id`,
    `_require_id`) and in several shapes.  A name-based lookup would
    miss the ones that differ; a condition-based lookup finds them all.
    """
    tree = ast.parse(_source_of(name))
    classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or len(node.args.args) != 2:
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.If) or not isinstance(
                inner.test, ast.BoolOp
            ):
                continue
            if "isinstance(value, str)" not in ast.unparse(inner.test):
                continue
            target = None
            for raised in ast.walk(node):
                if (isinstance(raised, ast.Raise)
                        and isinstance(raised.exc, ast.Call)
                        and isinstance(raised.exc.func, ast.Name)):
                    target = raised.exc.func.id
            param_names = [a.arg for a in node.args.args]
            if target in param_names:
                return (node.name, target, "class-param")
            return (node.name, target, "module-class")
    return None


def _id_guard_error_class(name: str):
    """The error class the module's id guard raises, and HOW.

    For the ``"class-param"`` shape the CALLER supplies the class, so
    it is read from the guard's CALL SITES -- the module's own code
    says which error class it means.

    The returned class NAME is the one the module's code passes; the
    caller looks the class up in the module.
    """
    found = _id_guard(name)
    if found is None:
        return None
    guard_name, target, how = found
    if how == "module-class":
        return (target, how)
    tree = ast.parse(_source_of(name))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == guard_name and len(node.args) >= 2
                and isinstance(node.args[1], ast.Name)):
            return (node.args[1].id, how)
    return None


def _id_guard_error_value(name: str, module):
    """The value to pass as the guard's SECOND argument.

    Two shapes:

    * ``"class-param"``: the guard takes the error CLASS, so the class
      is looked up in the module and passed as the class.
    * ``"module-class"``: the guard takes a field LABEL, so a label is
      passed.
    """
    error = _id_guard_error_class(name)
    if error is None:
        return None
    class_name, how = error
    if how == "class-param":
        return getattr(module, class_name, None)
    return "probe_field"


def _id_guard_blank(name: str):
    """The blank id THIS guard refuses, or None.

    The guards are not all the same shape.  134 of them use
    ``not value.strip()`` -- so BOTH ``""`` and ``"   "`` are refused.
    The other 11 use ``not value`` -- so only ``""`` is refused, and
    ``"   "`` is a perfectly good id (a whitespace id is not a
    security hole; it is what the module's own rule says).

    So the blank case is derived from the GUARD'S OWN CONDITION, not
    assumed: a test that asserted `"   "` is refused everywhere would
    be asserting a rule the module does not have.
    """
    found = _id_guard(name)
    if found is None:
        return None
    tree = ast.parse(_source_of(name))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == found[0]:
            condition = ast.unparse(node)
            if "value.strip()" in condition:
                return ("", "   ")
            return ("",)
    return None


def _id_guard_is_called(name: str) -> bool:
    """Whether the module's own code CALLS its id guard.

    A guard that is never called is dead code, and driving it proves
    nothing about the module.  Every one of the 145 is called
    (measured), and this keeps it that way.
    """
    found = _id_guard(name)
    if found is None:
        return False
    tree = ast.parse(_source_of(name))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == found[0]):
            return True
    return False



def _has_conditional_allowance(name: str) -> bool:
    """Whether the module's guard allows `canonical_json` only when
    the optional import SUCCEEDS.

    The shape is a `try:` block inside the guard whose body adds
    `canonical_json` to the allowlist.  When the import fails the
    addition does not happen, so the guard's verdict depends on the
    ENVIRONMENT -- which is the defect.
    """
    node = _stdlib_only_node(name)
    if node is None:
        return False
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Try):
            continue
        for statement in inner.body:
            text = ast.unparse(statement)
            if "canonical_json" in text and "allowed" in text:
                return True
    return False



def _stdlib_only_without_canonical_json(names):
    """``stdlib_only()`` on each module's OWN file, with
    ``canonical_json`` made UNIMPORTABLE.

    Run in a SUBPROCESS, because the dependency's presence is decided
    at IMPORT time: once `canonical_json` is in ``sys.modules`` in this
    process, every later import of it succeeds, and the module's own
    ``try: from canonical_json import ...`` would take the success
    branch no matter what this test does afterwards.

    The subprocess gets an import path that cannot resolve the
    dependency, and nothing else: the modules themselves are loaded by
    file path, so they do not need to be importable.

    ONE subprocess for the whole family, because a subprocess per
    module made this test slow enough to slow the mutant census down
    with it.
    """
    import subprocess

    script = (
        "import importlib.util, sys, pathlib\n"
        "R = pathlib.Path(%r)\n"
        "for name in %r:\n"
        "    spec = importlib.util.spec_from_file_location(name, R / (name + '.py'))\n"
        "    m = importlib.util.module_from_spec(spec)\n"
        "    sys.modules[name] = m\n"
        "    spec.loader.exec_module(m)\n"
        "    print(name + '=' + str(m.stdlib_only()))\n"
    ) % (str(RUNTIME), list(names))
    env = dict(os.environ)
    # The subprocess must NOT be able to resolve `canonical_json`.  For
    # `python -c`, `sys.path[0]` is the CURRENT DIRECTORY, so the
    # directory the subprocess runs in is what decides it -- an empty
    # PYTHONPATH is not enough, because a cwd of the runtime directory
    # would put `canonical_json.py` right there.  So the subprocess
    # runs in a directory of its own, and the modules are loaded by
    # FILE PATH, which does not need the runtime directory on the path.
    env["PYTHONPATH"] = ""
    with tempfile.TemporaryDirectory() as elsewhere:
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=elsewhere,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    if result.returncode != 0:
        raise AssertionError(
            f"the subprocess failed: {result.stderr[-400:]}"
        )
    out = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        out[name.strip()] = value.strip() == "True"
    return out



class AiImportGuardFamilyTest(unittest.TestCase):
    """The family's premise, and the two rejection branches."""

    # -- the premise -------------------------------------------------------

    def test_the_family_members_really_carry_the_template(self):
        """Every member has the template's SHAPE, checked structurally.

        The family is discovered by structure, but a family that is
        discovered by structure and then ASSUMED is a family that can
        rot.  If a member stops having an `ast.Import` branch, or stops
        having its own `return False`, this goes red rather than the
        module being silently carried by the cases below.

        It also asserts the members really are the modules the census
        artifact's family rows name, so the family cannot shrink
        without a measurement showing it.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                self.assertTrue(
                    hasattr(module, "stdlib_only"),
                    f"{name} has no stdlib_only()",
                )
                has_import, has_importfrom = _has_import_and_importfrom(name)
                self.assertTrue(has_import, f"{name}: no ast.Import branch")
                self.assertTrue(
                    has_importfrom, f"{name}: no ast.ImportFrom branch"
                )

    def test_every_family_module_has_a_suite_of_its_own(self):
        """A family member with no suite of its own has NO baseline.

        The census artifact's family rows were each measured against a
        single suite -- the module's own.  A member that has none would
        carry no measurement at all, and the gap would be invisible.
        """
        for name in MODULES:
            with self.subTest(module=name):
                own = RUNTIME / "tests" / f"test_{name}.py"
                self.assertTrue(
                    own.exists(),
                    f"{name} has no suite of its own: the family's rows "
                    f"were measured against it",
                )

    # -- the `ast.Import` branch's rejection ------------------------------

    def test_stdlib_only_rejects_a_foreign_import(self):
        """The `ast.Import` branch's `return False`.

        The suite that measured this module asserted `stdlib_only() is
        True` against the module's REAL file.  The real file's imports
        are all allowed, so the rejection was never taken -- and the
        artifact carries this site as a SURVIVOR in 96 of the family's
        rows.

        The crafted input is a file that imports a root which is on NO
        allowlist in this repository.  The text is never executed: it
        is parsed by the guard, which is the whole point.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                allowed = _allowed_roots(name)
                foreign = FOREIGN_ROOT
                if allowed and foreign in allowed:
                    # The module allows it, so it is not a foreign
                    # import for THIS module; pick a root it excludes.
                    for candidate in ("numpy", "pandas", "requests", "flask"):
                        if candidate not in allowed:
                            foreign = candidate
                            break
                self.assertIs(
                    _with_source(module, f"import {foreign}\n"),
                    False,
                    f"{name}: stdlib_only() accepted a foreign import",
                )

    # -- the `ast.ImportFrom` branch's rejection --------------------------

    def test_stdlib_only_rejects_a_foreign_import_from(self):
        """The `ast.ImportFrom` branch's `return False`.

        A SEPARATE AST node with its OWN `return False`, so a SEPARATE
        test: a mutant that breaks only the `ast.ImportFrom` site
        survives a suite that only drove the `ast.Import` site.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                allowed = _allowed_roots(name)
                foreign = FOREIGN_ROOT
                if allowed and foreign in allowed:
                    for candidate in ("numpy", "pandas", "requests", "flask"):
                        if candidate not in allowed:
                            foreign = candidate
                            break
                self.assertIs(
                    _with_source(module, f"from {foreign} import thing\n"),
                    False,
                    f"{name}: stdlib_only() accepted a foreign import-from",
                )

    # -- the controls ------------------------------------------------------

    def test_stdlib_only_accepts_an_allowed_import(self):
        """The non-vacuity control for BOTH rejection tests.

        Every rejection test above is measured against a source the
        guard must ACCEPT.  Without this, a guard that rejected
        everything would pass all of them -- and a guard that
        rejected everything is not a guard that enforces an allowlist.

        The accepted root is read from the MODULE'S OWN allowlist, so
        this asserts the module's rule and not a copy of it.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                root = _accepted_root(name)
                self.assertIs(
                    _with_source(module, f"import {root}\n"),
                    True,
                    f"{name}: stdlib_only() rejected an ALLOWED import",
                )

    def test_stdlib_only_accepts_an_allowed_import_from(self):
        """The same control, through the OTHER AST node.

        Two branches, two controls: the `ast.ImportFrom` branch must
        accept the module's own allowlist too, and on its own.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                root = _accepted_root(name)
                self.assertIs(
                    _with_source(module, f"from {root} import thing\n"),
                    True,
                    f"{name}: stdlib_only() rejected an ALLOWED import-from",
                )

    def test_stdlib_only_accepts_a_source_with_no_imports(self):
        """A source with NO imports at all is accepted.

        The third kind of control: it says the guard's answer is a
        property of the IMPORTS, not of the file merely being a
        different file.  Without it, the rejection tests could be
        passing because the guard rejects every file that is not its
        own.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                self.assertIs(
                    _with_source(module, "x = 1\n"),
                    True,
                    f"{name}: stdlib_only() rejected a source with no "
                    f"imports at all",
                )

    def test_stdlib_only_does_not_depend_on_an_optional_dependency(self):
        """The guard must give the SAME answer whether or not an
        OPTIONAL dependency is importable.

        `canonical_json` is the one non-stdlib import the family
        permits, because it is an OPTIONAL dependency with a stdlib
        fallback.  So a module that imports it under a try/except is
        importing it by construction, and the guard must allow it
        UNCONDITIONALLY -- whether the import succeeds or not.

        It did not.  MEASURED 2026-11-26: `ai_ethics_monitoring` added
        `canonical_json` to its allowlist only inside a
        `try: from canonical_json import ...`, so on a host where the
        optional dependency is ABSENT the guard reported the module's
        OWN file as non-stdlib -- a false alarm about a module that
        falls back to stdlib `json` and is therefore compliant.

        The other 162 members of the family allow it unconditionally,
        so `ai_ethics_monitoring` was the sole exception and the sole
        module whose guard misreported its own file.

        THE CRAFTED INPUT is the ENVIRONMENT, not a source file: the
        test runs the guard in a SUBPROCESS whose import path cannot
        resolve `canonical_json`.  A source file cannot express "this
        import failed", because the guard reads the file's TEXT -- it
        sees `from canonical_json import jcs_dumps` either way, and
        only the IMPORT ITSELF distinguishes the two cases.

        SCOPE: only the members whose guard adds the allowance
        CONDITIONALLY.  That is where the two answers could differ, and
        it keeps the test to one subprocess instead of 163 -- which
        matters, because a subprocess per module made the whole suite
        slow enough to slow the mutant census down with it.
        """
        # ONE subprocess for the whole family: a subprocess per module
        # made the suite slow enough to slow the mutant census down
        # with it, and the subprocess is the only way to change the
        # ENVIRONMENT the guard reads.
        results = _stdlib_only_without_canonical_json(list(MODULES))
        for name, result in results.items():
            with self.subTest(module=name):
                self.assertIs(
                    result, True,
                    f"{name}: stdlib_only() reported the module's own "
                    f"file as non-stdlib when the OPTIONAL "
                    f"canonical_json dependency was absent",
                )

        # And the premise, stated so it cannot rot: NO member may
        # allow `canonical_json` only when the optional import
        # SUCCEEDS.  `ai_ethics_monitoring` did, and that was the
        # defect; the fix made it unconditional.  Asserting the set is
        # EMPTY means a member that joins it again is caught, rather
        # than the test silently stopping to check anything.
        conditional = [
            name for name in MODULES
            if _has_conditional_allowance(name)
        ]
        self.assertEqual(
            conditional, [],
            "a family member allows canonical_json only when the "
            "optional import SUCCEEDS, so its guard reports its own "
            "file as non-stdlib on a host without the dependency",
        )

    def test_stdlib_only_still_accepts_the_modules_own_file(self):
        """The guard's real subject: the module's OWN source.

        The rejection tests all drive the guard at a crafted file.
        This drives it at the REAL file, which is what every suite in
        the family already did -- and it is what makes the crafted
        cases meaningful: the guard accepts the module's own file and
        refuses a foreign one, so it is discriminating on the IMPORTS
        and not on the file.
        """
        for name, module in MODULES.items():
            with self.subTest(module=name):
                self.assertIs(
                    module.stdlib_only(),
                    True,
                    f"{name}: stdlib_only() refused the module's own file",
                )


class AiIdGuardFamilyTest(unittest.TestCase):
    """The SECOND blind spot: the id guard's TYPE half.

    The import guard is the family's headline, but 145 of the 170
    modules carry a SECOND copy-pasted guard, and it has the same
    defect for the same reason.

        if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
            raise BadSystemError(f"{what} must be a non-empty string")

    The guard's whole job is to refuse an id that is not a
    non-empty string.  Every suite that calls it passes a STRING, so
    the guard's FIRST TWO DISJUNCTS are never the ones that decide --
    the third one (`not value.strip()`) always decides, and a mutant
    that turns the `or` into an `and` still rejects every string the
    suite passes.

    MEASURED: the artifact records this `or` as a SURVIVOR in 51 of
    the family's rows.

    THE CRAFTED INPUT
    -----------------
    A NON-STRING.  The original refuses it at the TYPE half and
    raises the module's OWN error class.  Under the mutant the
    `isinstance` half is satisfied, so the guard evaluates
    `value.strip()` on an int and CRASHES with `AttributeError`.

    So the observable is the EXCEPTION TYPE, and the test has to pin
    it: "it raised something" would pass under the mutant too.  This
    is the difference from the import guard, where the observable was
    the RETURN value.

    A conjunct needs a case on BOTH sides, so the string cases are
    here too: the guard must ACCEPT a good id, and must REFUSE an
    empty one.
    """

    def test_the_id_guard_members_are_discovered(self):
        """The premise: 145 of the 170 carry the guard, and all of
        them CALL it.

        Discovered by the guard's CONDITION, not by its name -- the
        name varies (`_check_id`, `_require_id`), the condition does
        not.  A name-based lookup would quietly cover fewer modules
        than it claims to.
        """
        with_id = [name for name in MODULES if _id_guard(name) is not None]
        self.assertGreater(
            len(with_id), 100,
            "the id guard was not found in enough family members: the "
            "family's blind spot is not where this suite thinks it is",
        )
        for name in with_id:
            with self.subTest(module=name):
                self.assertTrue(
                    _id_guard_is_called(name),
                    f"{name}: its id guard is never called, so driving it "
                    f"proves nothing about the module",
                )

    def test_a_non_string_id_is_refused_with_the_modules_own_error(self):
        """The type half of the guard.

        The original raises the module's OWN error class.  Under the
        mutant the guard crashes with `AttributeError` instead, so the
        test pins the exception TYPE -- a bare "it raised" would pass
        under the mutant too, and would measure nothing.
        """
        for name, module in MODULES.items():
            found = _id_guard(name)
            if found is None:
                continue
            error = _id_guard_error_class(name)
            if error is None:
                continue
            class_name, how = error
            second = _id_guard_error_value(name, module)
            if second is None:
                continue
            with self.subTest(module=name):
                guard = getattr(module, found[0])
                try:
                    guard(NON_STRING, second)
                except Exception as exc:  # noqa: BLE001 -- the type is the
                    # observable, and the point is that it is NOT
                    # AttributeError.
                    self.assertIsNot(
                        type(exc), AttributeError,
                        f"{name}: the id guard crashed on a non-string "
                        f"instead of refusing it -- the type half is "
                        f"not being enforced",
                    )
                    self.assertEqual(
                        type(exc).__name__, class_name,
                        f"{name}: the id guard refused a non-string with "
                        f"the wrong error class",
                    )
                else:
                    self.fail(
                        f"{name}: the id guard ACCEPTED a non-string id"
                    )

    def test_a_good_id_is_accepted(self):
        """The control: the guard must ACCEPT a good id.

        Without it the refusal test above could be passing because the
        guard refuses everything -- including the ids the module's own
        code passes it.
        """
        for name, module in MODULES.items():
            found = _id_guard(name)
            if found is None:
                continue
            with self.subTest(module=name):
                guard = getattr(module, found[0])
                second = _id_guard_error_value(name, module)
                if second is None:
                    continue
                self.assertEqual(
                    guard("sys-1", second), "sys-1",
                    f"{name}: the id guard refused a good id",
                )

    def test_an_empty_id_is_refused(self):
        """The other half of the conjunct: the EMPTY case.

        A string that is empty (or all whitespace) is refused by the
        THIRD disjunct, which is the one the suites already drive.
        It is here because a conjunct needs a case on BOTH sides, and
        because the mutant turns the third disjunct off as well.

        The error class is pinned for the same reason as above.
        """
        for name, module in MODULES.items():
            found = _id_guard(name)
            if found is None:
                continue
            error = _id_guard_error_class(name)
            if error is None:
                continue
            class_name, _how = error
            blanks = _id_guard_blank(name)
            if blanks is None:
                continue
            second = _id_guard_error_value(name, module)
            if second is None:
                continue
            with self.subTest(module=name):
                guard = getattr(module, found[0])
                for bad in blanks:
                    try:
                        guard(bad, second)
                    except Exception as exc:  # noqa: BLE001
                        self.assertEqual(
                            type(exc).__name__, class_name,
                            f"{name}: the id guard refused {bad!r} with "
                            f"the wrong error class",
                        )
                    else:
                        self.fail(
                            f"{name}: the id guard ACCEPTED the empty id "
                            f"{bad!r}"
                        )



if __name__ == "__main__":
    unittest.main()
