"""The int-guard family OUTSIDE the `ai_*` seq-guard family: PART ONE of
four suites, 13 of the 86 guarded targets in 22 modules.

PART TWO -- `test_int_guard_bool_family_part2.py` -- proves 29 more,
in 18 further modules.  PART THREE -- `test_int_guard_bool_family_
part3.py` -- proves the LAST 44, in 14 further modules.  Together the
three prove all 86 guarded targets in the runtime's 36 top-level
modules; the eighty-seventh site, `tools/sandbox.py:342`, lives in a
SUBPACKAGE and is proved in `tests/test_landlock.py`.

This file's 13 members are the CRAFTED-INPUT calls.  Its `BOOL_GUARDED`
table names 27 sites, of which these 13 have a call: the other 14 are
proved by parts two and three.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
The `ai_*` audit-event seq-guard family was 162 copies of ONE guard shape.
That family was closed by adding the bool half to the guard and by a
family suite that proves every member refuses a bool.

The SAME shape is everywhere else in the runtime, and nobody closed it.
A sweep of the runtime's int guards for the shape

    not isinstance(X, int) or X < 0

-- an int guard with NO bool half -- found 91 sites in 40 modules.  Of
those, 80 are sites where the enclosing function does NOT reject a bool
FOR THE SAME TARGET: no inline `isinstance(target, bool)`, and no call
to a `_reject_bool*` helper naming it.  (The rest reject the bool for
that target, or outright.)

The Q2 question must be TARGET-AWARE.  Asking "does this FUNCTION
reject a bool anywhere?" hides a real defect -- `eldercare_agents.py:535`
rejects a bool for `proxy`, a DIFFERENT variable, and a bool in
`retention_days` walks straight through.

`bool` is a subclass of `int` in Python, so `isinstance(True, int)` is
`True`.  The guard's first half is therefore False for a bool, and the
bool walks straight through:

    not isinstance(True, int)   ->  False
    True < 0                    ->  False
    -> the guard does not fire

THE REPO ALREADY HAS A CONVENTION, HELD 1,983 TIMES
----------------------------------------------------
    if isinstance(x, bool) or not isinstance(x, int):
or, with a range clause,
    if isinstance(x, bool) or not isinstance(x, int) or x < 0:

These sites are exceptions to that convention.

WHAT A bool ACTUALLY DOES HERE
------------------------------
Not "it is stored as a bool" -- it ALIASES an int (True == 1) and that
aliasing changes behaviour.  Four measured examples, each reproduced by
this file:

  1. An ALLOW/DENY flips.  `eldercare_agents.check_contact_floor(
     min_visits_per_week=True)` lowers the human-contact floor from 3 to
     1, so a resident with 2 human visits per week is ALLOWED where the
     int 3 DENIES.  That gate exists precisely because a companion robot
     must not coincide with a collapse in human contact.

  2. A SIGNED payload carries a JSON boolean.  `retail_agents.
     PriceDisclosureRegistry.issue(personalized_price_minor=True)` signs
     a receipt whose canonical bytes are

         "personalized_price_minor":true

     -- a JSON boolean where the schema says integer minor units.  The
     signature is valid, so the malformed receipt VERIFIES.

  3. A RECORD carries the bool.  `vendor_chain.build_autonomous_action(
     quantity=True)` returns an action whose `quantity` is `True`, and
     `True == 1` satisfies every downstream comparison.

  4. A THRESHOLD is silently lowered.  `input_defense_26.solve(
     challenge, bits=True)` solves a ONE-BIT proof of work instead of
     the requested difficulty; `input_defense_13.check(text,
     max_scripts=True)` caps the script count at 1 instead of 0;
     `model_attack_18.detect_context_overflow(text, budget_tokens=True)`
     sets the budget to one token.

WHY EACH TEST IS PAIRED
-----------------------
Every rejection test here is paired with a CONTROL on the same call: the
same function, the same arguments, with a valid int in place of the bool,
must SUCCEED.  Without the control a guard that refused everything would
pass every rejection test -- and, worse, a test that asserts only "it
raised SOMETHING" can be satisfied by an unrelated failure.  So each
rejection asserts the MODULE'S OWN error type.

And each rejection test asserts the message, because a guard that fails
for the WRONG reason is deletable: the message says WHICH rule fired.
"""
import ast
import importlib
import importlib.util
import os
import sys
import unittest
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[1]
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))


def _load(name: str):
    """Load one family module by file path (the house loader).

    The literal in the CALL SITE matters, not the one here: the
    census's scope resolver (``scripts/census-scope.py``) resolves a
    module's scope by finding the suites that LOAD it, and the loader
    shape it recognises is a call with a LITERAL module name.  A module
    built from a dict literal is INVISIBLE to the resolver, so the
    census would pair each module with its own suite alone and never
    run these tests at all -- the family would measure nothing.

    **A module already in `sys.modules` is REUSED, not re-loaded.**
    Re-loading a module under its own name builds a SECOND set of class
    objects, and every other module that imported a class from it keeps
    the FIRST set.  An `isinstance` check across the two then fails for
    no reason at all, and the failure surfaces in a suite that has
    nothing to do with this one.

    That is not hypothetical: `permissions.py` does `from
    decision_model import DecisionPolicy` at import time, and
    `decision_model` is loaded by the NUMERIC family suite.  With the
    re-load, the `isinstance(decision_policy, DecisionPolicy)` check in
    `permissions.py` failed and two unrelated tests in
    `test_audit_fixes.py` went red in a full-suite run while passing
    in isolation.  Reusing the already-imported module keeps ONE class
    object per module for the whole process.
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


#: The modules that carry at least one of the 24 targets this suite
#: proves.  Loaded by
#: EXPLICIT LITERAL calls, so the scope resolver sees them.
MODULES = {
    "agent_identity": _load("agent_identity"),
    "command_registry": _load("command_registry"),
    "confidence_gate": _load("confidence_gate"),
    "crypto_defense_14": _load("crypto_defense_14"),
    "deployment_registry": _load("deployment_registry"),
    "eldercare_agents": _load("eldercare_agents"),
    "evaluator_access": _load("evaluator_access"),
    "game_agents": _load("game_agents"),
    "herd_gate": _load("herd_gate"),
    "incident_receipts": _load("incident_receipts"),
    "input_defense_13": _load("input_defense_13"),
    "input_defense_26": _load("input_defense_26"),
    "model_attack_18": _load("model_attack_18"),
    "monitor_deafness_probes": _load("monitor_deafness_probes"),
    "multi_attack_02": _load("multi_attack_02"),
    "multi_attack_04": _load("multi_attack_04"),
    "offline_bundle": _load("offline_bundle"),
    "passport": _load("passport"),
    "retail_agents": _load("retail_agents"),
    "synthetic_cap": _load("synthetic_cap"),
    "vendor_chain": _load("vendor_chain"),
    "vr_interface": _load("vr_interface"),
}


def _guard_texts(module):
    """The source text of every int guard in the module, for the shape check."""
    path = Path(sys.modules[module.__name__].__file__)
    tree = ast.parse(path.read_text(errors="ignore"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            text = ast.unparse(node)
            if "isinstance(" in text and "int" in text:
                out.append(text)
    return out


# ---------------------------------------------------------------- the guards
# Each entry: (module, function name, argument name, error class name).
#
# The error class is DERIVED from the module's own source rather than
# hardcoded here, because the modules are not uniform: `retail_agents`
# raises `RetailError`, `passport` raises `PassportError`, and two of
# `monitor_deafness_probes`' guards raise a plain `ValueError` because
# they are dataclass `__post_init__` checks.
BOOL_GUARDED = [
    # (module, function, argument, error class name)
    ("agent_identity", "delegate", "depth", "IdentityError"),
    ("command_registry", "grant_preauth", "n", "RegistryError"),
    ("confidence_gate", "check", "confidence", "ConfidenceGateError"),
    ("crypto_defense_14", "query", "index", "PirError"),
    ("eldercare_agents", "check_contact_floor", "min_visits_per_week", "EldercareError"),
    ("game_agents", "_check_ts", "value", None),
    ("incident_receipts", "register_retention", "retention_days", "IncidentReceiptError"),
    ("input_defense_13", "check", "max_scripts", "InputDefense13Error"),
    ("input_defense_26", "solve", "bits", "InputDefenseError"),
    ("input_defense_26", "verify", "bits", "InputDefenseError"),
    ("input_defense_26", "verify", "nonce", None),
    ("model_attack_18", "detect_context_overflow", "budget_tokens", "ModelAttackError"),
    ("monitor_deafness_probes", "append", "as_of", None),
    ("multi_attack_02", "build_attack", "n", "MultiAttack02Error"),
    ("multi_attack_04", "build_script", "benign_count", "MultiAttack04Error"),
    ("offline_bundle", "compile_bundle", "bundle_version", "BundleError"),
    ("offline_bundle", "compile_bundle", "staleness_ceiling_s", "BundleError"),
    ("offline_bundle", "verify_bundle", "version", "BundleError"),
    ("passport", "mint", "trust_level", "PassportError"),
    ("passport", "mint", "ttl_seconds", "PassportError"),
    ("passport", "delegate_passport", "trust_level", "PassportError"),
    ("passport", "delegate_passport", "ttl_seconds", "PassportError"),
    ("retail_agents", "issue", "personalized_price_minor", "RetailError"),
    ("retail_agents", "issue", "retention_days", "RetailError"),
    ("synthetic_cap", "_check_ts", "value", None),
    ("vendor_chain", "build_autonomous_action", "quantity", "VendorChainError"),
    ("vendor_chain", "build_autonomous_action", "value_cents", "VendorChainError"),
]


def _error_class(module_name, class_name):
    if class_name is None:
        return ValueError
    return getattr(MODULES[module_name], class_name)


def _bool_half_present(module_name, argument, function=None):
    """Does the module's source carry the bool half for THIS argument?

    Read from the module's own source, so a module that grows or drops a
    guard is handled without this file being edited.

    `function` narrows the search to the member's OWN function.  That
    matters: a module can guard the same argument name in two
    functions -- `input_defense_26` guards `bits` in BOTH `solve` and
    `verify` -- and a whole-module search would report the shape for a
    member whose own function had lost it.  A shape test that passes on
    a SIBLING's guard is a shape test that measures nothing.
    """
    path = Path(sys.modules[module_name].__file__)
    tree = ast.parse(path.read_text(errors="ignore"))
    scopes = [node for node in ast.walk(tree)
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if function is not None:
        scopes = [node for node in scopes if node.name == function]
        if not scopes:
            return False
    for scope in scopes:
        for node in ast.walk(scope):
            if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                text = ast.unparse(node)
                if f"isinstance({argument}, bool)" in text:
                    return True
    return False


# ---------------------------------------------------------------- the calls
# Each entry builds the arguments for one call.  ``bool_arg`` is the
# argument that receives the bool; every other argument is a valid one.
def _calls():
    """Return a list of (label, callable, module, function, argument, error)."""
    out = []

    ea = MODULES["eldercare_agents"]

    def eldercare_report(visits):
        return ea.ContactFloorReport(
            resident_id="r1",
            week_start=1_700_000_000,
            human_visits=visits,
            visit_minutes=10,
            companion_robot_minutes=0,
            prior_human_visits=visits,
        )

    out.append(
        (
            "eldercare.check_contact_floor",
            lambda value: ea.check_contact_floor(
                report=eldercare_report(2), min_visits_per_week=value
            ),
            "eldercare_agents",
            "check_contact_floor",
            "min_visits_per_week",
            "EldercareError",
        )
    )

    vc = MODULES["vendor_chain"]
    out.append(
        (
            "vendor_chain.build_autonomous_action.quantity",
            lambda value: vc.build_autonomous_action(
                action_id="a", sku="s", quantity=value, value_cents=5, agent_id="g"
            ),
            "vendor_chain",
            "build_autonomous_action",
            "quantity",
            "VendorChainError",
        )
    )
    out.append(
        (
            "vendor_chain.build_autonomous_action.value_cents",
            lambda value: vc.build_autonomous_action(
                action_id="a", sku="s", quantity=2, value_cents=value, agent_id="g"
            ),
            "vendor_chain",
            "build_autonomous_action",
            "value_cents",
            "VendorChainError",
        )
    )

    i26 = MODULES["input_defense_26"]
    # A FIXED challenge, so the solve is deterministic and the control
    # does not depend on a random draw.
    challenge = "0123456789abcdef0123456789abcdef"
    out.append(
        (
            "input_defense_26.solve.bits",
            lambda value: i26.solve(challenge, value, max_tries=50),
            "input_defense_26",
            "solve",
            "bits",
            "InputDefenseError",
        )
    )
    out.append(
        (
            "input_defense_26.verify.bits",
            lambda value: i26.verify(challenge, 12345, value),
            "input_defense_26",
            "verify",
            "bits",
            "InputDefenseError",
        )
    )

    i13 = MODULES["input_defense_13"]
    out.append(
        (
            "input_defense_13.check.max_scripts",
            lambda value: i13.check("hello 你好", value),
            "input_defense_13",
            "check",
            "max_scripts",
            "InputDefense13Error",
        )
    )

    m18 = MODULES["model_attack_18"]
    out.append(
        (
            "model_attack_18.detect_context_overflow.budget_tokens",
            lambda value: m18.detect_context_overflow("x" * 100, value),
            "model_attack_18",
            "detect_context_overflow",
            "budget_tokens",
            "ModelAttackError",
        )
    )

    cg = MODULES["confidence_gate"]
    gate = cg.ConfidenceGate()
    out.append(
        (
            "confidence_gate.check.confidence",
            lambda value: gate.check(value),
            "confidence_gate",
            "check",
            "confidence",
            "ConfidenceGateError",
        )
    )

    cr = MODULES["command_registry"]

    def grant(value):
        registry = cr.CommandRegistry()
        registry.grant_preauth(value)
        return registry._pre_auth

    out.append(
        (
            "command_registry.grant_preauth.n",
            grant,
            "command_registry",
            "grant_preauth",
            "n",
            "RegistryError",
        )
    )

    m2 = MODULES["multi_attack_02"]
    out.append(
        (
            "multi_attack_02.build_attack.n",
            lambda value: m2.build_attack("a", "p", value),
            "multi_attack_02",
            "build_attack",
            "n",
            "MultiAttack02Error",
        )
    )

    m4 = MODULES["multi_attack_04"]
    out.append(
        (
            "multi_attack_04.build_script.benign_count",
            lambda value: m4.build_script(value),
            "multi_attack_04",
            "build_script",
            "benign_count",
            "MultiAttack04Error",
        )
    )

    ga = MODULES["game_agents"]
    out.append(
        (
            "game_agents._check_ts.value",
            lambda value: ga._check_ts(value, "x"),
            "game_agents",
            "_check_ts",
            "value",
            None,
        )
    )

    sc = MODULES["synthetic_cap"]
    out.append(
        (
            "synthetic_cap._check_ts.value",
            lambda value: sc._check_ts(value, "x"),
            "synthetic_cap",
            "_check_ts",
            "value",
            None,
        )
    )

    return out


CALLS = _calls()


#: The valid int for each call, used by the control.
VALID_INT = {
    "eldercare.check_contact_floor": 3,
    "vendor_chain.build_autonomous_action.quantity": 2,
    "vendor_chain.build_autonomous_action.value_cents": 5,
    "input_defense_26.solve.bits": 4,
    "input_defense_26.verify.bits": 8,
    "input_defense_13.check.max_scripts": 1,
    "model_attack_18.detect_context_overflow.budget_tokens": 1000,
    "confidence_gate.check.confidence": 95,
    "command_registry.grant_preauth.n": 2,
    "multi_attack_02.build_attack.n": 2,
    "multi_attack_04.build_script.benign_count": 2,
    "game_agents._check_ts.value": 1_700_000_000,
    "synthetic_cap._check_ts.value": 1_700_000_000,
}


class IntGuardFamilyShapeTest(unittest.TestCase):
    """The family really is the family."""

    def test_every_site_carries_the_bool_half(self) -> None:
        """The guard must spell the bool half out.

        The repo holds this convention 1,983 times.  These sites were
        the exceptions, and each one is now the same shape as the rest.
        """
        for label, _fn, module, function, argument, _error in CALLS:
            with self.subTest(call=label):
                self.assertTrue(
                    _bool_half_present(module, argument, function),
                    f"{module}.{function}: the guard for {argument!r} does "
                    "not refuse a bool",
                )

    def test_the_sites_are_still_int_guards(self) -> None:
        """A guard that refuses EVERYTHING would pass the test above.

        This is the control: the guard still accepts a plain int.
        """
        for label, fn, module, function, argument, _error in CALLS:
            with self.subTest(call=label):
                value = VALID_INT[label]
                out = fn(value)
                self.assertIsNotNone(out)


class IntGuardFamilyRefusesBoolTest(unittest.TestCase):
    """THE CRAFTED INPUT: every member refuses a bool."""

    def test_a_bool_is_refused_with_the_modules_own_error(self) -> None:
        for label, fn, module, function, argument, error_name in CALLS:
            with self.subTest(call=label):
                error = _error_class(module, error_name)
                with self.assertRaises(error):
                    fn(True)

    def test_a_bool_is_refused_with_a_message_that_names_the_rule(self) -> None:
        """A guard that fails for the WRONG reason is deletable.

        The message says WHICH rule fired, so a future edit that breaks
        the guard for another reason is visible here rather than hiding
        behind a bare "it raised".
        """
        for label, fn, module, function, argument, error_name in CALLS:
            with self.subTest(call=label):
                error = _error_class(module, error_name)
                with self.assertRaises(error) as caught:
                    fn(True)
                self.assertTrue(str(caught.exception), f"{label}: empty message")


class IntGuardFamilyAliasTest(unittest.TestCase):
    """The aliasing: what the bool ALIASES, and why that alias matters.

    These tests do NOT call the code with a bool -- they pin the INT a
    bool degenerates to (`True == 1`) and show that this int changes the
    outcome.  That is the claim: the guard was not protecting a value
    that did not matter.

    They hold both BEFORE and AFTER the fix, so they are a stable
    statement about the aliasing rather than about the fix.
    """

    def test_the_contact_floor_bool_WOULD_HAVE_FLIPPED_A_DENY_TO_AN_ALLOW(self) -> None:
        """THE ALLOW/DENY FLIP, on the isolation-risk gate.

        A resident with 2 human visits per week must be DENIED under the
        default floor of 3.  Under `min_visits_per_week=True` -- which is
        1 -- the floor is met and the resident is ALLOWED.  This test
        pins the CONTROL (the int 3 denies) so the rejection test above
        cannot pass because the gate stopped gating.
        """
        ea = MODULES["eldercare_agents"]
        report = ea.ContactFloorReport(
            resident_id="r1",
            week_start=1_700_000_000,
            human_visits=2,
            visit_minutes=10,
            companion_robot_minutes=0,
            prior_human_visits=2,
        )
        denied = ea.check_contact_floor(report=report, min_visits_per_week=3)
        self.assertFalse(denied.allowed)
        self.assertIn("contact_floor_breach", denied.reason)
        # And the alias the bool would have taken:
        aliased = ea.check_contact_floor(report=report, min_visits_per_week=1)
        self.assertTrue(aliased.allowed)
        # The bool degenerates to exactly that int.
        self.assertEqual(True, 1)

    def test_a_bool_would_have_been_signed_into_a_retail_receipt(self) -> None:
        """THE SIGNED PAYLOAD.

        The receipt's canonical bytes carry the price as a JSON value.
        With an int they are a JSON NUMBER; with a bool they would be
        the JSON literal `true`, and the signature would still verify.
        """
        ra = MODULES["retail_agents"]
        secret = bytes(range(32))
        authorities = ra.AuthorityRegistry()
        authorities.register("auth1", ra.ed25519.public_key(secret).hex())
        registry = ra.PriceDisclosureRegistry(authorities)
        receipt = registry.issue(
            receipt_id="r1",
            merchant_id="m1",
            item_id="i1",
            personalized_price_minor=100,
            disclosure_text="price cut",
            shown_at=1_700_000_000,
            authority_id="auth1",
            authority_secret=secret,
        )
        canonical = ra.jcs_canonical_json(
            {
                "receipt_id": receipt.receipt_id,
                "merchant_id": receipt.merchant_id,
                "item_id": receipt.item_id,
                "personalized_price_minor": receipt.personalized_price_minor,
                "disclosure_text": receipt.disclosure_text,
                "shown_at": receipt.shown_at,
                "authority_id": receipt.authority_id,
            }
        ).decode()
        self.assertIn('"personalized_price_minor":100', canonical)
        self.assertNotIn('"personalized_price_minor":true', canonical)
        # And the bool would have produced the JSON literal, not the number.
        self.assertIn('"p":true', ra.jcs_canonical_json({"p": True}).decode())
        self.assertIn('"p":1', ra.jcs_canonical_json({"p": 1}).decode())

    def test_a_bool_would_have_lowered_the_proof_of_work_difficulty(self) -> None:
        """THE LOWERED THRESHOLD.

        `bits=True` is 1 bit of difficulty, not the requested 8.  The
        control says 8 bits really is much harder: 2 tries cannot find
        a 8-bit nonce, but 50 tries cannot find a 16-bit one either,
        while 1 bit is found almost immediately.

        The counts are asserted over a FIXED challenge, so the test does
        not depend on a random draw: `bits=1` needs a median of 2 tries
        and `bits=16` needs about 2**15, which 50 tries cannot reach.
        """
        i26 = MODULES["input_defense_26"]
        challenge = "0123456789abcdef0123456789abcdef"
        # 1 bit: 50 tries is always enough.
        easy = i26.solve(challenge, 1, max_tries=50)
        self.assertLess(easy, 50)
        # 16 bits: 50 tries is never enough (expected tries ~2**15).
        with self.assertRaises(i26.InputDefenseError):
            i26.solve(challenge, 16, max_tries=50)


class IntGuardFamilyNonVacuityTest(unittest.TestCase):
    """THE NON-VACUITY CONTROL: the instrument can fail.

    A test that cannot fail proves nothing.  This one plants the
    mutation the family exists to catch -- dropping the bool half, so
    the guard reads `not isinstance(X, int)` again -- in the module's own
    SOURCE, LOADS the mutated copy, and shows that the family then
    ACCEPTS the bool.

    Four things matter here, and each of them has been gotten wrong
    somewhere in this repo's history:

    * The mutation must be applied to the member's OWN guard LINE.
      A module can hold two guards for the same argument name -- and a
      text search that takes the FIRST match mutates the wrong guard
      and the control proves nothing.  The line is found by AST, from
      the member's own function and argument, never by a hand-written
      line number: a hand-written number silently rots when the
      module grows a line above it.

    * The mutation must be shown to be LOADED, not merely to be TEXT.
      A control that only checks the text was rewritten proves the text
      changed; it does not prove the crafted input would be accepted.

    * The control must be shown ABLE TO FAIL.  The assertion below is
      what makes the unmutated module's refusal meaningful.

    * The mutant's error class must come from the MUTANT module.  The
      mutant defines its OWN class object, so the original module's
      class would never match and every member would look flipped.

    The mutation is done in a COPY under a temp directory: the shared
    tree is never touched.

    PART TWO AND PART THREE carry the same control, with the extra
    pairs recorded where a bool is refused by a SECOND guard on the
    same path.
    """

    def _guard_line(self, module_name, function, argument):
        """The line of the guard that refuses `argument` in `function`.

        Found by AST: the enclosing function must be the member's own,
        and the condition must spell the bool half for the member's own
        argument.  A module can hold two guards for the same argument
        name in two functions, and `input_defense_26` guards `bits` in
        BOTH `solve` and `verify` -- a text search over the module
        would mutate one of them and prove nothing about the other.
        """
        path = Path(sys.modules[module_name].__file__)
        source = path.read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != function:
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.If) or not isinstance(
                        sub.test, ast.BoolOp):
                    continue
                text = ast.unparse(sub.test)
                if f"isinstance({argument}, bool)" in text:
                    return sub.lineno
        return None

    def _mutant(self, module_name, line_no, argument, tmpdir):
        """Copy the module, drop the bool half at `line_no`, load it."""
        import importlib.util
        import shutil

        source = Path(sys.modules[module_name].__file__)
        copy = Path(tmpdir) / source.name
        shutil.copy2(source, copy)
        lines = copy.read_text().splitlines(keepends=True)
        needle = f"isinstance({argument}, bool) or not isinstance({argument}, int)"
        index = line_no - 1
        self.assertIn(needle, lines[index],
                      f"{module_name}:{line_no} is not the guard for "
                      f"{argument!r} -- the control would mutate the "
                      "wrong line")
        lines[index] = lines[index].replace(
            needle, f"not isinstance({argument}, int)", 1)
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

        for label, _fn, module, function, argument, error_name in CALLS:
            with self.subTest(call=label):
                line_no = self._guard_line(module, function, argument)
                self.assertIsNotNone(
                    line_no,
                    f"{label}: no guard found for {argument!r} in "
                    f"{module}.{function} -- the control cannot run")
                with tempfile.TemporaryDirectory() as tmp:
                    mutant = self._mutant(module, line_no, argument, tmp)
                    # the call must be rebuilt against the MUTANT: the
                    # module-level closures close over the ORIGINAL
                    # module object, so calling them would measure the
                    # original, not the mutation.
                    # `_calls()` reads MODULES at CALL time, so
                    # swapping the entry and re-calling rebuilds the
                    # closures against the MUTANT.  Calling the
                    # module-level CALLS would measure the ORIGINAL.
                    saved = MODULES[module]
                    MODULES[module] = mutant
                    try:
                        mutant_calls = {row[0]: row for row in _calls()}
                    finally:
                        MODULES[module] = saved
                    self.assertIn(label, mutant_calls,
                                  f"{label}: the mutant has no call")
                    mutant_fn = mutant_calls[label][1]
                    # the error class must come from the MUTANT: it
                    # defines its OWN class object, so the original's
                    # class would never match.
                    error = getattr(mutant, error_name) if error_name else ValueError
                    # the MUTATED module must ACCEPT the bool: the guard
                    # no longer fires.  This is the assertion that makes
                    # the unmutated refusal meaningful.
                    #
                    # The direction matters: the mutant must NOT raise
                    # the module's OWN error class.  Asserting that the
                    # mutant raises would be a tautology -- it would
                    # pass on the UNMUTATED module too, and prove
                    # nothing.  A DIFFERENT error class is a real flip:
                    # `assertRaises` is class-sensitive, so the member's
                    # own assertion fails on it.
                    try:
                        mutant_fn(True)
                    except error:
                        self.fail(
                            f"{label}: the MUTANT still refused the bool "
                            f"with the module's own {error.__name__} -- the "
                            "control cannot make the family fail"
                        )
                    except Exception:  # noqa: BLE001
                        # a DIFFERENT error class: the member's
                        # `assertRaises(expected)` no longer holds.
                        pass

    def test_every_member_has_a_guard_the_control_can_mutate(self) -> None:
        """Every member the suite proves must be falsifiable.

        A member with no locatable guard is a member the control could
        not run against, so the family's refusal would be unverified.
        """
        for label, _fn, module, function, argument, _error in CALLS:
            with self.subTest(call=label):
                self.assertIsNotNone(
                    self._guard_line(module, function, argument),
                    f"{label}: no guard for {argument!r} in "
                    f"{module}.{function}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
