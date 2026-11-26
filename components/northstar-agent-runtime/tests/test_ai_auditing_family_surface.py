"""The `ai_*_auditing` family: one guard shape, nine modules, one blind spot.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
Eight sibling modules -- ``ai_accountability_auditing``,
``ai_compliance_auditing``, ``ai_contestability_auditing``,
``ai_ethics_auditing``, ``ai_fairness_auditing``, ``ai_safety_auditing``,
``ai_traceability_auditing`` and ``ai_transparency_auditing`` -- all
score **18/27** in the census artifact, and they score it for the SAME
REASON.

MEASURED: the four functions that carry every survivor are
BYTE-IDENTICAL across all eight modules (compared by hashing
``ast.unparse`` of each function):

    _valid_digest        edec9845   in all eight
    _check_mutation_seq  836a6c3d   in all eight
    _check_read_seq      5c8cca7a   in all eight
    stdlib_only          6e597f49   in all eight

So this is not eight coincidences.  It is ONE guard shape, replicated
eight times, with the same blind spot replicated eight times -- and a
blind spot replicated eight times is invisible to a per-module reading,
because each module's own suite looks like a normal suite.

> **A template hides TWO levels of gap.**
>
> The first level is the shared guard: never driven with the input it
> rejects.  The SECOND level is that the guard is REPLICATED -- so
> fixing one module's copy teaches nothing about the other seven, and a
> suite that only covers one of the eight looks complete.

THE NINE SURVIVORS (per module), AND WHAT EACH NEEDS
----------------------------------------------------
  or@271   `_valid_digest`: `not isinstance(value, str) or not
           value.startswith("sha256:")`.
           The suites feed the digest `"bad"`.  Under the mutant
           (`or` -> `and`) `"bad"` is REJECTED -- it is a str AND does
           not start with `sha256:` -- so both spellings agree on the
           suite's only input.  The CRAFTED INPUT is a NON-STRING: the
           original rejects it at the type half, while the mutant
           evaluates `value.startswith(...)` on an int and CRASHES with
           `AttributeError`.  The crash is the observable.

  eq@274 / and@274   `_valid_digest`: `len(tail) == 64 and all(c in
           "0123456789abcdef" for c in tail)`.
           The suites never call `_valid_digest` with a WELL-FORMED
           digest, so the `len` half is never the one that decides.
           The crafted inputs are a digest of 63 hex chars (too short),
           one of 65 (too long), and one of 64 NON-HEX chars -- each
           puts exactly ONE half of the conjunct at issue.

  retF@304   `AuditRecord.verify()`: `if not self.audit_digest: return
           False`.  The suites only verify records the ledger minted,
           and a minted record ALWAYS has a digest -- so the empty
           branch is never taken.  The crafted input is a record with
           an EMPTY digest, which must NOT verify.

  or@397   `_check_mutation_seq`: `isinstance(seq, bool) or not
           isinstance(seq, int) or seq < 1`.
           The suites pass `True` and expect `BadSeqError` -- and they
           get one, but from a DIFFERENT guard: the mutation's audit
           event routes through `_check_read_seq`, whose guard raises
           first.  **A SECOND PATH REACHES THE SAME ANSWER.**  So the
           discriminating observable is not the exception but the
           LEDGER STATE: under the mutant the `True` seq is CONSUMED
           (`last_seq` becomes `True`) and an audit row is BOOKED.

  or@405   `_check_read_seq`: `isinstance(seq, bool) or not
           isinstance(seq, int) or seq < 0`.  Same shape as `or@397`,
           but on the READ side there is no second path: a read that
           accepts `True` RETURNS a report instead of raising.

  eq@708 / retF@711 / retF@717   `stdlib_only()`: the AST
           import-allowlist.  The suites assert `stdlib_only() is
           True` on the REAL file -- whose imports are all allowed --
           so every REJECTION branch is untaken.  The CRAFTED INPUT is
           a source file that imports something outside the allowlist,
           and the module is re-parsed with a patched `__file__`, so the
           real file is never modified.

WHY THIS SUITE IS WRITTEN LINE-INDEPENDENTLY
---------------------------------------------
The eight modules put the same functions at DIFFERENT lines (the
digest guard is at 244 in one and 291 in another), so a suite that
named a line number would pin one module and silently skip the rest.
Every test here drives the module through its PUBLIC API, so it works
on all eight without a line number anywhere.

The modules also have DIFFERENT audit-kind vocabularies
(``internal-safety-audit`` in one, ``internal-fairness-audit`` in
another), so the suite reads the vocabulary from the module rather than
hardcoding one.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile

import pytest

RUNTIME = pathlib.Path(__file__).resolve().parent.parent

#: The eight modules that carry the identical guard shape.
#:
#: MEASURED 2026-11-26 by hashing ``ast.unparse`` of `_valid_digest`,
#: `_check_mutation_seq`, `_check_read_seq` and `stdlib_only` in each:
#: all eight agree.  The list is asserted by
#: ``test_the_family_modules_really_share_the_guard_shape``, so a
#: module that stops matching cannot be absorbed into the family.
FAMILY = (
    "ai_accountability_auditing",
    "ai_compliance_auditing",
    "ai_contestability_auditing",
    "ai_ethics_auditing",
    "ai_fairness_auditing",
    "ai_safety_auditing",
    "ai_traceability_auditing",
    "ai_transparency_auditing",
)


def _load(name: str):
    """Load a module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Every family module, loaded by an EXPLICIT LITERAL call.
#:
#: The literal matters: ``scripts/census-scope.py`` only recognises a
#: load whose module name is a literal, so a loop-built list would
#: make the scope resolver see NO suite and the census would SKIP
#: these rows.
MODULES = {
    "ai_accountability_auditing": _load("ai_accountability_auditing"),
    "ai_compliance_auditing": _load("ai_compliance_auditing"),
    "ai_contestability_auditing": _load("ai_contestability_auditing"),
    "ai_ethics_auditing": _load("ai_ethics_auditing"),
    "ai_fairness_auditing": _load("ai_fairness_auditing"),
    "ai_safety_auditing": _load("ai_safety_auditing"),
    "ai_traceability_auditing": _load("ai_traceability_auditing"),
    "ai_transparency_auditing": _load("ai_transparency_auditing"),
}


def _ledger_class(module):
    """The ledger class of a family module.

    Found by CAPABILITY, not by name: the class that has an `audit`
    method.  A name-derived lookup would be a second assumption about
    the family, and the family suite's whole point is that it makes as
    few assumptions as possible.
    """
    name = module.__name__.split(".")[-1]
    candidates = []
    for attr, value in vars(module).items():
        if isinstance(value, type) and callable(getattr(value, "audit", None)):
            candidates.append(value)
    if len(candidates) != 1:
        raise AssertionError(
            f"{name}: expected exactly one ledger class with an `audit` "
            f"method, found {candidates!r}"
        )
    return candidates[0]


def _with_source(module, source: str):
    """Call ``stdlib_only()`` against a CRAFTED source file.

    ``stdlib_only()`` parses ``pathlib.Path(__file__)``.  Re-parsing
    the REAL file can only ever produce the REAL answer, so the
    rejection branch is unverifiable against it.  This points the
    guard at a file that VIOLATES the rule the guard enforces.

    The real module file is never modified.
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
# 0. The family's premise, asserted
# ---------------------------------------------------------------------------


def test_the_family_modules_really_share_the_guard_shape():
    """The premise of this file, asserted rather than assumed.

    A family suite that runs against modules whose guards have DIVERGED
    measures nothing for the ones that did not match -- and it would do
    so silently.  So the shared shape is checked here: the four
    functions that carry every survivor must be byte-identical across
    all eight modules.

    If a sibling's guard is refactored, this test goes red and the
    family suite has to be re-measured for it -- which is the correct
    outcome, because a diverged module needs its OWN cases.
    """
    import ast
    import hashlib

    shapes = {}
    for name in FAMILY:
        tree = ast.parse((RUNTIME / f"{name}.py").read_text(encoding="utf-8"))
        per_module = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in (
                "_valid_digest",
                "_check_mutation_seq",
                "_check_read_seq",
                "stdlib_only",
            ):
                per_module[node.name] = hashlib.sha256(
                    ast.unparse(node).encode("utf-8")
                ).hexdigest()
        shapes[name] = per_module

    reference = shapes[FAMILY[0]]
    for name in FAMILY[1:]:
        for func, digest in shapes[name].items():
            assert digest == reference[func], (
                f"{name}.{func} no longer matches {FAMILY[0]}.{func}: "
                "the family suite's cases may not apply to it"
            )


# ---------------------------------------------------------------------------
# 1. The digest guard: `_valid_digest`
# ---------------------------------------------------------------------------


def test_a_non_string_digest_is_rejected():
    """`or@271`: the TYPE half of the guard.

    The suites' only malformed digest is the STRING `"bad"`, and under
    BOTH spellings that is rejected -- so it cannot tell them apart.

    The crafted input is a NON-STRING.  The original rejects it at the
    type half and returns False.  The mutant evaluates
    `value.startswith("sha256:")` on an int, which CRASHES with
    `AttributeError` -- and the crash is the observable.
    """
    for name, module in MODULES.items():
        for value in (123, None, 4.5, True, ["sha256:"], {"a": 1}, b"sha256:"):
            # The original returns False.  The mutant CRASHES with
            # AttributeError, which fails the test on its own -- so a
            # plain assert is the whole discriminator.
            assert module._valid_digest(value) is False, (
                f"{name}: the digest guard accepted a non-string"
            )


def test_a_string_digest_that_is_not_sha256_is_rejected():
    """The CONTROL for `or@271`: a string is rejected, not crashed on.

    The mutant must be distinguishable from the original on a STRING
    too -- otherwise the non-string case above would be the only
    discriminator, and the crash would be the whole story.
    """
    for name, module in MODULES.items():
        for value in ("bad", "sha256", "SHA256:" + "0" * 64,
                      " sha256:" + "0" * 64):
            assert module._valid_digest(value) is False, (
                f"{name}: the digest guard accepted a malformed digest"
            )


def test_a_well_formed_digest_is_accepted():
    """The non-vacuity control for the whole digest guard.

    A guard that only ever rejects is measured on one side.  This pins
    the ACCEPTING side, so a guard that rejected everything -- or that
    crashed on everything -- would be caught.
    """
    for name, module in MODULES.items():
        assert module._valid_digest("sha256:" + "0" * 64) is True, name
        assert module._valid_digest("sha256:" + "abcdef0123456789" * 4) is True, name
        assert module._valid_digest("") is True, name


def test_a_digest_of_the_wrong_length_is_rejected():
    """`eq@274` and `and@274`: the LENGTH half of the guard.

    A digest that is one character SHORT and one that is one character
    LONG put exactly ONE half of the conjunct at issue: `len(tail) ==
    64` decides for them, while every character is still hex.

    The `and` mutant (`and` -> `or`) accepts both, because the `all()`
    half is True for a hex-only tail -- so the length is what decides.

    And a 64-character tail of NON-HEX characters puts the OTHER half
    at issue: the length is right, so only the hex check can reject it.
    """
    for name, module in MODULES.items():
        assert module._valid_digest("sha256:" + "0" * 63) is False, name
        assert module._valid_digest("sha256:" + "0" * 65) is False, name
        assert module._valid_digest("sha256:" + "z" * 64) is False, name
        assert module._valid_digest("sha256:" + "0" * 63 + "g") is False, name


# ---------------------------------------------------------------------------
# 2. `AuditRecord.verify()`: the empty-digest branch
# ---------------------------------------------------------------------------


def test_a_record_with_an_empty_digest_does_not_verify():
    """`retF@304`: the branch the ledger can never reach.

    A record the ledger mints ALWAYS has a digest -- the ledger
    computes it.  So `if not self.audit_digest: return False` is
    unreachable from the ledger, and the suites' verification tests
    never take that branch.

    The crafted input is a record with an EMPTY digest.  It must not
    verify.
    """
    for name, module in MODULES.items():
        record = module.AuditRecord(
            audit_id="aud-1",
            system_id="sys-1",
            seq=1,
            audit_kind=module.AUDIT_KINDS[0],
            verdict=module.AUDIT_VERDICTS[0],
            severity=0,
            audit_digest="",
        )
        assert record.verify() is False, name


# ---------------------------------------------------------------------------
# 3. The seq guards: a SECOND PATH reaches the same answer
# ---------------------------------------------------------------------------


def test_a_boolean_mutation_seq_is_refused_without_consuming_the_ledger():
    """`or@397`: the discriminator is the LEDGER STATE, not the exception.

    The suites pass `True` to `audit()` and expect `BadSeqError` -- and
    they get one.  But under the mutant they get one TOO, because the
    mutation's audit event routes through `_check_read_seq`, whose guard
    raises first.  **A SECOND PATH REACHES THE SAME ANSWER.**

    So the exception is not the observable.  The observable is the
    LEDGER: under the mutant the `True` seq is CONSUMED (`last_seq`
    becomes `True`) and an audit row is BOOKED -- the guard failed
    open, and the ledger now believes a `True` is a valid seq.
    """
    for name, module in MODULES.items():
        ledger = _ledger_class(module)()
        with pytest.raises(module.BadSeqError):
            ledger.audit("sys-1", True)

        stats = ledger.stats(0)
        assert stats["n_audits"] == 0, (
            f"{name}: a refused mutation booked an audit row: the seq "
            "guard failed open"
        )
        assert stats["last_seq"] == 0, (
            f"{name}: a refused mutation consumed its seq: the seq guard "
            "failed open (last_seq is %r)" % (stats["last_seq"],)
        )


def test_a_boolean_read_seq_is_refused():
    """`or@405`: the READ guard, which has no second path.

    On the read side there is nothing downstream: `verify()` is a pure
    read, so if the guard accepts `True` the call RETURNS a report
    instead of raising.
    """
    for name, module in MODULES.items():
        ledger = _ledger_class(module)()
        ledger.audit("sys-1", 1)
        report = None
        with pytest.raises(module.BadSeqError):
            report = ledger.verify("aud-1", True)
        assert report is None, (
            f"{name}: a boolean read seq was accepted and returned {report!r}"
        )


def test_an_empty_audit_id_is_refused_by_the_read():
    """`or@556`: the READ's own `audit_id` guard.

    MEASURED 2026-11-26: the family census closed seven of the eight
    modules at 27/27 but left `ai_safety_auditing` at **26/27** -- the
    one survivor was `or@556`, the read's `not isinstance(audit_id, str)
    or not audit_id` guard.

    The reason is visible in the sibling suites: SEVEN of the eight
    already assert `verify("", 0)` raises `BadSystemError`, and
    `ai_safety_auditing`'s suite does not.  So the guard was covered
    seven times over and missed once -- and the miss was invisible
    precisely because the family suite did not drive it.

    So the family suite drives it for ALL EIGHT.  That is the point of
    a family suite: a case that one sibling's suite happens to cover is
    NOT covered until every sibling's suite covers it, and the family
    suite is where "every sibling" is enforced.

    The crafted input is the EMPTY string -- the boundary the guard's
    two spellings disagree about -- and the CONTROL is a NON-STRING,
    which the original rejects at the type half while the mutant
    evaluates `not audit_id` on it (which is False, so the mutant
    accepts it).
    """
    for name, module in MODULES.items():
        ledger = _ledger_class(module)()
        ledger.audit("sys-1", 1)
        with pytest.raises(module.BadSystemError):
            ledger.verify("", 0)
        # The type half: a non-string is refused too.
        for bad in (None, 123, 4.5, ["aud-1"], {"a": 1}):
            with pytest.raises(module.BadSystemError):
                ledger.verify(bad, 0)
        # And the CONTROL: a real audit id is accepted.  The id is
        # read from the record the ledger minted, because the MINTED
        # PREFIX differs per module (`aud-`, `cau-`, ...) -- hardcoding
        # one would fail on the others for the wrong reason.
        minted = ledger.audit("sys-2", 2)
        assert ledger.verify(minted.audit_id, 0).verdict == "verified", name


# ---------------------------------------------------------------------------
# 4. `stdlib_only()`: the rejection branches
# ---------------------------------------------------------------------------


def test_stdlib_only_rejects_a_non_stdlib_import():
    """`retF@711`: the `ast.Import` branch's rejection.

    The suites assert `stdlib_only() is True` on the REAL file, whose
    imports are all allowed -- so the rejection is never taken.
    """
    for name, module in MODULES.items():
        assert _with_source(module, "import numpy\n") is False, name


def test_stdlib_only_rejects_a_non_stdlib_import_from():
    """`retF@717`: the `ast.ImportFrom` branch's rejection.

    A SEPARATE AST node with its own `return False`, so a SEPARATE
    test: a mutant that breaks only the `ast.ImportFrom` site would
    survive a test that only drove the `ast.Import` site.
    """
    for name, module in MODULES.items():
        assert _with_source(module, "from numpy import array\n") is False, name


def test_stdlib_only_allows_the_optional_canonical_json_dependency():
    """The `canonical_json` allowance, from BOTH AST nodes.

    `canonical_json` is the one non-stdlib import the module permits,
    because it is an optional dependency with a stdlib fallback.  The
    allowance appears TWICE -- once per AST node -- so it needs two
    cases.

    And the control: a genuinely foreign import is still rejected, so
    this test is not passing because the guard accepts everything.
    """
    for name, module in MODULES.items():
        assert _with_source(module, "import canonical_json\n") is True, name
        assert _with_source(module, "from canonical_json import jcs_dumps\n") is True, name
        assert _with_source(module, "import numpy\n") is False, name
        assert _with_source(module, "from numpy import array\n") is False, name


def test_stdlib_only_accepts_a_source_with_only_allowed_imports():
    """The non-vacuity control for the rejection tests.

    Every rejection test above is measured against a source the guard
    must ACCEPT.  Without this, a guard that rejected everything would
    pass all of them.
    """
    for name, module in MODULES.items():
        assert _with_source(module, "import ast\n") is True, name
        assert _with_source(module, "from pathlib import Path\n") is True, name
        assert _with_source(module, "from __future__ import annotations\n") is True, name
        assert _with_source(module, "import hashlib\nimport json\n") is True, name


def test_stdlib_only_allows_a_submodule_of_the_optional_dependency():
    """`eq@708`: the `root == "canonical_json"` comparison.

    `alias.name.split(".")[0]` reduces `canonical_json.sub` to
    `canonical_json`, so a SUBMODULE of the optional dependency is
    still allowed.  Under the `eq` -> `!=` mutant it is not.

    So the crafted input is `import canonical_json.sub` -- which must
    be allowed -- and the mutant rejects it.
    """
    for name, module in MODULES.items():
        assert _with_source(module, "import canonical_json.sub\n") is True, name
        assert _with_source(module, "from canonical_json.sub import thing\n") is True, name
