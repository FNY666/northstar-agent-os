"""The `ai_transparency_auditing` surface: the branches its own suite never drove.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
`ai_transparency_auditing.py` is the AI-transparency-audit execution
decision ledger.  The artifact measured the module at **18/27** -- nine
survivors -- and every one of them was a branch the suite exercised
only on ONE side of a boundary, or a guard the suite never drove with
the input it exists to reject.

THE NINE SURVIVORS, AND WHAT EACH NEEDED
-----------------------------------------
  or@271   `_valid_digest`: `not isinstance(value, str) or not
           value.startswith("sha256:")`.
           The suite feeds the digest `"bad"`.  Under the mutant
           (`or` -> `and`) `"bad"` is REJECTED -- because `"bad"` is a
           str AND does not start with `sha256:` -- so both spellings
           agree on the suite's only input.  The CRAFTED INPUT is a
           NON-STRING: `123` is not a str, so the original rejects it
           at the type half, while the mutant evaluates
           `value.startswith(...)` on an int and CRASHES with
           `AttributeError`.  The crash is the observable.

  eq@274 / and@274   `_valid_digest`: `len(tail) == 64 and all(c in
           "0123456789abcdef" for c in tail)`.
           The suite never calls `_valid_digest` with a WELL-FORMED
           digest, so the `len` half is never the one that decides.
           The crafted inputs are a digest of 63 hex chars (too short),
           one of 65 (too long), and one of 64 NON-HEX chars -- each
           puts exactly ONE half of the conjunct at issue.

  retF@304   `AuditRecord.verify()`: `if not self.audit_digest: return
           False`.  The suite only verifies records the ledger minted,
           and a minted record ALWAYS has a digest -- so the empty
           branch is never taken.  The crafted input is a record with
           an EMPTY digest, which must NOT verify.

  or@397   `_check_mutation_seq`: `isinstance(seq, bool) or not
           isinstance(seq, int) or seq < 1`.
           The suite passes `True` and expects `BadSeqError` -- and it
           gets one, but from a DIFFERENT guard: the mutation's audit
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
           import-allowlist.  The suite asserts `stdlib_only() is
           True` on the REAL file -- a file whose imports are all
           allowed -- so every REJECTION branch is untaken.  The
           CRAFTED INPUT is a source file that imports something
           outside the allowlist, and the module is re-parsed with a
           patched `__file__`, so the real file is never modified.

TWO HARNESS FACTS
-----------------
* The three `stdlib_only()` sites are SEPARATE AST nodes -- the
  `ast.Import` branch and the `ast.ImportFrom` branch, each with its
  own `root == "canonical_json"` allowance and its own `return False`.
  A test that only drives one of them leaves the others untested.

* The `canonical_json` allowance is a THIRD thing: it is the one
  import the module permits that is not stdlib, because it is an
  optional dependency with a stdlib fallback.  A test that drives
  `stdlib_only()` with a `canonical_json` import proves the allowance
  works; a test that drives it with `numpy` proves the rejection
  works.  Both are needed, or the guard is measured from one side.

A NOTE ON HOW EACH DISCRIMINATOR WORKS
--------------------------------------
Every test here asserts the ORIGINAL's answer.  The census then plants
one mutant at a time and asks whether the suite notices.  Where the
mutant's answer is "the same exception, but a different ledger
behind it" -- `or@397` -- the test asserts the LEDGER, because the
exception cannot tell the two apart.
"""

from __future__ import annotations

import os
import pathlib
import sys
import tempfile

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import ai_transparency_auditing as m  # noqa: E402


def _with_source(source: str):
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
    real = m.__file__
    m.__file__ = handle.name
    try:
        return m.stdlib_only()
    finally:
        m.__file__ = real
        os.unlink(handle.name)


# ---------------------------------------------------------------------------
# 1. The digest guard: `_valid_digest`
# ---------------------------------------------------------------------------


def test_a_non_string_digest_is_rejected():
    """`or@271`: the TYPE half of the guard.

    The suite's only malformed digest is the STRING `"bad"`, and under
    BOTH spellings that is rejected -- so it cannot tell them apart.

    The crafted input is a NON-STRING.  The original rejects it at the
    type half and returns False.  The mutant evaluates
    `value.startswith("sha256:")` on an int, which CRASHES with
    `AttributeError` -- and the crash is the observable, because the
    original returns a bool and the mutant raises.
    """
    for value in (123, None, 4.5, True, ["sha256:"], {"a": 1}, b"sha256:"):
        # The original returns False.  The mutant CRASHES with
        # AttributeError, which fails the test on its own -- so a plain
        # assert is the whole discriminator.
        assert m._valid_digest(value) is False, (
            f"{value!r}: the digest guard accepted a non-string"
        )


def test_a_string_digest_that_is_not_sha256_is_rejected():
    """The CONTROL for `or@271`: a string is rejected, not crashed on.

    The mutant must be distinguishable from the original on a STRING
    too -- otherwise the non-string case above would be the only
    discriminator, and the crash would be the whole story.
    """
    for value in ("bad", "sha256", "SHA256:" + "0" * 64,
                  " sha256:" + "0" * 64):
        assert m._valid_digest(value) is False, (
            f"{value!r}: the digest guard accepted a malformed digest"
        )


def test_a_well_formed_digest_is_accepted():
    """The non-vacuity control for the whole digest guard.

    A guard that only ever rejects is measured on one side.  This pins
    the ACCEPTING side, so a guard that rejected everything -- or that
    crashed on everything -- would be caught.
    """
    assert m._valid_digest("sha256:" + "0" * 64) is True
    assert m._valid_digest("sha256:" + "abcdef0123456789" * 4) is True
    assert m._valid_digest("") is True


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
    assert m._valid_digest("sha256:" + "0" * 63) is False
    assert m._valid_digest("sha256:" + "0" * 65) is False
    assert m._valid_digest("sha256:" + "z" * 64) is False
    assert m._valid_digest("sha256:" + "0" * 63 + "g") is False


# ---------------------------------------------------------------------------
# 2. `AuditRecord.verify()`: the empty-digest branch
# ---------------------------------------------------------------------------


def test_a_record_with_an_empty_digest_does_not_verify():
    """`retF@304`: the branch the ledger can never reach.

    A record the ledger mints ALWAYS has a digest -- the ledger
    computes it.  So `if not self.audit_digest: return False` is
    unreachable from the ledger, and the suite's verification tests
    never take that branch.

    The crafted input is a record with an EMPTY digest.  It must not
    verify.
    """
    record = m.AuditRecord(
        audit_id="aud-1",
        system_id="sys-1",
        seq=1,
        audit_kind="internal-transparency-audit",
        verdict="transparent",
        severity=0,
        audit_digest="",
    )
    assert record.verify() is False


# ---------------------------------------------------------------------------
# 3. The seq guards: a SECOND PATH reaches the same answer
# ---------------------------------------------------------------------------


def test_a_boolean_mutation_seq_is_refused_without_consuming_the_ledger():
    """`or@397`: the discriminator is the LEDGER STATE, not the exception.

    The suite passes `True` to `audit()` and expects `BadSeqError` --
    and it gets one.  But under the mutant it gets one TOO, because
    the mutation's audit event routes through `_check_read_seq`, whose
    guard raises first.  **A SECOND PATH REACHES THE SAME ANSWER.**

    So the exception is not the observable.  The observable is the
    LEDGER: under the mutant the `True` seq is CONSUMED (`last_seq`
    becomes `True`) and an audit row is BOOKED -- the guard failed
    open, and the ledger now believes a `True` is a valid seq.

    This is the shape of the defect: the mutation guard decides
    whether a seq is CONSUMED, and the read guard decides whether it
    is ACCEPTED.  A test that only reads the exception sees neither.
    """
    ledger = m.AITransparencyAuditing()
    with pytest.raises(m.BadSeqError):
        ledger.audit("sys-1", True)

    stats = ledger.stats(0)
    assert stats["n_audits"] == 0, (
        "a refused mutation booked an audit row: the seq guard failed open"
    )
    assert stats["last_seq"] == 0, (
        "a refused mutation consumed its seq: the seq guard failed open "
        "(last_seq is %r)" % (stats["last_seq"],)
    )


def test_a_boolean_read_seq_is_refused():
    """`or@405`: the READ guard, which has no second path.

    On the read side there is nothing downstream: `verify()` is a pure
    read, so if the guard accepts `True` the call RETURNS a report
    instead of raising.  The suite already asserts the raise -- but the
    observable that distinguishes the two spellings is the RETURN, and
    a suite that only saw the exception could not tell them apart if
    the exception came from elsewhere.
    """
    ledger = m.AITransparencyAuditing()
    ledger.audit("sys-1", 1)
    report = None
    with pytest.raises(m.BadSeqError):
        report = ledger.verify("aud-1", True)
    assert report is None, (
        "a boolean read seq was accepted and returned %r" % (report,)
    )


# ---------------------------------------------------------------------------
# 4. `stdlib_only()`: the rejection branches
# ---------------------------------------------------------------------------


def test_stdlib_only_rejects_a_non_stdlib_import():
    """`retF@711`: the `ast.Import` branch's rejection.

    The suite asserts `stdlib_only() is True` on the REAL file, whose
    imports are all allowed -- so the rejection is never taken.
    """
    assert _with_source("import numpy\n") is False


def test_stdlib_only_rejects_a_non_stdlib_import_from():
    """`retF@717`: the `ast.ImportFrom` branch's rejection.

    A SEPARATE AST node with its own `return False`, so a SEPARATE
    test: a mutant that breaks only the `ast.ImportFrom` site would
    survive a test that only drove the `ast.Import` site.
    """
    assert _with_source("from numpy import array\n") is False


def test_stdlib_only_allows_the_optional_canonical_json_dependency():
    """The `canonical_json` allowance, from BOTH AST nodes.

    `canonical_json` is the one non-stdlib import the module permits,
    because it is an optional dependency with a stdlib fallback.  The
    allowance appears TWICE -- once per AST node -- so it needs two
    cases.

    And the control: a genuinely foreign import is still rejected, so
    this test is not passing because the guard accepts everything.
    """
    assert _with_source("import canonical_json\n") is True
    assert _with_source("from canonical_json import jcs_dumps\n") is True
    assert _with_source("import numpy\n") is False
    assert _with_source("from numpy import array\n") is False


def test_stdlib_only_accepts_a_source_with_only_allowed_imports():
    """The non-vacuity control for the rejection tests.

    Every rejection test above is measured against a source the guard
    must ACCEPT.  Without this, a guard that rejected everything would
    pass all of them.
    """
    assert _with_source("import ast\n") is True
    assert _with_source("from pathlib import Path\n") is True
    assert _with_source("from __future__ import annotations\n") is True
    assert _with_source("import hashlib\nimport json\n") is True


def test_stdlib_only_allows_a_submodule_of_the_optional_dependency():
    """`eq@708`: the `root == "canonical_json"` comparison.

    `alias.name.split(".")[0]` reduces `canonical_json.sub` to
    `canonical_json`, so a SUBMODULE of the optional dependency is
    still allowed.  Under the `eq` -> `!=` mutant it is not.

    So the crafted input is `import canonical_json.sub` -- which must
    be allowed -- and the mutant rejects it.
    """
    assert _with_source("import canonical_json.sub\n") is True
    assert _with_source("from canonical_json.sub import thing\n") is True
