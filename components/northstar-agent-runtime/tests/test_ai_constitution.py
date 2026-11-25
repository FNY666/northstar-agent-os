"""Tests for ai_constitution: declare/verify/evaluate ledger (simulated)."""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_constitution.py"
_spec = importlib.util.spec_from_file_location("ai_constitution", _MOD_PATH)
acm = importlib.util.module_from_spec(_spec)
sys.modules["ai_constitution"] = acm
_spec.loader.exec_module(acm)

AIConstitution = acm.AIConstitution
RetiredConstitutionError = acm.RetiredConstitutionError
UnknownConstitutionError = acm.UnknownConstitutionError
UnknownDeclarationError = acm.UnknownDeclarationError
DoubleRetireError = acm.DoubleRetireError
BadIdError = acm.BadIdError
BadArticleKindError = acm.BadArticleKindError
BadStandingError = acm.BadStandingError
BadDigestError = acm.BadDigestError
BadReasonError = acm.BadReasonError
SeqOrderError = acm.SeqOrderError
AuditKindError = acm.AuditKindError

GOOD_DIGEST = "sha256:" + "ab" * 32


def new() -> AIConstitution:
    return AIConstitution()


# 1. pins and vocabularies -------------------------------------------------
def test_pins_and_vocabularies():
    assert acm.AI_CONSTITUTION_VERSION == "ai-constitution.v1"
    assert acm.AI_CONSTITUTION_SCHEMA == "northstar.ai-constitution.v1"
    assert acm.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(acm.ARTICLE_KINDS) == 8
    assert len(acm.STANDINGS) == 4
    assert len(acm.POSTURES) == 5
    assert len(acm.REASONS) == 4
    for k in acm.ARTICLE_KINDS:
        assert isinstance(k, str) and k and " " not in k
    for p in acm.POSTURES:
        assert isinstance(p, str) and p


# 2. stdlib-only -----------------------------------------------------------
def test_stdlib_only_ast():
    tree = ast.parse(_MOD_PATH.read_text())
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "json", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                # canonical_json is the one blessed sibling-convention
                # fallback (the same shape `status_page.py` and
                # `graph_database.py` use).
                assert root in allowed or root == "canonical_json", \
                    f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            root = node.module.split(".")[0]
            # canonical_json is the one blessed sibling-convention fallback
            assert root in allowed or root == "canonical_json", \
                f"non-stdlib import: {node.module}"
    assert acm.stdlib_only()


# 3. declare roundtrip / minting / verify() / frozen ------------------------
def test_declare_roundtrip_verify_frozen():
    ac = new()
    rec = ac.declare("cai-1", 1, "public-safety", "adopted", GOOD_DIGEST)
    assert rec.declaration_id == "dec-1"
    assert rec.constitution_id == "cai-1"
    assert rec.article_kind == "public-safety"
    assert rec.standing == "adopted"
    assert rec.principle_digest == GOOD_DIGEST
    assert rec.seq == 1
    assert rec.verify("dec-1", "cai-1", "public-safety", "adopted",
                      GOOD_DIGEST)
    assert not rec.verify("dec-1", "cai-1", "public-safety", "repealed",
                          GOOD_DIGEST)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.standing = "repealed"  # type: ignore[misc]


# 4. bad-input table + seq-burn + rejected rows + rewind ---------------------
def test_declare_bad_inputs_burn_and_rewind():
    ac = new()
    cases = [
        ("", "empty id"),
        ("bad id", "whitespace id"),
        ("x" * 300, "long id"),
        (None, "non-str id"),
        (True, "bool id"),
    ]
    seq = 1
    for bad, _label in cases:
        with pytest.raises(acm.AIConstitutionError):
            ac.declare(bad, seq, "public-safety", "adopted")  # type: ignore[arg-type]
        seq += 1
    with pytest.raises(BadArticleKindError):
        ac.declare("cai-x", seq, "not-a-kind", "adopted")
    seq += 1
    with pytest.raises(BadStandingError):
        ac.declare("cai-x", seq, "public-safety", "not-a-standing")
    seq += 1
    with pytest.raises(BadDigestError):
        ac.declare("cai-x", seq, "public-safety", "adopted", "nope")
    seq += 1
    rows = [r for r in ac.audit_log() if r["kind"] == "rejected"]
    assert len(rows) == len(cases) + 3
    assert [r["seq"] for r in rows] == list(range(1, seq))
    # rewind: bare, no rows
    with pytest.raises(SeqOrderError):
        ac.declare("cai-2", 1, "public-safety", "adopted")
    assert len(ac.audit_log()) == len(cases) + 3
    # malformed seqs
    for bad_seq in ("1", 1.5, None, True, -2):
        with pytest.raises(SeqOrderError):
            ac.declare("cai-3", bad_seq, "public-safety", "adopted")  # type: ignore[arg-type]


# 5. full 8-article vocabulary ----------------------------------------------
def test_full_article_kind_vocabulary():
    ac = new()
    seq = 1
    for kind in acm.ARTICLE_KINDS:
        rec = ac.declare("cai-v", seq, kind, "adopted")
        assert rec.article_kind == kind
        assert rec.declaration_id == f"dec-{seq}"
        seq += 1
    assert ac.stats()["declarations"] == 8


# 6. full 4-standing vocabulary ----------------------------------------------
def test_full_standing_vocabulary():
    ac = new()
    seq = 1
    for standing in acm.STANDINGS:
        rec = ac.declare("cai-s", seq, "sincerity", standing)
        assert rec.standing == standing
        seq += 1
    ev = ac.evaluate("cai-s", seq)
    # repealed outranks everything
    assert ev.posture == "repeal-open"
    assert ev.n_proposed == 1 and ev.n_adopted == 1
    assert ev.n_amended == 1 and ev.n_repealed == 1


# 7. verify semantics + tamper-as-data + unknown + read purity ----------------
def test_verify_semantics_tamper_and_purity():
    ac = new()
    ac.declare("cai-1", 1, "virtues", "adopted", GOOD_DIGEST)
    n_audit = len(ac.audit_log())
    vr = ac.verify("dec-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dec-1", "verified")
    # pure read: same seq twice, no rows, no consumption
    vr2 = ac.verify("dec-1", 2)
    assert vr2.verdict == "verified"
    assert len(ac.audit_log()) == n_audit
    # unknown declaration
    with pytest.raises(UnknownDeclarationError):
        ac.verify("dec-99", 3)
    # tamper as data: verdict flips, never raises
    rec = ac.declaration_record("dec-1", 4)
    object.__setattr__(rec, "standing", "repealed")
    vr3 = ac.verify("dec-1", 5)
    assert vr3.verdict == "tampered"
    assert vr3.verify("dec-1", "tampered")


# 8. evaluate posture math: precedence, tallies, unknown, purity ------------
def test_evaluate_posture_math():
    ac = new()
    # repeal-open precedence
    ac.declare("a", 1, "public-safety", "adopted")
    ac.declare("a", 2, "sincerity", "repealed")
    ac.declare("a", 3, "virtues", "amended")
    ac.declare("a", 4, "legal-compliance", "proposed")
    ev = ac.evaluate("a", 5)
    assert ev.posture == "repeal-open"
    assert ev.n_declarations == 4 and ev.n_repealed == 1
    assert ev.integrity_ok
    assert ev.verify("a", "repeal-open")
    # amending
    ac.declare("b", 6, "public-safety", "adopted")
    ac.declare("b", 7, "virtues", "amended")
    assert ac.evaluate("b", 8).posture == "amending"
    # proposed
    ac.declare("c", 9, "public-safety", "adopted")
    ac.declare("c", 10, "virtues", "proposed")
    assert ac.evaluate("c", 11).posture == "proposed"
    # adopted
    ac.declare("d", 12, "public-safety", "adopted")
    ac.declare("d", 13, "virtues", "adopted")
    ev = ac.evaluate("d", 14)
    assert ev.posture == "adopted"
    assert ev.n_adopted == 2
    # unknown constitution
    with pytest.raises(UnknownConstitutionError):
        ac.evaluate("zzz", 15)
    # read purity: same seq twice, no rows
    n_audit = len(ac.audit_log())
    assert ac.evaluate("d", 14).posture == "adopted"
    assert len(ac.audit_log()) == n_audit
    # tamper flips integrity_ok as data
    rec = ac.declaration_record("dec-9", 16)
    object.__setattr__(rec, "principle_digest", GOOD_DIGEST)
    ev2 = ac.evaluate("d", 17)
    assert ev2.posture == "adopted"  # posture unchanged
    assert not ev2.integrity_ok


# 9. retire terminality ------------------------------------------------------
def test_retire_terminality():
    ac = new()
    ac.declare("cai-1", 1, "public-safety", "adopted")
    ac.declare("cai-2", 2, "sincerity", "adopted")
    rr = ac.retire("cai-1", 3, "superseded")
    assert rr.verify("cai-1", "superseded")
    assert ac.retired_ids(4) == ("cai-1",)
    # post-retire mutation refused
    with pytest.raises(RetiredConstitutionError):
        ac.declare("cai-1", 5, "virtues", "adopted")
    # double retire
    with pytest.raises(DoubleRetireError):
        ac.retire("cai-1", 6)
    # bad reason burns
    with pytest.raises(BadReasonError):
        ac.retire("cai-2", 7, "bogus")
    # reads still work post-retire
    ev = ac.evaluate("cai-1", 8)
    assert ev.posture == "adopted"
    assert ac.declaration_record("dec-1", 9).constitution_id == "cai-1"
    assert ac.declarations_for("cai-1", 10) == ("dec-1",)
    # other constitution unaffected
    ac.declare("cai-2", 11, "virtues", "adopted")
    assert ac.evaluate("cai-2", 12).n_declarations == 2
    # id non-recycling: a fresh constitution gets dec-4, never dec-1
    ac.declare("cai-3", 13, "public-safety", "adopted")
    assert ac.declaration_record("dec-4", 14).constitution_id == "cai-3"


# 10. seq discipline ----------------------------------------------------------
def test_seq_discipline():
    ac = new()
    # failed mutation consumes seq
    with pytest.raises(BadArticleKindError):
        ac.declare("cai-x", 1, "nope", "adopted")
    rec = ac.declare("cai-1", 2, "public-safety", "adopted")
    assert rec.seq == 2
    assert rec.declaration_id == "dec-1"
    # rewind is bare: no rejected row, seq not consumed
    n_audit = len(ac.audit_log())
    with pytest.raises(SeqOrderError):
        ac.declare("cai-2", 2, "public-safety", "adopted")
    assert len(ac.audit_log()) == n_audit
    rec2 = ac.declare("cai-2", 3, "public-safety", "adopted")
    assert rec2.declaration_id == "dec-2"
    # malformed seqs on views
    for bad_seq in ("x", 1.0, None, True, -1):
        with pytest.raises(SeqOrderError):
            ac.declaration_record("dec-1", bad_seq)  # type: ignore[arg-type]


# 11. audit shapes + leak ban + bad kind --------------------------------------
def test_audit_shapes_and_leak_ban():
    ac = new()
    ac.declare("cai-1", 1, "public-safety", "adopted", GOOD_DIGEST)
    ac.retire("cai-1", 2)
    kinds = [r["kind"] for r in ac.audit_log()]
    assert kinds == ["declared", "retired"]
    declared = ac.audit_log()[0]
    assert declared["schema"] == "audit.ndjson/1"
    assert declared["module"] == "ai-constitution.v1"
    assert declared["seq"] == 1
    assert declared["detail"]["principle_digest"] == GOOD_DIGEST
    # pinned labels may cross; raw content may not
    assert declared["detail"]["article_kind"] == "public-safety"
    with pytest.raises(AuditKindError):
        acm.ai_constitution_audit_event(
            "declared", {"article_text": "raw"}, 3)
    with pytest.raises(AuditKindError):
        acm.ai_constitution_audit_event("declared", {"preamble": "raw"}, 3)
    with pytest.raises(AuditKindError):
        acm.ai_constitution_audit_event("bogus", {}, 3)


# 12. cross-instance determinism + tamper breaks verify -----------------------
def test_cross_instance_determinism():
    a = new()
    b = new()
    ra = a.declare("cai-1", 1, "public-safety", "adopted", GOOD_DIGEST)
    rb = b.declare("cai-1", 1, "public-safety", "adopted", GOOD_DIGEST)
    assert ra.digest == rb.digest
    assert a.evaluate("cai-1", 2).digest == b.evaluate("cai-1", 2).digest
    assert a.verify("dec-1", 3).digest == b.verify("dec-1", 3).digest
    # tamper breaks verify()
    object.__setattr__(ra, "digest", "sha256:" + "ff" * 32)
    assert not ra.verify("dec-1", "cai-1", "public-safety", "adopted",
                         GOOD_DIGEST)


# 13. views + stats + unknown lookups ------------------------------------------
def test_views_stats_unknown():
    ac = new()
    ac.declare("cai-1", 1, "public-safety", "adopted")
    ac.declare("cai-1", 2, "sincerity", "amended")
    ac.declare("cai-2", 3, "virtues", "proposed")
    assert ac.declarations_for("cai-1", 4) == ("dec-1", "dec-2")
    assert ac.constitution_ids(5) == ("cai-1", "cai-2")
    assert ac.retired_ids(6) == ()
    assert ac.declaration_record("dec-3", 7).constitution_id == "cai-2"
    stats = ac.stats()
    assert stats == {"constitutions": 2, "declarations": 3,
                     "retired": 0, "audit_rows": 3}
    with pytest.raises(UnknownDeclarationError):
        ac.declaration_record("dec-99", 8)
    with pytest.raises(UnknownConstitutionError):
        ac.declarations_for("zzz", 9)


# 14. thread smoke + frozen-ness -----------------------------------------------
def test_thread_read_smoke_and_frozen():
    ac = new()
    ac.declare("cai-1", 1, "public-safety", "adopted", GOOD_DIGEST)
    errors = []

    def reader(n: int):
        try:
            for _ in range(25):
                ac.verify("dec-1", n + 100)
                ac.evaluate("cai-1", n + 200)
                ac.declaration_record("dec-1", n + 300)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rec = ac.declaration_record("dec-1", 500)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.constitution_id = "zzz"  # type: ignore[misc]
    ev = ac.evaluate("cai-1", 501)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.posture = "repeal-open"  # type: ignore[misc]


# 15. main() subprocess ---------------------------------------------------------
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True, text=True, cwd=os.fspath(_MOD_PATH.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-constitution OK" in proc.stdout


# ---------------------------------------------------------------------------
# 16. The digest-pin defects (B173 slice, measured 2026-11-25)
#
# `ai_constitution.py` carried four defects of the same family that
# `graph_database.py`, `status_page.py` and `zero_knowledge.py` carried
# before their slices (commits 66e6ccd4, 9f01f1ef and the
# zero-knowledge slice).  Measured on the tree as it stood:
#
# 1. `AIConstitution.declare(constitution_id="\ud800", ...)` raised
#    `canonical_json.JcsError` -- a ValueError, but NOT an
#    `AIConstitutionError` -- so the module's own guards did not catch
#    it and the caller's taxonomy was bypassed.
# 2. The stdlib fallback ACCEPTED a lone surrogate and emitted non-JCS
#    bytes: b'{"domain":"northstar.ai-constitution.v1","parts":["\\ud800"]}'.
# 3. `canonical_json` serializes an integer outside the safe range as
#    an IEEE-754 double (RFC 8785 Appendix B note (2)), so 2**53 and
#    2**53+1 canonicalize to the SAME bytes.  The seq rides in the
#    declaration pin, so a record whose seq was bumped from 2**53 to
#    2**53+1 still verified True.
# 4. A failed pin booked NO `rejected` row: `declare()`'s `_pin(...)`
#    call sat outside the `try` that burns the seq.
#
# NOTE the per-method shape: `ai_constitution_audit_event` carries NO
# digest pin at all, so the seq's fail-open shows up on the RECORD
# pin, not on the audit row.


SURROGATE = "\ud800"


def test_a_refusal_raises_the_modules_own_error_type():
    """The module's own taxonomy, not the sibling helper's.

    `JcsError` is a `ValueError`, so a caller guarding on
    `except ValueError` would treat a refused mutation as a parse
    error.  The module's error must be what escapes.
    """
    ac = new()
    with pytest.raises(acm.AIConstitutionError):
        ac.declare(SURROGATE, 1, principle_digest=GOOD_DIGEST)


def test_a_failed_mutation_still_consumes_its_seq():
    """A failed pin at a valid seq burns the seq and books a row.

    This is the second refusal convention (`docs/design/
    refusal-hold-wiring.md` §21.3): a malformed ARGUMENT at a valid
    seq consumes the seq and books a `rejected` row.  Without this, the
    trail cannot tell "the ledger refused this constitution" from "the
    ledger never saw it".
    """
    ac = new()
    with pytest.raises(acm.AIConstitutionError):
        ac.declare(SURROGATE, 1, principle_digest=GOOD_DIGEST)
    kinds = [e["kind"] for e in ac.audit_log()]
    assert acm.KIND_REJECTED in kinds
    # the seq was consumed: the next claim must be strictly greater
    with pytest.raises(SeqOrderError):
        ac.declare("cai-1", 1, principle_digest=GOOD_DIGEST)
    ac.declare("cai-1", 2, principle_digest=GOOD_DIGEST)
    assert len(ac.declarations_for("cai-1", 3)) == 1


def test_the_shipped_path_and_the_fallback_agree_about_legality():
    """Both configurations must refuse a lone surrogate.

    They need not agree about the resulting digest bytes -- the
    fallback's tagged form is deliberately its own string -- but a
    value one refuses must be refused by both.  RFC 8785 §3.2.2.3
    requires a compliant implementation to terminate with an error.
    """
    saved = acm._cj
    try:
        assert acm._cj is not None, "the shipped path is not installed"

        acm._cj = saved
        with pytest.raises(acm.AIConstitutionError):
            acm._canonical([SURROGATE])

        acm._cj = None
        with pytest.raises(acm.AIConstitutionError):
            acm._canonical([SURROGATE])
    finally:
        acm._cj = saved


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    Without this, a fallback that refused every input would satisfy
    the test above vacuously.
    """
    saved = acm._cj
    try:
        for cfg in (saved, None):
            acm._cj = cfg
            assert acm._canonical(["ordinary", 7, ["a"]])
    finally:
        acm._cj = saved


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted.

    Without this bound, 2**53 and 2**53+1 canonicalize to the same
    bytes, so the digest stops pinning the seq.
    """
    ac = new()
    with pytest.raises(acm.AIConstitutionError):
        ac.declare("cai-1", 2 ** 53, principle_digest=GOOD_DIGEST)


def test_an_oversized_seq_is_refused_as_a_malformed_seq():
    """The refusal's SHAPE, not just its type.

    A malformed SEQ consumes nothing and books nothing -- the call
    never reached the ledger.  A failed PIN at a valid seq consumes the
    seq and books a row.  Both raise `AIConstitutionError`, so only the
    shape distinguishes them.
    """
    ac = new()
    with pytest.raises(acm.AIConstitutionError):
        ac.declare("cai-1", 2 ** 53, principle_digest=GOOD_DIGEST)
    # nothing booked
    assert ac.audit_log() == ()
    # nothing consumed: seq 1 is still claimable
    ac.declare("cai-1", 1, principle_digest=GOOD_DIGEST)
    assert len(ac.declarations_for("cai-1", 2)) == 1


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control: the digest must pin the seq.

    This is the property the bound protects.  The seq rides in the
    declaration pin, so a record whose seq was bumped must not still
    verify -- and the pin cannot even be MINTED over an out-of-range
    seq, because `_refuse_unsafe_int` refuses the payload.
    """
    digest = acm._pin(
        "declaration", "dec-1", "cai-1", acm.ARTICLE_PUBLIC_SAFETY,
        acm.STANDING_ADOPTED, GOOD_DIGEST, 2 ** 53 - 1,
    )
    tampered = acm.DeclarationRecord(
        declaration_id="dec-1",
        constitution_id="cai-1",
        article_kind=acm.ARTICLE_PUBLIC_SAFETY,
        standing=acm.STANDING_ADOPTED,
        principle_digest=GOOD_DIGEST,
        seq=2 ** 53 + 1,
        digest=digest,
    )
    assert tampered.verify(
        "dec-1", "cai-1", acm.ARTICLE_PUBLIC_SAFETY,
        acm.STANDING_ADOPTED, GOOD_DIGEST,
    ) is False
    # and the pin cannot be minted over an out-of-range seq at all
    with pytest.raises(acm.AIConstitutionError):
        acm._pin(
            "declaration", "dec-1", "cai-1", acm.ARTICLE_PUBLIC_SAFETY,
            acm.STANDING_ADOPTED, GOOD_DIGEST, 2 ** 53,
        )


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not over-refuse.

    2**53 - 1 is the last integer JCS pins exactly.
    """
    ac = new()
    ac.declare("cai-1", 2 ** 53 - 1, principle_digest=GOOD_DIGEST)
    assert len(ac.declarations_for("cai-1", 2 ** 53 - 1)) == 1


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """A payload integer that cannot be pinned must be refused.

    The shipped path loses the distinction between 2**53 and
    2**53+1, so a pin over such a payload stops pinning it.
    """
    with pytest.raises(acm.AIConstitutionError):
        acm._canonical([2 ** 53])
    with pytest.raises(acm.AIConstitutionError):
        acm._canonical([2 ** 53 + 1])


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the pin refusal must not over-reach."""
    assert acm._canonical([2 ** 53 - 1])


def test_verify_answers_false_for_a_record_it_cannot_canonicalize():
    """`verify()` answers a question; a question is not an exception.

    The record's digest cannot be recomputed over a lone surrogate, so
    the answer is "not intact" -- `False`.  It must not raise.
    """
    rec = acm.DeclarationRecord(
        declaration_id="dec-1",
        constitution_id=SURROGATE,
        article_kind=acm.ARTICLE_PUBLIC_SAFETY,
        standing=acm.STANDING_ADOPTED,
        principle_digest=GOOD_DIGEST,
        seq=1,
        digest="sha256:" + "0" * 64,
    )
    assert rec.verify(
        "dec-1", SURROGATE, acm.ARTICLE_PUBLIC_SAFETY,
        acm.STANDING_ADOPTED, GOOD_DIGEST,
    ) is False
