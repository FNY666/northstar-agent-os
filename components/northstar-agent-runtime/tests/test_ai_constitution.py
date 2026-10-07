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
                assert root in allowed, f"non-stdlib import: {alias.name}"
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
