"""Tests for the AI-principles declaration ledger (simulated)."""

from __future__ import annotations

import ast
import copy
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(
    0, str(Path(__file__).resolve().parent.parent))

from ai_principles import (  # noqa: E402
    AI_PRINCIPLES_VERSION,
    AI_PRINCIPLES_SCHEMA,
    AIPrinciples,
    AIPrinciplesError,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadPrincipleKindError,
    BadReasonError,
    BadStatusError,
    DoubleRetireError,
    EvaluationReport,
    POSTURE_DECLARED,
    POSTURE_SUSPENDED_OPEN,
    POSTURE_UNDER_REVIEW,
    POSTURES,
    PRINCIPLE_KINDS,
    REASON_MANUAL,
    REASONS,
    RetiredPrincipalError,
    SeqOrderError,
    STATUS_ADOPTED,
    STATUS_AMENDED,
    STATUS_PROPOSED,
    STATUS_SUSPENDED,
    STATUSES,
    UnknownDeclarationError,
    UnknownPrincipalError,
    ai_principles_audit_event,
    stdlib_only,
)

_MODULE_PATH = Path(__file__).resolve().parent.parent / "ai_principles.py"

_DIGEST = "sha256:" + "ab" * 32


def _declare_many(ap, principal_id, kinds, seq_start=1):
    seq = seq_start
    for kind in kinds:
        ap.declare(principal_id, kind, STATUS_ADOPTED, seq, _DIGEST)
        seq += 1
    return seq


def test_pins():
    assert AI_PRINCIPLES_VERSION == "ai-principles.v1"
    assert AI_PRINCIPLES_SCHEMA == "northstar.ai-principles.v1"
    assert len(PRINCIPLE_KINDS) == 8
    assert len(STATUSES) == 4
    assert len(POSTURES) == 4
    assert len(REASONS) == 4
    assert STATUS_ADOPTED in STATUSES and STATUS_AMENDED in STATUSES
    assert POSTURE_DECLARED == "declared"
    assert stdlib_only()


def test_stdlib_only_ast():
    tree = ast.parse(_MODULE_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            if mod:
                imported.add(mod)
    assert imported.issubset(
        {"__future__", "hashlib", "re", "threading", "dataclasses",
         "typing", "canonical_json", "json"}), imported


def test_declare_roundtrip_verify_frozen():
    ap = AIPrinciples()
    rec = ap.declare("p-1", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 1, _DIGEST)
    assert rec.declaration_id == "dcl-1"
    assert rec.principal_id == "p-1"
    assert rec.verify("dcl-1", "p-1", PRINCIPLE_KINDS[0], STATUS_ADOPTED,
                      _DIGEST)
    assert not rec.verify("dcl-1", "p-1", PRINCIPLE_KINDS[0], STATUS_SUSPENDED,
                          _DIGEST)
    with pytest.raises(Exception):
        rec.status = STATUS_AMENDED  # frozen
    assert rec.status == STATUS_ADOPTED
    vr = ap.verify("dcl-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dcl-1", "verified")


def test_declare_bad_inputs_burn_seq_and_reject():
    ap = AIPrinciples()
    bad_calls = [
        lambda: ap.declare("", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 1),
        lambda: ap.declare("p-x", "wrong-kind", STATUS_ADOPTED, 2),
        lambda: ap.declare("p-x", PRINCIPLE_KINDS[0], "wrong-status", 3),
        lambda: ap.declare("p-x", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 4,
                           "not-a-pin"),
        lambda: ap.declare("p-x", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 5,
                           "sha256:" + "ZZ" * 32),
        lambda: ap.declare("has space", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 6),
        lambda: ap.declare(True, PRINCIPLE_KINDS[0], STATUS_ADOPTED, 7),
        lambda: ap.declare("p-x", PRINCIPLE_KINDS[0], STATUS_ADOPTED, True),
        lambda: ap.declare("p-x", PRINCIPLE_KINDS[0], STATUS_ADOPTED, -1),
    ]
    errors = (BadIdError, BadPrincipleKindError, BadStatusError,
              BadDigestError, SeqOrderError)
    for i, call in enumerate(bad_calls, start=1):
        with pytest.raises(errors):
            call()
        # rejected row booked (except malformed seqs, which burn nothing)
        if i < 8:
            assert ap.stats()["audit_rows"] >= i
    kinds = [r["kind"] for r in ap.audit_log()]
    assert kinds == ["rejected"] * len(kinds)


def test_full_principle_kind_vocabulary():
    ap = AIPrinciples()
    seq = _declare_many(ap, "vocab-p", PRINCIPLE_KINDS, seq_start=1)
    assert seq == 9
    assert ap.stats()["declarations"] == 8
    assert ap.declarations_for("vocab-p", 9) == tuple(
        f"dcl-{i}" for i in range(1, 9))
    ev = ap.evaluate("vocab-p", 10)
    assert ev.posture == POSTURE_DECLARED
    assert ev.n_adopted == 8 and ev.integrity_ok


def test_full_status_vocabulary():
    ap = AIPrinciples()
    statuses = [STATUS_PROPOSED, STATUS_ADOPTED, STATUS_AMENDED,
                STATUS_SUSPENDED]
    for i, status in enumerate(statuses, start=1):
        rec = ap.declare("p-2", PRINCIPLE_KINDS[i - 1], status, i, _DIGEST)
        assert rec.status == status
    ev = ap.evaluate("p-2", 5)
    assert ev.posture == POSTURE_SUSPENDED_OPEN  # suspended outranks proposed
    assert (ev.n_proposed, ev.n_adopted, ev.n_amended,
            ev.n_suspended) == (1, 1, 1, 1)


def test_verify_tamper_as_data_and_read_purity():
    ap = AIPrinciples()
    ap.declare("p-3", PRINCIPLE_KINDS[1], STATUS_AMENDED, 1, _DIGEST)
    rec = ap.declaration_record("dcl-1", 2)
    # same-seq read twice: no audit rows, no seq consumption
    rows_before = len(ap.audit_log())
    vr1 = ap.verify("dcl-1", 3)
    vr2 = ap.verify("dcl-1", 3)
    assert vr1.verdict == "verified" == vr2.verdict
    assert len(ap.audit_log()) == rows_before
    # tamper via object.__setattr__ flips verdict to tampered as data
    object.__setattr__(rec, "status", STATUS_SUSPENDED)
    assert ap.verify("dcl-1", 4).verdict == "tampered"
    ev = ap.evaluate("p-3", 5)
    assert ev.integrity_ok is False


def test_verify_unknown_refusal():
    ap = AIPrinciples()
    ap.declare("p-3b", PRINCIPLE_KINDS[1], STATUS_AMENDED, 1, _DIGEST)
    rows_before = len(ap.audit_log())
    with pytest.raises(UnknownDeclarationError):
        ap.verify("dcl-404", 2)
    with pytest.raises(UnknownDeclarationError):
        ap.declaration_record("dcl-404", 3)
    assert len(ap.audit_log()) == rows_before  # refusals write no rows


def test_evaluate_posture_math_and_unknown():
    ap = AIPrinciples()
    with pytest.raises(UnknownPrincipalError):
        ap.evaluate("no-such-principal", 1)
    ap.declare("p-4", PRINCIPLE_KINDS[0], STATUS_AMENDED, 2, _DIGEST)
    assert ap.evaluate("p-4", 3).posture == POSTURE_DECLARED
    ap.declare("p-4", PRINCIPLE_KINDS[1], STATUS_PROPOSED, 4, _DIGEST)
    assert ap.evaluate("p-4", 5).posture == POSTURE_UNDER_REVIEW
    ap.declare("p-4", PRINCIPLE_KINDS[2], STATUS_SUSPENDED, 6, _DIGEST)
    ev = ap.evaluate("p-4", 7)
    assert ev.posture == POSTURE_SUSPENDED_OPEN
    assert ev.verify("p-4", POSTURE_SUSPENDED_OPEN)
    assert not ev.verify("p-4", POSTURE_UNDER_REVIEW)
    assert ev.n_declarations == 3


def test_retire_terminality_id_non_recycling_post_retire_reads():
    ap = AIPrinciples()
    _declare_many(ap, "p-5", PRINCIPLE_KINDS[:2], seq_start=1)
    rr = ap.retire("p-5", 3, REASON_MANUAL)
    assert rr.verify("p-5", REASON_MANUAL)
    assert ap.retired_ids(4) == ("p-5",)
    with pytest.raises(DoubleRetireError):
        ap.retire("p-5", 5)
    with pytest.raises(RetiredPrincipalError):
        ap.declare("p-5", PRINCIPLE_KINDS[2], STATUS_ADOPTED, 6)
    with pytest.raises(BadReasonError):
        ap.retire("p-6", 7, "bogus-reason")
    # reads still work after retirement
    assert ap.evaluate("p-5", 8).posture == POSTURE_DECLARED
    assert ap.declaration_record("dcl-1", 9).principle_kind == \
        PRINCIPLE_KINDS[0]
    kinds = [r["kind"] for r in ap.audit_log()]
    assert kinds == ["declared", "declared", "retired",
                     "rejected", "rejected", "rejected"]


def test_retire_all_reasons_and_id_non_recycling():
    ap = AIPrinciples()
    seq = 1
    for i, reason in enumerate(REASONS, start=1):
        ap.declare(f"p-r{i}", PRINCIPLE_KINDS[i - 1], STATUS_ADOPTED, seq,
                   _DIGEST)
        seq += 1
        rr = ap.retire(f"p-r{i}", seq, reason)
        assert rr.verify(f"p-r{i}", reason)
        seq += 1
    assert ap.retired_ids(seq) == tuple(f"p-r{i}" for i in range(1, 5))
    seq += 1
    # ids are never recycled: declaring on a retired principal always fails
    with pytest.raises(RetiredPrincipalError):
        ap.declare("p-r1", PRINCIPLE_KINDS[0], STATUS_ADOPTED, seq)
    assert ap.stats()["retired"] == 4


def test_seq_discipline():
    ap = AIPrinciples()
    ap.declare("p-7", PRINCIPLE_KINDS[0], STATUS_ADOPTED, 1)
    with pytest.raises(SeqOrderError):
        ap.declare("p-7", PRINCIPLE_KINDS[1], STATUS_ADOPTED, 1)  # rewind
    assert ap.stats()["audit_rows"] == 1  # only the declared row; rewind burns nothing, bare raise
    for bad_seq in (True, 1.5, "2", None, -1):
        with pytest.raises(SeqOrderError):
            ap.declare("p-7", PRINCIPLE_KINDS[1], STATUS_ADOPTED, bad_seq)
    assert ap.stats()["audit_rows"] == 1  # malformed seqs burn nothing
    # failed mutation consumes its seq: next good claim must exceed it
    ap.declare("p-7", PRINCIPLE_KINDS[1], STATUS_ADOPTED, 2)
    with pytest.raises(AIPrinciplesError):
        ap.declare("p-7", "wrong-kind", STATUS_ADOPTED, 3)
    assert ap.stats()["audit_rows"] == 3  # 2 declared + 1 rejected
    ap.declare("p-7", PRINCIPLE_KINDS[2], STATUS_ADOPTED, 4)
    assert ap.stats()["declarations"] == 3


def test_audit_shapes_leak_ban_bad_kind():
    ev = ai_principles_audit_event("declared",
                                   {"principal_id": "p-8",
                                    "principle_kind": PRINCIPLE_KINDS[0],
                                    "status": STATUS_ADOPTED}, 1)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == AI_PRINCIPLES_VERSION
    assert ev["kind"] == "declared" and ev["seq"] == 1
    for banned in ("charter_text", "wording", "rationale", "explanation"):
        with pytest.raises(AuditKindError):
            ai_principles_audit_event("declared",
                                      {"principal_id": "p-8", banned: "x"}, 2)
    with pytest.raises(AuditKindError):
        ai_principles_audit_event("bogus", {"principal_id": "p-8"}, 3)
    with pytest.raises(SeqOrderError):
        ai_principles_audit_event("declared", {"principal_id": "p-8"}, -1)


def test_views_stats_unknown_lookups_determinism():
    ap = AIPrinciples()
    seq = _declare_many(ap, "a-1", PRINCIPLE_KINDS[:3], seq_start=1)
    _declare_many(ap, "b-1", PRINCIPLE_KINDS[:2], seq_start=seq)
    assert ap.principal_ids(8) == ("a-1", "b-1")
    assert ap.stats()["principals"] == 2
    assert ap.stats()["declarations"] == 5
    with pytest.raises(UnknownPrincipalError):
        ap.declarations_for("ghost", 9)
    with pytest.raises(UnknownDeclarationError):
        ap.declaration_record("dcl-404", 9)
    # cross-instance determinism: same ops, same digests
    ap2 = AIPrinciples()
    _declare_many(ap2, "a-1", PRINCIPLE_KINDS[:3], seq_start=1)
    _declare_many(ap2, "b-1", PRINCIPLE_KINDS[:2], seq_start=seq)
    for i in range(1, 6):
        assert ap.declaration_record(f"dcl-{i}", 10).digest == \
            ap2.declaration_record(f"dcl-{i}", 10).digest


def test_thread_read_smoke_and_main():
    ap = AIPrinciples()
    _declare_many(ap, "conc-p", PRINCIPLE_KINDS, seq_start=1)
    errors = []

    def reader():
        try:
            for _ in range(50):
                assert ap.verify("dcl-1", 9).verdict == "verified"
                assert ap.evaluate("conc-p", 9).posture == POSTURE_DECLARED
                assert ap.stats()["declarations"] == 8
        except Exception as exc:  # pragma: no cover - thread errors fail test
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    result = subprocess.run(
        [sys.executable, str(_MODULE_PATH)], capture_output=True, text=True,
        cwd=_MODULE_PATH.parent, timeout=60)
    assert result.returncode == 0
    assert "ai-principles OK" in result.stdout
