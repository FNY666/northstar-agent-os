"""Targeted tests for ai_circuit.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_circuit
from ai_circuit import (
    AI_CIRCUIT_SCHEMA,
    AI_CIRCUIT_VERSION,
    CIRCUIT_KINDS,
    KIND_ANALYZED,
    KIND_ATTENTION_HEAD,
    KIND_COPY_CIRCUIT,
    KIND_FACTUAL_RECALL,
    KIND_FEATURE_MAP,
    KIND_GREATER_THAN_CIRCUIT,
    KIND_INDUCTION_HEAD,
    KIND_IOI_CIRCUIT,
    KIND_MLP_NEURON,
    KIND_REJECTED,
    KIND_RETIRED,
    POSTURE_CONTESTED,
    POSTURE_IDENTIFIED,
    POSTURE_NOT_IDENTIFIED,
    POSTURE_PARTIALLY_IDENTIFIED,
    POSTURE_UNANALYZED,
    POSTURES,
    REASON_ANALYSIS_LOSS,
    REASON_DECOMMISSIONED,
    REASON_MANUAL,
    REASON_SCOPE_CHANGE,
    REASONS,
    VERDICT_IDENTIFIED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_ANALYZED,
    VERDICT_NOT_FOUND,
    VERDICT_PARTIAL,
    VERDICTS,
    AICircuit,
    AuditKindError,
    BadCircuitKindError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    BadVerdictError,
    DoubleRetireError,
    RetiredSystemError,
    SeqOrderError,
    UnknownCircuitError,
    UnknownSystemError,
    ai_circuit_audit_event,
)

_HERE = Path(__file__).resolve().parent.parent
_GOOD_DIGEST = "sha256:" + "0" * 64


def _fresh() -> AICircuit:
    return AICircuit()


# 1 -- pins and vocabularies
def test_pins_and_vocabularies():
    assert AI_CIRCUIT_VERSION == "ai-circuit.v1"
    assert AI_CIRCUIT_SCHEMA == "northstar.ai-circuit.v1"
    assert len(CIRCUIT_KINDS) == 8
    assert len(set(CIRCUIT_KINDS)) == 8
    assert len(VERDICTS) == 5
    assert len(set(VERDICTS)) == 5
    assert len(POSTURES) == 5
    assert len(set(POSTURES)) == 5
    assert len(REASONS) == 4
    assert len(set(REASONS)) == 4
    assert KIND_INDUCTION_HEAD in CIRCUIT_KINDS
    assert VERDICT_IDENTIFIED in VERDICTS
    assert POSTURE_IDENTIFIED in POSTURES
    assert REASON_MANUAL in REASONS


# 2 -- stdlib-only AST check
def test_stdlib_only():
    src = (_HERE / "ai_circuit.py").read_text()
    tree = ast.parse(src)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "__future__", "json", "canonical_json"}
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"
    assert ai_circuit.stdlib_only()


# 3 -- analyze roundtrip, crc-N minting, verify(), frozen-ness
def test_analyze_roundtrip():
    ac = _fresh()
    rec = ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
                     _GOOD_DIGEST)
    assert rec.circuit_id == "crc-1"
    assert rec.system_id == "sys-1"
    assert rec.circuit_kind == KIND_INDUCTION_HEAD
    assert rec.verdict == VERDICT_IDENTIFIED
    assert rec.seq == 1
    assert rec.verify("crc-1", "sys-1", KIND_INDUCTION_HEAD,
                      VERDICT_IDENTIFIED, _GOOD_DIGEST)
    assert not rec.verify("crc-1", "sys-1", KIND_INDUCTION_HEAD,
                          VERDICT_NOT_FOUND, _GOOD_DIGEST)
    rec2 = ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_PARTIAL, 2,
                      _GOOD_DIGEST)
    assert rec2.circuit_id == "crc-2"
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec2.verdict = VERDICT_IDENTIFIED  # type: ignore[misc]
    assert ac.circuit_record("crc-1", 3) is rec
    assert ac.circuits_for("sys-1", 4) == ("crc-1", "crc-2")


# 4 -- bad-input table: fail-closed, seq burned, rejected row booked
def test_analyze_bad_inputs():
    ac = _fresh()
    bad = [
        ("", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, BadIdError),
        ("sys-1", "not-a-kind", VERDICT_IDENTIFIED, BadCircuitKindError),
        ("sys-1", KIND_INDUCTION_HEAD, "not-a-verdict", BadVerdictError),
        ("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, BadDigestError),
        ("bad id", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, BadIdError),
        (True, KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, BadIdError),
        ("sys-1", True, VERDICT_IDENTIFIED, BadCircuitKindError),
        ("sys-1", KIND_INDUCTION_HEAD, True, BadVerdictError),
    ]
    seq = 1
    for system_id, kind, verdict, exc in bad:
        digest = _GOOD_DIGEST if exc is not BadDigestError else "bogus"
        with pytest.raises(exc):
            ac.analyze(system_id, kind, verdict, seq, digest)
        seq += 1
    assert ac.stats()["audit_rows"] == len(bad)
    assert all(row["kind"] == KIND_REJECTED for row in ac.audit_log())
    # rewind raises bare SeqOrderError with zero new rows
    rows_before = ac.stats()["audit_rows"]
    with pytest.raises(SeqOrderError):
        ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1)
    assert ac.stats()["audit_rows"] == rows_before


# 5 -- full 8-kind vocabulary accepted
def test_full_circuit_kind_vocabulary():
    ac = _fresh()
    seq = 1
    for i, kind in enumerate(CIRCUIT_KINDS):
        rec = ac.analyze(f"sys-{i}", kind, VERDICT_IDENTIFIED, seq,
                         _GOOD_DIGEST)
        assert rec.circuit_kind == kind
        assert rec.circuit_id == f"crc-{i + 1}"
        seq += 1
    assert ac.stats()["circuits"] == 8
    assert ac.stats()["systems"] == 8


# 6 -- full 5-verdict vocabulary + tally math
def test_full_verdict_vocabulary():
    ac = _fresh()
    seq = 1
    for verdict in VERDICTS:
        ac.analyze("sys-1", KIND_FEATURE_MAP, verdict, seq, _GOOD_DIGEST)
        seq += 1
    ev = ac.evaluate("sys-1", seq)
    assert ev.n_circuits == 5
    assert ev.n_identified == 1
    assert ev.n_partial == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_found == 1
    assert ev.n_not_analyzed == 1
    # not-found outranks everything below it
    assert ev.posture == POSTURE_NOT_IDENTIFIED


# 7 -- verify semantics: verified/tampered as data, unknown refusal, purity
def test_verify_semantics():
    ac = _fresh()
    ac.analyze("sys-1", KIND_IOI_CIRCUIT, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    vr = ac.verify("crc-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("crc-1", "verified")
    assert not vr.verify("crc-1", "tampered")
    # tamper is reported as data, never raised
    rec = ac.circuit_record("crc-1", 3)
    object.__setattr__(rec, "verdict", VERDICT_NOT_FOUND)
    vr2 = ac.verify("crc-1", 4)
    assert vr2.verdict == "tampered"
    assert vr2.verify("crc-1", "tampered")
    # unknown id refused
    with pytest.raises(UnknownCircuitError):
        ac.verify("crc-999", 5)
    # pure read: no audit rows, seq not consumed
    rows = ac.stats()["audit_rows"]
    ac.verify("crc-1", 5)
    ac.verify("crc-1", 5)  # same seq twice is fine for reads
    assert ac.stats()["audit_rows"] == rows


# 8 -- evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    ac = _fresh()
    # all identified -> identified
    ac.analyze("s-id", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    assert ac.evaluate("s-id", 2).posture == POSTURE_IDENTIFIED
    # any not-found -> not-identified (outranks)
    ac.analyze("s-nf", KIND_COPY_CIRCUIT, VERDICT_NOT_FOUND, 3,
               _GOOD_DIGEST)
    ac.analyze("s-nf", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 4,
               _GOOD_DIGEST)
    assert ac.evaluate("s-nf", 5).posture == POSTURE_NOT_IDENTIFIED
    # any inconclusive -> contested (outranks partial)
    ac.analyze("s-c", KIND_FACTUAL_RECALL, VERDICT_INCONCLUSIVE, 6,
               _GOOD_DIGEST)
    ac.analyze("s-c", KIND_MLP_NEURON, VERDICT_PARTIAL, 7, _GOOD_DIGEST)
    assert ac.evaluate("s-c", 8).posture == POSTURE_CONTESTED
    # any partial -> partially-identified
    ac.analyze("s-p", KIND_ATTENTION_HEAD, VERDICT_PARTIAL, 9,
               _GOOD_DIGEST)
    assert ac.evaluate("s-p", 10).posture == POSTURE_PARTIALLY_IDENTIFIED
    # any not-analyzed (without above) -> partially-identified
    ac.analyze("s-na", KIND_GREATER_THAN_CIRCUIT, VERDICT_NOT_ANALYZED,
               11, _GOOD_DIGEST)
    ac.analyze("s-na", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 12,
               _GOOD_DIGEST)
    assert ac.evaluate("s-na", 13).posture == POSTURE_PARTIALLY_IDENTIFIED
    # precedence: not-found beats inconclusive beats partial
    ac.analyze("s-all", KIND_INDUCTION_HEAD, VERDICT_PARTIAL, 14,
               _GOOD_DIGEST)
    ac.analyze("s-all", KIND_IOI_CIRCUIT, VERDICT_INCONCLUSIVE, 15,
               _GOOD_DIGEST)
    ac.analyze("s-all", KIND_COPY_CIRCUIT, VERDICT_NOT_FOUND, 16,
               _GOOD_DIGEST)
    assert ac.evaluate("s-all", 17).posture == POSTURE_NOT_IDENTIFIED


# 9 -- evaluate read purity + unknown-system refusal + integrity flip
def test_evaluate_read_purity():
    ac = _fresh()
    with pytest.raises(UnknownSystemError):
        ac.evaluate("nope", 1)
    ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    rows = ac.stats()["audit_rows"]
    ev1 = ac.evaluate("sys-1", 2)
    ev2 = ac.evaluate("sys-1", 2)  # same seq twice: pure read
    assert ev1.posture == ev2.posture == POSTURE_IDENTIFIED
    assert ev1.integrity_ok
    assert ac.stats()["audit_rows"] == rows
    # tamper flips integrity_ok as data
    rec = ac.circuit_record("crc-1", 3)
    object.__setattr__(rec, "verdict", VERDICT_PARTIAL)
    ev3 = ac.evaluate("sys-1", 4)
    assert not ev3.integrity_ok
    assert ev3.posture == POSTURE_PARTIALLY_IDENTIFIED
    assert ev3.verify("sys-1", POSTURE_PARTIALLY_IDENTIFIED)


# 10 -- retire terminality: ids never recycled, post-retire reads work
def test_retire_terminality():
    ac = _fresh()
    ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    rr = ac.retire("sys-1", 2)
    assert rr.verify("sys-1", REASON_MANUAL)
    assert ac.retired_ids(3) == ("sys-1",)
    # post-retire mutations refused (seq burned + rejected row)
    with pytest.raises(RetiredSystemError):
        ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_IDENTIFIED, 4,
                    _GOOD_DIGEST)
    # post-retire reads still work
    assert ac.verify("crc-1", 5).verdict == "verified"
    assert ac.evaluate("sys-1", 6).posture == POSTURE_IDENTIFIED
    assert ac.circuit_record("crc-1", 7).circuit_id == "crc-1"
    # bad reason refused
    with pytest.raises(BadReasonError):
        ac.retire("sys-2", 8, "bogus-reason")


# 11 -- all 4 retire reasons + double-retire + unknown-system retire
def test_retire_reasons_and_double():
    ac = _fresh()
    seq = 1
    for i, reason in enumerate(REASONS):
        ac.analyze(f"sys-{i}", KIND_FEATURE_MAP, VERDICT_IDENTIFIED,
                   seq, _GOOD_DIGEST)
        seq += 1
        rr = ac.retire(f"sys-{i}", seq, reason)
        seq += 1
        assert rr.reason == reason
        assert rr.verify(f"sys-{i}", reason)
    with pytest.raises(DoubleRetireError):
        ac.retire("sys-0", seq)
    seq += 1  # the failed double-retire burned its seq
    # retiring a never-seen system is allowed (terminal marker)
    rr = ac.retire("ghost", seq)
    seq += 1
    assert rr.system_id == "ghost"
    assert ac.retired_ids(seq) == ("sys-0", "sys-1", "sys-2", "sys-3",
                                   "ghost")


# 12 -- seq discipline: genesis rewind, malformed seqs, burn accounting
def test_seq_discipline():
    ac = _fresh()
    # genesis rewind (seq 0 then seq 0) raises bare with zero rows
    ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 0,
               _GOOD_DIGEST)
    with pytest.raises(SeqOrderError):
        ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_IDENTIFIED, 0,
                   _GOOD_DIGEST)
    assert ac.stats()["audit_rows"] == 1  # only the first analyzed row
    # malformed seqs raise without consuming
    for bad_seq in (-1, True, 1.5, "2", None):
        with pytest.raises(SeqOrderError):
            ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_IDENTIFIED,
                       bad_seq, _GOOD_DIGEST)
    assert ac.stats()["audit_rows"] == 1
    # gap seqs are allowed (strictly increasing only)
    ac.analyze("sys-1", KIND_MLP_NEURON, VERDICT_IDENTIFIED, 100,
               _GOOD_DIGEST)
    assert ac.circuit_record("crc-2", 101).seq == 100


# 13 -- audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ac = _fresh()
    ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    ac.retire("sys-1", 2)
    rows = ac.audit_log()
    assert [r["kind"] for r in rows] == [KIND_ANALYZED, KIND_RETIRED]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-circuit.v1"
        assert isinstance(row["seq"], int)
        assert isinstance(row["detail"], dict)
    # banned raw-material keys rejected at the boundary
    with pytest.raises(AuditKindError):
        ai_circuit_audit_event(KIND_ANALYZED,
                               {"activations": "raw-tensor"}, 3)
    with pytest.raises(AuditKindError):
        ai_circuit_audit_event(KIND_ANALYZED,
                               {"attention_pattern": "raw"}, 3)
    with pytest.raises(AuditKindError):
        ai_circuit_audit_event(KIND_REJECTED, {"weights": "raw"}, 3)
    # pinned vocab values remain emittable as declared data
    ok = ai_circuit_audit_event(KIND_ANALYZED,
                                {"circuit_kind": KIND_INDUCTION_HEAD,
                                 "verdict": VERDICT_IDENTIFIED,
                                 "circuit_digest": _GOOD_DIGEST}, 3)
    assert ok["detail"]["circuit_kind"] == KIND_INDUCTION_HEAD
    # bad kind rejected
    with pytest.raises(AuditKindError):
        ai_circuit_audit_event("bogus-kind", {}, 3)


# 14 -- cross-instance digest determinism + views + stats
def test_cross_instance_digest_determinism():
    a, b = _fresh(), _fresh()
    ra = a.analyze("sys-1", KIND_IOI_CIRCUIT, VERDICT_PARTIAL, 1,
                   _GOOD_DIGEST)
    rb = b.analyze("sys-1", KIND_IOI_CIRCUIT, VERDICT_PARTIAL, 1,
                   _GOOD_DIGEST)
    assert ra.digest == rb.digest
    assert ra.circuit_id == rb.circuit_id == "crc-1"
    # tamper breaks verify(): ledger-level re-derivation reads the
    # record's current (tampered) fields, so the verdict flips to data
    object.__setattr__(ra, "circuit_digest", "sha256:" + "f" * 64)
    vr = a.verify("crc-1", 2)
    assert vr.verdict == "tampered"
    assert vr.verify("crc-1", "tampered")
    # views
    assert a.system_ids(2) == ("sys-1",)
    stats = a.stats()
    assert stats["systems"] == 1
    assert stats["circuits"] == 1
    assert stats["retired"] == 0
    assert stats["audit_rows"] == 1


# 15 -- 8-thread read smoke + main() subprocess check
def test_thread_smoke_and_main():
    ac = _fresh()
    ac.analyze("sys-1", KIND_INDUCTION_HEAD, VERDICT_IDENTIFIED, 1,
               _GOOD_DIGEST)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ac.verify("crc-1", 2)
                ac.evaluate("sys-1", 3)
                ac.circuit_record("crc-1", 4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    proc = subprocess.run(
        [sys.executable, str(_HERE / "ai_circuit.py")],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-circuit OK: analyze, verify, evaluate, retire, pins, audit" \
        in proc.stdout
