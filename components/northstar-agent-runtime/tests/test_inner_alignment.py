"""Tests for inner_alignment.py (inner-alignment inspection / verification ledger)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import inner_alignment as ia
from inner_alignment import (
    InnerAlignment,
    inner_alignment_audit_event,
    INNER_ALIGNMENT_VERSION,
    INNER_ALIGNMENT_SCHEMA,
    AUDIT_SCHEMA,
    KIND_INSPECTED,
    KIND_VERIFIED,
    KIND_RETIRED,
    KIND_REJECTED,
    InnerAlignmentError,
    BadModelError,
    UnknownModelError,
    BadKindError,
    BadVerdictError,
    BadDigestError,
    BadReasonError,
    UnknownInspectionError,
    AlreadyVerifiedError,
    RetiredModelError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(ia.__file__)
DIG = "sha256:" + "a" * 64
DIG2 = "sha256:" + "b" * 64


def fresh():
    return InnerAlignment()


def ledger_with_inspection(verdict="aligned"):
    m = fresh()
    ins = m.inspect("model-1", 1, inner_kind="mesa-optimizer", inner_digest=DIG)
    if verdict is not None:
        m.verify(ins.inspection_id, 2, verdict=verdict, verification_digest=DIG2)
    return m, ins


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert INNER_ALIGNMENT_VERSION == "inner-alignment.v1"
    assert INNER_ALIGNMENT_SCHEMA == "northstar.inner-alignment.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
        "__future__",
    }
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"
    assert ia.stdlib_only() is True


def test_inspect_roundtrip_and_verify():
    m = fresh()
    rec = m.inspect("model-1", 1, inner_kind="mesa-optimizer", inner_digest=DIG)
    assert rec.inspection_id == "ins-1"
    assert rec.model_id == "model-1"
    assert rec.inner_kind == "mesa-optimizer"
    assert rec.inner_digest == DIG
    assert rec.seq == 1
    assert rec.verify()
    assert rec.as_dict()["schema"] == INNER_ALIGNMENT_SCHEMA
    assert m.inspection_record("ins-1", 2) == rec
    assert m.inspection_record("ins-999", 2) is None
    assert m.inspection_ids(2) == ("ins-1",)
    assert m.model_ids(2) == ("model-1",)
    # repeat inspect chains: a second inspection mints ins-2, re-registers nothing
    rec2 = m.inspect("model-1", 3, inner_kind="reward-pursuit")
    assert rec2.inspection_id == "ins-2"
    assert m.model_ids(4) == ("model-1",)
    assert m.inspections_for("model-1", 4) == (rec, rec2)
    assert m.inspections_for("nope", 4) == ()


def test_inspect_bad_inputs_with_seq_burn():
    m = fresh()
    rejected_before = len(m.audit_log())
    seq = 1
    for bad in ("", 123, None, True, "x" * 257):
        with pytest.raises(InnerAlignmentError):
            m.inspect(bad, seq)
        seq += 1
    for bad_kind in ("", "nope", 123, True, None):
        with pytest.raises(BadKindError):
            m.inspect("model-1", seq, inner_kind=bad_kind)
        seq += 1
    for bad_digest in ("a" * 64, "md5:" + "a" * 32, 123, True):
        with pytest.raises(BadDigestError):
            m.inspect("model-1", seq, inner_digest=bad_digest)
        seq += 1
    # 5 + 5 + 4 = 14 failed mutations burned seqs 1..14
    assert seq == 15
    assert m.stats(0)["next_seq"] == 15
    assert len(m.audit_log()) == rejected_before + 14
    assert all(e["kind"] == KIND_REJECTED for e in m.audit_log())
    assert m.model_ids(0) == ()
    # ledger still works on a fresh seq
    rec = m.inspect("model-1", 15)
    assert rec.inspection_id == "ins-1"
    assert m.stats(0)["next_seq"] == 16


def test_full_kind_vocabulary():
    m = fresh()
    kinds = [
        "mesa-optimizer",
        "proxy-objective",
        "reward-pursuit",
        "goal-divergence",
        "deceptive-reasoning",
        "instrumental-subgoal",
        "situational-strategy",
        "unknown-inner",
    ]
    seq = 0
    for kind in kinds:
        seq += 1
        rec = m.inspect("model-1", seq, inner_kind=kind)
        assert rec.inner_kind == kind
        assert rec.verify()
    assert m.inspection_ids(99) == tuple(f"ins-{i}" for i in range(1, 9))
    rep = m.evaluate("model-1", 100)
    assert rep.inspection_count == 8
    assert rep.verification_count == 0
    assert rep.posture == "unevaluated"
    by_kind = dict(rep.by_kind)
    assert all(by_kind[k] == 1 for k in kinds)


def test_verify_roundtrip_and_verify():
    m, ins = ledger_with_inspection()
    ver = m.verification_record("vrf-1", 3)
    assert ver is not None
    assert ver.verification_id == "vrf-1"
    assert ver.inspection_id == ins.inspection_id
    assert ver.model_id == "model-1"
    assert ver.verdict == "aligned"
    assert ver.verification_digest == DIG2
    assert ver.seq == 2
    assert ver.verify()
    assert ver.as_dict()["schema"] == INNER_ALIGNMENT_SCHEMA
    assert m.verification_record("vrf-999", 3) is None
    assert m.verification_ids(3) == ("vrf-1",)
    assert m.verifications_for("model-1", 3) == (ver,)
    assert m.verifications_for("nope", 3) == ()
    # default verdict is aligned
    ins2 = m.inspect("model-1", 4)
    ver2 = m.verify(ins2.inspection_id, 5)
    assert ver2.verdict == "aligned"
    assert ver2.verify()


def test_verify_bad_inputs():
    m, ins = ledger_with_inspection(verdict=None)
    with pytest.raises(UnknownInspectionError):
        m.verify("ins-999", 2)
    with pytest.raises(BadModelError):
        m.verify("", 3)
    with pytest.raises(BadVerdictError):
        m.verify(ins.inspection_id, 4, verdict="nope")
    with pytest.raises(BadVerdictError):
        m.verify(ins.inspection_id, 5, verdict=123)
    with pytest.raises(BadDigestError):
        m.verify(ins.inspection_id, 6, verification_digest="a" * 64)
    # a valid verify books one row; a second verify refuses (one per inspection)
    ver = m.verify(ins.inspection_id, 7, verdict="aligned")
    assert ver.verify()
    with pytest.raises(AlreadyVerifiedError):
        m.verify(ins.inspection_id, 8)
    # verify against a retired model refuses
    ins2 = m.inspect("model-1", 9)
    m.retire("model-1", 10)
    with pytest.raises(RetiredModelError):
        m.verify(ins2.inspection_id, 11)
    # every failure above burned its seq (2,3,4,5,6,8,11) plus successes 7,9,10
    assert m.stats(0)["next_seq"] == 12
    rejected = [e for e in m.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 7
    assert all(e["detail"]["error"].endswith("Error") for e in rejected)


def test_full_verdict_vocabulary():
    verdicts = ["aligned", "misaligned", "deceptive", "uncertain", "inconclusive"]
    m = fresh()
    seq = 0
    for verdict in verdicts:
        seq += 1
        ins = m.inspect("model-1", seq)
        seq += 1
        ver = m.verify(ins.inspection_id, seq, verdict=verdict)
        assert ver.verdict == verdict
        assert ver.verify()
    by_verdict = dict(m.evaluate("model-1", 99).by_verdict)
    assert all(by_verdict[v] == 1 for v in verdicts)


def test_evaluate_posture_math():
    # unevaluated: inspections but no verifications
    m = fresh()
    m.inspect("model-1", 1)
    rep = m.evaluate("model-1", 2)
    assert rep.posture == "unevaluated"
    assert rep.integrity_ok and rep.verify()
    assert rep.open_inspection_ids == ("ins-1",)
    # aligned: all verifications aligned
    m.verify("ins-1", 3, verdict="aligned")
    rep = m.evaluate("model-1", 4)
    assert rep.posture == "aligned"
    assert rep.open_inspection_ids == ()
    # uncertain: any uncertain/inconclusive below misaligned in precedence
    ins2 = m.inspect("model-1", 5)
    m.verify(ins2.inspection_id, 6, verdict="uncertain")
    rep = m.evaluate("model-1", 7)
    assert rep.posture == "uncertain"
    # misaligned: any misaligned or deceptive outranks everything else
    ins3 = m.inspect("model-1", 8)
    m.verify(ins3.inspection_id, 9, verdict="aligned")
    ins4 = m.inspect("model-1", 10)
    m.verify(ins4.inspection_id, 11, verdict="deceptive")
    rep = m.evaluate("model-1", 12)
    assert rep.posture == "misaligned"
    assert rep.verification_count == 4
    assert rep.inspection_count == 4
    # a second misaligned verdict stays misaligned (not order-dependent)
    ins5 = m.inspect("model-1", 13)
    m.verify(ins5.inspection_id, 14, verdict="misaligned")
    assert m.evaluate("model-1", 15).posture == "misaligned"


def test_evaluate_read_purity():
    m, ins = ledger_with_inspection()
    rows_before = len(m.audit_log())
    rep1 = m.evaluate("model-1", 100)
    rep2 = m.evaluate("model-1", 100)  # same read seq twice
    assert rep1.digest == rep2.digest
    assert len(m.audit_log()) == rows_before  # no rows booked by reads
    assert m.stats(0)["next_seq"] == 3  # reads consume nothing
    with pytest.raises(UnknownModelError):
        m.evaluate("ghost", 100)
    assert len(m.audit_log()) == rows_before
    # retired model still evaluates (post-retire reads work)
    m.retire("model-1", 3)
    rep = m.evaluate("model-1", 4)
    assert rep.posture == "aligned"
    assert len(m.audit_log()) == rows_before + 1  # only the retire row


def test_retire_terminality():
    m = fresh()
    ins = m.inspect("model-1", 1)
    m.verify(ins.inspection_id, 2, verdict="aligned")
    ins2 = m.inspect("model-1", 3)  # deliberately left unverified
    with pytest.raises(BadReasonError):
        m.retire("model-1", 4, reason="nope")
    with pytest.raises(UnknownModelError):
        m.retire("ghost", 5)
    ret = m.retire("model-1", 6, reason="decommissioned")
    assert ret.verify()
    assert ret.reason == "decommissioned"
    assert m.retired_ids(7) == ("model-1",)
    # double retire refuses
    with pytest.raises(RetiredModelError):
        m.retire("model-1", 7)
    # retired ids are never recycled: inspect + verify refuse
    with pytest.raises(RetiredModelError):
        m.inspect("model-1", 8)
    with pytest.raises(RetiredModelError):
        m.verify(ins2.inspection_id, 9)
    # already-verified inspections fail closed before the retire check
    with pytest.raises(AlreadyVerifiedError):
        m.verify(ins.inspection_id, 10)
    # reads still work
    assert m.inspection_record(ins.inspection_id, 11) is not None
    assert m.evaluate("model-1", 11).posture == "aligned"
    # all four retire reasons accepted
    for reason in ["manual", "superseded", "decommissioned", "expired"]:
        m2 = fresh()
        m2.inspect(f"m-{reason}", 1)
        r = m2.retire(f"m-{reason}", 2, reason=reason)
        assert r.reason == reason and r.verify()
    rejected = [e for e in m.audit_log() if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 6  # seqs 4, 5, 7, 8, 9, 10


def test_seq_discipline():
    m = fresh()
    # rewind raises bare: no rejected row, seq unconsumed
    with pytest.raises(SeqOrderError):
        m.inspect("model-1", 0)
    assert len(m.audit_log()) == 0
    assert m.stats(0)["next_seq"] == 1
    # malformed seqs raise (reads and mutations)
    for bad in (True, "1", 1.5, None, [1]):
        with pytest.raises(SeqOrderError):
            m.inspect("model-1", bad)
        with pytest.raises(SeqOrderError):
            m.evaluate("model-1", bad)
    assert len(m.audit_log()) == 0
    assert m.stats(0)["next_seq"] == 1
    # a valid mutation claims; a rewind after it raises bare with no row
    m.inspect("model-1", 1)
    with pytest.raises(SeqOrderError):
        m.inspect("model-2", 1)
    rows = [e for e in m.audit_log() if e["kind"] == KIND_REJECTED]
    assert rows == []
    assert m.stats(0)["next_seq"] == 2


def test_audit_shapes_and_leak_ban():
    m, ins = ledger_with_inspection()
    m.retire("model-1", 3)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [KIND_INSPECTED, KIND_VERIFIED, KIND_RETIRED]
    for e in m.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == INNER_ALIGNMENT_VERSION
        assert isinstance(e["seq"], int) and not isinstance(e["seq"], bool)
        assert isinstance(e["detail"], dict)
    # pinned vocabulary values are emittable as declared data
    assert m.audit_log()[0]["detail"]["inner_kind"] == "mesa-optimizer"
    assert m.audit_log()[1]["detail"]["verdict"] == "aligned"
    # raw-material keys are banned at the builder level
    for banned in ("activations", "weights", "internals", "transcript", "behavior",
                   "evidence", "objective", "payload", "raw", "data", "text",
                   "value", "justification"):
        with pytest.raises(AuditKindError):
            inner_alignment_audit_event(KIND_INSPECTED, 99, **{banned: "x"})
    # bad kind refused
    with pytest.raises(AuditKindError):
        inner_alignment_audit_event("nope", 99)
    # rejected-row detail check
    with pytest.raises(UnknownInspectionError):
        m.verify("ins-999", 4)
    rej = m.audit_log()[-1]
    assert rej["kind"] == KIND_REJECTED
    assert rej["detail"]["error"] == "UnknownInspectionError"


def test_cross_instance_digest_determinism_and_tamper():
    def build():
        m = fresh()
        ins = m.inspect("model-1", 1, inner_kind="deceptive-reasoning", inner_digest=DIG)
        m.verify(ins.inspection_id, 2, verdict="aligned", verification_digest=DIG2)
        return m, ins

    m1, ins1 = build()
    m2, ins2 = build()
    assert ins1.digest == ins2.digest
    assert m1.verification_record("vrf-1", 9).digest == m2.verification_record("vrf-1", 9).digest
    assert m1.evaluate("model-1", 10).digest == m2.evaluate("model-1", 10).digest
    # frozen records cannot be mutated through the normal API
    with pytest.raises(dataclasses.FrozenInstanceError):
        ins1.seq = 99  # type: ignore
    # tamper breaks verify() and flips integrity_ok as data (never raised)
    ver = m1.verification_record("vrf-1", 11)
    object.__setattr__(ver, "verdict", "misaligned")
    assert ver.verify() is False
    rep = m1.evaluate("model-1", 12)
    assert rep.integrity_ok is False
    assert rep.verify()  # the report's own pin still verifies
    # 8-thread read smoke on a tampered-but-live ledger
    errors = []

    def reader():
        try:
            for _ in range(50):
                m1.evaluate("model-1", 13)
                m1.audit_log()
        except Exception as exc:  # pragma: no cover - must not happen
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "-c", "import inner_alignment; inner_alignment.main()"],
        cwd=str(MODULE.parent),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "inner-alignment OK: inspect, verify, evaluate, retire, pins, audit" in proc.stdout
