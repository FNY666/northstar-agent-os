"""15 tests for the ai_standards module (house style)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ai_standards as m


DIGEST = "sha256:" + "ab" * 32


def fresh() -> "m.AIStandards":
    return m.AIStandards()


def test_01_pins():
    assert m.AI_STANDARDS_VERSION == "ai-standards.v1"
    assert m.AI_STANDARDS_SCHEMA == "northstar.ai-standards.v1"
    assert m.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(m.STANDARDS) == {
        "iso-42001", "nist-ai-rmf", "iso-23894", "eu-ai-act",
        "oecd-ai-principles", "ieee-7000", "iso-24028", "self-declared"}
    assert len(m.STANDARDS) == 8
    assert set(m.CONFORMANCES) == {
        "conformant", "non-conformant", "partially-conformant",
        "not-assessed"}
    assert set(m.POSTURES) == {
        "unevaluated", "non-conformant", "partially-conformant",
        "under-assessment", "conformant"}
    assert len(m.REASONS) == 4


def test_02_stdlib_only_ast():
    src = Path(m.__file__).read_text()
    tree = ast.parse(src)
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "__future__", "json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                assert top in allowed, f"banned import: {a.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in allowed | {"canonical_json"}, \
                f"banned import: {node.module}"
    assert m.stdlib_only()


def test_03_declare_roundtrip_verify_frozen():
    st = fresh()
    rec = st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1, DIGEST)
    assert rec.declaration_id == "dcl-1"
    assert rec.system_id == "sys-1"
    assert rec.standard == m.STD_ISO_42001
    assert rec.conformance == m.CONF_CONFORMANT
    assert rec.verify("dcl-1", "sys-1", m.STD_ISO_42001,
                      m.CONF_CONFORMANT, DIGEST)
    assert not rec.verify("dcl-1", "sys-1", m.STD_ISO_42001,
                          m.CONF_NON_CONFORMANT, DIGEST)
    with pytest.raises(Exception):
        rec.conformance = m.CONF_NOT_ASSESSED  # frozen dataclass


def test_04_declare_bad_inputs_seq_burn_rejected_rows():
    st = fresh()
    seq = 0
    bad = [
        lambda s: st.declare("", m.STD_ISO_42001, m.CONF_CONFORMANT, s),
        lambda s: st.declare("sys x", m.STD_ISO_42001, m.CONF_CONFORMANT, s),
        lambda s: st.declare("sys-1", "bogus-standard",
                             m.CONF_CONFORMANT, s),
        lambda s: st.declare("sys-1", 123, m.CONF_CONFORMANT, s),
        lambda s: st.declare("sys-1", m.STD_ISO_42001, "bogus-conf", s),
        lambda s: st.declare("sys-1", m.STD_ISO_42001,
                             m.CONF_CONFORMANT, s, "not-a-pin"),
        lambda s: st.declare("sys-1", m.STD_ISO_42001, True, s),
    ]
    for fn in bad:
        seq += 1
        with pytest.raises(m.AIStandardsError):
            fn(seq)
    rows = st.audit_log()
    assert len(rows) == len(bad)
    assert all(r["kind"] == m.KIND_REJECTED for r in rows)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    # every burned seq is booked as a rejected row: count matches
    assert st.stats()["audit_rows"] == len(bad)


def test_05_full_8_standard_vocabulary():
    st = fresh()
    seq = 0
    for i, std in enumerate(m.STANDARDS):
        seq += 1
        rec = st.declare("sys-std", std, m.CONF_CONFORMANT, seq)
        assert rec.standard == std
    assert st.stats()["declarations"] == 8
    ids = st.declarations_for("sys-std", seq + 1)
    assert ids == tuple(f"dcl-{i + 1}" for i in range(8))


def test_06_full_4_conformance_vocabulary():
    st = fresh()
    seq = 0
    for i, conf in enumerate(m.CONFORMANCES):
        seq += 1
        rec = st.declare("sys-conf", m.STD_ISO_42001, conf, seq)
        assert rec.conformance == conf
    assert st.stats()["declarations"] == 4
    ev = st.evaluate("sys-conf", seq + 1)
    assert ev.n_conformant == 1
    assert ev.n_non_conformant == 1
    assert ev.n_partially == 1
    assert ev.n_not_assessed == 1


def test_07_verify_semantics_tamper_read_purity_unknown():
    st = fresh()
    st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1, DIGEST)
    n_rows = len(st.audit_log())
    vr = st.verify("dcl-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("dcl-1", "verified")
    # same-seq read twice: no audit rows, no consumption
    vr2 = st.verify("dcl-1", 2)
    assert vr2.verdict == "verified"
    assert len(st.audit_log()) == n_rows
    # tamper reported as data, never raised
    import dataclasses
    rec = st.declaration_record("dcl-1", 3)
    object.__setattr__(rec, "conformance", m.CONF_NON_CONFORMANT)
    vr3 = st.verify("dcl-1", 4)
    assert vr3.verdict == "tampered"
    ev = st.evaluate("sys-1", 5)
    assert ev.integrity_ok is False
    with pytest.raises(m.UnknownDeclarationError):
        st.verify("dcl-999", 6)
    with pytest.raises(m.SeqOrderError):
        st.verify("dcl-1", -1)


def test_08_evaluate_posture_math_and_precedence():
    st = fresh()
    seq = 0
    # all conformant -> conformant
    seq += 1
    st.declare("s-conf", m.STD_ISO_42001, m.CONF_CONFORMANT, seq)
    seq += 1
    ev = st.evaluate("s-conf", seq)
    assert ev.posture == m.POSTURE_CONFORMANT
    assert ev.integrity_ok
    assert ev.verify("s-conf", m.POSTURE_CONFORMANT)
    # any not-assessed -> under-assessment
    seq += 1
    st.declare("s-not", m.STD_ISO_42001, m.CONF_CONFORMANT, seq)
    seq += 1
    st.declare("s-not", m.STD_NIST_AI_RMF, m.CONF_NOT_ASSESSED, seq)
    seq += 1
    assert st.evaluate("s-not", seq).posture == m.POSTURE_UNDER_ASSESSMENT
    # any partially-conformant outranks under-assessment
    seq += 1
    st.declare("s-part", m.STD_ISO_42001, m.CONF_NOT_ASSESSED, seq)
    seq += 1
    st.declare("s-part", m.STD_ISO_23894, m.CONF_PARTIALLY_CONFORMANT, seq)
    seq += 1
    assert st.evaluate("s-part", seq).posture == m.POSTURE_PARTIALLY
    # any non-conformant outranks everything
    seq += 1
    st.declare("s-non", m.STD_ISO_42001, m.CONF_PARTIALLY_CONFORMANT, seq)
    seq += 1
    st.declare("s-non", m.STD_EU_AI_ACT, m.CONF_NON_CONFORMANT, seq)
    seq += 1
    ev = st.evaluate("s-non", seq)
    assert ev.posture == m.POSTURE_NON_CONFORMANT
    with pytest.raises(m.UnknownSystemError):
        st.evaluate("nope", seq + 1)


def test_09_retire_terminality_id_nonrecycling_postretire_reads():
    st = fresh()
    st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1)
    st.declare("sys-2", m.STD_NIST_AI_RMF, m.CONF_CONFORMANT, 2)
    rr = st.retire("sys-1", 3)
    assert rr.verify("sys-1", m.REASON_MANUAL)
    assert st.retired_ids(4) == ("sys-1",)
    # retired ids never recycled: sys-1 stays retired even if re-declared ids
    with pytest.raises(m.RetiredSystemError):
        st.declare("sys-1", m.STD_ISO_23894, m.CONF_CONFORMANT, 5)
    # fresh system on same ledger still works; ids never recycled
    rec = st.declare("sys-2", m.STD_ISO_23894, m.CONF_CONFORMANT, 6)
    assert rec.declaration_id == "dcl-3"
    # post-retire reads still work
    ev = st.evaluate("sys-1", 7)
    assert ev.posture == m.POSTURE_CONFORMANT
    assert st.declaration_record("dcl-1", 8).system_id == "sys-1"
    # bad reason, double retire, unknown double-retire book rejected rows
    with pytest.raises(m.BadReasonError):
        st.retire("sys-2", 9, "bogus")
    with pytest.raises(m.DoubleRetireError):
        st.retire("sys-1", 10)
    rows = st.audit_log()
    # tail order: declared(dcl-1), declared(dcl-2), retired(sys-1),
    # rejected(seq5 retired-declare), declared(dcl-3),
    # rejected(bad reason), rejected(double retire)
    assert [r["kind"] for r in rows] == [
        m.KIND_DECLARED, m.KIND_DECLARED, m.KIND_RETIRED,
        m.KIND_REJECTED, m.KIND_DECLARED, m.KIND_REJECTED,
        m.KIND_REJECTED]
    assert rows[-4]["kind"] == m.KIND_REJECTED
    assert rows[-3]["kind"] == m.KIND_DECLARED
    assert rows[-2]["kind"] == m.KIND_REJECTED
    assert rows[-1]["kind"] == m.KIND_REJECTED
    # all 4 reasons accepted on fresh systems
    st2 = fresh()
    seq = 0
    for i, reason in enumerate(m.REASONS):
        seq += 1
        st2.declare(f"sys-r{i}", m.STD_ISO_42001, m.CONF_CONFORMANT, seq)
        seq += 1
        r = st2.retire(f"sys-r{i}", seq, reason)
        assert r.reason == reason


def test_10_seq_discipline():
    st = fresh()
    # rewind on fresh ledger raises bare with zero rows
    with pytest.raises(m.SeqOrderError):
        st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, -1)
    with pytest.raises(m.SeqOrderError):
        st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 0 - 1)
    assert st.stats()["audit_rows"] == 0
    st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1)
    # malformed seqs
    for bad in (True, 1.0, "2", None, -3):
        with pytest.raises(m.SeqOrderError):
            st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, bad)
    # rewind raises bare (no row, seq not consumed); the earlier
    # successful declare row (seq 1) is still the only audit row
    with pytest.raises(m.SeqOrderError):
        st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1)
    assert st.stats()["audit_rows"] == 1
    # failed mutation consumes its seq (burns a rejected row)
    with pytest.raises(m.BadStandardError):
        st.declare("sys-1", "bogus", m.CONF_CONFORMANT, 2)
    assert len(st.audit_log()) == 2
    assert st.audit_log()[-1]["kind"] == m.KIND_REJECTED
    # next live seq continues from the burned seq
    rec = st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 3)
    assert rec.declaration_id == "dcl-2"


def test_11_audit_shapes_leak_ban_bad_kind():
    st = fresh()
    ev_row = m.ai_standards_audit_event(
        m.KIND_DECLARED,
        {"system_id": "sys-1", "declaration_id": "dcl-1",
         "standard": "iso-42001", "conformance": "conformant",
         "claim_digest": DIGEST}, 7)
    assert ev_row["schema"] == "audit.ndjson/1"
    assert ev_row["module"] == "ai-standards.v1"
    assert ev_row["kind"] == m.KIND_DECLARED
    assert ev_row["seq"] == 7
    # raw material keys are banned at the builder
    for banned in ("evidence", "transcript", "weights", "finding",
                   "rationale", "score", "content"):
        with pytest.raises(m.AuditKindError):
            m.ai_standards_audit_event(
                m.KIND_DECLARED, {"system_id": "s", banned: "x"}, 8)
    # pinned vocabulary labels may cross the boundary as declared data
    ok = m.ai_standards_audit_event(
        m.KIND_DECLARED,
        {"system_id": "s", "standard": m.STD_ISO_42001,
         "conformance": m.CONF_CONFORMANT}, 9)
    assert ok["detail"]["standard"] == m.STD_ISO_42001
    with pytest.raises(m.AuditKindError):
        m.ai_standards_audit_event("bogus-kind", {"system_id": "s"}, 10)
    with pytest.raises(m.SeqOrderError):
        m.ai_standards_audit_event(m.KIND_DECLARED, {"system_id": "s"}, -1)


def test_12_views_stats_unknown_lookups():
    st = fresh()
    assert st.system_ids(0) == ()
    assert st.retired_ids(0) == ()
    assert st.stats() == {"systems": 0, "declarations": 0,
                          "retired": 0, "audit_rows": 0}
    st.declare("b-sys", m.STD_ISO_42001, m.CONF_CONFORMANT, 1)
    st.declare("a-sys", m.STD_NIST_AI_RMF, m.CONF_NOT_ASSESSED, 2)
    assert st.system_ids(3) == ("b-sys", "a-sys")  # first-declare order
    assert st.declarations_for("b-sys", 4) == ("dcl-1",)
    assert st.declaration_record("dcl-2", 5).standard == m.STD_NIST_AI_RMF
    stats = st.stats()
    assert stats["systems"] == 2 and stats["declarations"] == 2
    assert stats["retired"] == 0 and stats["audit_rows"] == 2
    with pytest.raises(m.UnknownSystemError):
        st.declarations_for("nope", 6)
    with pytest.raises(m.UnknownDeclarationError):
        st.declaration_record("dcl-999", 7)
    with pytest.raises(m.SeqOrderError):
        st.system_ids(-1)


def test_13_cross_instance_determinism_and_thread_smoke():
    st1, st2 = fresh(), fresh()
    for st in (st1, st2):
        st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1, DIGEST)
    assert (st1.declaration_record("dcl-1", 2).digest ==
            st2.declaration_record("dcl-1", 2).digest)
    ev1, ev2 = st1.evaluate("sys-1", 3), st2.evaluate("sys-1", 3)
    assert ev1.digest == ev2.digest
    # 8-thread read smoke
    errors = []
    def reader():
        try:
            for _ in range(50):
                assert st1.evaluate("sys-1", 3).posture == \
                    m.POSTURE_CONFORMANT
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_14_retire_bad_seq_and_audit_kind_rows():
    st = fresh()
    st.declare("sys-1", m.STD_ISO_42001, m.CONF_CONFORMANT, 1)
    with pytest.raises(m.SeqOrderError):
        st.retire("sys-1", 1)  # rewind, no row
    assert st.stats()["audit_rows"] == 1
    rr = st.retire("sys-1", 2)
    assert rr.seq == 2
    kinds = [r["kind"] for r in st.audit_log()]
    assert kinds == [m.KIND_DECLARED, m.KIND_RETIRED]
    row = st.audit_log()[-1]
    assert row["schema"] == "audit.ndjson/1"
    assert row["detail"]["system_id"] == "sys-1"
    assert row["detail"]["reason"] == m.REASON_MANUAL


def test_15_main_subprocess():
    proc = subprocess.run(
        [sys.executable, "-m", "ai_standards"],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-standards OK: declare, verify, evaluate, retire, pins, audit")
