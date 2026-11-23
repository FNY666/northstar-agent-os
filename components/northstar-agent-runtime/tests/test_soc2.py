"""Tests for soc2.py: assess/attest/monitor decision ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "soc2.py"


def _load():
    spec = importlib.util.spec_from_file_location("soc2", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["soc2"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


s2 = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32
BAD_DIGESTS = ["sha256:xyz", "ab" * 32, "sha256:" + "zz" * 32, "SHA256:" + "ab" * 32, None, 123]


def _fresh():
    return s2.SOC2()


# 1 -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert s2.SOC2_VERSION == "soc2.v1"
    assert s2.SOC2_SCHEMA == "northstar.soc2.v1"
    assert s2.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(s2.TYPES) == {"type1", "type2"}
    assert set(s2.CATEGORIES) == {
        "security", "availability", "confidentiality",
        "processing-integrity", "privacy",
    }
    assert set(s2.OPINIONS) == {"unqualified", "qualified", "adverse", "disclaimer"}
    assert set(s2.STATUSES) == {
        "effective", "deficient", "significant-deficiency", "material-weakness",
    }


# 2 -- stdlib only --------------------------------------------------------


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 -- assess roundtrip + verify -------------------------------------------


def test_assess_roundtrip_and_verify():
    m = _fresh()
    rec = m.assess("s2-1", 1, type="type2", category="security", scope_digest=DIGEST)
    assert rec.verify()
    assert rec.assessment_id == "s2-1" and rec.type == "type2" and rec.category == "security"
    d = rec.as_dict()
    assert d["schema"] == "northstar.soc2.v1"
    assert d["version"] == "soc2.v1"
    assert m.assessment_record("s2-1", 2) is rec
    assert m.assessment_ids(3) == ("s2-1",)
    assert m.pending_ids(4) == ("s2-1",)


# 4 -- assess duplicate + bad inputs burn seq and book rejected rows ------


def test_assess_duplicate_and_bad_inputs():
    m = _fresh()
    m.assess("s2-1", 1)
    seq = 1
    rejected = 0
    seq += 1
    with pytest.raises(s2.DuplicateAssessmentError):
        m.assess("s2-1", seq)
    rejected += 1
    for bad_id in ["", "  ", "has space", 123, None]:
        seq += 1
        with pytest.raises(s2.BadIdError):
            m.assess(bad_id, seq)
        rejected += 1
    for bad_t in ["type3", "", None, 1]:
        seq += 1
        with pytest.raises(s2.BadTypeError):
            m.assess("s2-x", seq, type=bad_t)
        rejected += 1
    for bad_c in ["reliability", "", None, 1]:
        seq += 1
        with pytest.raises(s2.BadCategoryError):
            m.assess("s2-x", seq, category=bad_c)
        rejected += 1
    for bad_d in BAD_DIGESTS:
        seq += 1
        with pytest.raises(s2.BadDigestError):
            m.assess("s2-x", seq, scope_digest=bad_d)
        rejected += 1
    stats = m.stats(seq + 1)
    assert stats["rejected_rows"] == rejected
    # all failures consumed their seq: the next free seq follows
    assert m._seq == seq


# 5 -- full vocabulary acceptance -----------------------------------------


def test_assess_full_vocabulary():
    m = _fresh()
    seq = 0
    for t in s2.TYPES:
        for c in s2.CATEGORIES:
            seq += 1
            rec = m.assess(f"a-{t}-{c}", seq, type=t, category=c)
            assert rec.verify()
    stats = m.stats(seq + 1)
    assert stats["assessed"] == len(s2.TYPES) * len(s2.CATEGORIES)
    assert stats["types"] == {"type1": 5, "type2": 5}
    assert stats["categories"] == {c: 2 for c in s2.CATEGORIES}


# 6 -- attest roundtrip + minted ids + verify ------------------------------


def test_attest_roundtrip_and_verify():
    m = _fresh()
    m.assess("s2-1", 1)
    att = m.attest("s2-1", 2, "unqualified", report_digest=DIGEST)
    assert att.verify()
    assert att.attestation_id == "att-1" and att.opinion == "unqualified"
    d = att.as_dict()
    assert d["schema"] == "northstar.soc2.v1"
    assert m.attestation_record("s2-1", 3) is att
    assert m.attested_ids(4) == ("s2-1",)
    assert m.pending_ids(5) == ()
    # all opinion kinds accepted on distinct assessments
    seq = 5
    for i, op in enumerate(("qualified", "adverse", "disclaimer")):
        seq += 1
        m.assess(f"s2-q{i}", seq)
        seq += 1
        a = m.attest(f"s2-q{i}", seq, op)
        assert a.verify() and a.attestation_id == f"att-{i + 2}"
    assert m.stats(seq + 1)["opinions"] == {
        "unqualified": 1, "qualified": 1, "adverse": 1, "disclaimer": 1,
    }


# 7 -- attest refusals ------------------------------------------------------


def test_attest_refusals():
    m = _fresh()
    seq = 0
    seq += 1
    with pytest.raises(s2.UnknownAssessmentError):
        m.attest("nope", seq)
    m.assess("s2-1", seq + 1)
    seq += 1
    for bad_op in ["mostly-fine", "", None, 1]:
        seq += 1
        with pytest.raises(s2.BadOpinionError):
            m.attest("s2-1", seq, bad_op)
    m.assess("s2-2", seq + 1)
    seq += 1
    for bad_d in BAD_DIGESTS:
        seq += 1
        with pytest.raises(s2.BadDigestError):
            m.attest("s2-2", seq, report_digest=bad_d)
    m.attest("s2-2", seq + 1)
    seq += 1
    seq += 1
    with pytest.raises(s2.AlreadyAttestedError):
        m.attest("s2-2", seq)
    assert m.stats(seq + 1)["rejected_rows"] == 1 + 4 + len(BAD_DIGESTS) + 1


# 8 -- monitor roundtrip + minted chain -------------------------------------


def test_monitor_roundtrip_and_chain():
    m = _fresh()
    m.assess("s2-1", 1)
    m1 = m.monitor("s2-1", 2, "effective", control_digest=DIGEST)
    assert m1.verify() and m1.monitoring_id == "mon-1"
    m2 = m.monitor("s2-1", 3, "deficient")
    assert m2.verify() and m2.monitoring_id == "mon-2"
    assert m.monitoring_record("mon-1", 4) is m1
    chain = m.monitorings_for("s2-1", 5)
    assert chain == (m1, m2)
    assert m.monitorings_for("s2-nope", 6) == ()
    # full status vocabulary accepted
    seq = 6
    for st in ("significant-deficiency", "material-weakness"):
        seq += 1
        rec = m.monitor("s2-1", seq, st)
        assert rec.verify()
    assert m.stats(seq + 1)["statuses"] == {
        "effective": 1, "deficient": 1,
        "significant-deficiency": 1, "material-weakness": 1,
    }


# 9 -- monitor refusals -----------------------------------------------------


def test_monitor_refusals():
    m = _fresh()
    seq = 0
    seq += 1
    with pytest.raises(s2.UnknownAssessmentError):
        m.monitor("nope", seq)
    m.assess("s2-1", seq + 1)
    seq += 1
    for bad_st in ["failing", "", None, 1]:
        seq += 1
        with pytest.raises(s2.BadStatusError):
            m.monitor("s2-1", seq, bad_st)
    for bad_d in BAD_DIGESTS:
        seq += 1
        with pytest.raises(s2.BadDigestError):
            m.monitor("s2-1", seq, control_digest=bad_d)
    assert m.stats(seq + 1)["rejected_rows"] == 1 + 4 + len(BAD_DIGESTS)
    assert m.stats(seq + 2)["monitorings"] == 0


# 10 -- seq discipline ------------------------------------------------------


def test_seq_discipline():
    m = _fresh()
    m.assess("s2-1", 1)
    # rewinds raise bare: no seq consumed, no rejected rows
    with pytest.raises(s2.SeqOrderError):
        m.assess("s2-2", 1)
    assert m._seq == 1
    assert m.stats(2)["rejected_rows"] == 0
    # malformed seqs
    for bad_seq in [True, "2", 2.5, 0, -1, None]:
        with pytest.raises(s2.SeqOrderError):
            m.assess("s2-2", bad_seq)
    assert m._seq == 1
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(s2.DuplicateAssessmentError):
        m.assess("s2-1", 2)
    assert m._seq == 2
    # reads validate but never consume
    assert m.assessment_record("s2-1", 2) is not None
    assert m._seq == 2


# 11 -- audit shapes + leak ban + bad kind ----------------------------------


def test_audit_shapes_leak_ban_bad_kind():
    m = _fresh()
    m.assess("s2-1", 1, scope_digest=DIGEST)
    m.attest("s2-1", 2, "unqualified")
    m.monitor("s2-1", 3, "effective")
    log = m.audit_log(4)
    kinds = [e["kind"] for e in log]
    assert kinds == ["soc2.assessed", "soc2.attested", "soc2.monitored"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "northstar.soc2.v1"
    # banned keys rejected at the builder boundary (raw material, never pinned vocab)
    with pytest.raises(s2.AuditKindError):
        s2.soc2_audit_event("soc2.assessed", 9, report="x")
    with pytest.raises(s2.AuditKindError):
        s2.soc2_audit_event("soc2.monitored", 9, evidence="x")
    with pytest.raises(s2.AuditKindError):
        s2.soc2_audit_event("soc2.attested", 9, workpaper="x")
    with pytest.raises(s2.AuditKindError):
        s2.soc2_audit_event("nope.kind", 9)
    # pinned vocabulary values (opinion/status) are emittable as declared data
    evt = s2.soc2_audit_event("soc2.attested", 9, opinion="unqualified")
    assert evt["detail"]["opinion"] == "unqualified"
    # no raw material leaks into stored rows
    blob = repr(log)
    for banned in ("raw", "transcript", "workpaper", "secret"):
        assert f"'{banned}':" not in blob


# 12 -- cross-instance determinism + tamper breaks verify -------------------


def test_digest_determinism_and_tamper():
    a = _fresh()
    b = _fresh()
    ra = a.assess("s2-1", 1, type="type2", category="privacy", scope_digest=DIGEST)
    rb = b.assess("s2-1", 1, type="type2", category="privacy", scope_digest=DIGEST)
    assert ra.digest == rb.digest
    aa = a.attest("s2-1", 2, "qualified", report_digest=DIGEST)
    ab = b.attest("s2-1", 2, "qualified", report_digest=DIGEST)
    assert aa.digest == ab.digest
    ma = a.monitor("s2-1", 3, "deficient", control_digest=DIGEST)
    mb = b.monitor("s2-1", 3, "deficient", control_digest=DIGEST)
    assert ma.digest == mb.digest
    # tamper reported as data, never raised
    object.__setattr__(ra, "category", "availability")
    assert not ra.verify()
    sta = a.status("s2-1", 4)
    assert not sta.integrity_ok


# 13 -- read purity + status view -------------------------------------------


def test_read_purity_and_status():
    m = _fresh()
    m.assess("s2-1", 1, type="type1", category="availability")
    st = m.status("s2-1", 2)
    assert st.verify() and st.integrity_ok
    assert st.assessed and not st.attested
    assert st.type == "type1" and st.category == "availability"
    assert st.opinion == "" and st.monitorings == 0 and st.last_status == ""
    # same-seq reads are free and write no rows
    rows_before = len(m.audit_log(3))
    m.status("s2-1", 2)
    m.status("s2-1", 2)
    assert len(m.audit_log(4)) == rows_before
    assert m._seq == 1
    # unknown ids on reads raise but consume nothing
    with pytest.raises(s2.UnknownAssessmentError):
        m.status("nope", 2)
    with pytest.raises(s2.UnknownAssessmentError):
        m.assessment_record("nope", 2)
    with pytest.raises(s2.UnknownAssessmentError):
        m.attestation_record("nope", 2)
    assert m.monitorings_for("s2-1", 2) == ()
    assert m._seq == 1
    # lifecycle: attest then monitor reflected in status
    m.attest("s2-1", 2, "adverse")
    m.monitor("s2-1", 3, "material-weakness")
    st2 = m.status("s2-1", 4)
    assert st2.attested and st2.opinion == "adverse"
    assert st2.monitorings == 1 and st2.last_status == "material-weakness"


# 14 -- frozen records + thread smoke ---------------------------------------


def test_frozen_and_threads():
    m = _fresh()
    rec = m.assess("s2-1", 1)
    with pytest.raises(Exception):
        rec.assessment_id = "x"  # frozen dataclass
    att = m.attest("s2-1", 2)
    mon = m.monitor("s2-1", 3)
    errors = []
    def reader():
        try:
            for _ in range(50):
                assert m.assessment_record("s2-1", 4) is rec
                assert m.attestation_record("s2-1", 5) is att
                assert m.monitoring_record("mon-1", 6) is mon
                assert m.monitorings_for("s2-1", 7) == (mon,)
                assert m.assessment_ids(8) == ("s2-1",)
                m.status("s2-1", 9)
                m.stats(10)
                m.audit_log(11)
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert rec.verify() and att.verify() and mon.verify()


# 15 -- main() subprocess check ---------------------------------------------


def test_main_subprocess():
    r = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MODULE_PATH.parent),
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "soc2 OK: assess, attest, monitor, status, pins, audit"
