"""Tests for standards.py — standards adoption and conformance bookkeeping."""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import standards
from standards import (
    AUDIT_KINDS,
    SCHEMA,
    VERSION,
    AuditKindError,
    AlreadyCertifiedError,
    DuplicateStandardError,
    NotConformantError,
    RetiredStandardError,
    SeqOrderError,
    Standards,
    StandardsError,
    UnknownStandardError,
    standards_audit_event,
)

COMP = Path(__file__).resolve().parent.parent


def test_01_version_and_schema_pins():
    assert standards.VERSION == "standards.v1"
    assert standards.SCHEMA == "northstar.standards.v1"
    assert VERSION == "standards.v1"
    assert SCHEMA == "northstar.standards.v1"
    assert "standards.rejected" in AUDIT_KINDS


def test_02_stdlib_only_ast_check():
    src = (COMP / "standards.py").read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"import {alias.name} not allowed"
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            assert top in allowed, f"from-import {node.module} not allowed"


def test_03_adopt_roundtrip_and_verify():
    st = Standards()
    rec = st.adopt("acme-ai", "nist-ai-rmf", 1, title="adoption memo")
    assert rec.standard_id == "acme-ai"
    assert rec.framework == "nist-ai-rmf"
    assert rec.title_digest.startswith("sha256:")
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    d = rec.as_dict()
    assert d["schema"] == SCHEMA and d["version"] == VERSION
    assert st.adoption_record("acme-ai", 2) == rec
    assert st.adoption_ids(3) == ("acme-ai",)
    log = st.audit_log(4)
    assert len(log) == 1 and log[0]["kind"] == "standard-adopted"


def test_04_adopt_bad_inputs_seq_burn_and_rejected_rows():
    st = Standards()
    bad = [
        ("", "nist-ai-rmf"),  # empty id
        ("x" * 129, "soc2"),  # too long
        (123, "soc2"),  # non-str id
        (True, "soc2"),  # bool id
        ("ok-id", "bogus-framework"),  # unknown framework
        ("ok-id", True),  # bool framework
    ]
    seq = 0
    for sid, fw in bad:
        seq += 1
        with pytest.raises(StandardsError):
            st.adopt(sid, fw, seq)
    # all failed mutations consumed their seq and booked rejected rows
    log = st.audit_log(seq + 1)
    rejected = [e for e in log if e["kind"] == "standards.rejected"]
    assert len(rejected) == len(bad)
    assert st.stats(seq + 2)["adoptions"] == 0
    assert st.stats(seq + 3)["seq"] == seq


def test_05_adopt_duplicate_refused():
    st = Standards()
    st.adopt("acme-ai", "soc2", 1)
    with pytest.raises(DuplicateStandardError):
        st.adopt("acme-ai", "iso-27001", 2)
    rejected = [e for e in st.audit_log(3) if e["kind"] == "standards.rejected"]
    assert len(rejected) == 1 and rejected[0]["detail"]["error"] == "DuplicateStandardError"


def test_06_verify_verdicts_and_coverage_text():
    st = Standards()
    st.adopt("acme-ai", "iso-27001", 1)
    full = st.verify("acme-ai", 2, requirements=("r1", "r2"), met=("r1", "r2"))
    assert full.verdict == "conformant" and full.coverage_text == "2/2"
    assert full.verify() is True
    assert full.verification_id == "ver-1"
    part = st.verify("acme-ai", 3, requirements=("r1", "r2"), met=("r1",))
    assert part.verdict == "partial" and part.coverage_text == "1/2"
    assert part.verification_id == "ver-2"
    non = st.verify("acme-ai", 4, requirements=("r1", "r2"), met=())
    assert non.verdict == "non-conformant" and non.coverage_text == "0/2"
    vers = st.verifications_for("acme-ai", 5)
    assert [v.verification_id for v in vers] == ["ver-1", "ver-2", "ver-3"]


def test_07_verify_bad_inputs():
    st = Standards()
    st.adopt("acme-ai", "soc2", 1)
    bad = [
        (("r1",), ("r1", "r2")),  # met not subset
        ((), ("r1",)),  # met not subset
        ((), ()),  # empty requirements
        (("r1", "r1"), ("r1",)),  # duplicate requirements
        (("r1",), ("r1", "r1")),  # duplicate met
        (("r1",), "r1"),  # met not a list
        ((123,), ("r1",)),  # non-str requirement
    ]
    seq = 1
    for req, met in bad:
        seq += 1
        with pytest.raises(StandardsError):
            st.verify("acme-ai", seq, requirements=req, met=met)
    with pytest.raises(UnknownStandardError):
        st.verify("nope", seq + 1, requirements=("x",), met=("x",))
    log = st.audit_log(seq + 2)
    rejected = [e for e in log if e["kind"] == "standards.rejected"]
    assert len(rejected) == len(bad) + 1
    assert st.stats(seq + 3)["verifications"] == 0


def test_08_certify_happy_path_and_terminality():
    st = Standards()
    st.adopt("acme-ai", "eu-ai-act", 1)
    with pytest.raises(NotConformantError):
        st.certify("acme-ai", 2)  # no verification booked
    st.verify("acme-ai", 3, requirements=("r1",), met=())
    with pytest.raises(NotConformantError):
        st.certify("acme-ai", 4)  # latest is non-conformant
    ver = st.verify("acme-ai", 5, requirements=("r1",), met=("r1",))
    cert = st.certify("acme-ai", 6)
    assert cert.certified is True
    assert cert.verification_id == ver.verification_id
    assert cert.verify() is True
    assert st.certification("acme-ai", 7) == cert
    with pytest.raises(AlreadyCertifiedError):
        st.certify("acme-ai", 8)
    with pytest.raises(UnknownStandardError):
        st.certify("nope", 9)
    kinds = [e["kind"] for e in st.audit_log(10)]
    assert kinds.count("certified") == 1


def test_09_retire_terminality():
    st = Standards()
    st.adopt("acme-ai", "custom", 1)
    with pytest.raises(UnknownStandardError):
        st.retire("nope", 2)
    ret = st.retire("acme-ai", 3)
    assert ret.verify() is True
    assert st.retired_ids(4) == ("acme-ai",)
    with pytest.raises(RetiredStandardError):
        st.retire("acme-ai", 5)
    with pytest.raises(RetiredStandardError):
        st.adopt("acme-ai", "soc2", 6)  # retired ids never recycled
    with pytest.raises(RetiredStandardError):
        st.verify("acme-ai", 7, requirements=("x",), met=("x",))
    with pytest.raises(RetiredStandardError):
        st.certify("acme-ai", 8)
    # reads still work
    assert st.adoption_record("acme-ai", 9).standard_id == "acme-ai"


def test_10_seq_discipline_rewind_bare_no_consumption():
    st = Standards()
    st.adopt("a", "soc2", 1)
    # rewind raises bare: no rejected row, seq not consumed
    with pytest.raises(SeqOrderError):
        st.adopt("b", "soc2", 1)
    with pytest.raises(SeqOrderError):
        st.verify("a", 1, requirements=("x",), met=("x",))
    log = st.audit_log(2)
    assert all(e["kind"] != "standards.rejected" for e in log)
    assert st.stats(3)["seq"] == 1
    # malformed seqs
    for bad_seq in (-1, True, "x", 1.5, None):
        with pytest.raises(SeqOrderError):
            st.adopt("b", "soc2", bad_seq)


def test_11_view_read_purity():
    st = Standards()
    st.adopt("a", "soc2", 1)
    st.verify("a", 2, requirements=("r1",), met=("r1",))
    st.certify("a", 3)
    # pure reads: same seq twice legal, no audit rows, no seq consumption
    assert st.stats(4)["seq"] == 3
    assert st.adoption_ids(4) == st.adoption_ids(4)
    assert len(st.audit_log(4)) == len(st.audit_log(4)) == 3
    assert st.stats(5)["seq"] == 3


def test_12_audit_shapes_and_leak_ban_and_bad_kind():
    st = Standards()
    st.adopt("a", "nist-ai-rmf", 1, title="top secret memo text")
    st.verify("a", 2, requirements=("super-secret-req",), met=("super-secret-req",))
    log = st.audit_log(3)
    for ev in log:
        assert ev["schema"] == "audit.ndjson/1"
        assert ev["module"] == "standards"
        assert ev["kind"] in AUDIT_KINDS
        assert ev["digest"].startswith("sha256:")
        detail_str = str(ev["detail"])
        assert "top secret memo text" not in detail_str
        assert "super-secret-req" not in detail_str
    with pytest.raises(AuditKindError):
        standards_audit_event("nope", 4)
    with pytest.raises(AuditKindError):
        standards_audit_event("standard-adopted", 4, title="raw text leaked")


def test_13_cross_instance_digest_determinism():
    def build():
        st = Standards()
        st.adopt("x", "iso-27001", 1, title="memo")
        v = st.verify("x", 2, requirements=("r1", "r2"), met=("r1", "r2"))
        st.certify("x", 3)
        return st, v

    st1, v1 = build()
    st2, v2 = build()
    assert st1.adoption_record("x", 4).digest == st2.adoption_record("x", 4).digest
    assert v1.digest == v2.digest
    assert st1.certification("x", 4).digest == st2.certification("x", 4).digest
    # tamper breaks verify
    tampered = dataclasses.replace(v1, verdict="non-conformant")
    assert tampered.verify() is False


def test_14_frozen_records_and_views():
    st = Standards()
    rec = st.adopt("a", "soc2", 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.framework = "hacked"  # frozen record
    with pytest.raises(UnknownStandardError):
        st.adoption_record("nope", 2)
    with pytest.raises(UnknownStandardError):
        st.verifications_for("nope", 2)
    assert st.certification("a", 2) is None


def test_15_main_subprocess_check():
    proc = subprocess.run(
        [sys.executable, str(COMP / "standards.py")],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "standards OK: adopt, verify, certify, retire, refusals" in proc.stdout
