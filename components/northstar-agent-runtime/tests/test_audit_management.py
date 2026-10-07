"""Tests for audit_management.py: plan/execute/followup decision ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "audit_management.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_management", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_management"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


am = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32
BAD_DIGESTS = ["sha256:xyz", "ab" * 32, "sha256:" + "zz" * 32, "SHA256:" + "ab" * 32, None, 123]


def _fresh():
    return am.AuditManagement()


# 1 -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert am.AUDIT_MANAGEMENT_VERSION == "audit-management.v1"
    assert am.AUDIT_MANAGEMENT_SCHEMA == "northstar.audit-management.v1"
    assert am.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(am.STANDARDS) == {
        "soc2-type1", "soc2-type2", "iso27001", "pci-dss", "hipaa", "internal", "vendor",
    }
    assert set(am.OUTCOMES) == {"clean", "findings", "opportunity", "qualified"}
    assert set(am.ACTIONS) == {"remediated", "accepted-risk", "escalated", "re-audited", "deferred"}


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


# 3 -- plan roundtrip + verify --------------------------------------------


def test_plan_roundtrip_and_verify():
    m = _fresh()
    plan = m.plan("aud-1", 1, standard="soc2-type2", scope_digest=DIGEST,
                 auditee_digest=DIGEST, period_digest=DIGEST)
    assert plan.verify()
    assert plan.audit_id == "aud-1" and plan.standard == "soc2-type2"
    d = plan.as_dict()
    assert d["schema"] == "northstar.audit-management.v1"
    assert d["version"] == "audit-management.v1"
    assert m.plan_record("aud-1", 2) is plan
    assert m.audit_ids(3) == ("aud-1",)
    assert m.pending_ids(4) == ("aud-1",)


# 4 -- plan duplicate + bad inputs burn seq and book rejected rows ---------


def test_plan_duplicate_and_bad_inputs():
    m = _fresh()
    m.plan("aud-1", 1)
    seq = 1
    rejected = 0
    seq += 1
    with pytest.raises(am.DuplicateAuditError):
        m.plan("aud-1", seq)
    rejected += 1
    for bad_id in ["", "  ", "has space", 123, None]:
        seq += 1
        with pytest.raises(am.BadIdError):
            m.plan(bad_id, seq)
        rejected += 1
    for bad_std in ["sox", "", None, 123]:
        seq += 1
        with pytest.raises(am.BadStandardError):
            m.plan(f"aud-x-{seq}", seq, standard=bad_std)
        rejected += 1
    for bad_dig in BAD_DIGESTS:
        seq += 1
        with pytest.raises(am.BadDigestError):
            m.plan(f"aud-y-{seq}", seq, scope_digest=bad_dig)
        rejected += 1
    assert m.stats(seq)["rejected_rows"] == rejected


# 5 -- execute roundtrip ---------------------------------------------------


def test_execute_roundtrip():
    m = _fresh()
    m.plan("aud-1", 1)
    exe = m.execute("aud-1", 2, "findings", evidence_digest=DIGEST)
    assert exe.verify()
    assert exe.execution_id == "exe-1"
    assert exe.audit_id == "aud-1" and exe.outcome == "findings"
    assert m.execution_record("aud-1", 3) is exe
    assert m.executed_ids(4) == ("aud-1",)
    assert m.pending_ids(5) == ()
    assert m.open_findings_ids(6) == ("aud-1",)  # no followup yet


# 6 -- execute refusals ----------------------------------------------------


def test_execute_refusals():
    m = _fresh()
    m.plan("aud-1", 1)
    seq = 1
    rejected = 0
    seq += 1
    with pytest.raises(am.UnknownAuditError):
        m.execute("nope", seq, "clean")
    rejected += 1
    seq += 1
    m.execute("aud-1", seq, "clean")
    seq += 1
    with pytest.raises(am.AlreadyExecutedError):
        m.execute("aud-1", seq, "clean")
    rejected += 1
    seq += 1
    m.plan("aud-2", seq)
    for bad_out in ["pass", "", None, 123]:
        seq += 1
        with pytest.raises(am.BadOutcomeError):
            m.execute("aud-2", seq, bad_out)
        rejected += 1
    for bad_dig in BAD_DIGESTS:
        seq += 1
        with pytest.raises(am.BadDigestError):
            m.execute("aud-2", seq, "clean", evidence_digest=bad_dig)
        rejected += 1
    assert m.stats(seq)["rejected_rows"] == rejected


# 7 -- all standard and outcome vocabularies -------------------------------


def test_vocabularies_accepted():
    m = _fresh()
    seq = 0
    for i, std in enumerate(am.STANDARDS):
        seq += 1
        plan = m.plan(f"aud-{i}", seq, standard=std)
        assert plan.verify()
        seq += 1
        exe = m.execute(f"aud-{i}", seq, am.OUTCOMES[i % len(am.OUTCOMES)])
        assert exe.verify()


# 8 -- followup chain ------------------------------------------------------


def test_followup_chain():
    m = _fresh()
    m.plan("aud-1", 1)
    m.execute("aud-1", 2, "findings")
    f1 = m.followup("aud-1", 3, "remediated", action_digest=DIGEST)
    assert f1.verify() and f1.followup_id == "fup-1"
    f2 = m.followup("aud-1", 4, "re-audited")
    assert f2.verify() and f2.followup_id == "fup-2"
    for act in am.ACTIONS:
        f = m.followup("aud-1", 5 + list(am.ACTIONS).index(act), act)
        assert f.verify()
    chain = m.followups_for("aud-1", 20)
    assert [r.followup_id for r in chain] == ["fup-1", "fup-2", "fup-3", "fup-4", "fup-5", "fup-6", "fup-7"]
    assert [r.action for r in chain] == ["remediated", "re-audited"] + list(am.ACTIONS)
    assert m.followup_record("fup-1", 21) is f1
    assert m.open_findings_ids(22) == ()  # followups now booked


# 9 -- followup refusals ---------------------------------------------------


def test_followup_refusals():
    m = _fresh()
    m.plan("aud-1", 1)
    seq = 1
    rejected = 0
    seq += 1
    with pytest.raises(am.UnknownAuditError):
        m.followup("nope", seq, "remediated")
    rejected += 1
    seq += 1
    with pytest.raises(am.NotExecutedError):
        m.followup("aud-1", seq, "remediated")
    rejected += 1
    m.execute("aud-1", 4, "clean")
    seq = 4
    for bad_act in ["fixed", "", None, 123]:
        seq += 1
        with pytest.raises(am.BadActionError):
            m.followup("aud-1", seq, bad_act)
        rejected += 1
    for bad_dig in BAD_DIGESTS:
        seq += 1
        with pytest.raises(am.BadDigestError):
            m.followup("aud-1", seq, "remediated", action_digest=bad_dig)
        rejected += 1
    assert m.stats(seq)["rejected_rows"] == rejected


# 10 -- seq discipline -----------------------------------------------------


def test_seq_discipline():
    m = _fresh()
    m.plan("aud-1", 1)
    before = m.stats(2)["rejected_rows"]
    with pytest.raises(am.SeqOrderError):
        m.plan("aud-2", 1)  # rewind: raises bare, burns nothing
    with pytest.raises(am.SeqOrderError):
        m.execute("aud-1", 1, "clean")  # rewind: raises bare, burns nothing
    assert m.stats(2)["rejected_rows"] == before  # no rejected rows on bare rewinds
    assert m.pending_ids(2) == ("aud-1",)  # seq still 1-consistency
    for bad in [0, -1, "2", 2.0, True, None]:
        with pytest.raises(am.SeqOrderError):
            m.plan("aud-2", bad)
    # failed mutation consumes its seq
    with pytest.raises(am.BadIdError):
        m.plan("", 5)
    with pytest.raises(am.SeqOrderError):
        m.plan("aud-2", 5)  # 5 already burned
    m.plan("aud-2", 6)
    assert m.audit_ids(7) == ("aud-1", "aud-2")


# 11 -- read purity --------------------------------------------------------


def test_view_read_purity():
    m = _fresh()
    m.plan("aud-1", 1)
    m.execute("aud-1", 2, "clean")
    m.followup("aud-1", 3, "deferred")
    n_before = len(m.audit_log(4))
    assert m.status("aud-1", 5) is not None
    assert m.status("aud-1", 5) == m.status("aud-1", 5)
    assert m.plan_record("aud-1", 5) is not None
    assert m.audit_ids(5) == ("aud-1",)
    assert len(m.audit_log(5)) == n_before  # reads wrote no audit rows
    st = m.status("aud-1", 5)
    assert st.verify() and st.integrity_ok
    assert st.outcome == "clean" and st.followups == 1 and st.last_action == "deferred"
    with pytest.raises(am.UnknownAuditError):
        m.status("nope", 6)


# 12 -- audit shapes, leak ban, bad kind ------------------------------------


def test_audit_shapes_and_leak_ban():
    m = _fresh()
    m.plan("aud-1", 1, scope_digest=DIGEST)
    m.execute("aud-1", 2, "findings")
    m.followup("aud-1", 3, "escalated")
    kinds = [e["kind"] for e in m.audit_log(4)]
    assert kinds == [
        "audit-management.planned",
        "audit-management.executed",
        "audit-management.followed-up",
    ]
    for e in m.audit_log(5):
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "northstar.audit-management.v1"
    with pytest.raises(am.AuditKindError):
        am.audit_management_audit_event("nope", 9)
    for banned in ("report", "finding", "evidence", "content", "text", "payload",
                   "notes", "scope", "plan", "auditee", "secret", "raw", "private",
                   "transcript", "period"):
        with pytest.raises(am.AuditKindError):
            am.audit_management_audit_event("audit-management.planned", 9, **{banned: "x"})
    ev = am.audit_management_audit_event("audit-management.planned", 9, audit_id="aud-1", standard="vendor")
    assert ev["detail"]["audit_id"] == "aud-1"


# 13 -- cross-instance determinism and tamper --------------------------------


def test_digest_determinism_and_tamper():
    m1, m2 = _fresh(), _fresh()
    p1 = m1.plan("aud-1", 1, standard="iso27001", scope_digest=DIGEST)
    p2 = m2.plan("aud-1", 1, standard="iso27001", scope_digest=DIGEST)
    assert p1.digest == p2.digest
    e1 = m1.execute("aud-1", 2, "findings", evidence_digest=DIGEST2)
    e2 = m2.execute("aud-1", 2, "findings", evidence_digest=DIGEST2)
    assert e1.digest == e2.digest
    f1 = m1.followup("aud-1", 3, "accepted-risk")
    f2 = m2.followup("aud-1", 3, "accepted-risk")
    assert f1.digest == f2.digest
    import dataclasses

    object.__setattr__(p1, "standard", "vendor")
    assert not p1.verify()
    st = m1.status("aud-1", 4)
    assert not st.integrity_ok
    st2 = m2.status("aud-1", 4)
    assert st2.integrity_ok


# 14 -- stats, frozen-ness, concurrency smoke --------------------------------


def test_stats_frozen_concurrency():
    m = _fresh()
    m.plan("aud-1", 1)
    m.plan("aud-2", 2, standard="vendor")
    m.execute("aud-1", 3, "findings")
    m.followup("aud-1", 4, "remediated")
    stats = m.stats(5)
    assert stats["planned"] == 2 and stats["executed"] == 1 and stats["followups"] == 1
    assert stats["pending"] == 1 and stats["open_findings"] == 0
    assert stats["outcomes"]["findings"] == 1
    assert stats["actions"]["remediated"] == 1
    plan = m.plan_record("aud-1", 6)
    with pytest.raises(Exception):
        plan.standard = "vendor"  # frozen
    errs = []
    def reader():
        try:
            for _ in range(200):
                m.status("aud-1", 6)
                m.audit_ids(6)
        except Exception as e:  # pragma: no cover
            errs.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15 -- main() self-check ----------------------------------------------------


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "audit-management OK: plan, execute, followup, status, pins, audit" in proc.stdout
