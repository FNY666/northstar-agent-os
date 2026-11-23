"""Tests for ai_recourse.py: 15 tests, house style."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ai_recourse as ar

D = "sha256:" + "ab" * 32


def _mod():
    return ar.AIRecourse()


# 1. version / schema / vocabulary pins -------------------------------------

def test_pins_and_vocabulary():
    assert ar.AI_RECOURSE_VERSION == "ai-recourse.v1"
    assert ar.AI_RECOURSE_SCHEMA == "northstar.ai-recourse.v1"
    assert ar.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(ar.RECOURSE_KINDS) == 8
    assert len(ar.OUTCOMES) == 4
    assert len(ar.RETIRE_REASONS) == 3
    assert ar.KIND_PROVIDED == "provided"
    assert ar.KIND_RETIRED == "retired"
    assert ar.KIND_REJECTED == "rejected"
    # version/schema pins on every record class
    m = _mod()
    rec = m.provide("sys-1", 1)
    assert rec.version == "ai-recourse.v1"
    assert rec.schema == "northstar.ai-recourse.v1"
    rep = m.verify("rcs-1", 2)
    assert rep.version == "ai-recourse.v1"
    evl = m.evaluate("sys-1", 3)
    assert evl.schema == "northstar.ai-recourse.v1"
    ret = m.retire("sys-1", 4)
    assert ret.version == "ai-recourse.v1"


# 2. stdlib-only AST check ---------------------------------------------------

def test_stdlib_only_ast():
    assert ar.stdlib_only()
    tree = ast.parse(Path(ar.__file__).read_text())
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in stdlib or \
                node.module.split(".")[0] == "canonical_json"


# 3. provide roundtrip / verify() / frozen-ness -------------------------------

def test_provide_roundtrip_verify_frozen():
    m = _mod()
    rec = m.provide("sys-1", 1,
                    recourse_kind=ar.RECOURSE_APPEAL,
                    outcome=ar.OUTCOME_RESOLVED,
                    recourse_digest=D)
    assert rec.recourse_id == "rcs-1"
    assert rec.system_id == "sys-1"
    assert rec.recourse_kind == ar.RECOURSE_APPEAL
    assert rec.outcome == ar.OUTCOME_RESOLVED
    assert rec.recourse_digest == D
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = ar.OUTCOME_DENIED  # type: ignore[misc]
    # defaults
    rec2 = m.provide("sys-2", 2)
    assert rec2.recourse_id == "rcs-2"
    assert rec2.recourse_kind == ar.RECOURSE_EXPLANATION
    assert rec2.outcome == ar.OUTCOME_NOT_REQUESTED
    assert rec2.recourse_digest == ""
    assert rec2.verify()


# 4. provide bad-input table + seq-burn + rejected-row accounting ------------

def test_provide_bad_input_seq_burn():
    m = _mod()
    bad_calls = [
        lambda s: m.provide("", s),                                   # bad id
        lambda s: m.provide("has space", s),                          # bad id
        lambda s: m.provide("sys", s, recourse_kind="bogus"),         # bad kind
        lambda s: m.provide("sys", s, outcome="bogus"),               # bad outcome
        lambda s: m.provide("sys", s, recourse_digest="not-a-digest"),  # bad digest
        lambda s: m.provide("sys", s, recourse_digest="sha256:zzz"),  # bad digest hex
        lambda s: m.provide("x" * 300, s),                            # id too long
    ]
    seq = 1
    for call in bad_calls:
        with pytest.raises(ar.AIRecourseError):
            call(seq)
        seq += 1
    # each failed mutation consumed its seq and booked a rejected row
    log = m.audit_log(999)
    rejected = [e for e in log if e["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert m.stats(999)["seq"] == len(bad_calls)
    # next good call needs a strictly larger seq
    rec = m.provide("sys-ok", seq)
    assert rec.recourse_id == "rcs-1"
    assert rec.verify()


# 5. full 8-kind recourse vocabulary ------------------------------------------

def test_full_recourse_kind_vocabulary():
    m = _mod()
    for i, kind in enumerate(ar.RECOURSE_KINDS):
        rec = m.provide(f"sys-{i}", i + 1, recourse_kind=kind)
        assert rec.recourse_kind == kind
        assert rec.verify()
    assert m.stats(999)["recourses"] == 8


# 6. full 4-outcome vocabulary ------------------------------------------------

def test_full_outcome_vocabulary():
    m = _mod()
    for i, outcome in enumerate(ar.OUTCOMES):
        rec = m.provide(f"sys-{i}", i + 1, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()


# 7. retired-system refusal + reads-still-work --------------------------------

def test_retired_system_refusal():
    m = _mod()
    m.provide("sys-1", 1)
    m.retire("sys-1", 2)
    with pytest.raises(ar.RetiredSystemError):
        m.provide("sys-1", 3)
    # retired id never recycled; reads still work
    rec = m.recourse_record("rcs-1", 4)
    assert rec.verify()
    assert m.recourses_for("sys-1", 5) == ("rcs-1",)
    rep = m.evaluate("sys-1", 6)
    assert rep.verify()


# 8. verify semantics: tamper-as-data + unknown + read purity -----------------

def test_verify_semantics_tamper():
    m = _mod()
    m.provide("sys-1", 1, recourse_kind=ar.RECOURSE_HUMAN_REVIEW,
              outcome=ar.OUTCOME_PENDING)
    rep = m.verify("rcs-1", 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    # read purity: same seq twice, no audit rows, no seq consumption
    before = m.audit_log(999)
    rep2 = m.verify("rcs-1", 2)
    assert rep2.digest == rep.digest
    assert m.audit_log(999) == before
    assert m.stats(999)["seq"] == 1
    # tamper as data: mutate via object.__setattr__ on the stored record
    stored = m._recourses["rcs-1"]
    object.__setattr__(stored, "outcome", ar.OUTCOME_RESOLVED)
    tampered = m.verify("rcs-1", 3)
    assert tampered.verdict == "tampered"
    assert not tampered.integrity_ok
    assert tampered.verify()
    # unknown recourse refuses
    with pytest.raises(ar.UnknownRecourseError):
        m.verify("rcs-999", 4)


# 9. evaluate posture math (all 4 reachable postures + precedence) ------------

def test_evaluate_posture_math():
    m = _mod()
    # denied outranks everything
    m.provide("s-den", 1, outcome=ar.OUTCOME_RESOLVED)
    m.provide("s-den", 2, outcome=ar.OUTCOME_DENIED)
    m.provide("s-den", 3, outcome=ar.OUTCOME_PENDING)
    assert m.evaluate("s-den", 4).posture == "denied-open"
    # pending outranks not-requested/resolved
    m.provide("s-pen", 5, outcome=ar.OUTCOME_NOT_REQUESTED)
    m.provide("s-pen", 6, outcome=ar.OUTCOME_PENDING)
    m.provide("s-pen", 7, outcome=ar.OUTCOME_RESOLVED)
    assert m.evaluate("s-pen", 8).posture == "pending-open"
    # not-requested -> unrequested
    m.provide("s-unr", 9, outcome=ar.OUTCOME_NOT_REQUESTED)
    rep = m.evaluate("s-unr", 10)
    assert rep.posture == "unrequested"
    assert rep.not_requested_count == 1
    # all resolved -> resolved
    m.provide("s-res", 11, outcome=ar.OUTCOME_RESOLVED)
    m.provide("s-res", 12, recourse_kind=ar.RECOURSE_ROLLBACK,
              outcome=ar.OUTCOME_RESOLVED)
    rep2 = m.evaluate("s-res", 13)
    assert rep2.posture == "resolved"
    assert rep2.resolved_count == 2
    assert rep2.recourse_count == 2
    assert rep2.integrity_ok
    assert rep2.verify()
    # unknown system refuses
    with pytest.raises(ar.UnknownSystemError):
        m.evaluate("no-such", 14)


# 10. evaluate read purity + tamper flips integrity_ok as data -----------------

def test_evaluate_read_purity_integrity_flip():
    m = _mod()
    m.provide("sys-1", 1, outcome=ar.OUTCOME_RESOLVED)
    before = m.audit_log(999)
    r1 = m.evaluate("sys-1", 5)
    r2 = m.evaluate("sys-1", 5)
    assert r1.digest == r2.digest
    assert m.audit_log(999) == before
    assert m.stats(999)["seq"] == 1
    # tamper flips integrity_ok as data, never raises
    stored = m._recourses["rcs-1"]
    object.__setattr__(stored, "recourse_kind", ar.RECOURSE_DELETION)
    r3 = m.evaluate("sys-1", 6)
    assert not r3.integrity_ok
    assert r3.posture == "resolved"  # posture still derives from booked data
    assert r3.verify()


# 11. retire terminality: bad reason / double-retire / unknown -----------------

def test_retire_terminality():
    m = _mod()
    m.provide("sys-1", 1)
    rec = m.retire("sys-1", 2)
    assert rec.verify()
    # double retire refuses
    with pytest.raises(ar.RetiredSystemError):
        m.retire("sys-1", 3)
    # retire unknown system refuses
    with pytest.raises(ar.UnknownSystemError):
        m.retire("no-such", 4)
    # bad reason burns seq
    m.provide("sys-2", 5)
    with pytest.raises(ar.BadReasonError):
        m.retire("sys-2", 6, reason="bogus")
    log = m.audit_log(999)
    assert [e for e in log if e["kind"] == "rejected"]
    # all pinned reasons accepted
    for i, reason in enumerate(ar.RETIRE_REASONS):
        m.provide(f"sys-r{i}", 7 + i * 2)
        rec = m.retire(f"sys-r{i}", 8 + i * 2, reason=reason)
        assert rec.reason == reason
        assert rec.verify()
    assert m.retired_ids(999) == ("sys-1", "sys-r0", "sys-r1", "sys-r2")


# 12. seq discipline: rewind bare / malformed / failed-mutation-consumes --------

def test_seq_discipline():
    m = _mod()
    # rewind on genesis raises bare, no rows booked
    with pytest.raises(ar.SeqOrderError):
        m.provide("sys-1", -1)  # malformed (negative)
    assert m.audit_log(999) == ()
    m.provide("sys-1", 1)
    # rewind raises bare without consuming
    with pytest.raises(ar.SeqOrderError):
        m.provide("sys-2", 1)
    assert m.audit_log(999) != ()  # only the provided row
    assert len([e for e in m.audit_log(999) if e["kind"] == "rejected"]) == 0
    assert m.stats(999)["seq"] == 1
    # malformed seqs (bool / float / str / None) raise bare
    for bad in (True, 1.5, "2", None):
        with pytest.raises(ar.SeqOrderError):
            m.provide("sys-2", bad)
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(ar.BadOutcomeError):
        m.provide("sys-2", 2, outcome="bogus")
    assert m.stats(999)["seq"] == 2
    assert len([e for e in m.audit_log(999) if e["kind"] == "rejected"]) == 1
    # next good call needs seq 3
    rec = m.provide("sys-2", 3)
    assert rec.recourse_id == "rcs-2"


# 13. audit shapes + banned-key leak ban + bad-kind -----------------------------

def test_audit_shapes_and_leak_ban():
    m = _mod()
    m.provide("sys-1", 1, recourse_kind=ar.RECOURSE_CORRECTION,
              outcome=ar.OUTCOME_PENDING)
    m.retire("sys-1", 2)
    log = m.audit_log(3)
    kinds = [e["kind"] for e in log]
    assert kinds == ["provided", "retired"]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["version"] == "ai-recourse.v1"
    provided = log[0]
    assert provided["detail"]["recourse_id"] == "rcs-1"
    assert provided["detail"]["recourse_kind"] == ar.RECOURSE_CORRECTION
    assert provided["detail"]["outcome"] == ar.OUTCOME_PENDING
    # banned raw-material keys are rejected at the builder level
    with pytest.raises(ar.AuditKindError):
        ar.ai_recourse_audit_event("provided", 4, case_file="raw-bytes")
    with pytest.raises(ar.AuditKindError):
        ar.ai_recourse_audit_event("provided", 4, complaint_text="hi")
    # bad audit kind
    with pytest.raises(ar.AuditKindError):
        ar.ai_recourse_audit_event("bogus", 4)


# 14. views/stats + cross-instance digest determinism ---------------------------

def test_views_stats_and_digest_determinism():
    m = _mod()
    rec = m.provide("sys-1", 1)
    assert m.recourse_record("rcs-1", 2) is rec
    assert m.recourses_for("sys-1", 3) == ("rcs-1",)
    assert m.system_ids(4) == ("sys-1",)
    assert m.recourse_ids(5) == ("rcs-1",)
    assert m.retired_ids(6) == ()
    stats = m.stats(7)
    assert stats == {"systems": 1, "recourses": 1,
                     "retired": 0, "seq": 1}
    with pytest.raises(ar.UnknownRecourseError):
        m.recourse_record("rcs-999", 8)
    with pytest.raises(ar.UnknownSystemError):
        m.recourses_for("no-such", 9)
    # cross-instance determinism: same inputs -> same digest
    m2 = _mod()
    rec2 = m2.provide("sys-1", 1)
    assert rec2.digest == rec.digest


# 15. main() subprocess check + 8-thread read smoke -----------------------------

def test_main_subprocess_and_thread_smoke():
    proc = subprocess.run(
        [sys.executable, "-m", "ai_recourse"],
        cwd=Path(ar.__file__).resolve().parent,
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "ai-recourse OK" in proc.stdout
    m = _mod()
    m.provide("sys-1", 1, outcome=ar.OUTCOME_RESOLVED)
    errors = []

    def reader():
        try:
            for _ in range(50):
                rep = m.evaluate("sys-1", 5)
                assert rep.posture == "resolved"
                vfy = m.verify("rcs-1", 5)
                assert vfy.verdict == "verified"
                m.stats(5)
                m.audit_log(5)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
