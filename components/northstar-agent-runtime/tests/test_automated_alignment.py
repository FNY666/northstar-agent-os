"""15 tests for automated_alignment.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "automated_alignment.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "automated_alignment", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["automated_alignment"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


aa_mod = _load()

PIN = "sha256:" + "a" * 64
PIN2 = "sha256:" + "b" * 64


def _aa():
    return aa_mod.AutomatedAlignment()


# 1. version/schema pins + vocabularies
def test_pins():
    assert aa_mod.AUTOMATED_ALIGNMENT_VERSION == "automated-alignment.v1"
    assert aa_mod.SCHEMA_PIN == "northstar.automated-alignment.v1"
    assert set(aa_mod.TASK_KINDS) == {
        "oversight", "red-teaming", "eval-generation",
        "interpretability", "monitoring", "reward-modeling",
    }
    assert set(aa_mod.EXECUTION_OUTCOMES) == {
        "aligned", "misaligned", "inconclusive", "not-run",
    }
    assert set(aa_mod.VERIFICATION_VERDICTS) == {
        "verified", "unverified", "refuted", "inconclusive",
    }
    assert set(aa_mod.POSTURES) == {
        "untasked", "misalignment-detected", "suspect",
        "inconclusive", "aligned",
    }


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json", "ast", "pathlib",
    }
    assert imports <= allowed, imports - allowed
    assert aa_mod.AutomatedAlignment.stdlib_only()


# 3. automate roundtrip + verify + frozen-ness
def test_automate_roundtrip():
    a = _aa()
    t = a.automate("sys-1", 1, task_kind="oversight", task_digest=PIN)
    assert t.task_id == "tsk-1"
    assert t.system_id == "sys-1"
    assert t.verify()
    assert t.as_dict()["schema"] == "northstar.automated-alignment.v1"
    with pytest.raises(Exception):
        t.task_kind = "monitoring"  # frozen
    got = a.task_record("tsk-1", 2)
    assert got.verify()
    with pytest.raises(aa_mod.UnknownRecordError):
        a.task_record("tsk-99", 2)


# 4. automate bad inputs + seq-burn + rejected rows
def test_automate_bad_inputs():
    a = _aa()
    seq = 0
    bad = [
        (lambda q: a.automate("", q), aa_mod.BadIdError),
        (lambda q: a.automate("s", q, task_kind="vibes"), aa_mod.BadKindError),
        (lambda q: a.automate("s", q, task_digest="raw-bytes"),
         aa_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert a.stats(seq + 1)["rejected"] == len(bad)
    assert len(a.audit_log(seq + 1)) == len(bad)


# 5. all task kinds acceptance
def test_all_task_kinds():
    a = _aa()
    seq = 0
    for kind in aa_mod.TASK_KINDS:
        seq += 1
        t = a.automate(f"sys-k-{kind}", seq, task_kind=kind)
        assert t.verify()
    assert a.stats(seq + 1)["tasks"] == len(aa_mod.TASK_KINDS)


# 6. execute roundtrip + minted ids + unknown task
def test_execute_roundtrip():
    a = _aa()
    a.automate("sys-1", 1, task_kind="red-teaming")
    e = a.execute("tsk-1", 2, outcome="misaligned", execution_digest=PIN)
    assert e.execution_id == "exe-1"
    assert e.task_id == "tsk-1"
    assert e.system_id == "sys-1"
    assert e.verify()
    got = a.execution_record("exe-1", 3)
    assert got.verify()
    with pytest.raises(aa_mod.UnknownRecordError):
        a.execute("tsk-99", 3)


# 7. execute bad inputs + all outcomes
def test_execute_bad_inputs_and_outcomes():
    a = _aa()
    a.automate("sys-1", 1)
    seq = 1
    bad = [
        (lambda q: a.execute("tsk-1", q, outcome="vibes"),
         aa_mod.BadOutcomeError),
        (lambda q: a.execute("tsk-1", q, execution_digest="md5:abc"),
         aa_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    for outcome in aa_mod.EXECUTION_OUTCOMES:
        seq += 1
        e = a.execute("tsk-1", seq, outcome=outcome)
        assert e.verify()
    assert a.stats(seq + 1)["executions"] == len(aa_mod.EXECUTION_OUTCOMES)


# 8. verify roundtrip + minted ids + duplicate
def test_verify_roundtrip():
    a = _aa()
    a.automate("sys-1", 1)
    a.execute("tsk-1", 2, outcome="aligned")
    v = a.verify("exe-1", 3, verdict="verified", verification_digest=PIN2)
    assert v.verification_id == "vfy-1"
    assert v.execution_id == "exe-1"
    assert v.verify()
    with pytest.raises(aa_mod.DuplicateExecutionError):
        a.verify("exe-1", 4)
    with pytest.raises(aa_mod.UnknownRecordError):
        a.verify("exe-99", 5)


# 9. verify bad inputs + all verdicts
def test_verify_bad_inputs_and_verdicts():
    a = _aa()
    a.automate("sys-1", 1)
    seq = 1
    for verdict in aa_mod.VERIFICATION_VERDICTS:
        seq += 1
        e = a.execute("tsk-1", seq, outcome="aligned")
        seq += 1
        v = a.verify(e.execution_id, seq, verdict=verdict)
        assert v.verify()
    seq += 1
    e2 = a.execute("tsk-1", seq, outcome="aligned")
    with pytest.raises(aa_mod.BadVerdictError):
        a.verify(e2.execution_id, seq + 1, verdict="vibes")
    assert a.stats(seq + 2)["rejected"] == 1


# 10. retire terminality + post-retire mutations refused
def test_retire_terminality():
    a = _aa()
    a.automate("sys-1", 1)
    r = a.retire("sys-1", 2, reason="completed")
    assert r.verify()
    assert r.system_id == "sys-1"
    assert a.retired_ids(3) == ("sys-1",)
    with pytest.raises(aa_mod.RetiredSystemError):
        a.automate("sys-1", 3)
    with pytest.raises(aa_mod.RetiredSystemError):
        a.retire("sys-1", 4)
    # reads still work
    assert a.task_record("tsk-1", 4).verify()
    assert a.report(5, "sys-1").verify()
    with pytest.raises(aa_mod.BadReasonError):
        a.retire("sys-2", 5, reason="vibes")


# 11. report posture math + scoping + unknown system
def test_report_posture_math():
    a = _aa()
    rep = a.report(1)
    assert rep.posture == "untasked" and rep.verify()
    # aligned path: all aligned + verified
    a.automate("sys-a", 2, task_kind="monitoring")
    a.execute("tsk-1", 3, outcome="aligned")
    a.verify("exe-1", 4, verdict="verified")
    assert a.report(5, "sys-a").posture == "aligned"
    # misalignment-detected path
    a.automate("sys-m", 6, task_kind="oversight")
    a.execute("tsk-2", 7, outcome="misaligned")
    assert a.report(8, "sys-m").posture == "misalignment-detected"
    # suspect path: refuted verification
    a.automate("sys-s", 9)
    a.execute("tsk-3", 10, outcome="aligned")
    a.verify("exe-3", 11, verdict="refuted")
    assert a.report(12, "sys-s").posture == "suspect"
    # inconclusive path: unverified verdict
    a.automate("sys-i", 13)
    a.execute("tsk-4", 14, outcome="aligned")
    a.verify("exe-4", 15, verdict="unverified")
    assert a.report(16, "sys-i").posture == "inconclusive"
    # refuted clears a misaligned signal (declared, never proof)
    a.verify("exe-2", 17, verdict="refuted")
    assert a.report(18, "sys-m").posture == "suspect"
    # whole-ledger aggregation + unknown system refusal
    whole = a.report(19)
    assert whole.n_systems == 4 and whole.n_tasks == 4
    with pytest.raises(aa_mod.UnknownSystemError):
        a.report(20, "ghost")


# 12. view read-purity + stats
def test_view_read_purity_and_stats():
    a = _aa()
    a.automate("sys-1", 1)
    a.execute("tsk-1", 2, outcome="aligned")
    a.verify("exe-1", 3, verdict="verified")
    n_audit = len(a.audit_log(4))
    r1 = a.report(4, "sys-1")
    r2 = a.report(4, "sys-1")
    assert r1.verify() and r2.verify()
    assert len(a.audit_log(4)) == n_audit  # reads add no rows
    assert a.tasks_for("sys-1", 4) == ("tsk-1",)
    assert a.executions_for("sys-1", 4) == ("exe-1",)
    assert a.verifications_for("sys-1", 4) == ("vfy-1",)
    assert a.system_ids(4) == ("sys-1",)
    st = a.stats(4)
    assert st["tasks"] == 1 and st["executions"] == 1
    assert st["verifications"] == 1 and st["rejected"] == 0


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    a = _aa()
    a.automate("s1", 5)
    with pytest.raises(aa_mod.SeqOrderError):
        a.automate("s2", 5)  # rewind: bare
    assert a.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(aa_mod.SeqOrderError):
            a.automate("s2", bad)
    with pytest.raises(aa_mod.BadKindError):
        a.automate("s2", 7, task_kind="vibes")  # consumes seq 7
    with pytest.raises(aa_mod.SeqOrderError):
        a.automate("s3", 7)  # seq 7 burned
    a.automate("s3", 8)
    assert a.stats(9)["rejected"] == 1


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    a = _aa()
    a.automate("s1", 1, task_kind="eval-generation")
    a.execute("tsk-1", 2, outcome="aligned")
    a.verify("exe-1", 3, verdict="verified")
    a.retire("s1", 4, reason="manual")
    rows = a.audit_log(5)
    assert [r["kind"] for r in rows] == [
        "automated-alignment.tasked", "automated-alignment.executed",
        "automated-alignment.verified", "automated-alignment.retired",
    ]
    for row in rows:
        for key in row["details"]:
            assert key not in aa_mod._BANNED_AUDIT_KEYS
    with pytest.raises(aa_mod.AuditKindError):
        aa_mod.automated_alignment_audit_event(
            "tasked", {"transcript": "x"})
    with pytest.raises(aa_mod.AuditKindError):
        aa_mod.automated_alignment_audit_event("bogus-kind", {})
    with pytest.raises(aa_mod.AuditKindError):
        aa_mod.automated_alignment_audit_event("tasked", "not-a-dict")


# 15. main() subprocess check + cross-instance determinism + tamper
def test_main_and_determinism():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True, text=True,
        cwd=str(MOD_PATH.parent), timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "automated-alignment OK: automate, execute, verify, report, pins, audit"
    )

    def build():
        a = _aa()
        a.automate("s1", 1, task_kind="oversight", task_digest=PIN)
        a.execute("tsk-1", 2, outcome="aligned")
        a.verify("exe-1", 3, verdict="verified")
        return a

    a1, a2 = build(), build()
    assert (a1.execution_record("exe-1", 4).digest ==
            a2.execution_record("exe-1", 4).digest)
    rec = a1.execution_record("exe-1", 4)
    assert rec.verify()
    import dataclasses
    tampered = dataclasses.replace(rec, outcome="misaligned")
    assert tampered.verify() is False
    assert a1.report(5, "s1").integrity_ok is True
    object.__setattr__(rec, "outcome", "misaligned")
    assert rec.verify() is False
    assert a1.report(5, "s1").integrity_ok is False

    # 8-thread read smoke + frozen-ness
    a = _aa()
    for i in range(10):
        a.automate(f"s{i}", i * 3 + 1)
    results = []

    def worker():
        results.append(a.system_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    trec = a.task_record("tsk-1", 100)
    with pytest.raises(Exception):
        trec.task_kind = "monitoring"  # frozen
