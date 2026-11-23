"""Tests for the scalable-oversight-v2 allocation ledger (Simulated)."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "scalable_oversight_v2.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("scalable_oversight_v2", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["scalable_oversight_v2"] = module
    spec.loader.exec_module(module)
    return module


so = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert so.SCALABLE_OVERSIGHT_V2_VERSION == "scalable-oversight-v2.v1"
    assert so.SCHEMA_PIN == "northstar.scalable-oversight-v2.v1"
    assert so.OVERSIGHT_METHODS == (
        "direct-review",
        "spot-check",
        "debate-adjudication",
        "amplified-check",
        "constitutional-review",
        "automated-screen",
        "human-escalation",
        "committee-review",
    )
    assert so.VERDICTS == (
        "clear",
        "flagged",
        "escalated",
        "blocked",
        "inconclusive",
        "not-assessed",
    )
    assert so.RETIRE_REASONS == (
        "manual",
        "system-superseded",
        "protocol-upgraded",
        "invalidated",
    )
    assert so.POSTURES == (
        "unexamined",
        "blocked-open",
        "at-risk",
        "contested",
        "covered",
    )
    assert so.AUDIT_KINDS == ("supervised", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "ast",
        "pathlib",
    }
    assert imports <= allowed, imports - allowed
    assert so.ScalableOversight.stdlib_only()


# 3. supervise roundtrip / minting / frozen-ness
def test_supervise_roundtrip():
    o = so.ScalableOversight()
    r1 = o.supervise(
        "SYS-1", 1, method="spot-check", verdict="clear", evidence_digest=PIN
    )
    r2 = o.supervise("SYS-1", 2, method="debate-adjudication", verdict="flagged")
    assert r1.supervision_id == "sup-1"
    assert r2.supervision_id == "sup-2"
    assert r1.system_id == "SYS-1" and r2.system_id == "SYS-1"
    assert r1.method == "spot-check" and r2.verdict == "flagged"
    assert r1.evidence_digest == PIN
    assert r1.verify() and r2.verify()
    assert r1.as_dict()["digest"] == r1.digest
    for rec in (r1, r2):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.verdict = "clear"  # type: ignore
    # records are re-fetchable by id
    assert o.supervision_record("sup-1", 0) == r1
    assert o.supervisions_for("SYS-1", 0) == ("sup-1", "sup-2")
    # audit rows are digest-pin only: raw digest hex never crosses the boundary
    for row in o.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        flat = str(row["details"])
        assert "ab" * 32 not in flat


# 4. supervise bad-input table + seq-burn + rejected-row accounting
def test_supervise_bad_inputs():
    o = so.ScalableOversight()
    o.supervise("SYS", 1)
    bad_calls = [
        lambda: o.supervise("", 2),
        lambda: o.supervise(123, 3),  # type: ignore
        lambda: o.supervise("x" * 129, 4),
        lambda: o.supervise("SYS", 5, method="telepathy"),
        lambda: o.supervise("SYS", 6, method=""),
        lambda: o.supervise("SYS", 7, verdict="probably-fine"),
        lambda: o.supervise("SYS", 8, verdict=""),
        lambda: o.supervise("SYS", 9, evidence_digest="not-a-pin"),
        lambda: o.supervise("SYS", 10, evidence_digest="sha256:zz"),
    ]
    for bad in bad_calls:
        with pytest.raises(so.ScalableOversightV2Error):
            bad()
    # each failed mutation burned its seq (2..10) and booked a rejected row
    assert o.stats(0)["rejected"] == len(bad_calls)
    assert o.stats(0)["seq"] == 10
    assert all(row["kind"] == "rejected" for row in o.audit_log(0)[1:])
    # a rewind is bare: raises without consuming, no rejected row
    before = len(o.audit_log(0))
    with pytest.raises(so.SeqOrderError):
        o.supervise("SYS", 10)
    assert len(o.audit_log(0)) == before


# 5. full 8-method vocabulary acceptance
def test_full_method_vocabulary():
    o = so.ScalableOversight()
    for i, method in enumerate(so.OVERSIGHT_METHODS, start=1):
        r = o.supervise("SYS", i, method=method, verdict="clear")
        assert r.method == method and r.verify()
    assert o.stats(0)["supervisions"] == 8


# 6. full 6-verdict vocabulary acceptance
def test_full_verdict_vocabulary():
    o = so.ScalableOversight()
    for i, verdict in enumerate(so.VERDICTS, start=1):
        r = o.supervise("SYS", i, method="direct-review", verdict=verdict)
        assert r.verdict == verdict and r.verify()


# 7. evaluate posture math (all 5 postures + precedence + unknown refusal)
def test_evaluate_posture_math():
    o = so.ScalableOversight()
    o.supervise("COVERED", 1, verdict="clear")
    o.supervise("COVERED", 2, verdict="clear")
    o.supervise("ATRISK", 3, verdict="clear")
    o.supervise("ATRISK", 4, verdict="flagged")
    o.supervise("BLOCKED", 5, verdict="flagged")
    o.supervise("BLOCKED", 6, verdict="blocked")  # blocked outranks at-risk
    o.supervise("CONTESTED", 7, verdict="clear")
    o.supervise("CONTESTED", 8, verdict="inconclusive")
    o.supervise("NA", 9, verdict="not-assessed")  # not-assessed -> contested
    o.supervise("ESCALATED", 10, verdict="escalated")  # escalated -> at-risk
    assert o.evaluate("COVERED", 0).posture == "covered"
    assert o.evaluate("ATRISK", 0).posture == "at-risk"
    assert o.evaluate("BLOCKED", 0).posture == "blocked-open"
    assert o.evaluate("CONTESTED", 0).posture == "contested"
    assert o.evaluate("NA", 0).posture == "contested"
    assert o.evaluate("ESCALATED", 0).posture == "at-risk"
    e = o.evaluate("ATRISK", 0)
    assert e.verify()
    assert e.n_supervisions == 2
    assert dict(e.verdict_tally)["flagged"] == 1
    assert dict(e.verdict_tally)["clear"] == 1
    with pytest.raises(so.UnknownSystemError):
        o.evaluate("NOPE", 0)


# 8. evaluate read purity (same-seq twice, no audit rows, no seq consumption)
def test_evaluate_read_purity():
    o = so.ScalableOversight()
    o.supervise("SYS", 1, verdict="clear")
    rows_before = len(o.audit_log(0))
    e1 = o.evaluate("SYS", 0)
    e2 = o.evaluate("SYS", 0)
    assert e1 == e2 and e1.verify()
    assert len(o.audit_log(0)) == rows_before
    assert o.stats(0)["seq"] == 1  # reads never consume the mutation seq


# 9. verify roundtrip + tamper-as-data + unknown refusal
def test_verify_semantics():
    o = so.ScalableOversight()
    r = o.supervise("SYS", 1, method="automated-screen", verdict="clear")
    v = o.verify("sup-1", 0)
    assert v.verdict == "verified" and v.integrity_ok and v.verify()
    # tamper a frozen record via object.__setattr__: reported, never raised
    object.__setattr__(o._supervisions["sup-1"], "verdict", "blocked")
    v2 = o.verify("sup-1", 0)
    assert v2.verdict == "tampered" and not v2.integrity_ok and v2.verify()
    # tamper flips evaluate's integrity_ok as data, and the posture too
    e = o.evaluate("SYS", 0)
    assert not e.integrity_ok
    with pytest.raises(so.UnknownSupervisionError):
        o.verify("sup-999", 0)


# 10. retire terminality + id non-recycling + post-retire reads + bad reason
def test_retire_terminality():
    o = so.ScalableOversight()
    o.supervise("SYS", 1, verdict="clear")
    rec = o.retire("SYS", 2, reason="protocol-upgraded")
    assert rec.verify()
    assert o.retired_ids(0) == ("SYS",)
    # post-retire mutations refused and burned
    with pytest.raises(so.RetiredSystemError):
        o.supervise("SYS", 3)
    with pytest.raises(so.RetiredSystemError):
        o.retire("SYS", 4)
    # ids never recycled: reads still work
    assert o.evaluate("SYS", 0).posture == "covered"
    assert o.supervision_record("sup-1", 0).system_id == "SYS"
    # bad reason / unknown system
    o.supervise("SYS2", 5)
    with pytest.raises(so.BadReasonError):
        o.retire("SYS2", 6, reason="nope")
    with pytest.raises(so.UnknownSystemError):
        o.retire("GHOST", 7)
    assert o.stats(0)["rejected"] == 4


# 11. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    o = so.ScalableOversight()
    o.supervise("SYS", 1)
    with pytest.raises(so.SeqOrderError):
        o.supervise("SYS", 1)  # rewind: bare, no rejected row
    assert o.stats(0)["rejected"] == 0
    for bad_seq in (True, 1.5, "2", None, -1):
        with pytest.raises(so.SeqOrderError):
            o.supervise("SYS", bad_seq)  # type: ignore
    # failed mutation consumes its seq and books rejected
    with pytest.raises(so.BadMethodError):
        o.supervise("SYS", 2, method="bogus")
    assert o.stats(0)["rejected"] == 1
    assert o.stats(0)["seq"] == 2
    # views reject malformed seqs
    for bad_seq in (True, -1, "x"):
        with pytest.raises(so.SeqOrderError):
            o.evaluate("SYS", bad_seq)  # type: ignore


# 12. audit shapes + leak ban + bad-kind + rejected-row detail
def test_audit_shapes():
    o = so.ScalableOversight()
    o.supervise("SYS", 1, method="spot-check", verdict="clear", evidence_digest=PIN)
    o.retire("SYS", 2)
    # bad verdict on a live system: burns its seq and books rejected
    with pytest.raises(so.BadVerdictError):
        o.supervise("SYS2", 3, verdict="bogus")
    rows = o.audit_log(0)
    assert [r["kind"] for r in rows] == ["supervised", "retired", "rejected"]
    assert rows[0]["details"]["method"] == "spot-check"
    assert rows[2]["details"]["rejected_kind"] == "supervise"
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
    # builder bans raw-material keys
    with pytest.raises(so.AuditKindError):
        so.scalable_oversight_v2_audit_event("supervised", 1, transcript="raw")
    with pytest.raises(so.AuditKindError):
        so.scalable_oversight_v2_audit_event("supervised", 1, evidence="raw")
    # builder rejects bad kind and bad seq
    with pytest.raises(so.AuditKindError):
        so.scalable_oversight_v2_audit_event("audited", 1)
    with pytest.raises(so.SeqOrderError):
        so.scalable_oversight_v2_audit_event("supervised", -1)


# 13. cross-instance digest determinism + integrity flip + views/stats
def test_determinism_and_views():
    a, b = so.ScalableOversight(), so.ScalableOversight()
    ra = a.supervise("SYS", 1, method="committee-review", verdict="clear",
                     evidence_digest=PIN)
    rb = b.supervise("SYS", 1, method="committee-review", verdict="clear",
                     evidence_digest=PIN)
    assert ra.digest == rb.digest
    assert a.evaluate("SYS", 0).digest == b.evaluate("SYS", 0).digest
    assert a.system_ids(0) == ("SYS",)
    assert a.supervision_ids(0) == ("sup-1",)
    assert a.supervisions_for("SYS", 0) == ("sup-1",)
    st = a.stats(0)
    assert st == {"systems": 1, "supervisions": 1, "retired": 0,
                  "rejected": 0, "audit_rows": 1, "seq": 1}
    with pytest.raises(so.UnknownSystemError):
        a.supervisions_for("GHOST", 0)
    with pytest.raises(so.UnknownSupervisionError):
        a.supervision_record("sup-999", 0)


# 14. 8-thread read smoke + frozen-ness
def test_threaded_read_smoke():
    o = so.ScalableOversight()
    o.supervise("SYS", 1, verdict="clear")
    o.supervise("SYS", 2, verdict="flagged")
    errors = []

    def reader(_):
        try:
            for _ in range(50):
                assert o.evaluate("SYS", 0).verify()
                assert o.verify("sup-1", 0).verdict == "verified"
                assert o.supervision_record("sup-2", 0).verdict == "flagged"
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rec = o.supervision_record("sup-1", 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.method = "spot-check"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "scalable-oversight-v2 OK: supervise, evaluate, verify, pins, audit" in proc.stdout
