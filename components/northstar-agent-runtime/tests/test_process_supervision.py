"""Tests for the process-supervision decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "process_supervision.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("process_supervision", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["process_supervision"] = module
    spec.loader.exec_module(module)
    return module


ps = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ps.PROCESS_SUPERVISION_VERSION == "process-supervision.v1"
    assert ps.SCHEMA_PIN == "northstar.process-supervision.v1"
    assert ps.STEP_VERDICTS == (
        "correct",
        "incorrect",
        "uncertain",
        "not-assessed",
    )
    assert ps.VERIFY_VERDICTS == (
        "verified",
        "tampered",
    )
    assert ps.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. supervise roundtrip + verify + frozen-ness
def test_supervise_roundtrip():
    p = ps.ProcessSupervision()
    rec = p.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=PIN)
    assert rec.supervision_id == "sup-1"
    assert rec.system_id == "sys-1"
    assert rec.step_id == "step-1"
    assert rec.verdict == "correct"
    assert rec.step_digest == PIN
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == "northstar.process-supervision.v1"
    with pytest.raises(Exception):
        rec.verdict = "incorrect"  # frozen


# 4. supervise bad-input table + seq-burn + rejected rows
def test_supervise_bad_inputs():
    p = ps.ProcessSupervision()
    seq = 0
    bad = [
        (lambda s: p.supervise("", "step-1", s, step_digest=PIN), ps.BadIdError),
        (lambda s: p.supervise(123, "step-1", s, step_digest=PIN), ps.BadIdError),
        (lambda s: p.supervise("sys-1", "", s, step_digest=PIN), ps.BadIdError),
        (lambda s: p.supervise("sys-1", "step-1", s, step_digest=PIN, verdict="vibes"), ps.BadVerdictError),
        (lambda s: p.supervise("sys-1", "step-1", s, verdict="correct", step_digest="raw"), ps.BadDigestError),
        (lambda s: p.supervise("sys-1", "step-1", s, verdict="correct", step_digest="md5:abc"), ps.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert p.stats(seq + 1)["rejected"] == 6
    # next good seq still books (claim-then-burn, no poisoning)
    rec = p.supervise("sys-1", "step-1", seq + 2, verdict="correct", step_digest=PIN)
    assert rec.supervision_id == "sup-1"
    assert p.stats(seq + 3)["rejected"] == 6


# 5. duplicate (system, step) refused
def test_duplicate_step_refused():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=PIN)
    with pytest.raises(ps.DuplicateStepError):
        p.supervise("sys-1", "step-1", 2, verdict="correct", step_digest=PIN)
    assert p.stats(3)["rejected"] == 1
    # same step id under a different system is fine
    rec = p.supervise("sys-2", "step-1", 3, verdict="correct", step_digest=PIN)
    assert rec.supervision_id == "sup-2"


# 6. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=PIN)
    p.retire("sys-1", 2, reason="decommissioned")
    with pytest.raises(ps.RetiredSystemError):
        p.retire("sys-1", 3, reason="manual")
    with pytest.raises(ps.RetiredSystemError):
        p.supervise("sys-1", "step-2", 4, verdict="correct", step_digest=PIN)
    # retired check fires before reason validity (fail-closed ordering)
    with pytest.raises(ps.RetiredSystemError):
        p.retire("sys-1", 5, reason="vibes")
    p2 = ps.ProcessSupervision()
    p2.supervise("sys-2", "step-1", 1, verdict="correct", step_digest=PIN)
    with pytest.raises(ps.BadReasonError):
        p2.retire("sys-2", 2, reason="vibes")  # fail-closed: known system, bad reason
    assert p.stats(6)["rejected"] == 3
    assert p.retired_ids(7) == ("sys-1",)
    # reads still work post-retire
    assert p.evaluate("sys-1", 8).posture == "supervised"
    assert p.verify("sup-1", 9).verdict == "verified"


# 7. verify semantics: verified roundtrip, tampered as data, unknown refusal
def test_verify_semantics():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=PIN)
    rep = p.verify("sup-1", 2)
    assert rep.verdict == "verified"
    assert rep.verify() is True
    assert rep.as_dict()["schema"] == "northstar.process-supervision.v1"
    # tamper the underlying record -> tampered reported as data, never raised
    rec = p.supervision_record("sup-1", 3)
    object.__setattr__(rec, "verdict", "incorrect")
    rep2 = p.verify("sup-1", 4)
    assert rep2.verdict == "tampered"
    assert rep2.verify() is True
    with pytest.raises(ps.UnknownSupervisionError):
        p.verify("sup-999", 5)


# 8. verify read purity: same seq twice, no audit rows
def test_verify_read_purity():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=PIN)
    n_audit = len(p.audit_log(2))
    r1 = p.verify("sup-1", 3)
    r2 = p.verify("sup-1", 3)
    assert r1.verdict == r2.verdict == "verified"
    assert len(p.audit_log(3)) == n_audit  # reads add no rows


# 9. evaluate posture math: unevaluated -> supervised -> uncertain -> error-detected
def test_evaluate_posture_math():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "s1", 1, verdict="correct", step_digest=PIN)
    ev = p.evaluate("sys-1", 2)
    assert ev.posture == "supervised"
    assert ev.n_steps == 1
    assert ev.n_correct == 1
    assert ev.n_incorrect == 0
    assert ev.n_uncertain == 0
    assert ev.integrity_ok is True
    assert ev.verify() is True
    p.supervise("sys-1", "s2", 3, verdict="uncertain", step_digest=PIN)
    assert p.evaluate("sys-1", 4).posture == "uncertain"
    p.supervise("sys-1", "s3", 5, verdict="incorrect", step_digest=PIN)
    ev = p.evaluate("sys-1", 6)
    assert ev.posture == "error-detected"  # incorrect outranks uncertain
    assert ev.n_steps == 3
    assert ev.n_incorrect == 1
    # not-assessed verdicts keep the supervised posture
    p.supervise("sys-2", "s1", 7, verdict="not-assessed", step_digest=PIN)
    assert p.evaluate("sys-2", 8).posture == "supervised"
    with pytest.raises(ps.UnknownSystemError):
        p.evaluate("sys-999", 9)


# 10. evaluate read purity
def test_evaluate_read_purity():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "s1", 1, verdict="correct", step_digest=PIN)
    n_audit = len(p.audit_log(2))
    ev1 = p.evaluate("sys-1", 3)
    ev2 = p.evaluate("sys-1", 3)
    assert ev1.posture == ev2.posture == "supervised"
    assert len(p.audit_log(3)) == n_audit  # reads add no rows


# 11. tamper flips integrity_ok as data in evaluate
def test_evaluate_integrity_flip():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "s1", 1, verdict="correct", step_digest=PIN)
    assert p.evaluate("sys-1", 2).integrity_ok is True
    rec = p.supervision_record("sup-1", 3)
    object.__setattr__(rec, "verdict", "incorrect")
    ev = p.evaluate("sys-1", 4)
    assert ev.integrity_ok is False
    assert ev.posture == "error-detected"  # ledger derives from live state
    assert ev.verify() is True  # the report itself is still digest-pinned


# 12. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "s1", 5, verdict="correct", step_digest=PIN)
    with pytest.raises(ps.SeqOrderError):
        p.supervise("sys-1", "s2", 5, verdict="correct", step_digest=PIN)  # rewind: bare
    assert p.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(ps.SeqOrderError):
            p.supervise("sys-1", "s2", bad, verdict="correct", step_digest=PIN)
    # failed mutation consumes seq + books a rejected row
    with pytest.raises(ps.BadDigestError):
        p.supervise("sys-1", "s2", 7, verdict="correct", step_digest="raw")
    assert p.stats(8)["rejected"] == 1
    rec = p.supervise("sys-1", "s2", 9, verdict="correct", step_digest=PIN)
    assert rec.supervision_id == "sup-2"


# 13. audit shapes + leak ban + bad-kind + bad audit seq
def test_audit_shapes_and_leak_ban():
    p = ps.ProcessSupervision()
    p.supervise("sys-1", "s1", 1, verdict="correct", step_digest=PIN)
    p.retire("sys-1", 2, reason="manual")
    rows = p.audit_log(3)
    assert [r["kind"] for r in rows] == ["supervised", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in ps._BANNED_AUDIT_KEYS
    # rejected row shape
    p2 = ps.ProcessSupervision()
    with pytest.raises(ps.BadDigestError):
        p2.supervise("s", "st", 1, verdict="correct", step_digest="raw")
    (rej,) = p2.audit_log(2)
    assert rej["kind"] == "rejected"
    assert rej["details"]["method"] == "supervise"
    assert rej["details"]["error"] == "BadDigestError"
    # banned raw keys raise at the builder level
    with pytest.raises(ps.AuditKindError):
        ps.process_supervision_audit_event("supervised", 1, reasoning="chain of thought")
    with pytest.raises(ps.AuditKindError):
        ps.process_supervision_audit_event("bogus-kind", 1)
    with pytest.raises(ps.SeqOrderError):
        ps.process_supervision_audit_event("supervised", -1)


# 14. cross-instance digest determinism + views
def test_determinism_and_views():
    def build():
        p = ps.ProcessSupervision()
        p.supervise("sys-1", "s1", 1, verdict="correct", step_digest=PIN)
        p.supervise("sys-1", "s2", 2, verdict="uncertain", step_digest=PIN2)
        p.supervise("sys-2", "s1", 3, verdict="correct", step_digest=PIN3)
        return p

    p1, p2 = build(), build()
    assert p1.supervision_record("sup-1", 4).digest == p2.supervision_record("sup-1", 4).digest
    assert p1.evaluate("sys-1", 5).digest == p2.evaluate("sys-1", 5).digest
    assert p1.system_ids(6) == ("sys-1", "sys-2")
    assert p1.supervision_ids(6) == ("sup-1", "sup-2", "sup-3")
    assert p1.supervisions_for("sys-1", 7) == ("sup-1", "sup-2")
    assert p1.supervisions_for("sys-2", 7) == ("sup-3",)
    assert p1.supervision_record("sup-2", 8).verdict == "uncertain"
    stats = p1.stats(9)
    assert stats == {"systems": 2, "supervisions": 3, "retired": 0, "rejected": 0}
    with pytest.raises(ps.UnknownSystemError):
        p1.supervisions_for("sys-999", 10)


# 15. main() subprocess check + thread read smoke
def test_main_self_check_and_threads():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "process-supervision OK: supervise, evaluate, verify, pins, audit"
    )
    p = ps.ProcessSupervision()
    for i in range(10):
        p.supervise("sys-1", f"s{i}", i + 1, verdict="correct", step_digest=PIN)
    results = []

    def worker():
        results.append(p.evaluate("sys-1", 100).posture)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(r == "supervised" for r in results)
    rec = p.supervision_record("sup-1", 100)
    with pytest.raises(Exception):
        rec.step_id = "tampered"  # frozen
    assert rec.verify() is True
