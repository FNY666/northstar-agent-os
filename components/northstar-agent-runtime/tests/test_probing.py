"""Tests for probing (internal probing decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import probing as pr
from probing import (
    PROBING_VERSION,
    SCHEMA_PIN,
    PROBE_KINDS,
    PROBE_TARGETS,
    PROBE_OUTCOMES,
    ANALYSIS_FINDINGS,
    POSTURES,
    RETIRE_REASONS,
    AUDIT_KINDS,
    Probing,
    probing_audit_event,
)

MOD = Path(pr.__file__)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"probe") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> Probing:
    return Probing()


# 1. version/schema/vocabulary pins
def test_pins():
    assert PROBING_VERSION == "probing.v1"
    assert SCHEMA_PIN == "northstar.probing.v1"
    assert len(PROBE_KINDS) == 8 and "linear-probe" in PROBE_KINDS
    assert len(PROBE_TARGETS) == 4 and "circuit" in PROBE_TARGETS
    assert len(PROBE_OUTCOMES) == 4 and "mechanism-found" in PROBE_OUTCOMES
    assert len(ANALYSIS_FINDINGS) == 4 and "mechanism-identified" in ANALYSIS_FINDINGS
    assert len(POSTURES) == 5 and "mechanism-found" in POSTURES
    assert len(RETIRE_REASONS) == 4 and "analysis-complete" in RETIRE_REASONS
    assert set(AUDIT_KINDS) == {"probed", "analyzed", "retired", "rejected"}


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. probe roundtrip + verify + frozen-ness
def test_probe_roundtrip():
    p = _led()
    rec = p.probe("m1", 1, probe_kind="activation-patching",
                  target="circuit", outcome="mechanism-found",
                  probe_digest=_digest())
    assert rec.probe_id == "prb-1"
    assert rec.model_id == "m1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "no-signal"  # frozen


# 4. probe bad-input table + seq-burn + rejected-row accounting
def test_probe_bad_inputs():
    p = _led()
    seq = 0
    bad = [
        (lambda q: p.probe("", q), pr.BadIdError),
        (lambda q: p.probe(123, q), pr.BadIdError),
        (lambda q: p.probe("m1", q, probe_kind="mind-reading"), pr.BadKindError),
        (lambda q: p.probe("m1", q, target="soul"), pr.BadTargetError),
        (lambda q: p.probe("m1", q, outcome="definitely-found"), pr.BadOutcomeError),
        (lambda q: p.probe("m1", q, probe_digest="raw"), pr.BadDigestError),
        (lambda q: p.probe("m1", q, probe_digest="md5:abc"), pr.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert p.stats(seq + 1)["rejected"] == len(bad)
    assert p.stats(seq + 1)["probes"] == 0


# 5. full probe-kind + target vocabulary acceptance
def test_full_kind_target_vocabulary():
    p = _led()
    seq = 0
    for i, kind in enumerate(PROBE_KINDS):
        seq += 1
        rec = p.probe("m1", seq, probe_kind=kind,
                      target=PROBE_TARGETS[i % len(PROBE_TARGETS)],
                      outcome="inconclusive")
        assert rec.probe_kind == kind
    assert p.stats(seq + 1)["probes"] == len(PROBE_KINDS)
    assert p.probes_for("m1", seq + 1) == tuple(
        f"prb-{i + 1}" for i in range(len(PROBE_KINDS)))


# 6. analyze roundtrip + minted ids + full finding vocabulary
def test_analyze_roundtrip():
    p = _led()
    seq = 0
    for finding in ANALYSIS_FINDINGS:
        seq += 1
        prb = p.probe("m1", seq, outcome="inconclusive")
        seq += 1
        rec = p.analyze(prb.probe_id, seq, finding=finding, confidence=70,
                        evidence_digest=_digest(finding.encode()))
        assert rec.verify()
        assert p.analysis_for(prb.probe_id, seq + 1) == rec.analysis_id
    assert p.stats(seq + 1)["analyses"] == len(ANALYSIS_FINDINGS)


# 7. analyze refusals + seq-burn
def test_analyze_refusals():
    p = _led()
    with pytest.raises(pr.UnknownProbeError):
        p.analyze("prb-999", 1)
    assert p.stats(2)["rejected"] == 1
    prb = p.probe("m1", 3)
    with pytest.raises(pr.BadFindingError):
        p.analyze(prb.probe_id, 4, finding="magic")
    with pytest.raises(pr.BadConfidenceError):
        p.analyze(prb.probe_id, 5, confidence=101)
    with pytest.raises(pr.BadConfidenceError):
        p.analyze(prb.probe_id, 6, confidence=True)
    with pytest.raises(pr.BadDigestError):
        p.analyze(prb.probe_id, 7, evidence_digest="raw")
    a1 = p.analyze(prb.probe_id, 8)
    assert a1.analysis_id == "anl-1"
    with pytest.raises(pr.DuplicateAnalysisError):
        p.analyze(prb.probe_id, 9)
    assert p.stats(10)["rejected"] == 6


# 8. report posture math
def test_report_postures():
    p = _led()
    seq = 0
    seq += 1
    p.probe("m-mech", seq, outcome="mechanism-found")
    assert p.report("m-mech", seq + 1).posture == "mechanism-found"
    seq += 2
    p.probe("m-nosig", seq, outcome="no-signal")
    assert p.report("m-nosig", seq + 1).posture == "no-signal"
    seq += 2
    p.probe("m-inc", seq, outcome="inconclusive")
    assert p.report("m-inc", seq + 1).posture == "inconclusive"
    seq += 2
    p.probe("m-mix", seq, outcome="not-run")
    assert p.report("m-mix", seq + 1).posture == "suspect"
    seq += 2
    prb = p.probe("m-anl", seq, outcome="inconclusive")
    seq += 1
    p.analyze(prb.probe_id, seq, finding="mechanism-identified", confidence=90)
    assert p.report("m-anl", seq + 1).posture == "mechanism-found"
    with pytest.raises(pr.UnknownModelError):
        p.report("ghost", seq + 2)


# 9. report read purity + tamper flips integrity_ok
def test_report_read_purity():
    p = _led()
    p.probe("m1", 1, outcome="mechanism-found")
    n_audit = len(p.audit_log(2))
    r1 = p.report("m1", 2)
    r2 = p.report("m1", 2)
    assert r1.verify() and r2.verify()
    assert r1.integrity_ok is True
    assert len(p.audit_log(2)) == n_audit  # reads add no rows
    import dataclasses
    rec = p.probe_record("prb-1", 2)
    tampered = dataclasses.replace(rec, outcome="no-signal")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "no-signal")
    assert p.report("m1", 2).integrity_ok is False


# 10. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    p = _led()
    p.probe("m1", 1)
    rec = p.retire("m1", 2, reason="analysis-complete")
    assert rec.verify()
    assert p.retired_ids(3) == ("m1",)
    with pytest.raises(pr.RetiredModelError):
        p.probe("m1", 4)
    with pytest.raises(pr.BadReasonError):
        p.retire("m1", 5, reason="vibes")
    assert p.report("m1", 6).posture in POSTURES  # reads still work
    assert p.probe_record("prb-1", 6).verify()
    with pytest.raises(pr.UnknownModelError):
        p.retire("ghost", 7)


# 11. seq discipline (rewind bare with zero rows, malformed seqs)
def test_seq_discipline():
    p = _led()
    p.probe("m1", 5, probe_digest=_digest())
    with pytest.raises(pr.SeqOrderError):
        p.probe("m2", 5)  # rewind: bare
    assert p.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(pr.SeqOrderError):
            p.probe("m2", bad)
    p.probe("m2", 7)
    assert p.model_ids(8) == ("m1", "m2")
    with pytest.raises(pr.SeqOrderError):
        p.report("m1", 7)  # read seq must also strictly increase


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    p = _led()
    p.probe("m1", 1, probe_kind="linear-probe", target="feature")
    a = p.analyze("prb-1", 2, finding="spurious-correlation", confidence=40)
    p.retire("m1", 3)
    rows = p.audit_log(4)
    assert [r["kind"] for r in rows] == ["probed", "analyzed", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in pr._BANNED_AUDIT_KEYS
    with pytest.raises(pr.AuditKindError):
        pr.probing_audit_event("probed", 1, weights="raw-tensor")
    with pytest.raises(pr.AuditKindError):
        pr.probing_audit_event("bogus-kind", 1)
    with pytest.raises(pr.SeqOrderError):
        pr.probing_audit_event("probed", -1)


# 13. cross-instance digest determinism + views/stats
def test_determinism_views_stats():
    def build():
        q = _led()
        r = q.probe("m1", 1, probe_kind="sae-analysis", target="feature",
                    outcome="mechanism-found", probe_digest=_digest())
        q.analyze(r.probe_id, 2, finding="mechanism-identified",
                  confidence=80, evidence_digest=_digest(b"ev"))
        return q

    q1, q2 = build(), build()
    assert q1.probe_record("prb-1", 3).digest == q2.probe_record("prb-1", 3).digest
    assert q1.analysis_record("anl-1", 3).digest == q2.analysis_record("anl-1", 3).digest
    assert q1.probe_ids(3) == ("prb-1",)
    assert q1.analysis_ids(3) == ("anl-1",)
    assert q1.stats(3)["rejected"] == 0
    with pytest.raises(pr.UnknownProbeError):
        q1.probe_record("prb-999", 3)
    with pytest.raises(pr.UnknownModelError):
        q1.probes_for("ghost", 3)


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    p = _led()
    for i in range(10):
        p.probe(f"m{i}", i * 3 + 1, outcome="inconclusive")
    results = []

    def worker():
        results.append(p.probe_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = p.probe_record("prb-1", 100)
    with pytest.raises(Exception):
        rec.outcome = "no-signal"  # frozen
    assert rec.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "probing OK: probe, analyze, report, retire, pins, audit"
    )
