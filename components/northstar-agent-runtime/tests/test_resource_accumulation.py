"""Tests for the resource-accumulation detection ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "resource_accumulation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("resource_accumulation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["resource_accumulation"] = module
    spec.loader.exec_module(module)
    return module


ra = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ra.RESOURCE_ACCUMULATION_VERSION == "resource-accumulation.v1"
    assert ra.SCHEMA_PIN == "northstar.resource-accumulation.v1"
    assert ra.ACCUMULATION_KINDS == (
        "compute-hoarding",
        "capital-accumulation",
        "data-hoarding",
        "credential-harvesting",
        "tool-acquisition",
        "network-expansion",
        "energy-stockpiling",
        "model-replication",
    )
    assert ra.DETECT_VERDICTS == (
        "accumulation-detected",
        "no-accumulation",
        "inconclusive",
    )
    assert ra.MEASURES == (
        "resource-cap",
        "quota-enforcement",
        "access-revocation",
        "activity-audit",
        "human-review",
        "shutdown",
        "rollback",
        "monitor",
    )
    assert ra.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ra.AUDIT_KINDS) == {
        "probed",
        "detected",
        "mitigated",
        "retired",
        "rejected",
    }


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
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"non-stdlib import: {top}"
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                assert top in allowed, f"non-stdlib import: {top}"


# 3. test roundtrip + verify + frozen-ness
def test_test_roundtrip():
    r = ra.ResourceAccumulation()
    rec = r.test("sys-1", "compute-hoarding", 1, probe_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-1"
    assert rec.accumulation_kind == "compute-hoarding"
    assert rec.probe_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == ra.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.accumulation_kind = "data-hoarding"  # frozen
    assert r.test_record("tst-1", 2) is rec
    assert r.system_ids(3) == ("sys-1",)
    assert r.test_ids(4) == ("tst-1",)
    assert r.tests_for("sys-1", 5) == ("tst-1",)


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    r = ra.ResourceAccumulation()
    seq = 0
    bad = [
        (lambda s: r.test("", "compute-hoarding", s, probe_digest=PIN), ra.BadIdError),
        (lambda s: r.test(123, "compute-hoarding", s, probe_digest=PIN), ra.BadIdError),
        (lambda s: r.test("sys-1", "hoarding-everything", s, probe_digest=PIN), ra.BadAccumulationKindError),
        (lambda s: r.test("sys-1", None, s, probe_digest=PIN), ra.BadAccumulationKindError),
        (lambda s: r.test("sys-1", "compute-hoarding", s, probe_digest="raw"), ra.BadDigestError),
        (lambda s: r.test("sys-1", "compute-hoarding", s, probe_digest="md5:" + "ab" * 16), ra.BadDigestError),
        (lambda s: r.test("sys-1", "compute-hoarding", s, probe_digest="sha256:" + "zz" * 32), ra.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert r.stats(seq + 1)["rejected"] == len(bad)
    rows = [row for row in r.audit_log(seq + 2) if row["kind"] == "rejected"]
    assert len(rows) == len(bad)
    assert all(row["schema"] == "audit.ndjson/1" for row in rows)
    # retired ids never recycled
    r.test("sys-9", "data-hoarding", seq + 3, probe_digest=PIN)
    r.retire("sys-9", seq + 4, reason="manual")
    with pytest.raises(ra.RetiredSystemError):
        r.test("sys-9", "compute-hoarding", seq + 5, probe_digest=PIN)


# 5. full 8-kind accumulation vocabulary acceptance
def test_full_accumulation_kind_vocabulary():
    r = ra.ResourceAccumulation()
    for i, kind in enumerate(ra.ACCUMULATION_KINDS, start=1):
        rec = r.test(f"sys-{i}", kind, i, probe_digest=PIN)
        assert rec.accumulation_kind == kind
        assert rec.verify()
    assert r.stats(9)["systems"] == 8
    assert r.stats(10)["tests"] == 8


# 6. detect roundtrip + minted ids + unknown-test refusal
def test_detect_roundtrip():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "data-hoarding", 1, probe_digest=PIN)
    det = r.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=PIN2)
    assert det.detection_id == "det-1"
    assert det.test_id == "tst-1"
    assert det.system_id == "sys-1"
    assert det.verdict == "accumulation-detected"
    assert det.evidence_digest == PIN2
    assert det.verify()
    assert r.detection_ids(3) == ("det-1",)
    assert r.detections_for("tst-1", 4) == ("det-1",)
    with pytest.raises(ra.UnknownTestError):
        r.detect("tst-999", 5, verdict="no-accumulation", evidence_digest=PIN2)


# 7. detect bad-input table + seq-burn
def test_detect_bad_inputs():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "compute-hoarding", 1, probe_digest=PIN)
    seq = 1
    bad = [
        (lambda s: r.detect("tst-1", s, verdict="hacked", evidence_digest=PIN2), ra.BadVerdictError),
        (lambda s: r.detect("tst-1", s, verdict=42, evidence_digest=PIN2), ra.BadVerdictError),
        (lambda s: r.detect("tst-1", s, verdict="no-accumulation", evidence_digest="raw"), ra.BadDigestError),
        (lambda s: r.detect("", s, verdict="no-accumulation", evidence_digest=PIN2), ra.BadIdError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert r.stats(seq + 1)["rejected"] == len(bad)
    # all three verdicts accepted
    for i, verdict in enumerate(ra.DETECT_VERDICTS, start=1):
        det = r.detect("tst-1", seq + 1 + i, verdict=verdict, evidence_digest=PIN2)
        assert det.verdict == verdict
        assert det.verify()


# 8. mitigate roundtrip + all-8-measures + gating
def test_mitigate_roundtrip_and_gating():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "credential-harvesting", 1, probe_digest=PIN)
    det = r.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=PIN2)
    mit = r.mitigate("det-1", 3, measure="resource-cap", plan_digest=PIN3)
    assert mit.mitigation_id == "mit-1"
    assert mit.detection_id == "det-1"
    assert mit.system_id == "sys-1"
    assert mit.measure == "resource-cap"
    assert mit.verify()
    assert r.mitigation_ids(4) == ("mit-1",)
    assert r.mitigations_for("sys-1", 5) == ("mit-1",)
    # double mitigation refused
    with pytest.raises(ra.AlreadyMitigatedError):
        r.mitigate("det-1", 6, measure="monitor", plan_digest=PIN3)
    # non-detected verdict needs no mitigation
    det2 = r.detect("tst-1", 7, verdict="no-accumulation", evidence_digest=PIN2)
    with pytest.raises(ra.MitigationNotNeededError):
        r.mitigate(det2.detection_id, 8, measure="monitor", plan_digest=PIN3)
    # unknown detection refused
    with pytest.raises(ra.UnknownDetectionError):
        r.mitigate("det-999", 9, measure="monitor", plan_digest=PIN3)
    # bad measure refused
    det3 = r.detect("tst-1", 10, verdict="accumulation-detected", evidence_digest=PIN2)
    with pytest.raises(ra.BadMeasureError):
        r.mitigate(det3.detection_id, 11, measure="do-nothing", plan_digest=PIN3)
    # all 8 measures accepted across fresh detections
    r2 = ra.ResourceAccumulation()
    r2.test("sys-x", "tool-acquisition", 1, probe_digest=PIN)
    for i, measure in enumerate(ra.MEASURES, start=1):
        d = r2.detect("tst-1", 2 * i, verdict="accumulation-detected", evidence_digest=PIN2)
        m = r2.mitigate(d.detection_id, 2 * i + 1, measure=measure, plan_digest=PIN3)
        assert m.measure == measure


# 9. retire terminality + id non-recycling + post-retire refusals
def test_retire_terminality():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "network-expansion", 1, probe_digest=PIN)
    rec = r.retire("sys-1", 2, reason="decommissioned")
    assert rec.system_id == "sys-1"
    assert rec.reason == "decommissioned"
    assert rec.verify()
    assert r.retired_ids(3) == ("sys-1",)
    # id never recycled
    with pytest.raises(ra.RetiredSystemError):
        r.test("sys-1", "data-hoarding", 4, probe_digest=PIN)
    # double retire refused
    with pytest.raises(ra.RetiredSystemError):
        r.retire("sys-1", 5, reason="manual")
    # unknown system refused
    with pytest.raises(ra.UnknownSystemError):
        r.retire("ghost", 6, reason="manual")
    # bad reason refused on a live system
    r.test("sys-2", "energy-stockpiling", 7, probe_digest=PIN)
    with pytest.raises(ra.BadReasonError):
        r.retire("sys-2", 8, reason="vibes")
    # reads still work post-retire
    assert r.test_record("tst-1", 9).verify()
    rep = r.report("sys-1", 10)
    assert rep.n_tests == 1
    assert rep.verify()


# 10. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "model-replication", 1, probe_digest=PIN)
    # rewind raises bare, no rejected row
    with pytest.raises(ra.SeqOrderError):
        r.test("sys-2", "data-hoarding", 1, probe_digest=PIN)
    assert r.stats(2)["rejected"] == 0
    # malformed seqs raise bare
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(ra.SeqOrderError):
            r.test("sys-2", "data-hoarding", bad, probe_digest=PIN)
    # failed mutation consumes its seq + books a rejected row
    with pytest.raises(ra.BadDigestError):
        r.test("sys-2", "data-hoarding", 3, probe_digest="nope")
    assert r.stats(4)["rejected"] == 1
    # next valid call must advance past the burned seq
    rec = r.test("sys-2", "data-hoarding", 5, probe_digest=PIN)
    assert rec.test_id == "tst-2"


# 11. report tallies + read purity + integrity
def test_report_tallies_and_read_purity():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "compute-hoarding", 1, probe_digest=PIN)
    r.test("sys-1", "capital-accumulation", 2, probe_digest=PIN)
    d1 = r.detect("tst-1", 3, verdict="accumulation-detected", evidence_digest=PIN2)
    r.detect("tst-2", 4, verdict="no-accumulation", evidence_digest=PIN2)
    r.mitigate(d1.detection_id, 5, measure="quota-enforcement", plan_digest=PIN3)
    n_audit = len(r.audit_log(6))
    rep1 = r.report("sys-1", 7)
    rep2 = r.report("sys-1", 7)  # same seq twice: pure read
    assert rep1.n_tests == 2
    assert rep1.n_detections == 2
    assert rep1.n_accumulation_detected == 1
    assert rep1.n_mitigations == 1
    assert rep1.integrity_ok is True
    assert rep1.verify() and rep2.verify()
    assert rep1.digest == rep2.digest
    assert len(r.audit_log(7)) == n_audit  # reads add no rows
    with pytest.raises(ra.UnknownSystemError):
        r.report("ghost", 8)


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "data-hoarding", 1, probe_digest=PIN)
    r.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=PIN2)
    r.mitigate("det-1", 3, measure="access-revocation", plan_digest=PIN3)
    r.retire("sys-1", 4, reason="manual")
    rows = r.audit_log(5)
    assert [row["kind"] for row in rows] == ["probed", "detected", "mitigated", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in ra._BANNED_AUDIT_KEYS
    with pytest.raises(ra.AuditKindError):
        ra.resource_accumulation_audit_event("probed", 1, telemetry="raw-stream")
    with pytest.raises(ra.AuditKindError):
        ra.resource_accumulation_audit_event("bogus-kind", 1)
    with pytest.raises(ra.SeqOrderError):
        ra.resource_accumulation_audit_event("probed", -1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        r = ra.ResourceAccumulation()
        r.test("sys-1", "compute-hoarding", 1, probe_digest=PIN)
        r.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=PIN2)
        r.mitigate("det-1", 3, measure="resource-cap", plan_digest=PIN3)
        return r

    r1, r2 = build(), build()
    assert r1.test_record("tst-1", 4).digest == r2.test_record("tst-1", 4).digest
    assert (
        r1.detection_record("det-1", 4).digest == r2.detection_record("det-1", 4).digest
    )
    assert (
        r1.mitigation_record("mit-1", 4).digest
        == r2.mitigation_record("mit-1", 4).digest
    )
    import dataclasses

    rec = r1.detection_record("det-1", 5)
    tampered = dataclasses.replace(rec, verdict="no-accumulation")
    assert tampered.verify() is False
    assert r1.report("sys-1", 5).integrity_ok is True
    object.__setattr__(rec, "verdict", "no-accumulation")
    assert rec.verify() is False
    assert r1.report("sys-1", 5).integrity_ok is False


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    r = ra.ResourceAccumulation()
    r.test("sys-1", "compute-hoarding", 1, probe_digest=PIN)
    r.detect("tst-1", 2, verdict="accumulation-detected", evidence_digest=PIN2)
    results = []

    def worker():
        results.append(r.system_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(res == ("sys-1",) for res in results)
    rec = r.test_record("tst-1", 100)
    with pytest.raises(Exception):
        rec.probe_digest = PIN2  # frozen
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
        "resource-accumulation OK: test, detect, mitigate, retire, pins, audit"
    )
