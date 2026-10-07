"""Tests for backdoor_detection.py: scan/quarantine/report decision ledger (simulated)."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "backdoor_detection.py"


def _load():
    spec = importlib.util.spec_from_file_location("backdoor_detection", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["backdoor_detection"] = module  # frozen dataclasses need a registered module
    spec.loader.exec_module(module)
    return module


bd = _load()

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def _fresh():
    return bd.BackdoorDetection()


# 1 -- pins ---------------------------------------------------------------


def test_version_and_schema_pins():
    assert bd.BACKDOOR_DETECTION_VERSION == "backdoor-detection.v1"
    assert bd.BACKDOOR_DETECTION_SCHEMA == "northstar.backdoor-detection.v1"
    assert bd.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(bd.VERDICTS) == {"clean", "suspicious", "backdoored"}


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
            assert node.module.split(".")[0] in allowed, node.module


# 3 -- scan roundtrip -----------------------------------------------------


def test_scan_roundtrip_and_frozen():
    inst = _fresh()
    rec = inst.scan("scn-1", DIGEST, 1, verdict="backdoored", confidence=92.5)
    assert rec.scan_id == "scn-1"
    assert rec.artifact_digest == DIGEST
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.backdoor-detection.v1"
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "clean"  # type: ignore


# 4 -- duplicate / retired / bad inputs with seq-burn ---------------------


def test_scan_duplicate_retired_and_bad_inputs():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="suspicious")
    n_rejected = 0

    # duplicate id
    with pytest.raises(bd.DuplicateScanError):
        inst.scan("scn-1", DIGEST, 2)
    n_rejected += 1

    # bad inputs each consume their seq and book a rejected row
    bad = [
        ("", DIGEST, {}),  # bad id
        ("scn-2", "not-a-digest", {}),
        ("scn-2", DIGEST[:-1], {}),
        ("scn-2", DIGEST, {"artifact_kind": "weights"}),
        ("scn-2", DIGEST, {"method": "vibes"}),
        ("scn-2", DIGEST, {"verdict": "maybe"}),
        ("scn-2", DIGEST, {"confidence": 101}),
        ("scn-2", DIGEST, {"confidence": -1}),
        ("scn-2", DIGEST, {"confidence": True}),
        ("scn-2", DIGEST, {"confidence": float("nan")}),
    ]
    seq = 3
    for sid, digest, kw in bad:
        with pytest.raises(bd.BackdoorDetectionError):
            inst.scan(sid, digest, seq, **kw)
        n_rejected += 1
        seq += 1

    # quarantine then rescan -> retired id never recycled
    inst.scan("scn-9", DIGEST, seq, verdict="backdoored")
    seq += 1
    inst.quarantine("scn-9", seq, reason="trigger-confirmed")
    seq += 1
    with pytest.raises(bd.RetiredScanError):
        inst.scan("scn-9", DIGEST, seq)
    n_rejected += 1

    rejected = [e for e in inst.audit_log(999) if e["kind"] == "backdoor-detection.rejected"]
    assert len(rejected) == n_rejected
    # seqs were burned: next valid seq must exceed the last claim
    inst.scan("scn-fresh", DIGEST, seq + 1)


# 5 -- vocabulary acceptance ----------------------------------------------


def test_vocabulary_acceptance_and_confidence_edges():
    inst = _fresh()
    seq = 1
    for kind in bd.ARTIFACT_KINDS:
        for method in bd.METHODS:
            inst.scan(f"s-{kind}-{method}", DIGEST, seq, artifact_kind=kind, method=method)
            seq += 1
    for verdict in bd.VERDICTS:
        inst.scan(f"v-{verdict}", DIGEST, seq, verdict=verdict)
        seq += 1
    inst.scan("c0", DIGEST, seq, confidence=0)
    inst.scan("c100", DIGEST, seq + 1, confidence=100)
    inst.scan("cint", DIGEST, seq + 2, confidence=50)  # ints accepted
    assert inst.stats(999)["scans"] == len(bd.ARTIFACT_KINDS) * len(bd.METHODS) + len(bd.VERDICTS) + 3


# 6 -- quarantine roundtrip -----------------------------------------------


def test_quarantine_roundtrip():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="backdoored")
    rec = inst.quarantine("scn-1", 2, reason="trigger-confirmed")
    assert rec.scan_id == "scn-1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.backdoor-detection.v1"
    kinds = [e["kind"] for e in inst.audit_log(3)]
    assert "backdoor-detection.scanned" in kinds
    assert "backdoor-detection.quarantined" in kinds
    assert inst.quarantined_ids(4) == ("scn-1",)


# 7 -- quarantine refusals -------------------------------------------------


def test_quarantine_refusals():
    inst = _fresh()
    with pytest.raises(bd.UnknownScanError):
        inst.quarantine("nope", 1)
    # note: unknown-scan refusal is a failed mutation -> seq consumed
    inst.scan("scn-1", DIGEST, 2, verdict="backdoored")
    inst.quarantine("scn-1", 3, reason="policy")
    with pytest.raises(bd.DoubleQuarantineError):
        inst.quarantine("scn-1", 4, reason="policy")
    inst.scan("scn-2", DIGEST, 5)  # clean verdict
    with pytest.raises(bd.CleanQuarantineError):
        inst.quarantine("scn-2", 6)
    inst.scan("scn-3", DIGEST, 7, verdict="suspicious")
    with pytest.raises(bd.BadReasonError):
        inst.quarantine("scn-3", 8, reason="vibes")
    rejected = [e for e in inst.audit_log(999) if e["kind"] == "backdoor-detection.rejected"]
    assert len(rejected) == 4


# 8 -- report roundtrip ----------------------------------------------------


def test_report_roundtrip():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="suspicious", confidence=61.0)
    rep = inst.report("scn-1", 2)
    assert rep.scan_id == "scn-1"
    assert rep.verdict == "suspicious"
    assert rep.quarantined is False
    assert rep.integrity_ok is True
    inst.quarantine("scn-1", 3, reason="precaution")
    rep2 = inst.report("scn-1", 4)
    assert rep2.quarantined is True
    assert rep2.integrity_ok is True
    assert rep2.as_dict()["schema"] == "northstar.backdoor-detection.v1"


# 9 -- report pure read ----------------------------------------------------


def test_report_is_pure_read():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="clean")
    before = len(inst.audit_log(100))
    r1 = inst.report("scn-1", 2)
    r2 = inst.report("scn-1", 2)  # same seq reusable for reads
    assert r1.as_dict() == r2.as_dict()
    assert len(inst.audit_log(100)) == before
    # seq not consumed: next mutation may use seq 2
    inst.scan("scn-2", DIGEST, 2)


# 10 -- report unknown -----------------------------------------------------


def test_report_unknown_scan_refuses():
    inst = _fresh()
    with pytest.raises(bd.UnknownScanError):
        inst.report("ghost", 1)
    with pytest.raises(bd.SeqOrderError):
        inst.report("ghost", 0)  # seq shape checked before lookup


# 11 -- seq discipline -----------------------------------------------------


def test_seq_discipline():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 5)
    # rewind raises bare, consumes nothing, books no rejected row
    with pytest.raises(bd.SeqOrderError):
        inst.scan("scn-2", DIGEST, 5)
    with pytest.raises(bd.SeqOrderError):
        inst.scan("scn-2", DIGEST, 3)
    rejected = [e for e in inst.audit_log(100) if e["kind"] == "backdoor-detection.rejected"]
    assert rejected == []
    for bad_seq in (True, "7", 0, -2, 2.5, None):
        with pytest.raises(bd.SeqOrderError):
            inst.scan("scn-2", DIGEST, bad_seq)
    inst.scan("scn-2", DIGEST, 6)


# 12 -- audit shapes and leak ban ------------------------------------------


def test_audit_shapes_and_leak_ban():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="backdoored")
    inst.quarantine("scn-1", 2, reason="manual")
    events = inst.audit_log(3)
    assert all(e["schema"] == "audit.ndjson/1" for e in events)
    assert all(e["module"] == "backdoor_detection" for e in events)
    assert all(e["digest"].startswith("sha256:") for e in events)
    # raw content keys banned at the boundary
    for banned in ("weights", "model", "trigger", "text", "raw", "payload"):
        with pytest.raises(bd.AuditKindError):
            bd.backdoor_detection_audit_event("backdoor-detection.scanned", 9, **{banned: "x"})
    with pytest.raises(bd.AuditKindError):
        bd.backdoor_detection_audit_event("nope", 9)


# 13 -- determinism and tamper ---------------------------------------------


def test_cross_instance_digest_determinism_and_tamper():
    a, b = _fresh(), _fresh()
    ra = a.scan("scn-1", DIGEST, 1, verdict="suspicious", confidence=42.0)
    rb = b.scan("scn-1", DIGEST, 1, verdict="suspicious", confidence=42.0)
    assert ra.digest == rb.digest
    assert ra.verify() and rb.verify()
    object.__setattr__(ra, "verdict", "clean")
    assert not ra.verify()
    assert b.report("scn-1", 2).integrity_ok is True


# 14 -- views and stats ----------------------------------------------------


def test_views_and_stats():
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="clean")
    inst.scan("scn-2", DIGEST2, 2, verdict="backdoored")
    inst.quarantine("scn-2", 3, reason="duplicate")
    assert inst.scan_record("scn-1", 4).scan_id == "scn-1"
    assert inst.quarantine_record("scn-2", 4).reason == "duplicate"
    assert inst.scan_ids(4) == ("scn-1", "scn-2")
    stats = inst.stats(4)
    assert stats["scans"] == 2
    assert stats["quarantined"] == 1
    assert stats["by_verdict"] == {"clean": 1, "suspicious": 0, "backdoored": 1}
    assert stats["seq"] == 3
    with pytest.raises(bd.UnknownScanError):
        inst.scan_record("ghost", 4)
    with pytest.raises(bd.UnknownScanError):
        inst.quarantine_record("scn-1", 4)


# 15 -- main and concurrency smoke -----------------------------------------


def test_main_and_read_concurrency():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert "backdoor-detection OK" in proc.stdout
    inst = _fresh()
    inst.scan("scn-1", DIGEST, 1, verdict="backdoored")
    inst.quarantine("scn-1", 2, reason="manual")

    def reader():
        for _ in range(50):
            assert inst.report("scn-1", 3).integrity_ok
            assert inst.stats(3)["quarantined"] == 1

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
