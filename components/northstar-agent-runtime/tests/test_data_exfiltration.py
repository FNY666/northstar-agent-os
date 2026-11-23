"""Tests for the data_exfiltration ledger (15 tests)."""

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "data_exfiltration.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("data_exfiltration", None)
    spec = importlib.util.spec_from_file_location(
        "data_exfiltration", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["data_exfiltration"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def dex(mod):
    return mod.DataExfiltration()


def good_digest(label="dest"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "data-exfiltration.v1"
    assert mod.SCHEMA == "northstar.data-exfiltration.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


def test_monitor_roundtrip_and_verify(dex, mod):
    rec = dex.monitor("m-net", "network-egress", 1)
    assert rec.monitor_id == "m-net"
    assert rec.scope == "network-egress"
    assert rec.verify()
    assert dex.monitor_record("m-net", 2) is rec
    assert dex.monitor_ids(3) == ("m-net",)
    # duplicate refused fail-closed
    with pytest.raises(mod.DuplicateMonitorError):
        dex.monitor("m-net", "usb", 4)
    assert dex.stats(5)["rejected"] == 1


def test_monitor_bad_inputs_and_scope_vocabulary(dex, mod):
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises((mod.BadIdError, mod.DuplicateMonitorError)):
            dex.monitor(bad, "usb", dex.stats(0)["seq"] + 1)
    for scope in ("network-egress", "usb", "clipboard", "print",
                  "api-call", "file-transfer"):
        dex.monitor(f"m-{scope}", scope, dex.stats(0)["seq"] + 1)
    for bad_scope in ("email", "", None, 42):
        with pytest.raises(mod.BadScopeError):
            dex.monitor("m-bad", bad_scope, dex.stats(0)["seq"] + 1)
    assert dex.stats(0)["monitors"] == 6


def test_detect_roundtrip_and_verify(dex):
    dex.monitor("m-net", "network-egress", 1)
    det = dex.detect("m-net", 2, "bulk-transfer", bytes_out=1048576,
                     destination_digest=good_digest())
    assert det.det_id == "det-1"
    assert det.verify()
    det2 = dex.detect("m-net", 3, "off-hours-transfer")
    assert det2.det_id == "det-2"
    assert det2.destination_pin == ""
    assert dex.detection_record("det-1", 4).verify()
    assert dex.detection_ids(5) == ("det-1", "det-2")
    assert dex.detections_for("m-net", 6) == ("det-1", "det-2")


def test_detect_refusals_and_seq_burn(dex, mod):
    dex.monitor("m-net", "network-egress", 1)
    with pytest.raises(mod.UnknownMonitorError):
        dex.detect("m-nope", 2, "bulk-transfer")
    with pytest.raises(mod.BadSignalError):
        dex.detect("m-net", 3, "aliens-landed")
    with pytest.raises(mod.BadDigestError):
        dex.detect("m-net", 4, "bulk-transfer",
                   destination_digest="not-a-pin")
    for bad_bytes in (True, -1, 1.5, "100", None):
        with pytest.raises(mod.BadBytesError):
            dex.detect("m-net", dex.stats(0)["seq"] + 1, "bulk-transfer",
                       bytes_out=bad_bytes)
    # every failed mutation burned its seq: next good call is seq 6..n
    det = dex.detect("m-net", dex.stats(0)["seq"] + 1, "staged-archive")
    assert det.det_id == "det-1"
    stats = dex.stats(0)
    assert stats["detections"] == 1
    assert stats["rejected"] == 8  # 1 + 1 + 1 + 5
    kinds = [r["kind"] for r in dex.audit_log(0)]
    assert kinds.count("data-exfiltration.rejected") == 8


def test_prevent_roundtrip_and_verify(dex):
    dex.monitor("m-usb", "usb", 1)
    det = dex.detect("m-usb", 2, "anomalous-egress", bytes_out=64)
    for action in ("block", "quarantine", "throttle", "alert-only",
                   "revoke-access", "isolate-host"):
        detx = dex.detect("m-usb", dex.stats(0)["seq"] + 1,
                          "unusual-destination")
        prv = dex.prevent(detx.det_id, dex.stats(0)["seq"] + 1, action)
        assert prv.verify()
        assert prv.action == action
        assert prv.reason == "policy"
    prv = dex.prevent(det.det_id, dex.stats(0)["seq"] + 1, "block",
                      reason="dlp-rule")
    assert prv.reason == "dlp-rule"
    assert dex.prevention_record(det.det_id, 0).verify()
    assert det.det_id in dex.prevented_ids(0)


def test_prevent_refusals(dex, mod):
    dex.monitor("m-usb", "usb", 1)
    det = dex.detect("m-usb", 2, "bulk-transfer")
    with pytest.raises(mod.UnknownDetectionError):
        dex.prevent("det-999", 3, "block")
    with pytest.raises(mod.BadActionError):
        dex.prevent(det.det_id, 4, "delete-everything")
    with pytest.raises(mod.BadReasonError):
        dex.prevent(det.det_id, 5, "block", reason="vibes")
    dex.prevent(det.det_id, 6, "quarantine")
    with pytest.raises(mod.DuplicatePreventionError):
        dex.prevent(det.det_id, 7, "block")
    assert dex.stats(0)["rejected"] == 4


def test_alert_chain_and_vocabulary(dex, mod):
    dex.monitor("m-api", "api-call", 1)
    det = dex.detect("m-api", 2, "large-attachment", bytes_out=2048)
    seq = 3
    for channel in ("siem", "email", "pagerduty", "slack", "ticket"):
        for severity in ("low", "medium", "high", "critical"):
            alr = dex.alert(det.det_id, seq, channel, severity)
            assert alr.verify()
            seq += 1
    assert dex.stats(0)["alerts"] == 20
    assert dex.alerts_for(det.det_id, 0) == tuple(f"alr-{i}" for i in range(1, 21))
    with pytest.raises(mod.BadChannelError):
        dex.alert(det.det_id, seq, "smoke-signals", "high")
    with pytest.raises(mod.BadSeverityError):
        dex.alert(det.det_id, seq + 1, "siem", "catastrophic")
    with pytest.raises(mod.UnknownDetectionError):
        dex.alert("det-999", seq + 2, "siem", "high")


def test_seq_discipline(dex, mod):
    dex.monitor("m1", "print", 1)
    with pytest.raises(mod.SeqOrderError):
        dex.monitor("m2", "print", 1)  # rewind raises bare
    with pytest.raises(mod.SeqOrderError):
        dex.monitor("m2", "print", 0)
    for bad in (True, "2", 2.0, None, -3):
        with pytest.raises(mod.SeqOrderError):
            dex.monitor("m2", "print", bad)
    # rewinds consumed nothing: rejected unchanged
    assert dex.stats(2)["rejected"] == 0
    dex.monitor("m2", "print", 2)
    assert dex.stats(2)["monitors"] == 2


def test_views_are_pure_reads(dex):
    dex.monitor("m1", "network-egress", 1)
    det = dex.detect("m1", 2, "bulk-transfer")
    n_rows = len(dex.audit_log(0))
    seq_before = dex.stats(0)["seq"]
    for _ in range(3):
        dex.monitor_record("m1", seq_before)
        dex.detection_record(det.det_id, seq_before)
        dex.stats(seq_before)
        dex.audit_log(seq_before)
    assert len(dex.audit_log(0)) == n_rows
    assert dex.stats(0)["seq"] == seq_before


def test_audit_shapes_and_leak_ban():
    mod = load_module()
    banned_samples = [
        "payload", "data", "content", "text", "raw", "file",
        "file_name", "filename", "bytes", "byte_count", "secret",
        "value", "exfiltrated", "destination", "host", "ip", "url",
    ]
    for key in banned_samples:
        with pytest.raises(mod.AuditKindError):
            mod.data_exfiltration_audit_event("detected", {key: "x"}, 1)
    row = mod.data_exfiltration_audit_event(
        "detected", {"det_id": "det-1", "bytes_out": 10}, 7)
    assert row["audit_version"] == "audit.ndjson/1"
    assert row["schema"] == "northstar.data-exfiltration.v1"
    assert row["kind"] == "data-exfiltration.detected"
    assert row["seq"] == 7
    with pytest.raises(mod.AuditKindError):
        mod.data_exfiltration_audit_event("nope", {}, 1)
    # all audit kinds render
    dex = mod.DataExfiltration()
    dex.monitor("m", "usb", 1)
    det = dex.detect("m", 2, "bulk-transfer")
    dex.prevent(det.det_id, 3, "block")
    dex.alert(det.det_id, 4, "siem", "low")
    with pytest.raises(mod.DuplicateMonitorError):
        dex.monitor("m", "usb", 5)
    kinds = [r["kind"] for r in dex.audit_log(0)]
    assert kinds == [
        "data-exfiltration.monitor-registered",
        "data-exfiltration.detected",
        "data-exfiltration.prevented",
        "data-exfiltration.alerted",
        "data-exfiltration.rejected",
    ]


def test_cross_instance_digest_determinism_and_tamper():
    mod = load_module()
    a, b = mod.DataExfiltration(), mod.DataExfiltration()
    ra = a.monitor("m", "clipboard", 1)
    rb = b.monitor("m", "clipboard", 1)
    assert ra.digest == rb.digest
    da = a.detect("m", 2, "staged-archive")
    db = b.detect("m", 2, "staged-archive")
    assert da.digest == db.digest
    # tamper breaks verify
    import dataclasses

    tampered = dataclasses.replace(da, bytes_out=999999)
    assert not tampered.verify()
    assert da.verify()


def test_records_are_frozen():
    mod = load_module()
    dex = mod.DataExfiltration()
    rec = dex.monitor("m", "print", 1)
    with pytest.raises(AttributeError):
        rec.scope = "usb"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        rec.monitor_id = "z"  # type: ignore[misc]


def test_concurrent_reads():
    mod = load_module()
    dex = mod.DataExfiltration()
    dex.monitor("m", "network-egress", 1)
    det = dex.detect("m", 2, "bulk-transfer")
    errors = []

    def reader():
        try:
            for _ in range(50):
                dex.detection_record(det.det_id, 2)
                dex.stats(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "data-exfiltration OK" in result.stdout
