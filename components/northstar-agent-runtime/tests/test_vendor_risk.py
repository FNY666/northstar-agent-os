"""Tests for vendor_risk: 15 tests."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import vendor_risk
from vendor_risk import (
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadReasonError,
    BadRiskClassError,
    BadStatusError,
    DuplicateVendorError,
    OffboardedVendorError,
    SeqOrderError,
    UnknownVendorError,
    VendorRisk,
    vendor_risk_audit_event,
)

MODULE = Path(vendor_risk.__file__)


def pin(seed: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def test_01_version_schema_pins():
    assert vendor_risk.VENDOR_RISK_VERSION == "vendor-risk.v1"
    assert vendor_risk.SCHEMA_PIN == "northstar.vendor-risk.v1"
    assert set(vendor_risk.AUDIT_KINDS) == {"assessed", "monitored", "offboarded", "rejected"}
    assert set(vendor_risk.RISK_CLASSES) == {"low", "medium", "high", "critical"}
    assert set(vendor_risk.OFFBOARD_REASONS) == {
        "manual", "risk-too-high", "contract-ended", "breach", "replaced",
    }
    assert set(vendor_risk.MONITOR_STATUSES) == {
        "unchanged", "improved", "elevated", "breach-reported",
    }


def test_02_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__",
               "canonical_json", "json"}
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


def test_03_assess_roundtrip():
    v = VendorRisk()
    rec = v.assess("vendor-1", 1, risk_class="high", profile_digest=pin("a"))
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.vendor-risk.v1"
    assert v.assessment_record("vendor-1", 1).vendor_id == "vendor-1"
    # duplicate refused, seq burned
    with pytest.raises(DuplicateVendorError):
        v.assess("vendor-1", 2)
    assert v.live_ids(2) == ("vendor-1",)


def test_04_assess_bad_inputs():
    v = VendorRisk()
    seq = 1
    bad = [
        ("", 1),  # empty id
        (None, 1),  # non-str id
        ("v-x", 1, "extreme"),  # bad risk class
        ("v-x", 1, "low", "not-a-pin"),  # bad digest
    ]
    seq_n = 0
    with pytest.raises(BadIdError):
        v.assess("", seq + seq_n); seq_n += 1
    seq_n += 1
    with pytest.raises(BadIdError):
        v.assess(None, seq + seq_n); seq_n += 1
    seq_n += 1
    with pytest.raises(BadRiskClassError):
        v.assess("v-x", seq + seq_n, risk_class="extreme"); seq_n += 1
    seq_n += 1
    with pytest.raises(BadDigestError):
        v.assess("v-x", seq + seq_n, profile_digest="not-a-pin"); seq_n += 1
    seq_n += 1
    assert len(bad) == 4
    # every failed mutation burned its seq + booked a rejected row
    rejected = [r for r in v.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 4
    assert v.stats(9)["vendors"] == 0


def test_05_all_risk_classes_accepted():
    v = VendorRisk()
    seq = 1
    for cls in vendor_risk.RISK_CLASSES:
        rec = v.assess(f"v-{cls}", seq, risk_class=cls)
        assert rec.verify()
        seq += 1
    assert len(v.vendor_ids(seq - 1)) == 4


def test_06_monitor_roundtrip_and_chain():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    m1 = v.monitor("vendor-1", 2, status="unchanged")
    m2 = v.monitor("vendor-1", 3, status="elevated", note_digest=pin("n"))
    assert m1.verify() and m2.verify()
    assert m1.monitor_id == "mon-1" and m2.monitor_id == "mon-2"
    assert v.monitors_for("vendor-1", 3) == ("mon-1", "mon-2")
    assert v.monitor_record("mon-1", 3).status == "unchanged"
    with pytest.raises(UnknownVendorError):
        v.monitor("vendor-nope", 4)


def test_07_monitor_bad_inputs():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    seq = 2
    with pytest.raises(BadStatusError):
        v.monitor("vendor-1", seq, status="critical-ish")
    seq += 1
    with pytest.raises(BadDigestError):
        v.monitor("vendor-1", seq, note_digest="raw text")
    seq += 1
    with pytest.raises(BadIdError):
        v.monitor("", seq)
    seq += 1
    rejected = [r for r in v.audit_log(seq + 1) if r["kind"] == "rejected"]
    assert len(rejected) == 3


def test_08_offboard_terminality():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    v.monitor("vendor-1", 2)
    o = v.offboard("vendor-1", 3, reason="breach")
    assert o.verify()
    assert v.offboarded_ids(3) == ("vendor-1",)
    assert v.live_ids(3) == ()
    # terminal: later assess/monitor refused, id never recycled
    with pytest.raises(OffboardedVendorError):
        v.assess("vendor-1", 4)
    with pytest.raises(OffboardedVendorError):
        v.monitor("vendor-1", 5)
    with pytest.raises(OffboardedVendorError):
        v.offboard("vendor-1", 6)
    # offboarded vendor still reads fine
    assert v.assessment_record("vendor-1", 6).risk_class == "medium"


def test_09_offboard_bad_inputs():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    with pytest.raises(BadReasonError):
        v.offboard("vendor-1", 2, reason="because")
    with pytest.raises(UnknownVendorError):
        v.offboard("vendor-ghost", 3)
    # failed offboard attempts burn seq + book rejected rows
    rejected = [r for r in v.audit_log(3) if r["kind"] == "rejected"]
    assert len(rejected) == 2
    # reads still fine for a live vendor
    with pytest.raises(UnknownVendorError):
        v.offboard_record("vendor-1", 3)


def test_10_seq_discipline():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    # rewind raises bare: no rejected row, no seq consumption
    n_before = len(v.audit_log(2))
    with pytest.raises(SeqOrderError):
        v.assess("vendor-2", 1)
    assert len(v.audit_log(2)) == n_before
    # malformed seqs
    for bad_seq in (True, "1", -1, None):
        with pytest.raises(SeqOrderError):
            v.assess("vendor-x", bad_seq)
    assert len(v.audit_log(2)) == n_before
    # seq 2 still free after rewind attempt
    rec = v.assess("vendor-2", 2)
    assert rec.verify()


def test_11_view_read_purity():
    v = VendorRisk()
    v.assess("vendor-1", 1)
    v.monitor("vendor-1", 2)
    n_before = len(v.audit_log(3))
    # same seq twice is fine for reads; no audit rows written
    assert v.assessment_record("vendor-1", 3) is v.assessment_record("vendor-1", 3)
    assert v.vendor_ids(3) == ("vendor-1",)
    assert v.stats(3)["monitors"] == 1
    assert v.monitors_for("vendor-1", 3) == ("mon-1",)
    assert len(v.audit_log(3)) == n_before


def test_12_audit_shapes_and_leak_ban():
    v = VendorRisk()
    v.assess("vendor-1", 1, profile_digest=pin("p"))
    v.monitor("vendor-1", 2)
    v.offboard("vendor-1", 3, reason="manual")
    kinds = [r["kind"] for r in v.audit_log(3)]
    assert kinds == ["assessed", "monitored", "offboarded"]
    for row in v.audit_log(3):
        assert row["audit"] == "audit.ndjson/1"
        assert "schema" not in row
    # raw-content keys banned at the boundary
    with pytest.raises(BadDigestError):
        vendor_risk_audit_event("assessed", 4, vendor_name="Acme Corp")
    with pytest.raises(BadDigestError):
        vendor_risk_audit_event("assessed", 4, profile="full text")
    # unknown audit kind
    with pytest.raises(AuditKindError):
        vendor_risk_audit_event("deleted", 4)


def test_13_cross_instance_determinism_and_tamper():
    v1, v2 = VendorRisk(), VendorRisk()
    r1 = v1.assess("vendor-1", 1, profile_digest=pin("p"))
    r2 = v2.assess("vendor-1", 1, profile_digest=pin("p"))
    assert r1.digest == r2.digest
    # tamper breaks verify()
    object.__setattr__(r1, "risk_class", "low")
    assert not r1.verify()
    # offboard tamper breaks verify()
    v3 = VendorRisk()
    v3.assess("vendor-1", 1)
    o = v3.offboard("vendor-1", 2)
    object.__setattr__(o, "reason", "breach")
    assert not o.verify()


def test_14_frozen_and_concurrent_reads():
    v = VendorRisk()
    rec = v.assess("vendor-1", 1)
    with pytest.raises(Exception):
        rec.vendor_id = "vendor-2"  # frozen dataclass
    errs = []
    def reader():
        try:
            v.vendor_ids(2)
            v.stats(2)
            rec.verify()
        except Exception as exc:  # pragma: no cover
            errs.append(exc)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


def test_15_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "vendor-risk OK: assess, monitor, offboard, pins, audit" in result.stdout
