"""15 tests for threat_intel.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "threat_intel.py"


def _load():
    spec = importlib.util.spec_from_file_location("threat_intel", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["threat_intel"] = mod
    spec.loader.exec_module(mod)
    return mod


ti_mod = _load()

PIN = "sha256:" + "a" * 64


def _ti():
    return ti_mod.ThreatIntel()


# 1. version/schema pins
def test_pins():
    assert ti_mod.THREAT_INTEL_VERSION == "threat-intel.v1"
    assert ti_mod.SCHEMA_PIN == "northstar.threat-intel.v1"
    assert set(ti_mod.VERDICTS) >= {"benign", "suspicious", "malicious", "unknown"}
    assert set(ti_mod.CHANNELS) >= {"stix", "taxii", "email", "api", "internal"}


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {"hashlib", "json", "threading", "dataclasses", "typing", "__future__",
               "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. collect roundtrip + verify
def test_collect_roundtrip():
    t = _ti()
    rec = t.collect("ioc-1", "domain", 1, value_digest=PIN, confidence="high")
    assert rec.indicator_id == "ioc-1"
    assert rec.indicator_type == "domain"
    assert rec.verify()
    assert t.indicator("ioc-1", 2) is rec


# 4. collect duplicate + bad inputs with seq-burn + rejected rows
def test_collect_bad_inputs():
    t = _ti()
    t.collect("ioc-1", "ip", 1, value_digest=PIN)
    with pytest.raises(ti_mod.DuplicateIndicatorError):
        t.collect("ioc-1", "ip", 2, value_digest=PIN)
    with pytest.raises(ti_mod.BadTypeError):
        t.collect("x", "nope", 3, value_digest=PIN)
    with pytest.raises(ti_mod.BadConfidenceError):
        t.collect("ioc-2", "ip", 4, value_digest=PIN, confidence="extreme")
    with pytest.raises(ti_mod.BadIdError):
        t.collect("", "ip", 5, value_digest=PIN)
    with pytest.raises(ti_mod.BadValueError):
        t.collect("ioc-3", "ip", 6, value_digest="not-a-pin")
    s = t.stats(7)
    assert s["rejected"] >= 5
    rows = [r for r in t.audit_log(8) if r["kind"] == "threat-intel.rejected"]
    assert len(rows) >= 5


# 5. analyze roundtrip + minted ids
def test_analyze_roundtrip():
    t = _ti()
    t.collect("ioc-1", "hash", 1, value_digest=PIN)
    a1 = t.analyze("ioc-1", 2, verdict="malicious", confidence="high")
    assert a1.analysis_id == "ana-1"
    assert a1.verify()
    a2 = t.analyze("ioc-1", 3, verdict="suspicious")
    assert a2.analysis_id == "ana-2"
    assert t.analyses_for("ioc-1", 4) == ("ana-1", "ana-2")


# 6. analyze bad inputs
def test_analyze_bad():
    t = _ti()
    with pytest.raises(ti_mod.UnknownIndicatorError):
        t.analyze("nope", 1, verdict="malicious")
    t.collect("ioc-1", "url", 2, value_digest=PIN)
    with pytest.raises(ti_mod.BadVerdictError):
        t.analyze("ioc-1", 3, verdict="evil")
    with pytest.raises(ti_mod.BadConfidenceError):
        t.analyze("ioc-1", 4, verdict="benign", confidence="x")


# 7. share roundtrip + duplicate-channel refusal
def test_share_roundtrip():
    t = _ti()
    t.collect("ioc-1", "domain", 1, value_digest=PIN)
    s1 = t.share("ioc-1", "stix", 2)
    assert s1.share_id == "shr-1"
    assert s1.verify()
    s2 = t.share("ioc-1", "taxii", 3)
    assert s2.share_id == "shr-2"
    with pytest.raises(ti_mod.DuplicateShareError):
        t.share("ioc-1", "stix", 4)
    assert t.shares_for("ioc-1", 5) == ("shr-1", "shr-2")


# 8. share bad inputs
def test_share_bad():
    t = _ti()
    with pytest.raises(ti_mod.UnknownIndicatorError):
        t.share("nope", "stix", 1)
    t.collect("ioc-1", "ip", 2, value_digest=PIN)
    with pytest.raises(ti_mod.BadChannelError):
        t.share("ioc-1", "carrier-pigeon", 3)


# 9. report aggregate + pure read
def test_report():
    t = _ti()
    t.collect("i1", "domain", 1, value_digest=PIN)
    t.collect("i2", "ip", 2, value_digest=PIN)
    t.analyze("i1", 3, verdict="malicious")
    t.analyze("i2", 4, verdict="benign")
    t.share("i1", "stix", 5)
    before = t.stats(6)["audit_rows"]
    r1 = t.report(7)
    r2 = t.report(7)  # same seq reuse allowed for reads
    assert r1.indicators == 2
    assert r1.shares == 1
    assert dict(r1.by_type) == {"domain": 1, "ip": 1}
    assert dict(r1.by_verdict) == {"malicious": 1, "benign": 1}
    assert r1.verify() and r2.verify()
    assert t.stats(8)["audit_rows"] == before  # no rows on reads


# 10. seq discipline: rewind bare, malformed seqs
def test_seq_discipline():
    t = _ti()
    t.collect("ioc-1", "domain", 5, value_digest=PIN)
    with pytest.raises(ti_mod.SeqOrderError):
        t.collect("ioc-2", "domain", 5, value_digest=PIN)  # rewind bare
    with pytest.raises(ti_mod.SeqOrderError):
        t.collect("ioc-2", "domain", 4, value_digest=PIN)
    for bad in (True, "6", None, 0):
        with pytest.raises(ti_mod.SeqOrderError):
            t.collect("ioc-9", "domain", bad, value_digest=PIN)
    # failed bare raises consume no rejected rows
    assert t.stats(10)["rejected"] == 0
    with pytest.raises(ti_mod.SeqOrderError):
        t.indicator("ioc-1", 0)  # read seq must be positive int


# 11. audit shapes + leak ban + bad kind
def test_audit():
    t = _ti()
    t.collect("ioc-1", "domain", 1, value_digest=PIN)
    t.analyze("ioc-1", 2, verdict="malicious")
    t.share("ioc-1", "stix", 3)
    rows = t.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["threat-intel.collected", "threat-intel.analyzed", "threat-intel.shared"]
    for r in rows:
        for k in r["details"]:
            assert k not in ti_mod._BANNED_AUDIT_KEYS
    with pytest.raises(ti_mod.AuditKindError):
        ti_mod.threat_intel_audit_event("nope", {})
    with pytest.raises(ti_mod.AuditKindError):
        ti_mod.threat_intel_audit_event("collected", {"payload": "x"})


# 12. cross-instance determinism + tamper breaks verify
def test_determinism_and_tamper():
    t1, t2 = _ti(), _ti()
    r1 = t1.collect("ioc-1", "domain", 1, value_digest=PIN)
    r2 = t2.collect("ioc-1", "domain", 1, value_digest=PIN)
    assert r1.digest == r2.digest
    a1 = t1.analyze("ioc-1", 2, verdict="malicious")
    assert a1.verify()
    object.__setattr__(a1, "verdict", "benign")
    assert not a1.verify()


# 13. frozen records + read concurrency smoke
def test_frozen_and_threads():
    t = _ti()
    rec = t.collect("ioc-1", "domain", 1, value_digest=PIN)
    with pytest.raises(Exception):
        rec.indicator_id = "x"  # frozen
    errs = []

    def reader():
        try:
            for _ in range(50):
                t.indicator("ioc-1", 2)
                t.report(3)
        except Exception as e:  # pragma: no cover
            errs.append(e)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    [th.start() for th in threads]
    [th.join() for th in threads]
    assert not errs


# 14. stats / views
def test_views():
    t = _ti()
    t.collect("ioc-1", "domain", 1, value_digest=PIN)
    t.collect("ioc-2", "ip", 2, value_digest=PIN)
    assert t.indicator_ids(3) == ("ioc-1", "ioc-2")
    s = t.stats(4)
    assert s["indicators"] == 2 and s["analyses"] == 0 and s["shares"] == 0
    with pytest.raises(ti_mod.UnknownIndicatorError):
        t.indicator("nope", 5)


# 15. main() subprocess check
def test_main():
    r = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                       text=True, timeout=30)
    assert r.returncode == 0
    assert r.stdout.strip() == "threat-intel OK: collect, analyze, share, report, pins, audit"
