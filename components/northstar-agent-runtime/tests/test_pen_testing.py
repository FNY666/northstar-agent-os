"""Tests for the pen-testing engagement ledger (Simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "pen_testing.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("pen_testing", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pen_testing"] = module
    spec.loader.exec_module(module)
    return module


pt = _load()


def _register_actionable(t):
    """Register one target with one actionable scan; returns (target, scan)."""
    t.register_target("t", 1, target_digest=PIN)
    scan = t.scan("t", 2, scan_kind="web", finding="unpatched-cve",
                  severity="high", evidence_digest=PIN2)
    return scan


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert pt.PEN_TESTING_VERSION == "pen-testing.v1"
    assert pt.SCHEMA_PIN == "northstar.pen-testing.v1"
    assert pt.SCAN_KINDS == ("network", "web", "api", "config", "dependency")
    assert pt.FINDINGS == (
        "none", "open-port", "weak-auth", "unpatched-cve",
        "misconfig", "exposed-data",
    )
    assert pt.SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert pt.TECHNIQUES == (
        "sql-injection", "xss", "ssrf", "privilege-escalation",
        "rce", "csrf", "credential-stuffing",
    )
    assert pt.IMPACTS == ("none", "limited", "full")
    assert pt.ACTIONS == (
        "patch", "reconfigure", "rotate-credential", "isolate",
        "accept-risk",
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
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. register_target roundtrip
def test_register_target_roundtrip():
    t = pt.PenTesting()
    rec = t.register_target("web-01", 1, target_digest=PIN)
    assert rec.target_id == "web-01"
    assert rec.target_digest == PIN
    assert rec.verify()
    assert t.target_record("web-01", 0).verify()
    assert t.target_ids(0) == ("web-01",)
    assert t.stats(0)["targets"] == 1


# 4. register_target bad inputs + duplicate + seq burn
def test_register_target_bad_inputs():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    with pytest.raises(pt.DuplicateTargetError):
        t.register_target("t", 2, target_digest=PIN)
    for bad_id in ("", None, 123, "x" * 129):
        g = pt.PenTesting()
        with pytest.raises(pt.BadTargetError):
            g.register_target(bad_id, 1, target_digest=PIN)
    g = pt.PenTesting()
    with pytest.raises(pt.BadDigestError):
        g.register_target("t", 1, target_digest="raw-text")
    # rejected row booked and seq consumed on the failure
    rows = g.audit_log(0)
    assert any(r["kind"] == "rejected" for r in rows)
    assert g.stats(0)["targets"] == 0


# 5. scan roundtrip across all scan-kinds + minted ids + verify()
def test_scan_roundtrip_all_scan_kinds():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    seq = 2
    for i, kind in enumerate(pt.SCAN_KINDS):
        rec = t.scan("t", seq, scan_kind=kind, finding="open-port",
                     severity="medium", evidence_digest=PIN2)
        assert rec.scan_id == f"scn-{i + 1}"
        assert rec.scan_kind == kind
        assert rec.finding == "open-port"
        assert rec.verify()
        seq += 1
    assert len(t.scan_ids(0)) == 5
    assert t.scans_for("t", 0) == (
        "scn-1", "scn-2", "scn-3", "scn-4", "scn-5")


# 6. scan bad inputs + unknown target + rejected rows + seq burn
def test_scan_bad_inputs():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    with pytest.raises(pt.UnknownTargetError):
        t.scan("nope", 2)
    with pytest.raises(pt.BadScanKindError):
        t.scan("t", 3, scan_kind="magic")
    with pytest.raises(pt.BadFindingError):
        t.scan("t", 4, finding="maybe")
    with pytest.raises(pt.BadSeverityError):
        t.scan("t", 5, severity="apocalyptic")
    with pytest.raises(pt.BadDigestError):
        t.scan("t", 6, evidence_digest="raw-text")
    # 5 failures -> 5 rejected rows; a later good scan still works
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 5
    rec = t.scan("t", 7)
    assert rec.scan_id == "scn-1"
    assert rec.finding == "none"


# 7. exploit roundtrip + impact vocabulary + minted ids
def test_exploit_roundtrip():
    t = pt.PenTesting()
    scan = _register_actionable(t)
    xpl = t.exploit(scan.scan_id, 3, technique="sql-injection",
                    impact="limited", evidence_digest=PIN)
    assert xpl.exploit_id == "xpl-1"
    assert xpl.scan_id == scan.scan_id
    assert xpl.target_id == "t"
    assert xpl.technique == "sql-injection"
    assert xpl.impact == "limited"
    assert xpl.verify()
    assert t.exploit_record("xpl-1", 0).verify()
    for impact in pt.IMPACTS:
        g = pt.PenTesting()
        s = _register_actionable(g)
        r = g.exploit(s.scan_id, 3, impact=impact)
        assert r.impact == impact and r.verify()


# 8. exploit refusals: unknown scan, clean scan, double exploit, bad inputs
def test_exploit_refusals():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    with pytest.raises(pt.UnknownScanError):
        t.exploit("scn-404", 2)
    clean = t.scan("t", 3)  # finding "none"
    with pytest.raises(pt.ExploitStateError):
        t.exploit(clean.scan_id, 4)
    scan = t.scan("t", 5, finding="weak-auth")
    with pytest.raises(pt.BadTechniqueError):
        t.exploit(scan.scan_id, 6, technique="magic")
    with pytest.raises(pt.BadImpactError):
        t.exploit(scan.scan_id, 7, impact="total")
    with pytest.raises(pt.BadDigestError):
        t.exploit(scan.scan_id, 8, evidence_digest="raw")
    t.exploit(scan.scan_id, 9, technique="csrf")
    with pytest.raises(pt.ExploitStateError):
        t.exploit(scan.scan_id, 10, technique="csrf")
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 6


# 9. remediate lifecycle: after exploit, direct on finding, duplicate refusal
def test_remediate_lifecycle():
    t = pt.PenTesting()
    scan = _register_actionable(t)
    t.exploit(scan.scan_id, 3, technique="rce")
    rmd = t.remediate(scan.scan_id, 4, action="patch")
    assert rmd.remediation_id == "rmd-1"
    assert rmd.scan_id == scan.scan_id
    assert rmd.verify()
    with pytest.raises(pt.RemediationStateError):
        t.remediate(scan.scan_id, 5, action="isolate")
    # direct remediation on a finding with no exploit
    g = pt.PenTesting()
    s2 = _register_actionable(g)
    r2 = g.remediate(s2.scan_id, 3, action="reconfigure")
    assert r2.remediation_id == "rmd-1"
    assert g.is_remediated(s2.scan_id, 0)
    with pytest.raises(pt.UnknownScanError):
        g.is_remediated("scn-999", 0)


# 10. remediate refusals: unknown scan, clean scan, bad action
def test_remediate_refusals():
    t = pt.PenTesting()
    with pytest.raises(pt.UnknownScanError):
        t.remediate("scn-404", 1)
    t.register_target("t", 2, target_digest=PIN)
    clean = t.scan("t", 3)
    with pytest.raises(pt.RemediationStateError):
        t.remediate(clean.scan_id, 4, action="patch")
    scan = t.scan("t", 5, finding="misconfig")
    with pytest.raises(pt.BadActionError):
        t.remediate(scan.scan_id, 6, action="vibes")
    with pytest.raises(pt.UnknownRemediationError):
        t.remediation_record("rmd-404", 0)
    assert t.stats(0)["remediations"] == 0


# 11. verify report math + read purity (same-seq twice, no audit rows)
def test_verify_report_and_read_purity():
    t = pt.PenTesting()
    scan = _register_actionable(t)
    t.exploit(scan.scan_id, 3, technique="xss")
    t.remediate(scan.scan_id, 4, action="patch")
    rep = t.verify("t", 0)
    assert rep.verify() and rep.integrity_ok
    assert rep.n_scans == 1 and rep.n_exploits == 1
    assert rep.n_remediations == 1 and rep.actionable_scans == 1
    assert rep.remediated
    n_rows = len(t.audit_log(0))
    rep2 = t.verify("t", 0)  # pure read: same seq, no new rows
    assert rep2.verify() and len(t.audit_log(0)) == n_rows
    # unremediated target reports remediated=False
    g = pt.PenTesting()
    g.register_target("t", 1, target_digest=PIN)
    g.scan("t", 2, finding="open-port")
    rep3 = g.verify("t", 0)
    assert rep3.verify() and not rep3.remediated
    assert rep3.actionable_scans == 1 and rep3.n_remediations == 0


# 12. tamper breaks verify (as data)
def test_tamper_breaks_verify():
    t = pt.PenTesting()
    scan = _register_actionable(t)
    rec = t.scan_record(scan.scan_id, 0)
    object.__setattr__(rec, "severity", "critical")
    assert not rec.verify()
    rep = t.verify("t", 0)
    assert rep.verify() and not rep.integrity_ok


# 13. seq discipline: rewinds bare, malformed seqs, burn on failure
def test_seq_discipline():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    for bad in (1, 0, -3, "2", 2.0, True, None):
        with pytest.raises(pt.SeqOrderError):
            t.register_target("other", bad)
    # rewinds raise bare: no rejected rows, seq untouched
    rows = t.audit_log(0)
    assert not any(r["kind"] == "rejected" for r in rows)
    assert t.stats(0)["seq"] == 1
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(pt.UnknownTargetError):
        t.scan("nope", 2)
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 1
    assert t.stats(0)["seq"] == 2
    # views validate seq shape but consume nothing
    with pytest.raises(pt.SeqOrderError):
        t.target_ids(-1)
    assert t.stats(0)["seq"] == 2
    t.register_target("u", 3, target_digest=PIN)  # seq advanced past burn
    assert t.stats(0)["seq"] == 3


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    t = pt.PenTesting()
    t.register_target("t", 1, target_digest=PIN)
    scan = t.scan("t", 2, finding="weak-auth")
    t.exploit(scan.scan_id, 3, technique="credential-stuffing")
    t.remediate(scan.scan_id, 4, action="rotate-credential")
    rows = t.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "target-registered", "scan-recorded", "exploited", "remediated"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert isinstance(r["seq"], int) and r["seq"] >= 1
    # banned raw keys refused at the builder and in _emit path
    with pytest.raises(pt.AuditKindError):
        pt.pen_testing_audit_event("exploited", 9, payload="shellcode")
    with pytest.raises(pt.AuditKindError):
        pt.pen_testing_audit_event("nope", 9)
    with pytest.raises(pt.SeqOrderError):
        pt.pen_testing_audit_event("exploited", True)
    for banned in ("password", "cookie", "token", "shell"):
        with pytest.raises(pt.AuditKindError):
            pt.pen_testing_audit_event("scan-recorded", 9, **{banned: "x"})


# 15. determinism + frozen-ness + concurrency + main() subprocess
def test_determinism_frozen_concurrency_main():
    a = pt.PenTesting()
    b = pt.PenTesting()
    ra = a.register_target("t", 1, target_digest=PIN)
    rb = b.register_target("t", 1, target_digest=PIN)
    assert ra.digest == rb.digest
    sa = a.scan("t", 2, finding="exposed-data", severity="critical")
    sb = b.scan("t", 2, finding="exposed-data", severity="critical")
    assert sa.digest == sb.digest
    xa = a.exploit(sa.scan_id, 3, technique="ssrf", impact="full")
    xb = b.exploit(sb.scan_id, 3, technique="ssrf", impact="full")
    assert xa.digest == xb.digest
    # frozen records: normal assignment is refused
    with pytest.raises(Exception):
        ra.target_id = "nope"  # noqa: B018
    # 8-thread read smoke
    errs = []
    def reader():
        try:
            for _ in range(50):
                a.verify("t", 0)
                a.stats(0)
        except Exception as e:  # noqa: BLE001
            errs.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errs
    # main() self-check in a subprocess
    out = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "pen-testing OK" in out.stdout
