"""Tests for the vuln-disclosure coordination ledger (Simulated)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "vuln_disclosure.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("vuln_disclosure", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["vuln_disclosure"] = module
    spec.loader.exec_module(module)
    return module


vd = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert vd.VULN_DISCLOSURE_VERSION == "vuln-disclosure.v1"
    assert vd.SCHEMA_PIN == "northstar.vuln-disclosure.v1"
    assert vd.SEVERITIES == ("critical", "high", "medium", "low", "informational")
    assert vd.ACTIONS == (
        "vendor-notified",
        "fix-requested",
        "timeline-set",
        "embargo-extended",
        "fix-verified",
    )
    assert vd.WITHDRAW_REASONS == ("manual", "false-positive", "duplicate", "out-of-scope")
    assert vd.AUDIT_KINDS == ("reported", "coordinated", "published", "withdrawn", "rejected")


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


# 3. report roundtrip + verify
def test_report_roundtrip():
    v = vd.VulnDisclosure()
    rec = v.report("VULN-1", 1, affected_digest=PIN, severity="critical",
                   reporter_digest=PIN2, description_digest=PIN)
    assert rec.report_id == "VULN-1"
    assert rec.severity == "critical"
    assert rec.verify()
    assert v.report_record("VULN-1", 0).verify()
    rows = v.audit_log(0)
    assert rows[-1]["kind"] == "reported"
    assert rows[-1]["details"]["report_id"] == "VULN-1"


# 4. duplicate + bad-input table + seq-burn + rejected rows
def test_report_bad_inputs_and_seq_burn():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    seq = 2
    with pytest.raises(vd.DuplicateReportError):
        v.report("VULN-1", seq)
    seq += 1
    with pytest.raises(vd.BadIdError):
        v.report("", seq)
    seq += 1
    with pytest.raises(vd.BadSeverityError):
        v.report("VULN-2", seq, severity="catastrophic")
    seq += 1
    with pytest.raises(vd.BadDigestError):
        v.report("VULN-2", seq, affected_digest="nope")
    # every failed mutation consumed its seq and booked a rejected row
    assert v.stats(0)["seq"] == seq
    rows2 = v.audit_log(0)
    assert len([r for r in rows2 if r["kind"] == "rejected"]) == 4
    # seq is burned: reusing it rewinds bare with no new row
    with pytest.raises(vd.SeqOrderError):
        v.report("VULN-3", seq)
    assert len([r for r in v.audit_log(0) if r["kind"] == "rejected"]) == 4


# 5. coordinate roundtrip + all-5-actions acceptance + minted ids
def test_coordinate_roundtrip():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    ids = []
    for i, action in enumerate(vd.ACTIONS, start=2):
        rec = v.coordinate("VULN-1", i, action=action, note_digest=PIN)
        assert rec.coordination_id == f"crd-{i - 1}"
        assert rec.verify()
        ids.append(rec.coordination_id)
    assert v.coordinations_for("VULN-1", 0) == tuple(ids)
    assert v.coordination_record("crd-1", 0).verify()
    assert v.stats(0)["coordinations"] == 5


# 6. coordinate refusals (unknown / withdrawn / published / bad action)
def test_coordinate_refusals():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    with pytest.raises(vd.UnknownReportError):
        v.coordinate("NOPE", 2, action="vendor-notified")
    v.report("VULN-2", 3)
    v.withdraw("VULN-2", 4, reason="duplicate")
    with pytest.raises(vd.CoordinationStateError):
        v.coordinate("VULN-2", 5, action="vendor-notified")
    v.coordinate("VULN-1", 6, action="vendor-notified")
    v.publish("VULN-1", 7)
    with pytest.raises(vd.CoordinationStateError):
        v.coordinate("VULN-1", 8, action="fix-requested")
    # bad action on a live report
    v.report("VULN-3", 9)
    with pytest.raises(vd.BadActionError):
        v.coordinate("VULN-3", 10, action="send-exploit")
    rows = v.audit_log(0)
    assert len([r for r in rows if r["kind"] == "rejected"]) == 4


# 7. publish roundtrip + terminality
def test_publish_roundtrip_and_terminal():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    v.coordinate("VULN-1", 2, action="vendor-notified")
    pub = v.publish("VULN-1", 3)
    assert pub.publication_id == "pub-1"
    assert pub.report_id == "VULN-1"
    assert pub.verify()
    assert v.publication_record("VULN-1", 0).verify()
    assert v.is_published("VULN-1", 0) is True
    assert v.published_ids(0) == ("VULN-1",)
    assert v.summary("VULN-1", 0).published is True
    # second publish refused; id never recycled
    with pytest.raises(vd.PublishStateError):
        v.publish("VULN-1", 4)
    with pytest.raises(vd.RetiredReportError):
        v.report("VULN-1", 5)
    assert v.stats(0)["published"] == 1


# 8. publish refused without coordination (fail-closed)
def test_publish_requires_coordination():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    with pytest.raises(vd.PublishStateError):
        v.publish("VULN-1", 2)
    with pytest.raises(vd.UnknownReportError):
        v.publish("NOPE", 3)
    # still open, can be coordinated and published later
    v.coordinate("VULN-1", 4, action="timeline-set")
    v.publish("VULN-1", 5)
    assert v.is_published("VULN-1", 0) is True


# 9. withdraw terminality + bad reason + id non-recycling
def test_withdraw_terminality():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    v.report("VULN-2", 2)
    wd = v.withdraw("VULN-1", 3, reason="false-positive")
    assert wd.reason == "false-positive"
    assert wd.verify()
    assert v.withdrawn_ids(0) == ("VULN-1",)
    # post-withdraw mutations refused
    with pytest.raises(vd.CoordinationStateError):
        v.coordinate("VULN-1", 4, action="vendor-notified")
    with pytest.raises(vd.PublishStateError):
        v.publish("VULN-1", 5)
    with pytest.raises(vd.RetiredReportError):
        v.withdraw("VULN-1", 6)
    with pytest.raises(vd.RetiredReportError):
        v.report("VULN-1", 7)
    # all 4 reasons accepted
    seq = 8
    for i, reason in enumerate(vd.WITHDRAW_REASONS):
        rid = f"W-{i}"
        v.report(rid, seq)
        seq += 1
        v.withdraw(rid, seq, reason=reason)
        seq += 1
    assert v.stats(0)["withdrawn"] == 5
    # bad reason refused with seq burn
    v.report("VULN-9", seq)
    with pytest.raises(vd.BadReasonError):
        v.withdraw("VULN-9", seq + 1, reason="bogus")


# 10. summary pure-read semantics
def test_summary_read_purity():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1, severity="high")
    v.coordinate("VULN-1", 2, action="vendor-notified")
    before = len(v.audit_log(0))
    s1 = v.summary("VULN-1", 0)
    s2 = v.summary("VULN-1", 0)
    assert s1.verify() and s2.verify()
    assert s1.coordination_ids == ("crd-1",)
    assert s1.severity == "high"
    assert s1.status == "open"
    assert s1.published is False
    assert len(v.audit_log(0)) == before  # no audit rows on reads
    assert v.stats(0)["seq"] == 2  # reads never consume seq
    with pytest.raises(vd.UnknownReportError):
        v.summary("NOPE", 0)
    assert len(v.audit_log(0)) == before


# 11. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1)
    n_rejected = len([r for r in v.audit_log(0) if r["kind"] == "rejected"])
    # rewind raises bare: no seq burn, no rejected row
    with pytest.raises(vd.SeqOrderError):
        v.report("VULN-2", 1)
    assert v.stats(0)["seq"] == 1
    assert len([r for r in v.audit_log(0) if r["kind"] == "rejected"]) == n_rejected
    # malformed seqs raise bare too
    for bad in (True, "2", 0, -1, 1.5, None):
        with pytest.raises(vd.SeqOrderError):
            v.report("VULN-X", bad)
    assert v.stats(0)["seq"] == 1
    # failed mutation consumes its seq
    with pytest.raises(vd.DuplicateReportError):
        v.report("VULN-1", 2)
    assert v.stats(0)["seq"] == 2


# 12. audit shapes + 16-key leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1, severity="critical")
    v.coordinate("VULN-1", 2, action="vendor-notified")
    v.publish("VULN-1", 3)
    v.report("VULN-2", 4)
    v.withdraw("VULN-2", 5, reason="manual")
    rows = v.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["reported", "coordinated", "published", "reported", "withdrawn"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["seq"] >= 1
        assert not (set(r["details"]) & {
            "exploit", "poc", "proof-of-concept", "payload", "vulnerability",
            "vuln", "crash", "stacktrace", "stack_trace", "secret",
            "raw", "text", "content", "data", "value", "input",
        })
    # banned raw keys refused at the builder boundary
    for key in ("exploit", "poc", "payload", "vulnerability", "crash",
                "stacktrace", "secret", "raw", "text", "content",
                "data", "value", "input", "proof-of-concept", "vuln", "stack_trace"):
        with pytest.raises(vd.AuditKindError):
            vd.vuln_disclosure_audit_event("reported", 1, **{key: "x"})
    with pytest.raises(vd.AuditKindError):
        vd.vuln_disclosure_audit_event("bogus-kind", 1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_digest_determinism_and_tamper():
    a = vd.VulnDisclosure()
    b = vd.VulnDisclosure()
    ra = a.report("VULN-1", 1, severity="high", affected_digest=PIN)
    rb = b.report("VULN-1", 1, severity="high", affected_digest=PIN)
    assert ra.digest == rb.digest
    ca = a.coordinate("VULN-1", 2, action="fix-requested")
    cb = b.coordinate("VULN-1", 2, action="fix-requested")
    assert ca.digest == cb.digest
    # tamper breaks verify (as data, never raised)
    object.__setattr__(ra, "severity", "low")
    assert ra.verify() is False
    # different instance with different content has a different pin
    c = vd.VulnDisclosure()
    rc = c.report("VULN-1", 1, severity="low", affected_digest=PIN)
    assert rc.digest != rb.digest


# 14. stats and views
def test_stats_and_views():
    v = vd.VulnDisclosure()
    v.report("VULN-1", 1, severity="critical")
    v.report("VULN-2", 2, severity="low")
    v.coordinate("VULN-1", 3, action="vendor-notified")
    v.coordinate("VULN-1", 4, action="fix-verified")
    v.publish("VULN-1", 5)
    v.withdraw("VULN-2", 6, reason="out-of-scope")
    assert v.report_ids(0) == ("VULN-1", "VULN-2")
    assert v.coordinations_for("VULN-1", 0) == ("crd-1", "crd-2")
    assert v.coordinations_for("VULN-2", 0) == ()
    assert v.published_ids(0) == ("VULN-1",)
    assert v.withdrawn_ids(0) == ("VULN-2",)
    assert v.is_published("VULN-1", 0) is True
    assert v.is_published("VULN-2", 0) is False
    stats = v.stats(0)
    assert stats["reports"] == 2
    assert stats["open"] == 0
    assert stats["published"] == 1
    assert stats["withdrawn"] == 1
    assert stats["coordinations"] == 2
    assert stats["audit_rows"] == 6
    with pytest.raises(vd.UnknownReportError):
        v.coordinations_for("NOPE", 0)
    with pytest.raises(vd.UnknownReportError):
        v.is_published("NOPE", 0)
    with pytest.raises(vd.UnknownReportError):
        v.publication_record("VULN-2", 0)
    # frozen-ness
    rec = v.report_record("VULN-1", 0)
    with pytest.raises(Exception):
        rec.severity = "low"


# 15. main() subprocess check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    assert "vuln-disclosure OK" in result.stdout
