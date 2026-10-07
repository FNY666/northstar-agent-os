"""Tests for the legal-hold (eDiscovery) decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "legal_hold.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("legal_hold", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["legal_hold"] = module
    spec.loader.exec_module(module)
    return module


lh = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert lh.LEGAL_HOLD_VERSION == "legal-hold.v1"
    assert lh.SCHEMA_PIN == "northstar.legal-hold.v1"
    assert lh.ISSUE_REASONS == (
        "litigation",
        "investigation",
        "regulatory-request",
        "subpoena",
        "audit",
        "manual",
    )
    assert lh.SCOPES == (
        "all-data",
        "email",
        "documents",
        "chat",
        "code",
        "backups",
        "financial-records",
    )
    assert lh.RELEASE_REASONS == (
        "matter-closed",
        "hold-superseded",
        "court-order",
        "scope-reduced",
        "manual",
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


# 3. issue roundtrip + verify()
def test_issue_roundtrip():
    h = lh.LegalHold()
    rec = h.issue("h1", 1, issue_reason="litigation", scope="email",
                  matter_digest=PIN, custodian_digest=PIN2)
    assert rec.hold_id == "h1"
    assert rec.issue_reason == "litigation"
    assert rec.scope == "email"
    assert rec.matter_digest == PIN
    assert rec.custodian_digest == PIN2
    assert rec.verify()
    assert h.hold_record("h1", 0).verify()
    assert h.hold_ids(0) == ("h1",)
    assert h.active_ids(0) == ("h1",)
    assert h.is_active("h1", 0)


# 4. issue bad inputs + duplicate + seq burn + rejected rows
def test_issue_bad_inputs():
    h = lh.LegalHold()
    h.issue("h1", 1, issue_reason="audit", scope="chat")
    with pytest.raises(lh.DuplicateHoldError):
        h.issue("h1", 2, issue_reason="audit", scope="chat")
    for bad_id in ("", None, 123, "x" * 129):
        g = lh.LegalHold()
        with pytest.raises(lh.BadHoldError):
            g.issue(bad_id, 1)
    g = lh.LegalHold()
    with pytest.raises(lh.BadReasonError):
        g.issue("h2", 1, issue_reason="revenge")
    g = lh.LegalHold()
    with pytest.raises(lh.BadScopeError):
        g.issue("h2", 1, scope="everything")
    g = lh.LegalHold()
    with pytest.raises(lh.BadDigestError):
        g.issue("h2", 1, matter_digest="not-a-pin")
    # seq burn: the failed duplicate consumed seq 2
    h.release("h1", 3)
    rows = h.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["details"]["rejected_kind"] == "issue"


# 5. release roundtrip + terminality
def test_release_roundtrip_and_terminality():
    h = lh.LegalHold()
    h.issue("h1", 1, issue_reason="subpoena", scope="documents")
    rel = h.release("h1", 2, reason="matter-closed")
    assert rel.hold_id == "h1"
    assert rel.reason == "matter-closed"
    assert rel.verify()
    assert h.release_record("h1", 0).verify()
    assert h.released_ids(0) == ("h1",)
    assert h.active_ids(0) == ()
    assert not h.is_active("h1", 0)
    # double release refused
    with pytest.raises(lh.ReleasedHoldError):
        h.release("h1", 3)
    # released id never recycled
    with pytest.raises(lh.ReleasedHoldError):
        h.issue("h1", 4)
    # unknown hold
    g = lh.LegalHold()
    with pytest.raises(lh.UnknownHoldError):
        g.release("nope", 1)
    # bad reason
    g2 = lh.LegalHold()
    g2.issue("h2", 1)
    with pytest.raises(lh.BadReasonError):
        g2.release("h2", 2, reason="because")


# 6. all vocabulary accepted
def test_full_vocabulary():
    h = lh.LegalHold()
    for i, reason in enumerate(lh.ISSUE_REASONS):
        h.issue(f"h-{reason}", i + 1, issue_reason=reason)
    assert h.stats(0)["holds"] == len(lh.ISSUE_REASONS)
    h2 = lh.LegalHold()
    for i, scope in enumerate(lh.SCOPES):
        h2.issue(f"s-{scope}", i + 1, scope=scope)
    assert h2.stats(0)["holds"] == len(lh.SCOPES)
    h3 = lh.LegalHold()
    for i, reason in enumerate(lh.RELEASE_REASONS):
        h3.issue(f"r{i}", 2 * i + 1)
        h3.release(f"r{i}", 2 * i + 2, reason=reason)
    assert h3.stats(0)["released"] == len(lh.RELEASE_REASONS)


# 7. audit report math + verify + read purity
def test_audit_report():
    h = lh.LegalHold()
    h.issue("a1", 1, scope="email")
    h.issue("a2", 2, scope="chat")
    h.release("a1", 3, reason="matter-closed")
    report = h.audit(0)
    assert report.verify()
    assert report.n_holds == 2
    assert report.n_active == 1
    assert report.n_released == 1
    assert report.statuses == (("a1", "released"), ("a2", "active"))
    assert report.integrity_ok
    # read purity: same seq twice, no audit rows, seq not consumed
    before = len(h.audit_log(0))
    report2 = h.audit(0)
    assert report2.verify()
    assert len(h.audit_log(0)) == before
    assert h.stats(0)["audit_rows"] == before
    # scoped audit
    one = h.audit(0, hold_id="a2")
    assert one.n_holds == 1 and one.n_active == 1 and one.n_released == 0
    assert one.statuses == (("a2", "active"),)
    # unknown hold as data
    none = h.audit(0, hold_id="ghost")
    assert none.n_holds == 0 and none.statuses == ()
    assert none.integrity_ok


# 8. seq discipline
def test_seq_discipline():
    h = lh.LegalHold()
    h.issue("s1", 5)
    with pytest.raises(lh.SeqOrderError):
        h.issue("s2", 5)
    with pytest.raises(lh.SeqOrderError):
        h.issue("s2", 3)
    with pytest.raises(lh.SeqOrderError):
        h.release("s1", True)
    with pytest.raises(lh.SeqOrderError):
        h.release("s1", "x")
    # rewind raises bare: no rejected row, seq still free
    before = len(h.audit_log(0))
    with pytest.raises(lh.SeqOrderError):
        h.release("s1", 1)
    assert len(h.audit_log(0)) == before
    # view read seq validation
    with pytest.raises(lh.SeqOrderError):
        h.hold_ids(-1)
    with pytest.raises(lh.SeqOrderError):
        h.audit(-1)


# 9. audit event builder shapes + leak ban + bad kind
def test_audit_event_builder():
    row = lh.legal_hold_audit_event("issued", 1, hold_id="h1",
                                    issue_reason="litigation", scope="email")
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "issued"
    assert row["seq"] == 1
    row = lh.legal_hold_audit_event("released", 2, hold_id="h1",
                                    reason="matter-closed")
    assert row["kind"] == "released"
    row = lh.legal_hold_audit_event("rejected", 3, rejected_kind="issue")
    assert row["kind"] == "rejected"
    with pytest.raises(lh.AuditKindError):
        lh.legal_hold_audit_event("published", 1)
    for banned in ("matter", "custodian", "email", "text", "content",
                   "payload", "raw", "description", "note", "secret"):
        with pytest.raises(lh.AuditKindError):
            lh.legal_hold_audit_event("issued", 1, **{banned: "x"})
    with pytest.raises(lh.SeqOrderError):
        lh.legal_hold_audit_event("issued", -1)
    with pytest.raises(lh.SeqOrderError):
        lh.legal_hold_audit_event("issued", True)


# 10. no raw matter/custodian material in audit log
def test_audit_log_has_no_raw_material():
    h = lh.LegalHold()
    h.issue("m1", 1, issue_reason="litigation", scope="email",
            matter_digest=PIN, custodian_digest=PIN2)
    h.release("m1", 2, reason="matter-closed")
    rows = h.audit_log(0)
    assert len(rows) == 2
    for row in rows:
        details = row["details"]
        assert "matter_digest" not in details or details.get(
            "matter_digest", "") == ""
        assert "custodian" not in details
        assert "matter" not in details
    kinds = [r["kind"] for r in rows]
    assert kinds == ["issued", "released"]
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)


# 11. tamper breaks verify
def test_tamper_breaks_verify():
    h = lh.LegalHold()
    rec = h.issue("t1", 1)
    assert rec.verify()
    object.__setattr__(rec, "scope", "chat")
    assert not rec.verify()
    rel = h.release("t1", 2)
    assert rel.verify()
    object.__setattr__(rel, "reason", "manual")
    assert not rel.verify()
    # audit report flags tamper as data
    report = h.audit(0)
    assert not report.integrity_ok
    assert report.verify()


# 12. cross-instance digest determinism
def test_cross_instance_determinism():
    h1 = lh.LegalHold()
    h2 = lh.LegalHold()
    r1 = h1.issue("d1", 1, issue_reason="investigation", scope="code",
                  matter_digest=PIN, custodian_digest=PIN2)
    r2 = h2.issue("d1", 1, issue_reason="investigation", scope="code",
                  matter_digest=PIN, custodian_digest=PIN2)
    assert r1.digest == r2.digest
    h1.release("d1", 2, reason="court-order")
    h2.release("d1", 2, reason="court-order")
    a1 = h1.audit(0)
    a2 = h2.audit(0)
    assert a1.digest == a2.digest


# 13. frozen records + concurrency smoke
def test_frozen_and_concurrent_reads():
    h = lh.LegalHold()
    h.issue("c1", 1)
    h.issue("c2", 2)
    rec = h.hold_record("c1", 0)
    with pytest.raises(Exception):
        rec.hold_id = "mutated"  # frozen dataclass
    errors = []

    def reader():
        try:
            for _ in range(50):
                h.hold_ids(0)
                h.stats(0)
                h.audit(0)
                h.audit_log(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 14. views and stats
def test_views_and_stats():
    h = lh.LegalHold()
    assert h.hold_ids(0) == ()
    assert h.stats(0) == {"holds": 0, "active": 0, "released": 0,
                          "audit_rows": 0}
    h.issue("v1", 1)
    h.issue("v2", 2)
    h.release("v1", 3)
    assert h.hold_ids(0) == ("v1", "v2")
    assert h.active_ids(0) == ("v2",)
    assert h.released_ids(0) == ("v1",)
    assert h.is_active("v2", 0)
    assert not h.is_active("ghost", 0)
    assert h.stats(0) == {"holds": 2, "active": 1, "released": 1,
                          "audit_rows": 3}
    with pytest.raises(lh.UnknownHoldError):
        h.hold_record("ghost", 0)
    with pytest.raises(lh.UnknownHoldError):
        h.release_record("v2", 0)


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "legal-hold OK: issue, release, audit, pins" in proc.stdout
