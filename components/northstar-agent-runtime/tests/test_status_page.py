"""Tests for status_page (Statuspage.io-shaped incident bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import status_page as sp

THIS_DIR = Path(__file__).resolve().parent.parent


def fresh(seed: str = "test") -> sp.StatusPage:
    return sp.StatusPage(seed=seed)


# -- pins --------------------------------------------------------------


def test_pins():
    assert sp.STATUS_PAGE_VERSION == "status-page.v1"
    assert sp.STATUS_PAGE_SCHEMA == "northstar.status-page.v1"
    assert sp.COMPONENT_STATUSES == (
        "operational",
        "degraded",
        "partial-outage",
        "major-outage",
        "maintenance",
    )
    assert sp.INCIDENT_STATUSES == (
        "investigating",
        "identified",
        "monitoring",
        "resolved",
    )
    assert sp.IMPACTS == ("none", "minor", "major", "critical")
    assert set(sp._KINDS) == {
        "status.component-registered",
        "status.component-status-set",
        "status.incident-created",
        "status.incident-updated",
        "status.incident-resolved",
        "status.rejected",
    }


def test_stdlib_only():
    tree = ast.parse((THIS_DIR / "status_page.py").read_text())
    allowed = {
        "hashlib",
        "hmac",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "__future__",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# -- components --------------------------------------------------------


def test_component_roundtrip():
    page = fresh()
    rec = page.component("api", "Public API", 0, group="core")
    assert rec.component_id == "api"
    assert rec.name == "Public API"
    assert rec.status == "operational"
    assert rec.group == "core"
    assert rec.verify(seed="test")
    assert page.component_ids() == ("api",)
    assert page.component_record("api") == rec


def test_component_bad_inputs_and_duplicate():
    page = fresh()
    with pytest.raises(sp.DuplicateComponentError):
        page.component("api", "Public API", 0)
        page.component("api", "Public API", 1)
    seq = 1
    for bad_id in ("", "  ", "has space"):
        seq += 1
        with pytest.raises(sp.StatusPageError):
            page.component(bad_id, "Name", seq)
    with pytest.raises(sp.UnknownComponentError):
        page.component_record("nope")


def test_set_status_roundtrip_and_history_chain():
    page = fresh()
    page.component("api", "Public API", 0)
    c1 = page.set_status("api", sp.STATUS_DEGRADED, 1)
    c2 = page.set_status("api", sp.STATUS_MAJOR_OUTAGE, 2)
    assert c1.change_id == "chg-1" and c1.prev_digest == "genesis"
    assert c2.prev_digest == c1.digest
    assert c1.verify(seed="test") and c2.verify(seed="test")
    assert page.component_record("api").status == sp.STATUS_MAJOR_OUTAGE
    hist = page.status_history("api")
    assert [c.change_id for c in hist] == ["chg-1", "chg-2"]
    with pytest.raises(sp.BadStatusError):
        page.set_status("api", "on-fire", 3)
    with pytest.raises(sp.UnknownComponentError):
        page.set_status("db", sp.STATUS_DEGRADED, 4)


# -- incidents ---------------------------------------------------------


def test_incident_roundtrip():
    page = fresh()
    page.component("api", "Public API", 0)
    inc = page.incident("inc-1", "API elevated errors", 1, ("api",), sp.IMPACT_MAJOR)
    assert inc.status == sp.INCIDENT_INVESTIGATING
    assert inc.impact == sp.IMPACT_MAJOR
    assert inc.component_ids == ("api",)
    assert inc.verify(seed="test")
    assert page.incident_ids() == ("inc-1",)
    with pytest.raises(sp.DuplicateIncidentError):
        page.incident("inc-1", "Again", 2)
    with pytest.raises(sp.BadIncidentError):
        page.incident("inc-2", "Ghost", 3, ("nope",))
    with pytest.raises(sp.UnknownIncidentError):
        page.incident_record("nope")


def test_update_feed_and_chaining():
    page = fresh()
    page.component("api", "Public API", 0)
    page.incident("inc-1", "API elevated errors", 1, ("api",))
    u1 = page.update("inc-1", sp.INCIDENT_IDENTIFIED, "Bad deploy, rolling back", 2)
    u2 = page.update("inc-1", sp.INCIDENT_MONITORING, "Error rate falling", 3)
    assert u1.update_id == "upd-1" and u1.prev_digest == "genesis"
    assert u2.prev_digest == u1.digest
    assert u1.verify(seed="test") and u2.verify(seed="test")
    assert page.incident_record("inc-1").status == sp.INCIDENT_MONITORING
    feed = page.updates_for("inc-1")
    assert [u.update_id for u in feed] == ["upd-1", "upd-2"]
    with pytest.raises(sp.BadUpdateError):
        page.update("inc-1", sp.INCIDENT_RESOLVED, "Wrong path", 4)
    with pytest.raises(sp.UnknownIncidentError):
        page.update("inc-9", sp.INCIDENT_IDENTIFIED, "Nope", 5)


def test_resolve_terminal():
    page = fresh()
    page.component("api", "Public API", 0)
    page.incident("inc-1", "API elevated errors", 1, ("api",))
    res = page.resolve("inc-1", "Errors back to baseline", 2)
    assert res.resolution_id == "res-1" and res.verify(seed="test")
    assert page.incident_record("inc-1").status == sp.INCIDENT_RESOLVED
    assert page.resolution_for("inc-1") == res
    with pytest.raises(sp.AlreadyResolvedError):
        page.update("inc-1", sp.INCIDENT_MONITORING, "Too late", 3)
    with pytest.raises(sp.AlreadyResolvedError):
        page.resolve("inc-1", "Twice", 4)


# -- seq discipline ----------------------------------------------------


def test_seq_rewind_bool_and_burn():
    page = fresh()
    page.component("api", "Public API", 0)
    n0 = len(page.audit_log())
    with pytest.raises(sp.SeqOrderError):
        page.set_status("api", sp.STATUS_DEGRADED, 0)  # rewind
    assert len(page.audit_log()) == n0  # seq not consumed on shape refusal
    with pytest.raises(sp.StatusPageError):
        page.set_status("api", sp.STATUS_DEGRADED, True)  # bool refused
    with pytest.raises(sp.BadStatusError):
        page.set_status("api", "nope", 1)  # bad value: seq consumed + rejected
    assert page.audit_log()[-1]["kind"] == "status.rejected"
    with pytest.raises(sp.SeqOrderError):
        page.set_status("api", sp.STATUS_DEGRADED, 1)  # burned


# -- aggregate view ----------------------------------------------------


def test_page_status_aggregate():
    page = fresh()
    page.component("api", "Public API", 0)
    page.component("db", "Database", 1)
    v1 = page.page_status(2)
    assert v1.overall == "operational" and v1.component_count == 2
    assert v1.open_incidents == 0 and v1.verify(seed="test")
    page.set_status("db", sp.STATUS_PARTIAL_OUTAGE, 3)
    page.set_status("api", sp.STATUS_DEGRADED, 4)
    page.incident("inc-1", "DB failover", 5, ("db",))
    v2 = page.page_status(6)
    assert v2.overall == "partial-outage"  # worst wins
    assert v2.open_incidents == 1
    assert v2.verify(seed="test")
    assert v2.seq == 6
    # view is read-only: incident still open, no seq consumed
    assert page.incident_record("inc-1").status == sp.INCIDENT_INVESTIGATING


# -- audit -------------------------------------------------------------


def test_audit_shapes_and_message_ban():
    page = fresh()
    page.component("api", "Public API", 0)
    page.set_status("api", sp.STATUS_DEGRADED, 1)
    kinds = [e["kind"] for e in page.audit_log()]
    assert kinds == ["status.component-registered", "status.component-status-set"]
    for e in page.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "status_page"
        assert e["module_version"] == "status-page.v1"
        assert "message" not in e["detail"]
    with pytest.raises(sp.StatusPageError):
        sp.status_page_audit_event("status.incident-updated", 2, message="leak")
    with pytest.raises(sp.StatusPageError):
        sp.status_page_audit_event("bogus.kind", 2)


def test_cross_instance_digest_determinism():
    a, b = fresh(seed="same"), fresh(seed="same")
    a.component("api", "Public API", 0)
    b.component("api", "Public API", 0)
    assert a.component_record("api").digest == b.component_record("api").digest


def test_lookup_errors_and_history_filtering():
    page = fresh()
    page.component("api", "Public API", 0)
    page.component("db", "Database", 1)
    page.set_status("api", sp.STATUS_DEGRADED, 2)
    page.incident("inc-1", "API elevated errors", 3, ("api",))
    with pytest.raises(sp.UnknownComponentError):
        page.status_history("nope")
    hist = page.status_history("db")
    assert hist == ()  # db had no changes; history is per-component
    assert len(page.status_history("api")) == 1
    with pytest.raises(sp.StatusPageError):
        page.resolution_for("inc-1")  # unresolved
    with pytest.raises(sp.UnknownIncidentError):
        page.updates_for("nope")


def test_thread_safety_smoke():
    import threading

    page = fresh()
    errors = []

    def worker(i: int):
        try:
            page.component(f"c-{i}", f"Comp {i}", i)
        except sp.StatusPageError as exc:  # seq races are fail-closed, not crashes
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert page.component_ids()  # at least one won the seq race


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(THIS_DIR / "status_page.py")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "status-page OK" in proc.stdout
