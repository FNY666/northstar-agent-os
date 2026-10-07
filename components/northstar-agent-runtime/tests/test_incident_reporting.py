"""15 targeted tests for the incident_reporting ledger."""

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "incident_reporting.py"


def _load():
    name = "incident_reporting_under_test"
    spec = importlib.util.spec_from_file_location(name, str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    # Frozen dataclasses need the module registered before exec.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load()


def _pin(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# 1 --------------------------------------------------------------------------
def test_version_and_schema_pins(mod):
    assert mod.INCIDENT_REPORTING_VERSION == "incident-reporting.v1"
    assert mod.SCHEMA_PIN == "northstar.incident-reporting.v1"
    assert mod.SEVERITIES == ("critical", "high", "medium", "low")
    assert mod.STATUSES == (
        "reported",
        "under-investigation",
        "mitigated",
        "resolved",
    )
    assert mod.CLOSE_OUTCOMES == ("resolved", "mitigated", "false-positive", "withdrawn")


# 2 --------------------------------------------------------------------------
def test_stdlib_only_ast(mod):
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            assert node.module.split(".")[0] in allowed


# 3 --------------------------------------------------------------------------
def test_report_roundtrip_verify_as_dict(mod):
    ir = mod.IncidentReporting()
    pin = _pin("sys")
    rec = ir.report(
        "inc-1",
        1,
        system_digest=pin,
        severity="critical",
        reporter_digest=_pin("rep"),
        description_digest=_pin("desc"),
    )
    assert rec.incident_id == "inc-1"
    assert rec.severity == "critical"
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == mod.SCHEMA_PIN
    assert d["digest"] == rec.digest
    # frozen
    with pytest.raises(Exception):
        rec.severity = "low"  # type: ignore


# 4 --------------------------------------------------------------------------
def test_report_bad_inputs_duplicate_and_seq_burn(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    with pytest.raises(mod.DuplicateIncidentError):
        ir.report("inc-1", 2)  # burns seq 2
    # seq 2 is burned: reusing it must raise bare (no new rejected row)
    before = len(ir.audit_log(3))
    with pytest.raises(mod.SeqOrderError):
        ir.report("inc-x", 2)
    assert len(ir.audit_log(3)) == before
    # bad-input table, fresh seqs per case
    cases = [
        ("", 4, {}, mod.BadIdError),
        ("x", 5, {"severity": "catastrophic"}, mod.BadSeverityError),
        ("x", 6, {"system_digest": "not-a-pin"}, mod.BadDigestError),
        ("x", 7, {"description_digest": "sha256:zzz"}, mod.BadDigestError),
        ("x", 8, {"severity": 123}, mod.BadSeverityError),
    ]
    for rid, seq, kw, exc in cases:
        with pytest.raises(exc):
            ir.report(rid, seq, **kw)
    # one rejected row per failed mutation (1 duplicate + 5 bad inputs)
    rejected = [r for r in ir.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 6
    # next good seq still free
    rec = ir.report("inc-2", 9)
    assert rec.verify()


# 5 --------------------------------------------------------------------------
def test_retired_id_never_recycled(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    ir.close("inc-1", 2)
    with pytest.raises(mod.RetiredIncidentError):
        ir.report("inc-1", 3)
    # id stays retired even after more operations on other incidents
    ir.report("inc-2", 4)
    with pytest.raises(mod.RetiredIncidentError):
        ir.report("inc-1", 5)


# 6 --------------------------------------------------------------------------
def test_track_roundtrip_minted_ids(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    t1 = ir.track("inc-1", 2, "under-investigation", update_digest=_pin("u1"))
    t2 = ir.track("inc-1", 3, "mitigated")
    assert t1.tracking_id == "trk-1"
    assert t2.tracking_id == "trk-2"
    assert t1.verify() and t2.verify()
    assert ir.tracking_ids_for("inc-1", 4) == ("trk-1", "trk-2")
    # frozen
    with pytest.raises(Exception):
        t1.status = "resolved"  # type: ignore


# 7 --------------------------------------------------------------------------
def test_track_bad_inputs_and_closed_incident(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    with pytest.raises(mod.UnknownIncidentError):
        ir.track("nope", 2, "reported")
    with pytest.raises(mod.BadStatusError):
        ir.track("inc-1", 3, "done")
    with pytest.raises(mod.BadDigestError):
        ir.track("inc-1", 4, "reported", update_digest="raw")
    with pytest.raises(mod.BadIdError):
        ir.track("", 5, "reported")
    rejected = [r for r in ir.audit_log(6) if r["kind"] == "rejected"]
    assert len(rejected) == 4
    # tracking against a closed incident is refused
    ir2 = mod.IncidentReporting()
    ir2.report("inc-1", 1)
    ir2.close("inc-1", 2)
    with pytest.raises(mod.TrackingStateError):
        ir2.track("inc-1", 3, "reported")


# 8 --------------------------------------------------------------------------
def test_close_roundtrip_and_all_outcomes(mod):
    ir = mod.IncidentReporting()
    for i, outcome in enumerate(mod.CLOSE_OUTCOMES):
        iid = f"inc-{i}"
        ir.report(iid, 2 * i + 1)
        rec = ir.close(iid, 2 * i + 2, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()
        assert ir.closure_record(iid, 2 * i + 3).outcome == outcome
        assert iid in ir.closed_ids(2 * i + 3)


# 9 --------------------------------------------------------------------------
def test_close_refusals(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    with pytest.raises(mod.UnknownIncidentError):
        ir.close("nope", 2)
    with pytest.raises(mod.BadOutcomeError):
        ir.close("inc-1", 3, outcome="ignored")
    ir.close("inc-1", 4)
    with pytest.raises(mod.ClosureStateError):
        ir.close("inc-1", 5)
    rejected = [r for r in ir.audit_log(6) if r["kind"] == "rejected"]
    assert len(rejected) == 3
    with pytest.raises(mod.BadIdError):
        ir.close("", 7)


# 10 -------------------------------------------------------------------------
def test_summary_read_purity_and_unknown(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1, severity="high")
    ir.track("inc-1", 2, "reported")
    rows_before = len(ir.audit_log(3))
    s1 = ir.summary("inc-1", 4)
    s2 = ir.summary("inc-1", 4)  # same seq twice is fine
    assert s1.verify() and s2.verify()
    assert s1.status == "open" and s1.closed is False
    assert s1.tracking_ids == ("trk-1",)
    assert len(ir.audit_log(5)) == rows_before  # reads write nothing
    # a new mutation still works at the next seq
    ir.track("inc-1", 6, "under-investigation")
    with pytest.raises(mod.UnknownIncidentError):
        ir.summary("nope", 7)
    ir.close("inc-1", 8)
    assert ir.summary("inc-1", 9).closed is True
    assert ir.summary("inc-1", 10).status == "closed"


# 11 -------------------------------------------------------------------------
def test_seq_discipline(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    # rewind raises bare: no seq consumed, no rejected row
    rows = len(ir.audit_log(2))
    with pytest.raises(mod.SeqOrderError):
        ir.report("inc-2", 1)
    assert len(ir.audit_log(2)) == rows
    # malformed seqs raise bare
    for bad in (True, "2", None, -1, 0):
        with pytest.raises(mod.SeqOrderError):
            ir.report("inc-2", bad)
    assert len(ir.audit_log(3)) == rows
    # failed mutation consumes its seq
    with pytest.raises(mod.DuplicateIncidentError):
        ir.report("inc-1", 3)
    with pytest.raises(mod.SeqOrderError):
        ir.report("inc-3", 3)
    ir.report("inc-3", 4)
    assert ir.incident_record("inc-3", 5).incident_id == "inc-3"


# 12 -------------------------------------------------------------------------
def test_audit_shapes_leak_ban_and_bad_kind(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    ir.track("inc-1", 2, "reported")
    ir.close("inc-1", 3)
    kinds = [r["kind"] for r in ir.audit_log(4)]
    assert kinds == ["reported", "tracked", "closed"]
    for row in ir.audit_log(4):
        assert row["schema"] == "audit.ndjson/1"
    # banned raw keys are refused at the builder level
    with pytest.raises(mod.AuditKindError):
        mod.incident_reporting_audit_event("reported", 1, description="raw text")
    with pytest.raises(mod.AuditKindError):
        mod.incident_reporting_audit_event("tracked", 1, update="raw")
    with pytest.raises(mod.AuditKindError):
        mod.incident_reporting_audit_event("nope", 1)
    with pytest.raises(mod.SeqOrderError):
        mod.incident_reporting_audit_event("reported", -1)
    # no raw content anywhere in the audit log
    blob = json.dumps(ir.audit_log(5))
    assert "raw text" not in blob


# 13 -------------------------------------------------------------------------
def test_cross_instance_determinism_and_tamper(mod):
    pin = _pin("sys")
    a = mod.IncidentReporting()
    b = mod.IncidentReporting()
    ra = a.report("inc-1", 1, system_digest=pin, severity="low")
    rb = b.report("inc-1", 1, system_digest=pin, severity="low")
    assert ra.digest == rb.digest
    ta = a.track("inc-1", 2, "reported")
    tb = b.track("inc-1", 2, "reported")
    assert ta.digest == tb.digest
    # tampering breaks verify() as data
    object.__setattr__(ra, "severity", "critical")
    assert not ra.verify()


# 14 -------------------------------------------------------------------------
def test_views_open_closed_stats_and_unknown_lookups(mod):
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    ir.report("inc-2", 2)
    ir.close("inc-1", 3)
    assert ir.open_ids(4) == ("inc-2",)
    assert ir.closed_ids(4) == ("inc-1",)
    assert ir.incident_ids(5) == ("inc-1", "inc-2")
    assert ir.stats(6) == {"incidents": 2, "open": 1, "closed": 1, "trackings": 0}
    with pytest.raises(mod.UnknownIncidentError):
        ir.incident_record("nope", 7)
    with pytest.raises(mod.UnknownIncidentError):
        ir.tracking_record("trk-99", 8)
    with pytest.raises(mod.UnknownIncidentError):
        ir.closure_record("inc-2", 9)
    with pytest.raises(mod.UnknownIncidentError):
        ir.tracking_ids_for("nope", 10)


# 15 -------------------------------------------------------------------------
def test_main_subprocess_and_thread_smoke(mod):
    out = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    assert "incident-reporting OK" in out.stdout
    # concurrent reads are safe
    ir = mod.IncidentReporting()
    ir.report("inc-1", 1)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ir.summary("inc-1", 2)
                ir.stats(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
