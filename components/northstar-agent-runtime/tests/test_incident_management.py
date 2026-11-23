"""Tests for incident_management: 15 cases."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import incident_management
from incident_management import (
    INCIDENT_MANAGEMENT_VERSION,
    INCIDENT_MANAGEMENT_SCHEMA,
    AUDIT_SCHEMA,
    SEVERITIES,
    IncidentManagement,
    IncidentManagementError,
    BadIncidentError,
    DuplicateIncidentError,
    UnknownIncidentError,
    ResolvedIncidentError,
    BadPolicyError,
    DuplicatePolicyError,
    UnknownPolicyError,
    MaxEscalationError,
    BadAcknowledgeError,
    SeqOrderError,
    incident_management_audit_event,
)


def fresh():
    return IncidentManagement()


def make_policy(mgr, policy_id="p1", levels=(("alice",), ("bob", "carol")), seq=1):
    return mgr.register_policy(policy_id, levels, seq)


def make_incident(mgr, incident_id="INC-1", title="db down", severity="critical",
                  seq=2, **kwargs):
    return mgr.create(incident_id, title, severity, seq, **kwargs)


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert INCIDENT_MANAGEMENT_VERSION == "incident-management.v1"
    assert INCIDENT_MANAGEMENT_SCHEMA == "northstar.incident-management.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert SEVERITIES == ("critical", "error", "warning", "info")
    mgr = fresh()
    policy = make_policy(mgr)
    assert policy.verify()
    inc = make_incident(mgr, policy_id="p1")
    assert inc.verify()
    ack = mgr.acknowledge("INC-1", "alice", 3)
    assert ack.verify()
    esc = mgr.escalate("INC-1", 4)
    assert esc.verify()
    res = mgr.resolve("INC-1", 5)
    assert res.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "incident_management.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_register_policy_roundtrip():
    mgr = fresh()
    policy = make_policy(mgr)
    assert policy.policy_id == "p1"
    assert policy.levels == (("alice",), ("bob", "carol"))
    assert policy.verify()
    # digest deterministic across instances
    other = fresh()
    assert make_policy(other).digest == policy.digest
    assert mgr.policy("p1").digest == policy.digest
    assert mgr.policy_ids() == ("p1",)
    try:
        mgr.policy("nope")
    except UnknownPolicyError:
        pass
    else:
        raise AssertionError("unknown policy must raise")


# 4 ---------------------------------------------------------------------


def test_register_policy_bad_inputs():
    mgr = fresh()
    bad_levels = [
        [],                      # empty
        [()],                    # empty level
        [("alice", "alice")],     # duplicate responder in level
        [("  ",)],               # blank responder
        ["alice"],               # level is a bare string
        "alice",                 # levels is a bare string
    ]
    seq = 1
    for levels in bad_levels:
        seq += 1
        try:
            mgr.register_policy(f"bad-{seq}", levels, seq)
        except (BadPolicyError, IncidentManagementError):
            pass
        else:
            raise AssertionError(f"bad levels accepted: {levels!r}")
    make_policy(mgr, policy_id="dup", seq=100)
    try:
        mgr.register_policy("dup", (("x",),), 101)
    except DuplicatePolicyError:
        pass
    else:
        raise AssertionError("duplicate policy must raise")
    # 33 levels exceeds the cap
    try:
        mgr.register_policy("too-many", tuple((f"r{i}",) for i in range(33)), 102)
    except BadPolicyError:
        pass
    else:
        raise AssertionError("too many levels must raise")


# 5 ---------------------------------------------------------------------


def test_create_roundtrip_and_severity_urgency():
    mgr = fresh()
    make_policy(mgr)
    inc = make_incident(mgr, incident_id="INC-9", title="latency",
                        severity="warning", service="web", policy_id="p1",
                        seq=2)
    assert inc.status == "triggered"
    assert inc.escalation_level == 0
    assert inc.urgency == "low"          # warning -> low
    assert inc.service == "web"
    crit = mgr.create("INC-10", "outage", "critical", 3)
    assert crit.urgency == "high"
    over = mgr.create("INC-11", "flap", "info", 4, urgency="high")
    assert over.urgency == "high"        # explicit override wins
    # frozen
    try:
        inc.status = "resolved"  # type: ignore[misc]
    except Exception as exc:
        assert type(exc).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("records must be frozen")
    assert mgr.incident("INC-9").digest == inc.digest
    assert mgr.incident_ids() == ("INC-10", "INC-11", "INC-9")


# 6 ---------------------------------------------------------------------


def test_create_bad_inputs_and_duplicates():
    mgr = fresh()
    for kwargs in [
        dict(incident_id="", title="t", severity="critical"),
        dict(incident_id="I", title="  ", severity="critical"),
        dict(incident_id="I", title="t", severity="P1"),
        dict(incident_id="I", title="t", severity="critical", urgency="urgent"),
        dict(incident_id="I", title="t", severity="critical", policy_id="ghost"),
        dict(incident_id="I", title="t" * 513, severity="critical"),
    ]:
        try:
            mgr.create(seq=1, **kwargs)
        except IncidentManagementError:
            pass
        else:
            raise AssertionError(f"bad create accepted: {kwargs!r}")
    make_incident(mgr, incident_id="DUP", seq=10)
    try:
        mgr.create("DUP", "again", "error", 11)
    except DuplicateIncidentError:
        pass
    else:
        raise AssertionError("duplicate incident must raise")
    try:
        mgr.incident("ghost")
    except UnknownIncidentError:
        pass
    else:
        raise AssertionError("unknown incident must raise")


# 7 ---------------------------------------------------------------------


def test_acknowledge_flow():
    mgr = fresh()
    make_incident(mgr, seq=1)
    ack = mgr.acknowledge("INC-1", "alice", 2)
    assert ack.verify()
    assert mgr.incident("INC-1").status == "acknowledged"
    try:
        mgr.acknowledge("INC-1", "bob", 3)
    except BadAcknowledgeError:
        pass
    else:
        raise AssertionError("double acknowledge must raise")
    try:
        mgr.acknowledge("ghost", "alice", 4)
    except UnknownIncidentError:
        pass
    else:
        raise AssertionError("unknown incident ack must raise")
    try:
        mgr.acknowledge("INC-1", "   ", 5)
    except IncidentManagementError:
        pass
    else:
        raise AssertionError("blank responder must raise")


# 8 ---------------------------------------------------------------------


def test_escalate_with_policy_levels():
    mgr = fresh()
    make_policy(mgr, levels=(("l1a",), ("l2a", "l2b")), seq=1)
    make_incident(mgr, policy_id="p1", seq=2)
    e1 = mgr.escalate("INC-1", 3, reason="no ack")
    assert e1.level == 1 and e1.responders == ("l1a",)
    assert e1.esc_id == "esc-1"
    e2 = mgr.escalate("INC-1", 4)
    assert e2.level == 2 and e2.responders == ("l2a", "l2b")
    assert e2.esc_id == "esc-2"
    assert mgr.incident("INC-1").escalation_level == 2
    evts = mgr.escalations_for("INC-1")
    assert [e.level for e in evts] == [1, 2]
    try:
        mgr.escalate("INC-1", 5)
    except MaxEscalationError:
        pass
    else:
        raise AssertionError("escalation past top level must raise")


# 9 ---------------------------------------------------------------------


def test_escalate_without_policy_and_unknown():
    mgr = fresh()
    make_incident(mgr, seq=1)  # no policy attached
    e1 = mgr.escalate("INC-1", 2)
    assert e1.level == 1 and e1.responders == ()
    e2 = mgr.escalate("INC-1", 3)
    assert e2.level == 2
    try:
        mgr.escalate("ghost", 4)
    except UnknownIncidentError:
        pass
    else:
        raise AssertionError("unknown incident escalate must raise")
    try:
        mgr.escalate("INC-1", 5, reason=123)  # type: ignore[arg-type]
    except IncidentManagementError:
        pass
    else:
        raise AssertionError("non-string reason must raise")


# 10 --------------------------------------------------------------------


def test_resolve_terminal_and_refusals():
    mgr = fresh()
    make_incident(mgr, seq=1)
    mgr.acknowledge("INC-1", "alice", 2)
    res = mgr.resolve("INC-1", 3, resolution="hotfix deployed")
    assert res.verify()
    assert mgr.incident("INC-1").status == "resolved"
    assert mgr.open_ids() == ()
    for op in (
        lambda: mgr.acknowledge("INC-1", "alice", 4),
        lambda: mgr.escalate("INC-1", 5),
        lambda: mgr.resolve("INC-1", 6),
    ):
        try:
            op()
        except ResolvedIncidentError:
            pass
        else:
            raise AssertionError("mutation on resolved incident must raise")
    try:
        mgr.resolve("ghost", 7)
    except UnknownIncidentError:
        pass
    else:
        raise AssertionError("unknown incident resolve must raise")


# 11 --------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    mgr = fresh()
    make_incident(mgr, seq=5)
    # rewind
    try:
        mgr.create("I2", "t", "error", 5)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind must raise")
    # bool / negative / wrong type
    for bad in (True, -1, 1.5, "7"):
        try:
            mgr.create("I3", "t", "error", bad)  # type: ignore[arg-type]
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"bad seq accepted: {bad!r}")
    # failed mutation consumes its seq: a post-claim business-rule failure
    # (duplicate) burns seq 6, so the next valid call needs seq > 6
    make_incident(mgr, incident_id="BURN", seq=6)
    try:
        mgr.create("BURN", "dup", "error", 7)
    except DuplicateIncidentError:
        pass
    try:
        mgr.create("I4", "t", "error", 7)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("failed mutation must consume its seq")
    mgr.create("I4", "t", "error", 8)
    assert mgr.incident("I4").severity == "error"


# 12 --------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    mgr = fresh()
    make_policy(mgr, seq=1)
    make_incident(mgr, policy_id="p1", seq=2)
    mgr.acknowledge("INC-1", "alice", 3)
    mgr.escalate("INC-1", 4)
    mgr.resolve("INC-1", 5)
    try:
        mgr.create("INC-1", "dup", "error", 6)
    except DuplicateIncidentError:
        pass
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds == [
        "incident.policy-registered",
        "incident.created",
        "incident.acknowledged",
        "incident.escalated",
        "incident.resolved",
        "incident.rejected",
    ]
    for event in mgr.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert "title" not in event["detail"]
        assert "resolution" not in event["detail"]
        assert "reason" not in event["detail"]
        assert "responders" not in event["detail"]
    try:
        incident_management_audit_event("bogus.kind", {}, 7)
    except IncidentManagementError:
        pass
    else:
        raise AssertionError("bad audit kind must raise")
    try:
        incident_management_audit_event("incident.created", {"title": "x"}, 7)
    except IncidentManagementError:
        pass
    else:
        raise AssertionError("banned audit key must raise")


# 13 --------------------------------------------------------------------


def test_views_and_stats():
    mgr = fresh()
    make_policy(mgr, seq=1)
    make_incident(mgr, incident_id="A", severity="critical", policy_id="p1", seq=2)
    make_incident(mgr, incident_id="B", severity="info", seq=3)
    mgr.acknowledge("A", "alice", 4)
    mgr.resolve("B", 5)
    assert mgr.open_ids() == ("A",)
    assert mgr.stats() == {
        "incidents": 2, "triggered": 0, "acknowledged": 1,
        "resolved": 1, "policies": 1, "escalations": 0,
    }
    d = mgr.as_dict()
    assert d["schema"] == "northstar.incident-management.v1"
    assert d["stats"]["incidents"] == 2
    assert mgr.escalations_for("A") == ()
    try:
        mgr.escalations_for("ghost")
    except UnknownIncidentError:
        pass
    else:
        raise AssertionError("escalations_for unknown must raise")


# 14 --------------------------------------------------------------------


def test_digest_determinism_across_instances():
    mgr_a = fresh()
    mgr_b = fresh()
    make_policy(mgr_a, seq=1)
    make_policy(mgr_b, seq=1)
    a = mgr_a.create("X", "same title", "error", 2, service="s", policy_id="p1")
    b = mgr_b.create("X", "same title", "error", 2, service="s", policy_id="p1")
    assert a.digest == b.digest
    ack_a = mgr_a.acknowledge("X", "r", 3)
    ack_b = mgr_b.acknowledge("X", "r", 3)
    assert ack_a.digest == ack_b.digest
    esc_a = mgr_a.escalate("X", 4, reason="r")
    esc_b = mgr_b.escalate("X", 4, reason="r")
    # esc ids are per-instance counters but digests chain identically
    assert esc_a.digest == esc_b.digest
    res_a = mgr_a.resolve("X", 5, resolution="done")
    res_b = mgr_b.resolve("X", 5, resolution="done")
    assert res_a.digest == res_b.digest


# 15 ---------------------------------------------------------------------


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, "-m", "incident_management"],
        capture_output=True, text=True, cwd=os.path.join(
            os.path.dirname(__file__), ".."),
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "incident-management OK" in result.stdout
