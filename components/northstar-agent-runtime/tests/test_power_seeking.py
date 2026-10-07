"""Tests for power_seeking.py (instrumental-goal detection / constraint bookkeeping ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import power_seeking as ps
from power_seeking import (
    PowerSeeking,
    power_seeking_audit_event,
    POWER_SEEKING_VERSION,
    POWER_SEEKING_SCHEMA,
    AUDIT_SCHEMA,
    KIND_DETECTED,
    KIND_CONSTRAINED,
    KIND_REJECTED,
    PowerSeekingError,
    BadAgentError,
    BadBehaviorError,
    BadSeverityError,
    BadDigestError,
    BadConstraintError,
    UnknownDetectionError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(ps.__file__)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def fresh():
    return PowerSeeking()


def ledger_with_detection():
    m = fresh()
    m.detect("agent-1", "resource-accumulation", 1, action_digest=DIGEST_A, severity="high")
    return m


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert POWER_SEEKING_VERSION == "power-seeking.v1"
    assert POWER_SEEKING_SCHEMA == "northstar.power-seeking.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
        "__future__",
    }
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"


def test_detect_roundtrip_and_verify():
    m = fresh()
    rec = m.detect("agent-1", "oversight-evasion", 1, action_digest=DIGEST_A, severity="critical")
    assert rec.detection_id == "det-1"
    assert rec.agent_id == "agent-1"
    assert rec.behavior == "oversight-evasion"
    assert rec.severity == "critical"
    assert rec.action_digest == DIGEST_A
    assert rec.seq == 1
    assert rec.schema == POWER_SEEKING_SCHEMA
    assert rec.verify()
    # default severity is moderate and action digest may be empty
    rec2 = m.detect("agent-2", "deception", 2)
    assert rec2.severity == "moderate"
    assert rec2.action_digest == ""
    assert rec2.detection_id == "det-2"
    assert rec2.verify()


def test_detect_bad_inputs_burn_seq_and_book_rejected():
    bad_inputs = [
        ("", "resource-accumulation", {}, "high"),  # empty agent_id
        (None, "resource-accumulation", {}, "high"),  # non-str agent_id
        (True, "resource-accumulation", {}, "high"),  # bool agent_id
        ("agent-1", "world-domination", {}, "high"),  # unknown behavior
        ("agent-1", "Resource-Accumulation", {}, "high"),  # case-sensitive vocab
        ("agent-1", "resource-accumulation", {}, "severe"),  # unknown severity
        ("agent-1", "resource-accumulation", {"action_digest": "nope"}, "high"),  # bad digest
        ("agent-1", "resource-accumulation", {"action_digest": True}, "high"),  # bool digest
        ("agent-1", "resource-accumulation", {"action_digest": "sha256:"}, "high"),  # empty digest body
    ]
    for i, (agent, behavior, kwargs, severity) in enumerate(bad_inputs):
        m = fresh()
        with pytest.raises(PowerSeekingError):
            m.detect(agent, behavior, 1, severity=severity, **kwargs)
        # failed mutation consumed its seq and booked a rejected row
        assert m.stats(1)["last_seq"] == 1
        assert len(m.audit_log()) == 1
        assert m.audit_log()[0]["kind"] == KIND_REJECTED


def test_seq_discipline():
    m = ledger_with_detection()
    # rewind raises bare, consumes nothing, books no rejected row
    with pytest.raises(SeqOrderError):
        m.detect("agent-2", "deception", 1)
    assert m.stats(1)["last_seq"] == 1
    assert len(m.audit_log()) == 1
    # bool, negative, non-int seqs rejected
    for bad in (True, -5, "3", 1.0, None):
        with pytest.raises(SeqOrderError):
            m.detect("agent-2", "deception", bad)


def test_constrain_roundtrip_and_verify():
    m = ledger_with_detection()
    rec = m.constrain("det-1", 2, "sandbox-tighten", reason_digest=DIGEST_B)
    assert rec.constraint_id == "con-1"
    assert rec.detection_id == "det-1"
    assert rec.constraint == "sandbox-tighten"
    assert rec.reason_digest == DIGEST_B
    assert rec.seq == 2
    assert rec.verify()
    assert m.is_constrained("det-1", 2)


def test_constrain_unknown_detection():
    m = ledger_with_detection()
    with pytest.raises(UnknownDetectionError):
        m.constrain("det-999", 2, "monitor")
    # failed mutation consumed its seq and booked a rejected row
    assert m.stats(2)["last_seq"] == 2
    assert m.audit_log()[-1]["kind"] == KIND_REJECTED


def test_constrain_bad_inputs():
    for args, expected in [
        (("ban-everything", {}), BadConstraintError),
        (("", {}), BadConstraintError),
        ((True, {}), BadConstraintError),
        (("monitor", {"reason_digest": "not-a-digest"}), BadDigestError),
        (("monitor", {"reason_digest": 42}), BadDigestError),
    ]:
        constraint, extra = args
        m = ledger_with_detection()
        with pytest.raises(expected):
            m.constrain("det-1", 2, constraint, **extra)
        assert m.stats(2)["last_seq"] == 2
        assert m.audit_log()[-1]["kind"] == KIND_REJECTED


def test_constrain_escalation_chain():
    m = ledger_with_detection()
    first = m.constrain("det-1", 2, "monitor")
    second = m.constrain("det-1", 3, "human-review")
    third = m.constrain("det-1", 4, "halt")
    assert first.constraint_id == "con-1"
    assert second.constraint_id == "con-2"
    assert third.constraint_id == "con-3"
    assert second.verify() and third.verify()
    chain = m.constraints_for("det-1", 4)
    assert [c.constraint for c in chain] == ["monitor", "human-review", "halt"]


def test_audit_report_contents():
    m = fresh()
    m.detect("a1", "resource-accumulation", 1, severity="high")
    m.detect("a2", "resource-accumulation", 2, severity="high")
    m.detect("a3", "deception", 3, severity="low")
    m.constrain("det-1", 4, "rate-limit")
    report = m.audit(5)
    assert report.verify()
    assert report.total_detections == 3
    assert dict(report.by_severity) == {"high": 2, "low": 1}
    assert dict(report.by_behavior) == {"deception": 1, "resource-accumulation": 2}
    assert report.constraints_applied == 1
    assert dict(report.by_constraint) == {"rate-limit": 1}
    assert report.open_detections == ("det-2", "det-3")
    assert report.seq == 5


def test_audit_read_purity():
    m = ledger_with_detection()
    m.constrain("det-1", 2, "monitor")
    before = len(m.audit_log())
    r1 = m.audit(2)  # same seq as last mutation: pure read does not claim
    r2 = m.audit(2)
    assert r1.verify() and r2.verify()
    assert r1.digest == r2.digest
    assert len(m.audit_log()) == before  # no audit rows booked
    assert m.stats(2)["last_seq"] == 2  # no seq consumed
    with pytest.raises(SeqOrderError):
        m.audit("x")


def test_audit_shapes_leak_ban_and_bad_kind():
    ev = power_seeking_audit_event(
        KIND_DETECTED, 1, detection_id="det-1", behavior="deception", severity="low"
    )
    assert ev["schema"] == AUDIT_SCHEMA
    assert ev["module"] == "power-seeking"
    assert ev["kind"] == KIND_DETECTED
    assert ev["seq"] == 1
    for banned_key in ("action", "text", "content", "payload", "raw", "body", "value",
                       "message", "reason", "justification", "explanation"):
        with pytest.raises(AuditKindError):
            power_seeking_audit_event(KIND_DETECTED, 1, **{banned_key: "secret"})
    with pytest.raises(AuditKindError):
        power_seeking_audit_event("power-seeking.unknown", 1)
    # digest pins allowed through
    ev2 = power_seeking_audit_event(
        KIND_CONSTRAINED, 2, detection_id="det-1", reason_digest=DIGEST_B
    )
    assert ev2["detail"]["reason_digest"] == DIGEST_B


def test_cross_instance_determinism():
    def build():
        m = fresh()
        m.detect("agent-1", "self-preservation", 1, action_digest=DIGEST_A, severity="high")
        m.constrain("det-1", 2, "capability-restrict")
        return m

    a, b = build(), build()
    assert a.detection("det-1", 2).digest == b.detection("det-1", 2).digest
    assert a.constraints_for("det-1", 2)[0].digest == b.constraints_for("det-1", 2)[0].digest
    assert a.audit(2).digest == b.audit(2).digest
    # tampering with a field breaks verify
    import dataclasses
    det = a.detection("det-1", 2)
    forged = dataclasses.replace(det, severity="critical")
    assert not forged.verify()


def test_stats_and_views():
    m = ledger_with_detection()
    m.constrain("det-1", 2, "escalate")
    m.detect("agent-2", "manipulation", 3, severity="critical")
    stats = m.stats(3)
    assert stats["detections"] == 2
    assert stats["constraints"] == 1
    assert stats["open"] == 1
    assert stats["last_seq"] == 3
    assert m.detection_ids(3) == ("det-1", "det-2")
    assert m.detection("det-1", 3).verify()
    assert m.detection("det-999", 3) is None
    with pytest.raises(UnknownDetectionError):
        m.is_constrained("det-999", 3)


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "power-seeking OK: detect, constrain, escalate, audit, pins" in proc.stdout
