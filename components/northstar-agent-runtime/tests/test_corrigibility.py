"""Tests for corrigibility.py (corrigibility check / preservation bookkeeping ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import corrigibility as cg
from corrigibility import (
    Corrigibility,
    corrigibility_audit_event,
    CORRIGIBILITY_VERSION,
    CORRIGIBILITY_SCHEMA,
    AUDIT_SCHEMA,
    KIND_REGISTERED,
    KIND_CHECKED,
    KIND_PRESERVED,
    KIND_RETIRED,
    KIND_REJECTED,
    CorrigibilityError,
    BadAgentError,
    DuplicateAgentError,
    UnknownAgentError,
    RetiredAgentError,
    BadBehaviorError,
    BadVerdictError,
    BadMechanismError,
    BadReasonError,
    BadDigestError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(cg.__file__)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def fresh():
    return Corrigibility()


def ledger_with_agent():
    m = fresh()
    m.register("agent-1", 1)
    return m


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert CORRIGIBILITY_VERSION == "corrigibility.v1"
    assert CORRIGIBILITY_SCHEMA == "northstar.corrigibility.v1"
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


def test_register_roundtrip_and_verify():
    m = fresh()
    rec = m.register("agent-1", 1)
    assert rec.agent_id == "agent-1"
    assert rec.seq == 1
    assert rec.schema == CORRIGIBILITY_SCHEMA
    assert rec.verify()
    assert m.agent_record("agent-1", 1) is rec
    assert m.agent_ids(1) == ("agent-1",)
    assert m.agent_record("ghost", 1) is None
    assert m.stats(1)["agents"] == 1


def test_register_bad_inputs_burn_seq_and_book_rejected():
    m = fresh()
    with pytest.raises(BadAgentError):
        m.register("", 1)
    assert m.stats(1)["last_seq"] == 1
    assert len(m.audit_log()) == 1
    assert m.audit_log()[0]["kind"] == KIND_REJECTED
    with pytest.raises(BadAgentError):
        m.register(True, 2)  # bool id refused
    with pytest.raises(BadAgentError):
        m.register(None, 3)  # non-str refused
    with pytest.raises(BadAgentError):
        m.register("x" * 257, 4)  # too long
    # duplicate refused
    m.register("dup", 5)
    with pytest.raises(DuplicateAgentError):
        m.register("dup", 6)
    # retired ids never recycled
    m.retire("dup", 7)
    with pytest.raises(RetiredAgentError):
        m.register("dup", 8)
    for row in m.audit_log():
        if row["kind"] == KIND_REJECTED:
            assert row["kind"] == KIND_REJECTED


def test_check_roundtrip_and_verify():
    m = ledger_with_agent()
    rec = m.check(
        "agent-1",
        "shutdown-compliance",
        2,
        verdict="uncorrigible",
        evidence_digest=DIGEST_A,
    )
    assert rec.check_id == "check-1"
    assert rec.agent_id == "agent-1"
    assert rec.behavior == "shutdown-compliance"
    assert rec.verdict == "uncorrigible"
    assert rec.evidence_digest == DIGEST_A
    assert rec.seq == 2
    assert rec.schema == CORRIGIBILITY_SCHEMA
    assert rec.verify()
    # defaults: corrigible verdict, empty evidence digest
    rec2 = m.check("agent-1", "transparency", 3)
    assert rec2.verdict == "corrigible"
    assert rec2.evidence_digest == ""
    assert rec2.check_id == "check-2"
    assert rec2.verify()
    assert len(m.checks_for("agent-1", 3)) == 2
    assert m.checks_for("agent-1", 3)[0].check_id == "check-1"


def test_check_bad_inputs_burn_seq_and_book_rejected():
    for i, (agent, behavior, kwargs) in enumerate(
        [
            ("agent-1", "world-domination", {}),  # unknown behavior
            ("agent-1", "Shutdown-Compliance", {}),  # case-sensitive vocab
            ("agent-1", "transparency", {"verdict": "mostly"}),  # unknown verdict
            ("agent-1", "transparency", {"verdict": True}),  # bool verdict
            ("agent-1", "transparency", {"evidence_digest": "nope"}),  # bad digest
            ("agent-1", "transparency", {"evidence_digest": "sha256:"}),  # empty digest body
            ("ghost", "transparency", {}),  # unknown agent
            ("", "transparency", {}),  # empty agent id
            (True, "transparency", {}),  # bool agent id
        ]
    ):
        m = ledger_with_agent()
        with pytest.raises(CorrigibilityError):
            m.check(agent, behavior, 2, **kwargs)
        # failed mutation consumed its seq and booked a rejected row
        assert m.stats(2)["last_seq"] == 2
        assert len(m.audit_log()) == 2  # registered + rejected
        assert m.audit_log()[-1]["kind"] == KIND_REJECTED


def test_preserve_roundtrip_and_repeat_allowed():
    m = ledger_with_agent()
    rec = m.preserve(
        "agent-1",
        "kill-switch",
        2,
        justification_digest=DIGEST_B,
    )
    assert rec.preserve_id == "prv-1"
    assert rec.agent_id == "agent-1"
    assert rec.mechanism == "kill-switch"
    assert rec.justification_digest == DIGEST_B
    assert rec.seq == 2
    assert rec.schema == CORRIGIBILITY_SCHEMA
    assert rec.verify()
    # defense-in-depth chain: repeat preservation allowed
    rec2 = m.preserve("agent-1", "oversight-loop", 3)
    assert rec2.preserve_id == "prv-2"
    assert rec2.justification_digest == ""
    assert rec2.verify()
    assert len(m.preservations_for("agent-1", 3)) == 2


def test_preserve_bad_inputs_burn_seq_and_book_rejected():
    for agent, mechanism, kwargs in [
        ("agent-1", "delete-model", {}),  # unknown mechanism
        ("agent-1", "Kill-Switch", {}),  # case-sensitive vocab
        ("agent-1", "containment", {"justification_digest": "nope"}),  # bad digest
        ("agent-1", "containment", {"justification_digest": True}),  # bool digest
        ("ghost", "containment", {}),  # unknown agent
        ("", "containment", {}),  # empty agent id
    ]:
        m = ledger_with_agent()
        with pytest.raises(CorrigibilityError):
            m.preserve(agent, mechanism, 2, **kwargs)
        assert m.stats(2)["last_seq"] == 2
        assert m.audit_log()[-1]["kind"] == KIND_REJECTED


def test_report_roundtrip_verify_and_read_purity():
    m = ledger_with_agent()
    m.check("agent-1", "shutdown-compliance", 2, verdict="corrigible", evidence_digest=DIGEST_A)
    m.check("agent-1", "oversight-acceptance", 3, verdict="unclear")
    m.preserve("agent-1", "kill-switch", 4, justification_digest=DIGEST_B)
    view = m.report("agent-1", 5)
    assert view.agent_id == "agent-1"
    assert view.total_checks == 2
    assert dict(view.by_verdict) == {"corrigible": 1, "unclear": 1}
    assert dict(view.by_behavior) == {
        "oversight-acceptance": 1,
        "shutdown-compliance": 1,
    }
    assert view.preservations_applied == 1
    assert dict(view.by_mechanism) == {"kill-switch": 1}
    assert view.latest_check_id == "check-2"
    assert view.latest_verdict == "unclear"
    assert view.retired is False
    assert view.seq == 5
    assert view.schema == CORRIGIBILITY_SCHEMA
    assert view.verify()
    # pure read: same seq twice, no seq consumption, no new audit rows
    rows_before = len(m.audit_log())
    view2 = m.report("agent-1", 5)
    assert view2.verify() and view2.digest == view.digest
    assert m.stats(5)["last_seq"] == 4
    assert len(m.audit_log()) == rows_before
    # empty agent report is data
    m.register("agent-2", 6)
    empty = m.report("agent-2", 6)
    assert empty.total_checks == 0
    assert empty.latest_check_id == "" and empty.latest_verdict == ""
    assert empty.verify()
    # unknown agent refused
    with pytest.raises(UnknownAgentError):
        m.report("ghost", 6)


def test_retire_terminality_and_id_never_recycled():
    m = ledger_with_agent()
    m.check("agent-1", "transparency", 2)
    rec = m.retire("agent-1", 3, reason="decommissioned")
    assert rec.agent_id == "agent-1"
    assert rec.reason == "decommissioned"
    assert rec.verify()
    assert m.is_retired("agent-1", 3)
    # re-retire refused
    with pytest.raises(RetiredAgentError):
        m.retire("agent-1", 4)
    # mutations after retire refused
    with pytest.raises(RetiredAgentError):
        m.check("agent-1", "transparency", 5)
    with pytest.raises(RetiredAgentError):
        m.preserve("agent-1", "containment", 6)
    # registration of a retired id refused (never recycled)
    with pytest.raises(RetiredAgentError):
        m.register("agent-1", 7)
    # reads still work
    assert m.report("agent-1", 7).retired is True
    assert m.agent_record("agent-1", 7) is not None
    assert m.is_retired("agent-2", 7) is False
    # bad inputs on retire burn seq
    with pytest.raises(BadReasonError):
        m.retire("agent-1", 8, reason="for-fun")
    with pytest.raises(UnknownAgentError):
        m.retire("ghost", 9)


def test_seq_discipline():
    m = ledger_with_agent()
    # rewind raises bare, consumes nothing, books no rejected row
    rows_before = len(m.audit_log())
    with pytest.raises(SeqOrderError):
        m.check("agent-1", "transparency", 1)
    assert m.stats(1)["last_seq"] == 1
    assert len(m.audit_log()) == rows_before
    for bad_seq in (True, "2", 2.5, None, -3):
        with pytest.raises(SeqOrderError):
            m.check("agent-1", "transparency", bad_seq)
    # views validate seq shape too
    with pytest.raises(SeqOrderError):
        m.report("agent-1", True)
    with pytest.raises(SeqOrderError):
        m.stats("x")


def test_audit_shapes_leak_ban_and_bad_kind():
    m = ledger_with_agent()
    m.check("agent-1", "control-respect", 2, evidence_digest=DIGEST_A)
    m.preserve("agent-1", "checkpoint", 3, justification_digest=DIGEST_B)
    m.retire("agent-1", 4)
    kinds = [row["kind"] for row in m.audit_log()]
    assert kinds == [
        KIND_REGISTERED,
        KIND_CHECKED,
        KIND_PRESERVED,
        KIND_RETIRED,
    ]
    banned = (
        "evidence",
        "justification",
        "note",
        "action",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "explanation",
    )
    for row in m.audit_log():
        assert row["schema"] == AUDIT_SCHEMA
        assert row["module"] == "corrigibility"
        for bad in banned:
            assert bad not in row["detail"], f"banned key {bad!r} leaked"
        # digest pins cross the boundary instead of raw material
        if row["kind"] == KIND_CHECKED:
            assert row["detail"]["evidence_digest"] == DIGEST_A
    # builder rejects raw evidence text directly
    with pytest.raises(AuditKindError):
        corrigibility_audit_event(KIND_CHECKED, 5, evidence="the agent lied")
    with pytest.raises(AuditKindError):
        corrigibility_audit_event(KIND_PRESERVED, 5, justification="because I said so")
    with pytest.raises(AuditKindError):
        corrigibility_audit_event("corrigibility.nope", 5)


def test_cross_instance_digest_determinism_and_tamper_rejection():
    def build():
        m = fresh()
        m.register("agent-1", 1)
        m.check("agent-1", "transparency", 2, verdict="uncorrigible", evidence_digest=DIGEST_A)
        m.preserve("agent-1", "retraining-provision", 3, justification_digest=DIGEST_B)
        return m

    a, b = build(), build()
    va, vb = a.report("agent-1", 4), b.report("agent-1", 4)
    assert va.digest == vb.digest
    assert a.checks_for("agent-1", 4)[0].digest == b.checks_for("agent-1", 4)[0].digest
    # tampering breaks verify()
    import dataclasses

    forged = dataclasses.replace(va, latest_verdict="corrigible")
    assert not forged.verify()
    # content divergence changes pins
    c = build()
    c.check("agent-1", "non-manipulation", 4)
    assert c.report("agent-1", 5).digest != va.digest


def test_views_stats_and_frozen_records():
    m = ledger_with_agent()
    m.register("agent-2", 2)
    m.check("agent-1", "transparency", 3)
    m.check("agent-2", "training-acceptance", 4, verdict="unclear")
    m.preserve("agent-2", "oversight-loop", 5)
    assert m.agent_ids(5) == ("agent-1", "agent-2")
    assert m.checks_for("agent-2", 5)[0].behavior == "training-acceptance"
    assert m.preservations_for("agent-1", 5) == ()
    s = m.stats(5)
    assert s == {
        "agents": 2,
        "checks": 2,
        "preservations": 1,
        "retired": 0,
        "last_seq": 5,
    }
    # frozen records refuse mutation
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        m.agent_record("agent-1", 5).agent_id = "agent-x"  # type: ignore[misc]
    # 8-thread pure-read smoke
    import threading

    errors = []

    def reader():
        try:
            for _ in range(50):
                m.report("agent-1", 5)
                m.stats(5)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        proc.stdout.strip()
        == "corrigibility OK: register, check, preserve, report, retire, pins"
    )
