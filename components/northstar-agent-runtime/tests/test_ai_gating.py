"""Tests for the ai-gating gating-decision ledger, Simulated."""

import dataclasses
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_gating.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_gating", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_gating"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.AI_GATING_VERSION == "ai-gating.v1"
    assert sa.SCHEMA_PIN == "northstar.ai-gating.v1"
    assert sa.GATE_KINDS == (
        "capability-allow",
        "capability-deny",
        "tool-allow",
        "tool-deny",
        "action-allow",
        "action-deny",
        "data-access-allow",
        "data-access-deny",
    )
    assert sa.GATE_DECISIONS == ("allow", "deny")
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("open", "allowlisted", "locked-down", "contested")


# 2. gate() books a declared gating decision with minted id and verified digest
def test_gate_books_decision():
    ledger = sa.AIGating()
    rec = ledger.gate("agent-1", 1, gate_kind="tool-deny", decision="deny",
                      context_digest=PIN)
    assert rec.gate_id == "gate-1"
    assert rec.agent_id == "agent-1"
    assert rec.gate_kind == "tool-deny"
    assert rec.decision == "deny"
    assert rec.context_digest == PIN
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    assert dataclasses.is_dataclass(rec)


# 3. gate() defaults: capability-allow / allow / empty digest
def test_gate_defaults():
    ledger = sa.AIGating()
    rec = ledger.gate("agent-1", 1)
    assert rec.gate_kind == "capability-allow"
    assert rec.decision == "allow"
    assert rec.context_digest == ""
    assert rec.verify() is True


# 4. bad gate_kind fails closed: burns seq and books rejected row
def test_gate_bad_kind_burns_seq():
    ledger = sa.AIGating()
    with pytest.raises(sa.BadGateKindError):
        ledger.gate("agent-1", 1, gate_kind="capability-maybe")
    rows = ledger.audit_log()
    assert len(rows) == 1
    assert rows[0]["kind"] == "rejected"
    assert rows[0]["seq"] == 1
    assert rows[0]["details"]["rejected_kind"] == "BadGateKindError"
    # seq is consumed: the next gate needs a strictly larger seq
    rec = ledger.gate("agent-1", 2)
    assert rec.gate_id == "gate-1"


# 5. bad decision fails closed
def test_gate_bad_decision_burns_seq():
    ledger = sa.AIGating()
    with pytest.raises(sa.BadDecisionError):
        ledger.gate("agent-1", 1, decision="abstain")
    rows = ledger.audit_log()
    assert rows[0]["details"]["rejected_kind"] == "BadDecisionError"


# 6. empty agent id fails closed
def test_gate_empty_agent_burns_seq():
    ledger = sa.AIGating()
    with pytest.raises(sa.BadAgentError):
        ledger.gate("", 1)
    assert ledger.audit_log()[0]["details"]["rejected_kind"] == "BadAgentError"


# 7. bad context digest fails closed
def test_gate_bad_digest_burns_seq():
    ledger = sa.AIGating()
    with pytest.raises(sa.BadDigestError):
        ledger.gate("agent-1", 1, context_digest="not-a-pin")
    assert ledger.audit_log()[0]["details"]["rejected_kind"] == "BadDigestError"


# 8. seq rewind raises bare: no audit row, no seq movement
def test_gate_seq_rewind_raises_bare():
    ledger = sa.AIGating()
    ledger.gate("agent-1", 5)
    with pytest.raises(sa.SeqOrderError):
        ledger.gate("agent-1", 5)
    rows = ledger.audit_log()
    assert len(rows) == 1
    assert rows[0]["kind"] == "gated"


# 9. gated audit row carries declared detail, never raw material
def test_gate_audit_row():
    ledger = sa.AIGating()
    ledger.gate("agent-1", 1, gate_kind="action-allow", decision="allow",
                context_digest=PIN)
    rows = ledger.audit_log()
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-gating"
    assert row["version"] == "ai-gating.v1"
    assert row["kind"] == "gated"
    assert row["details"]["gate_id"] == "gate-1"
    assert row["details"]["gate_kind"] == "action-allow"
    assert row["details"]["decision"] == "allow"
    # banned raw keys never cross the audit boundary
    with pytest.raises(sa.AIGatingError):
        sa.ai_gating_audit_event("gated", 2, prompt="raw prompt")


# 10. verify() re-derives the digest pin: verified verdict
def test_verify_verified():
    ledger = sa.AIGating()
    ledger.gate("agent-1", 1, context_digest=PIN)
    rep = ledger.verify("gate-1", 2)
    assert rep.record_id == "gate-1"
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.digest.startswith("sha256:")
    assert rep.verify() is True
    # pure read: no new audit row (only the original gated row)
    assert len(ledger.audit_log()) == 1


# 11. verify() unknown gate id raises
def test_verify_unknown_gate():
    ledger = sa.AIGating()
    with pytest.raises(sa.UnknownGateError):
        ledger.verify("gate-9", 1)


# 12. verify() detects tampering as data
def test_verify_tampered():
    ledger = sa.AIGating()
    rec = ledger.gate("agent-1", 1, context_digest=PIN)
    ledger._gates[rec.gate_id] = dataclasses.replace(rec, decision="deny")
    rep = ledger.verify(rec.gate_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify() is True  # report itself is intact


# 13. evaluate(): unknown agent evaluates as open, zero tallies
def test_evaluate_open_for_unknown_agent():
    ledger = sa.AIGating()
    rep = ledger.evaluate("no-such-agent", 1)
    assert rep.posture == "open"
    assert rep.n_gates == 0
    assert rep.n_allow == 0
    assert rep.n_deny == 0
    assert rep.integrity_ok is True
    assert rep.digest.startswith("sha256:")
    assert rep.verify() is True


# 14. evaluate(): contested / allowlisted / locked-down postures
def test_evaluate_postures():
    ledger = sa.AIGating()
    # only allows -> allowlisted
    ledger.gate("agent-a", 1, decision="allow")
    rep = ledger.evaluate("agent-a", 2)
    assert rep.posture == "allowlisted"
    assert rep.n_gates == 1 and rep.n_allow == 1 and rep.n_deny == 0
    # only denies -> locked-down
    ledger.gate("agent-b", 3, gate_kind="tool-deny", decision="deny")
    ledger.gate("agent-b", 4, gate_kind="capability-deny", decision="deny")
    rep = ledger.evaluate("agent-b", 5)
    assert rep.posture == "locked-down"
    assert rep.n_gates == 2 and rep.n_allow == 0 and rep.n_deny == 2
    # mixed -> contested
    ledger.gate("agent-c", 6, decision="allow")
    ledger.gate("agent-c", 7, gate_kind="data-access-deny", decision="deny")
    rep = ledger.evaluate("agent-c", 8)
    assert rep.posture == "contested"
    assert rep.n_gates == 2 and rep.n_allow == 1 and rep.n_deny == 1
    assert rep.verify() is True


# 15. evaluate() / verify() seq is shape-validated only, bad agent id raises
def test_evaluate_bad_agent_and_seq_shape():
    ledger = sa.AIGating()
    with pytest.raises(sa.BadAgentError):
        ledger.evaluate("  ", 1)
    with pytest.raises(sa.SeqOrderError):
        ledger.evaluate("agent-1", True)
    with pytest.raises(sa.SeqOrderError):
        ledger.verify("gate-1", "x")
