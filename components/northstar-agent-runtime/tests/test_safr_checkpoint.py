"""Tests for the SAFR checkpoint decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "safr_checkpoint.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("safr_checkpoint", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["safr_checkpoint"] = module
    spec.loader.exec_module(module)
    return module


sc = _load()


# 1. version/schema pins + vocabulary tuples
def test_version_schema_and_vocabularies():
    assert sc.SAFR_CHECKPOINT_VERSION == "safr-checkpoint.v1"
    assert sc.SCHEMA_PIN == "northstar.safr-checkpoint.v1"
    assert sc.AUTHORIZE_DECISIONS == ("allow", "deny", "conditional")
    assert sc.ASSESS_FINDINGS == ("pass", "fail", "inconclusive", "waived")
    assert sc.AUDIT_OUTCOMES == ("executed", "blocked", "aborted", "expired")
    assert sc.POSTURES == (
        "declared",
        "denied",
        "authorized",
        "assessment-failed",
        "assessed",
        "audited",
    )
    assert sc.AUDIT_KINDS == ("declared", "authorized", "assessed", "audited", "rejected")
    assert sc.RETIRE_REASONS == ("manual", "superseded", "expired")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert sc.stdlib_only() is True
    tree = ast.parse(MOD.read_text(encoding="utf-8"))
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. full lifecycle: declare -> authorize(allow) -> assess(pass) -> audit(executed)
def test_full_lifecycle_and_posture_ladder():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "deploy", "restart-service", "prod-api", PIN)
    assert d.declaration_id == "safd-1"
    assert d.seq == 1
    assert d.digest.startswith("sha256:")
    assert cp.posture(d.declaration_id) == "declared"
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.intent = "x"  # type: ignore[misc]

    a = cp.authorize(2, d.declaration_id, "allow", "policy-engine", PIN)
    assert a.authorization_id == "safa-1"
    assert cp.posture(d.declaration_id) == "authorized"

    s = cp.assess(3, d.declaration_id, "pass", PIN)
    assert s.assessment_id == "safs-1"
    assert cp.posture(d.declaration_id) == "assessed"

    u = cp.audit(4, d.declaration_id, "executed", PIN)
    assert u.audit_id == "safu-1"
    assert cp.posture(d.declaration_id) == "audited"

    stats = cp.stats()
    assert stats["declarations"] == 1
    assert stats["authorizations"] == 1
    assert stats["assessments"] == 1
    assert stats["audits"] == 1
    assert stats["rejected"] == 0


# 4. bad-input table
def test_bad_inputs():
    cp = sc.SafrCheckpoint()
    # declare: empty strings + bad pin
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(1, "", "act", "subj", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(2, "intent", "", "subj", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(3, "intent", "act", "", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(4, "intent", "act", "subj", "not-a-pin")
    d = cp.declare(5, "intent", "act", "subj", PIN)
    # authorize: bad decision, empty authorizer, bad pin, unknown declaration
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(6, d.declaration_id, "maybe", "authz", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(7, d.declaration_id, "allow", "", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(8, d.declaration_id, "allow", "authz", "bad-pin")
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(9, "safd-999", "allow", "authz", PIN)
    # non-int seq
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(True, "intent", "act", "subj", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare("10", "intent", "act", "subj", PIN)  # type: ignore[arg-type]
    a = cp.authorize(10, d.declaration_id, "allow", "authz", PIN)
    assert a.authorization_id == "safa-1"
    # assess: bad finding, bad pin
    with pytest.raises(sc.SafrCheckpointError):
        cp.assess(11, d.declaration_id, "meh", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.assess(12, d.declaration_id, "pass", "nope")
    s = cp.assess(13, d.declaration_id, "pass", PIN)
    assert s.assessment_id == "safs-1"
    # audit: bad outcome, bad pin
    with pytest.raises(sc.SafrCheckpointError):
        cp.audit(14, d.declaration_id, "done-ish", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.audit(15, d.declaration_id, "executed", "nope")
    u = cp.audit(16, d.declaration_id, "executed", PIN)
    assert u.audit_id == "safu-1"
    # posture on unknown declaration
    with pytest.raises(sc.SafrCheckpointError):
        cp.posture("safd-999")


# 5. deny is terminal
def test_deny_terminal():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "delete", "drop-table", "prod-db", PIN)
    cp.authorize(2, d.declaration_id, "deny", "policy-engine", PIN)
    assert cp.posture(d.declaration_id) == "denied"
    with pytest.raises(sc.SafrCheckpointError):
        cp.assess(3, d.declaration_id, "pass", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.audit(4, d.declaration_id, "blocked", PIN)
    assert cp.posture(d.declaration_id) == "denied"


# 6. fail does not block audit; posture goes assessment-failed then audited
def test_fail_then_audit():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "deploy", "restart", "svc", PIN)
    cp.authorize(2, d.declaration_id, "allow", "authz", PIN)
    cp.assess(3, d.declaration_id, "fail", PIN)
    assert cp.posture(d.declaration_id) == "assessment-failed"
    # audit is still allowed after a failed assessment
    u = cp.audit(4, d.declaration_id, "blocked", PIN)
    assert u.audit_id == "safu-1"
    assert cp.posture(d.declaration_id) == "audited"


# 7. double-gate raises
def test_double_gate_raises():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "i", "a", "s", PIN)
    cp.authorize(2, d.declaration_id, "allow", "authz", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(3, d.declaration_id, "allow", "authz", PIN)
    cp.assess(4, d.declaration_id, "pass", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.assess(5, d.declaration_id, "pass", PIN)
    cp.audit(6, d.declaration_id, "executed", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.audit(7, d.declaration_id, "executed", PIN)


# 8. out-of-order transitions raise
def test_out_of_order_raises():
    cp = sc.SafrCheckpoint()
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(1, "safd-1", "allow", "authz", PIN)  # no declaration yet
    d = cp.declare(2, "i", "a", "s", PIN)
    with pytest.raises(sc.SafrCheckpointError):
        cp.assess(3, d.declaration_id, "pass", PIN)  # not authorized yet
    with pytest.raises(sc.SafrCheckpointError):
        cp.audit(4, d.declaration_id, "executed", PIN)  # not assessed yet


# 9. seq discipline: rewind bare, gap allowed, failed burns + rejected
def test_seq_discipline():
    cp = sc.SafrCheckpoint()
    cp.declare(1, "i", "a", "s", PIN)
    cp.declare(2, "i", "a", "s", PIN)
    rejected_before = cp.stats()["rejected"]
    rows_before = cp.stats()["audit_rows"]
    with pytest.raises(sc.SafrCheckpointError):
        cp.declare(1, "i", "a", "s", PIN)  # rewind: bare
    assert cp.stats()["rejected"] == rejected_before
    assert cp.stats()["audit_rows"] == rows_before
    d3 = cp.declare(3, "i", "a", "s", PIN)  # seq not consumed by rewind
    assert d3.declaration_id == "safd-3"
    # gap allowed
    d10 = cp.declare(10, "i", "a", "s", PIN)
    assert d10.declaration_id == "safd-4"
    d11 = cp.declare(11, "i", "a", "s", PIN)
    assert d11.declaration_id == "safd-5"
    # failed authorize burns seq + rejected row
    with pytest.raises(sc.SafrCheckpointError):
        cp.authorize(12, d11.declaration_id, "bogus", "authz", PIN)
    assert cp.stats()["rejected"] == rejected_before + 1
    last_rejected = cp.audit_log()[-1]
    assert last_rejected["kind"] == "rejected"
    assert last_rejected["seq"] == 12
    # seq 12 is burned; 13 works
    a = cp.authorize(13, d11.declaration_id, "allow", "authz", PIN)
    assert a.authorization_id == "safa-1"


# 10. digest chaining across gates
def test_digest_chaining():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "i", "a", "s", PIN)
    a = cp.authorize(2, d.declaration_id, "allow", "authz", PIN2)
    assert a.declaration_digest == d.digest
    s = cp.assess(3, d.declaration_id, "pass", PIN2)
    assert s.authorization_digest == a.digest
    u = cp.audit(4, d.declaration_id, "executed", PIN2)
    assert u.assessment_digest == s.digest
    # records are frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.decision = "deny"  # type: ignore[misc]


# 11. to_sealed_event mapping
def test_to_sealed_event():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "deploy", "restart", "svc", PIN)
    event = cp.to_sealed_event(d.declaration_id)
    assert set(event.keys()) == {
        "intent",
        "action",
        "subject",
        "authorization",
        "inputs_digest",
        "logic_digest",
        "execution_digest",
        "outcome",
    }
    assert event["intent"] == "deploy"
    assert event["action"] == "restart"
    assert event["subject"] == "svc"
    assert event["authorization"] == "pending"
    assert event["inputs_digest"] == PIN
    assert event["outcome"] == "declared" == cp.posture(d.declaration_id)
    cp.authorize(2, d.declaration_id, "conditional", "authz", PIN)
    cp.assess(3, d.declaration_id, "waived", PIN)
    cp.audit(4, d.declaration_id, "aborted", PIN)
    full = cp.to_sealed_event(d.declaration_id)
    assert full["outcome"] == "audited"
    assert full["authorization"] == "safa-1"
    assert full["inputs_digest"] == PIN
    with pytest.raises(sc.SafrCheckpointError):
        cp.to_sealed_event("safd-999")


# 12. conditional authorize flows through assess and audit
def test_conditional_authorize():
    cp = sc.SafrCheckpoint()
    d = cp.declare(1, "i", "a", "s", PIN)
    cp.authorize(2, d.declaration_id, "conditional", "authz", PIN2)
    assert cp.posture(d.declaration_id) == "authorized"
    cp.assess(3, d.declaration_id, "inconclusive", PIN)
    assert cp.posture(d.declaration_id) == "assessed"
    cp.audit(4, d.declaration_id, "expired", PIN)
    assert cp.posture(d.declaration_id) == "audited"


# 13. stats after a scripted sequence
def test_stats():
    cp = sc.SafrCheckpoint()
    d1 = cp.declare(1, "i", "a", "s", PIN)
    cp.authorize(2, d1.declaration_id, "allow", "authz", PIN)
    cp.assess(3, d1.declaration_id, "pass", PIN)
    cp.audit(4, d1.declaration_id, "executed", PIN)
    d2 = cp.declare(5, "i", "a", "s", PIN)
    cp.authorize(6, d2.declaration_id, "deny", "authz", PIN)
    stats = cp.stats()
    assert stats["declarations"] == 2
    assert stats["authorizations"] == 2
    assert stats["assessments"] == 1
    assert stats["audits"] == 1
    assert stats["rejected"] == 0
    assert stats["audit_rows"] == 6
    kinds = [row["kind"] for row in cp.audit_log()]
    assert kinds == ["declared", "authorized", "assessed", "audited", "declared", "authorized"]
    for row in cp.audit_log():
        assert row["schema"] == "audit.ndjson/1"


# 14. thread smoke: 4 threads x 10 declarations, globally increasing seqs
def test_thread_smoke():
    cp = sc.SafrCheckpoint()
    seq_lock = threading.Lock()
    counter = [0]
    errors = []

    def worker():
        try:
            for _ in range(10):
                with seq_lock:
                    counter[0] += 1
                    s = counter[0]
                cp.declare(s, f"intent-{s}", "act", "subj", PIN)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert cp.stats()["declarations"] == 40
    assert cp.stats()["rejected"] == 0
    ids = sorted(
        (r["ref"] for r in cp.audit_log() if r["kind"] == "declared"),
        key=lambda v: int(v.split("-")[1]),
    )
    assert ids == [f"safd-{i}" for i in range(1, 41)]
    for i in range(1, 41):
        assert cp.posture(f"safd-{i}") == "declared"


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "OK" in proc.stdout
