"""Targeted tests for the governance module (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import governance
from governance import (
    GOVERNANCE_VERSION,
    GOVERNANCE_SCHEMA,
    Governance,
    GovernanceError,
    BadPolicyError,
    DuplicatePolicyError,
    UnknownPolicyError,
    RetiredPolicyError,
    BadFrameworkError,
    BadPrincipleError,
    BadTargetError,
    BadVerdictError,
    BadDigestError,
    BadReasonError,
    SeqOrderError,
    AuditKindError,
    FRAMEWORKS,
    VERDICTS,
    FRAMEWORK_NIST,
    FRAMEWORK_OECD,
    VERDICT_COMPLIANT,
    VERDICT_VIOLATION,
    VERDICT_REMEDIATION_REQUIRED,
    REASON_MANUAL,
    REASON_SUPERSEDED,
    governance_audit_event,
)

STDLIB_ALLOW = {"hashlib", "re", "threading", "dataclasses", "fractions",
                "typing", "__future__", "canonical_json", "json"}


def _digest(value):
    return "sha256:" + "0" * 64


def test_01_version_and_schema_pins():
    assert GOVERNANCE_VERSION == "governance.v1"
    assert GOVERNANCE_SCHEMA == "northstar.governance.v1"


def test_02_stdlib_only_ast():
    tree = ast.parse(Path(governance.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= STDLIB_ALLOW, f"non-stdlib imports: {imported}"


def test_03_policy_roundtrip_and_verify():
    gov = Governance()
    rec = gov.policy("g1", "Release policy", 1,
                     principles=("human-oversight", "red-team"),
                     framework=FRAMEWORK_OECD)
    assert rec.policy_id == "g1"
    assert rec.framework == FRAMEWORK_OECD
    assert rec.principles == ("human-oversight", "red-team")
    assert rec.verify()
    assert rec.as_dict()["schema"] == GOVERNANCE_SCHEMA
    assert gov.policy_ids(2) == ("g1",)


def test_04_policy_bad_inputs_rejected_with_seq_burn():
    gov = Governance()
    rejected_before = len(gov.audit_log(0))
    bad = [
        ("", "t"), ("g1", ""),
        ("g 1", "t"),  # empty id / empty title / whitespace id
    ]
    seq = 1
    for pid, title in bad[:3]:
        with pytest.raises(GovernanceError):
            gov.policy(pid, title, seq)
        seq += 1
    with pytest.raises(BadFrameworkError):
        gov.policy("g9", "t", seq, framework="bad-fw")
    seq += 1
    with pytest.raises(BadPrincipleError):
        gov.policy("g9", "t", seq, principles=("ok", ""))
    seq += 1
    with pytest.raises(BadPrincipleError):
        gov.policy("g9", "t", seq, principles=("a",) * 65)
    seq += 1
    # every failed mutation consumed its seq and booked a rejected row
    assert len(gov.audit_log(100)) > rejected_before
    with pytest.raises(SeqOrderError):  # rewind of a burned seq raises bare
        gov.policy("g10", "t", 1)


def test_05_policy_duplicate_and_retired_never_recycled():
    gov = Governance()
    gov.policy("g1", "T", 1)
    with pytest.raises(DuplicatePolicyError):
        gov.policy("g1", "T", 2)
    gov.retire("g1", 3, reason=REASON_SUPERSEDED)
    with pytest.raises(RetiredPolicyError):
        gov.policy("g1", "T", 4)
    assert gov.retired_ids(5) == ("g1",)


def test_06_enforce_roundtrip_verify():
    gov = Governance()
    gov.policy("g1", "T", 1)
    enf = gov.enforce("g1", "model-x", 2, verdict=VERDICT_VIOLATION,
                      action_digest=_digest({"r": 1}))
    assert enf.enforcement_id == "enf-1"
    assert enf.verify()
    assert enf.as_dict()["verdict"] == VERDICT_VIOLATION
    rpt = gov.report("g1", 3)
    assert rpt.enforcement_ids == ("enf-1",)
    assert rpt.verify()


def test_07_enforce_bad_inputs():
    gov = Governance()
    gov.policy("g1", "T", 1)
    with pytest.raises(BadVerdictError):
        gov.enforce("g1", "model-x", 2, verdict="maybe")
    with pytest.raises(BadDigestError):
        gov.enforce("g1", "model-x", 3, action_digest="not-a-pin")
    with pytest.raises(BadTargetError):
        gov.enforce("g1", "", 4)
    with pytest.raises(UnknownPolicyError):
        gov.enforce("nope", "model-x", 5)
    gov.retire("g1", 6)
    with pytest.raises(RetiredPolicyError):
        gov.enforce("g1", "model-x", 7)


def test_08_report_compliance_rate_math():
    gov = Governance()
    gov.policy("g1", "T", 1)
    gov.enforce("g1", "a", 2, verdict=VERDICT_COMPLIANT)
    gov.enforce("g1", "b", 3, verdict=VERDICT_VIOLATION)
    gov.enforce("g1", "c", 4, verdict=VERDICT_REMEDIATION_REQUIRED)
    rpt = gov.report("g1", 5)
    assert rpt.enforcement_count == 3
    assert rpt.compliant_count == 1
    assert rpt.violation_count == 1
    assert rpt.remediation_count == 1
    assert rpt.compliance_rate_text == "1/3"
    assert rpt.verify()
    # empty policy: rate is 0/1 (Fraction-normalized), empty as data
    gov.policy("g2", "T2", 6)
    empty = gov.report("g2", 7)
    assert empty.enforcement_count == 0
    assert empty.compliance_rate_text == "0/1"


def test_09_report_pure_read_semantics():
    gov = Governance()
    gov.policy("g1", "T", 1)
    gov.enforce("g1", "a", 2)
    n_audit = len(gov.audit_log(3))
    r1 = gov.report("g1", 4)
    r2 = gov.report("g1", 4)  # same seq reused: no consumption
    assert r1 == r2
    assert len(gov.audit_log(4)) == n_audit  # no audit rows written
    assert gov.stats(4)["enforcements"] == 1  # seq not consumed by views
    with pytest.raises(UnknownPolicyError):
        gov.report("nope", 4)


def test_10_seq_discipline():
    gov = Governance()
    with pytest.raises(SeqOrderError):
        gov.policy("g1", "T", True)  # bool is not a seq
    with pytest.raises(SeqOrderError):
        gov.policy("g1", "T", -1)
    gov.policy("g1", "T", 1)
    with pytest.raises(SeqOrderError):
        gov.enforce("g1", "a", 1)  # rewind raises bare, no audit row
    assert len(gov.audit_log(2)) == 1  # only the policy-adopted row


def test_11_audit_shapes_and_leak_ban():
    gov = Governance()
    gov.policy("g1", "Secret title text", 1,
               principles=("secret principle",))
    gov.enforce("g1", "m", 2, action_digest=_digest({"x": 1}))
    for row in gov.audit_log(3):
        detail = row["detail"]
        for banned in ("title", "principles", "text", "content", "raw",
                       "payload", "evidence", "justification", "action"):
            assert banned not in detail, f"leak: {banned}"
        text = str(detail)
        assert "Secret title text" not in text
        assert "secret principle" not in text
    with pytest.raises(AuditKindError):
        governance_audit_event("nope", 1)
    with pytest.raises(AuditKindError):
        governance_audit_event("enforced", 1, title="leak")


def test_12_retire_terminality():
    gov = Governance()
    gov.policy("g1", "T", 1)
    rec = gov.retire("g1", 2, reason=REASON_MANUAL)
    assert rec.verify()
    with pytest.raises(RetiredPolicyError):
        gov.retire("g1", 3)
    with pytest.raises(UnknownPolicyError):
        gov.retire("nope", 4)
    with pytest.raises(BadReasonError):
        gov.policy("g2", "T2", 5)
        gov.retire("g2", 6, reason="bad-reason")


def test_13_views_and_stats():
    gov = Governance()
    gov.policy("g1", "T", 1)
    gov.policy("g2", "T2", 2)
    gov.enforce("g1", "a", 3)
    assert gov.policy_ids(4) == ("g1", "g2")
    assert gov.policy_record("g1", 4).verify()
    assert gov.enforcement_record("enf-1", 4).verify()
    stats = gov.stats(4)
    assert stats == {"policies": 2, "enforcements": 1, "retired": 0,
                     "audit_events": 3}
    with pytest.raises(UnknownPolicyError):
        gov.policy_record("nope", 4)


def test_14_cross_instance_determinism():
    def build():
        g = Governance()
        g.policy("g1", "T", 1, principles=("b", "a"))
        g.enforce("g1", "m", 2)
        return g
    a, b = build(), build()
    assert a.policy_record("g1", 3).digest == b.policy_record("g1", 3).digest
    assert a.report("g1", 3).digest == b.report("g1", 3).digest
    # tamper: digest changes break verify; frozen records reject mutation
    rec = a.policy_record("g1", 3)
    with pytest.raises(Exception):
        rec.policy_id = "g2"


def test_15_main_subprocess():
    result = subprocess.run(
        [sys.executable, governance.__file__],
        capture_output=True, text=True, cwd="/tmp", timeout=60)
    assert result.returncode == 0, result.stderr
    assert "governance OK" in result.stdout


def test_16_concurrency_smoke():
    gov = Governance()
    gov.policy("g1", "T", 1)
    gov.enforce("g1", "a", 2)
    errors = []

    def read_many():
        try:
            for _ in range(50):
                gov.report("g1", 3)
                gov.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_many) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert gov.stats(3)["enforcements"] == 1
