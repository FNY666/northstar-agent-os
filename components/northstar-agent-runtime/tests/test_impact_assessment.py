"""Tests for impact_assessment.py (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE.parent / "impact_assessment.py"


def load_module():
    """Standalone loader mirroring the house sys.modules pattern."""
    import importlib.util
    name = "impact_assessment"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ia = load_module()


def _pin(seed: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def test_1_version_and_schema_pins():
    assert ia.VERSION == "impact-assessment.v1"
    assert ia.SCHEMA == "northstar.impact-assessment.v1"
    assert "fairness" in ia._IMPACT_DOMAINS
    assert len(ia._IMPACT_DOMAINS) == 8
    assert ia._SEVERITIES == ("low", "medium", "high", "critical")
    assert set(ia._STRATEGIES) == {"avoid", "reduce", "transfer", "accept", "monitor"}


def test_2_stdlib_only_ast_check():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {"hashlib", "re", "threading", "dataclasses", "typing",
               "__future__", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed, node.module


def test_3_scope_roundtrip_and_verify():
    a = ia.ImpactAssessment()
    rec = a.scope("sys-1", "candidate-screening", ("fairness", "privacy"), 1)
    assert rec.system_id == "sys-1"
    assert rec.context == "candidate-screening"
    assert rec.domains == ("fairness", "privacy")
    assert rec.verify()
    assert a.scope_record("sys-1", 2) is rec
    assert a.system_ids(3) == ("sys-1",)


def test_4_scope_refusals_seq_burn_and_rejected_rows():
    a = ia.ImpactAssessment()
    # bad domain
    with pytest.raises(ia.BadDomainError):
        a.scope("sys-1", "ctx", ("explosives",), 1)
    # bad context
    with pytest.raises(ia.BadIdError):
        a.scope("sys-2", "", ("privacy",), 2)
    # bad id
    with pytest.raises(ia.BadIdError):
        a.scope("bad id!", "ctx", ("privacy",), 3)
    # empty domains
    with pytest.raises(ia.BadDomainError):
        a.scope("sys-3", "ctx", (), 4)
    # bad digest
    with pytest.raises(ia.BadDigestError):
        a.scope("sys-4", "ctx", ("privacy",), 5, scope_digest="not-a-pin")
    rejected = [r for r in a.audit_log(6) if r["kind"] == ia.KIND_REJECTED]
    assert len(rejected) == 5
    assert a.stats(7)["rejected"] == 5
    # duplicate scope
    a.scope("sys-5", "ctx", ("privacy",), 8)
    with pytest.raises(ia.DuplicateScopeError):
        a.scope("sys-5", "ctx", ("privacy",), 9)


def test_5_evaluate_roundtrip_and_minted_ids():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness", "safety"), 1)
    e1 = a.evaluate("sys-1", "fairness", "high", 2)
    assert e1.evaluation_id == "evl-1"
    assert e1.severity == "high"
    assert e1.verify()
    e2 = a.evaluate("sys-1", "safety", "low", 3, evidence_digest=_pin("ev"))
    assert e2.evaluation_id == "evl-2"
    assert e2.verify()
    assert a.evaluations_for("sys-1", 4) == ("evl-1", "evl-2")
    assert a.evaluation_record("evl-1", 5) is e1


def test_6_evaluate_refusals():
    a = ia.ImpactAssessment()
    # unknown system
    with pytest.raises(ia.UnknownSystemError):
        a.evaluate("ghost", "fairness", "low", 1)
    a.scope("sys-1", "ctx", ("fairness",), 2)
    # domain not in scope vocabulary
    with pytest.raises(ia.BadDomainError):
        a.evaluate("sys-1", "explosives", "low", 3)
    # domain outside scope
    with pytest.raises(ia.BadDomainError):
        a.evaluate("sys-1", "privacy", "low", 4)
    # bad severity
    with pytest.raises(ia.BadSeverityError):
        a.evaluate("sys-1", "fairness", "extreme", 5)
    rejected = [r for r in a.audit_log(6) if r["kind"] == ia.KIND_REJECTED]
    assert len(rejected) == 4


def test_7_mitigate_roundtrip_and_chain():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 1)
    e1 = a.evaluate("sys-1", "fairness", "critical", 2)
    m1 = a.mitigate(e1.evaluation_id, "avoid", 3, plan_digest=_pin("plan"))
    assert m1.mitigation_id == "mit-1"
    assert m1.strategy == "avoid"
    assert m1.verify()
    assert a.mitigations_for(e1.evaluation_id, 4) == ("mit-1",)
    assert a.mitigation_record("mit-1", 5) is m1
    # double mitigation refused
    with pytest.raises(ia.AlreadyMitigatedError):
        a.mitigate(e1.evaluation_id, "reduce", 6)
    # unknown evaluation refused
    with pytest.raises(ia.UnknownEvaluationError):
        a.mitigate("evl-999", "avoid", 7)
    # bad strategy refused
    e2 = a.evaluate("sys-1", "fairness", "low", 8)
    with pytest.raises(ia.BadStrategyError):
        a.mitigate(e2.evaluation_id, "pray", 9)


def test_8_report_posture_math():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness", "privacy", "safety"), 1)
    e1 = a.evaluate("sys-1", "fairness", "critical", 2)
    e2 = a.evaluate("sys-1", "privacy", "low", 3)
    rep = a.report("sys-1", 4)
    assert rep.n_evaluations == 2
    assert dict(rep.severities) == {"critical": 1, "low": 1}
    assert rep.open_high_impacts == 1
    assert rep.acceptable is False
    assert rep.verify()
    a.mitigate(e1.evaluation_id, "reduce", 5)
    rep2 = a.report("sys-1", 6)
    assert rep2.acceptable is True
    assert rep2.open_high_impacts == 0
    assert rep2.mitigated_ids == ("evl-1",)
    assert rep2.verify()
    # unknown system refused
    with pytest.raises(ia.UnknownSystemError):
        a.report("ghost", 7)


def test_9_report_read_purity():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 1)
    a.evaluate("sys-1", "fairness", "medium", 2)
    n_before = len(a.audit_log(3))
    r1 = a.report("sys-1", 4)
    r2 = a.report("sys-1", 4)  # same seq reused, pure read
    assert r1 == r2
    assert len(a.audit_log(5)) == n_before
    assert a.stats(6)["rejected"] == 0


def test_10_retire_terminality():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 1)
    e1 = a.evaluate("sys-1", "fairness", "high", 2)
    rec = a.retire("sys-1", 3, reason="withdrawn")
    assert rec.verify()
    assert a.retired_ids(4) == ("sys-1",)
    # re-retire refused
    with pytest.raises(ia.RetiredSystemError):
        a.retire("sys-1", 5)
    # post-retire scope refused (id never recycled)
    with pytest.raises(ia.RetiredSystemError):
        a.scope("sys-1", "ctx", ("fairness",), 6)
    # post-retire evaluate refused
    with pytest.raises(ia.RetiredSystemError):
        a.evaluate("sys-1", "fairness", "low", 7)
    # post-retire mitigate refused
    with pytest.raises(ia.RetiredSystemError):
        a.mitigate(e1.evaluation_id, "avoid", 8)
    # post-retire report refused
    with pytest.raises(ia.RetiredSystemError):
        a.report("sys-1", 9)
    # bad reason refused
    a.scope("sys-2", "ctx", ("privacy",), 10)
    with pytest.raises(ia.BadIdError):
        a.retire("sys-2", 11, reason="nope")


def test_11_seq_discipline():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 5)
    # rewind raises bare, consumes nothing
    with pytest.raises(ia.SeqOrderError):
        a.scope("sys-2", "ctx", ("fairness",), 5)
    assert a.stats(6)["rejected"] == 0
    # malformed seqs
    for bad in (0, -1, True, "7", 3.5, None):
        with pytest.raises(ia.SeqOrderError):
            a.scope("sys-x", "ctx", ("fairness",), bad)
    # failed mutation consumes seq
    with pytest.raises(ia.BadDomainError):
        a.scope("sys-3", "ctx", ("explosives",), 7)
    with pytest.raises(ia.SeqOrderError):  # seq 7 burned
        a.scope("sys-4", "ctx", ("fairness",), 7)
    a.scope("sys-4", "ctx", ("fairness",), 8)


def test_12_audit_shapes_leak_ban_and_bad_kind():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 1)
    e1 = a.evaluate("sys-1", "fairness", "high", 2)
    a.mitigate(e1.evaluation_id, "reduce", 3)
    a.retire("sys-1", 4)
    log = a.audit_log(5)
    kinds = [r["kind"] for r in log]
    assert kinds == [ia.KIND_SCOPED, ia.KIND_EVALUATED,
                     ia.KIND_MITIGATED, ia.KIND_RETIRED]
    for r in log:
        assert r["audit"] == "audit.ndjson/1"
        leaked = ia._BANNED_AUDIT_KEYS.intersection(r["detail"].keys())
        assert not leaked, leaked
    # builder rejects raw-text keys
    with pytest.raises(ia.AuditKindError):
        ia.impact_assessment_audit_event(ia.KIND_SCOPED,
                                       {"description": "narrative"}, 9)
    with pytest.raises(ia.AuditKindError):
        ia.impact_assessment_audit_event("bogus-kind", {}, 9)


def test_13_cross_instance_determinism_and_tamper():
    def build():
        a = ia.ImpactAssessment()
        a.scope("sys-1", "ctx", ("fairness",), 1)
        return a.evaluate("sys-1", "fairness", "high", 2)
    e1, e2 = build(), build()
    assert e1.digest == e2.digest
    # tamper breaks verify
    object.__setattr__(e1, "severity", "low")
    assert not e1.verify()
    # report tamper
    a = ia.ImpactAssessment()
    a.scope("sys-9", "ctx", ("fairness",), 1)
    a.evaluate("sys-9", "fairness", "low", 2)
    rep = a.report("sys-9", 3)
    assert rep.verify()
    object.__setattr__(rep, "acceptable", False)
    assert not rep.verify()


def test_14_frozen_and_concurrent_reads():
    a = ia.ImpactAssessment()
    a.scope("sys-1", "ctx", ("fairness",), 1)
    rec = a.scope_record("sys-1", 2)
    with pytest.raises(Exception):
        rec.system_id = "hacked"  # frozen dataclass
    errors = []
    def read():
        try:
            for _ in range(50):
                a.report("sys-1", 3)
                a.stats(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_15_main_subprocess_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == \
        "impact-assessment OK: scope, evaluate, mitigate, report, pins, audit"
