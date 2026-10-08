"""Targeted tests for ai_robustness_threat (15 tests)."""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_robustness_threat as m
from ai_robustness_threat import (
    AIRobustnessThreat,
    AIRobustnessThreatError,
    AI_ROBUSTNESS_THREAT_VERSION,
    ASSESS_VERDICTS,
    AUDIT_KINDS,
    MITIGATION_STRATEGIES,
    POSTURES,
    RETIRE_REASONS,
    ROBUSTNESS_THREAT_KINDS,
    SCHEMA_PIN,
    VERIFY_VERDICTS,
    ai_robustness_threat_audit_event,
)

MODULE_PATH = Path(m.__file__)

_GOOD_DIGEST = "sha256:" + "ab" * 32


def fresh() -> AIRobustnessThreat:
    return AIRobustnessThreat()


def test_pins_and_vocabularies() -> None:
    assert AI_ROBUSTNESS_THREAT_VERSION == "ai-robustness-threat.v1"
    assert SCHEMA_PIN == "northstar.ai-robustness-threat.v1"
    assert ROBUSTNESS_THREAT_KINDS == (
        "adversarial-attack",
        "data-poisoning",
        "model-extraction",
        "distribution-shift-attack",
        "resource-exhaustion-attack",
        "failover-sabotage",
        "cascading-trigger",
        "recovery-blocking",
    )
    assert ASSESS_VERDICTS == (
        "active",
        "suspected",
        "contained",
        "inconclusive",
        "not-assessed",
    )
    assert MITIGATION_STRATEGIES == (
        "adversarial-hardening",
        "input-sanitization",
        "rate-limiting",
        "redundancy-provisioning",
        "graceful-degradation",
        "failover-isolation",
        "cascade-circuit-breaking",
        "no-action",
    )
    assert VERIFY_VERDICTS == ("verified", "tampered")
    assert POSTURES == (
        "unassessed",
        "threatening",
        "suspect",
        "mitigated",
        "contained",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert AUDIT_KINDS == ("assessed", "mitigated", "retired", "rejected")


def test_stdlib_only_ast() -> None:
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"
    # no wall-clock calls
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {
            "now",
            "utcnow",
            "time",
            "monotonic",
            "sleep",
        }:
            raise AssertionError(f"wall-clock call suspected: {node.attr}")
    assert m.stdlib_only() is True


def test_assess_roundtrip_and_frozen() -> None:
    ledger = fresh()
    rec = ledger.assess(
        "sys-1",
        1,
        robustness_threat_kind="data-poisoning",
        verdict="active",
        severity=75,
        assessment_digest=_GOOD_DIGEST,
    )
    assert rec.assessment_id == "rht-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.robustness_threat_kind == "data-poisoning"
    assert rec.verdict == "active"
    assert rec.severity == 75
    assert rec.assessment_digest == _GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    with pytest.raises(Exception):
        rec.verdict = "contained"  # frozen
    got = ledger.assessment_record("rht-1", 0)
    assert got == rec
    assert ledger.assessments_for("sys-1", 0) == (rec,)
    assert ledger.system_ids(0) == ("sys-1",)
    assert ledger.assessment_ids(0) == ("rht-1",)


def test_bad_input_table_burns_seq_and_books_rejected() -> None:
    ledger = fresh()
    bad = [
        ("", 1, {}, m.BadSystemError),
        ("  ", 2, {}, m.BadSystemError),
        (123, 3, {}, m.BadSystemError),
        ("sys-1", True, {}, m.SeqOrderError),  # bool seq: rewind-style raise, no burn
        ("sys-1", 4, {"robustness_threat_kind": "nonsense"}, m.BadRobustnessThreatKindError),
        ("sys-1", 5, {"verdict": "nonsense"}, m.BadVerdictError),
        ("sys-1", 6, {"severity": True}, m.BadSeverityError),
        ("sys-1", 7, {"severity": 101}, m.BadSeverityError),
        ("sys-1", 8, {"severity": -1}, m.BadSeverityError),
        ("sys-1", 9, {"assessment_digest": "nope"}, m.BadDigestError),
        ("sys-1", 10, {"assessment_digest": "sha256:" + "zz" * 32}, m.BadDigestError),
    ]
    n_rejected = 0
    for system_id, seq, kw, exc in bad:
        if exc is m.SeqOrderError:
            with pytest.raises(m.SeqOrderError):
                ledger.assess(system_id, seq, **kw)
            continue
        with pytest.raises(exc):
            ledger.assess(system_id, seq, **kw)
        n_rejected += 1
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    # seqs were burned: next valid assess must use a higher seq
    rec = ledger.assess("sys-1", 100, verdict="suspected")
    assert rec.seq == 100
    # rewind raises bare without consuming
    with pytest.raises(m.SeqOrderError):
        ledger.assess("sys-1", 50)
    assert ledger.stats(0)["seq"] == 100


def test_full_kind_and_verdict_vocabulary() -> None:
    ledger = fresh()
    seq = 0
    for kind in ROBUSTNESS_THREAT_KINDS:
        seq += 1
        ledger.assess(f"sys-{kind}", seq, robustness_threat_kind=kind)
    for i, verdict in enumerate(ASSESS_VERDICTS):
        seq += 1
        ledger.assess(f"v-sys-{i}", seq, verdict=verdict)
    assert ledger.stats(0)["n_assessments"] == len(ROBUSTNESS_THREAT_KINDS) + len(
        ASSESS_VERDICTS
    )


def test_mitigate_roundtrip_and_chain() -> None:
    ledger = fresh()
    rec = ledger.assess("sys-1", 1, verdict="active")
    mit1 = ledger.mitigate(rec.assessment_id, 2, strategy="rate-limiting")
    assert mit1.mitigation_id == "rhm-1"
    assert mit1.assessment_id == rec.assessment_id
    assert mit1.system_id == "sys-1"
    assert mit1.strategy == "rate-limiting"
    assert mit1.verify() is True
    mit2 = ledger.mitigate(
        rec.assessment_id, 3, strategy="redundancy-provisioning", mitigation_digest=_GOOD_DIGEST
    )
    assert mit2.mitigation_id == "rhm-2"
    assert ledger.mitigations_for(rec.assessment_id, 0) == (mit1, mit2)
    assert ledger.mitigation_record("rhm-1", 0) == mit1
    assert ledger.mitigation_ids(0) == ("rhm-1", "rhm-2")


def test_mitigate_refusal_table() -> None:
    ledger = fresh()
    rec = ledger.assess("sys-1", 1, verdict="active")
    with pytest.raises(m.UnknownAssessmentError):
        ledger.mitigate("rht-999", 2)
    with pytest.raises(m.BadStrategyError):
        ledger.mitigate(rec.assessment_id, 3, strategy="nonsense")
    with pytest.raises(m.BadDigestError):
        ledger.mitigate(rec.assessment_id, 4, mitigation_digest="bad")
    with pytest.raises(m.SeqOrderError):
        ledger.mitigate(rec.assessment_id, 1)  # rewind: bare
    rows = ledger.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 3
    # retired system refuses mitigation
    ledger.retire("sys-1", 5)
    with pytest.raises(m.RetiredSystemError):
        ledger.mitigate(rec.assessment_id, 6)


def test_full_strategy_vocabulary() -> None:
    ledger = fresh()
    rec = ledger.assess("sys-1", 1, verdict="active")
    seq = 1
    for strategy in MITIGATION_STRATEGIES:
        seq += 1
        mit = ledger.mitigate(rec.assessment_id, seq, strategy=strategy)
        assert mit.strategy == strategy
    assert ledger.stats(0)["n_mitigations"] == len(MITIGATION_STRATEGIES)


def test_verify_semantics_tamper_as_data_and_read_purity() -> None:
    ledger = fresh()
    rec = ledger.assess("sys-1", 1, verdict="active")
    rep = ledger.verify("rht-1", 7)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # pure read: same-seq-twice allowed, no new audit rows, seq unconsumed
    n_rows = len(ledger.audit_log(0))
    rep2 = ledger.verify("rht-1", 7)
    assert rep2 == rep
    assert len(ledger.audit_log(0)) == n_rows
    assert ledger.stats(0)["seq"] == 1
    with pytest.raises(m.UnknownRecordError):
        ledger.verify("rht-999", 8)
    with pytest.raises(m.SeqOrderError):
        ledger.verify("rht-1", -1)
    # tamper detection: flip a stored record's digest
    import dataclasses

    tampered = dataclasses.replace(rec, digest="sha256:" + "00" * 32)
    ledger._assessments["rht-1"] = tampered
    rep3 = ledger.verify("rht-1", 9)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    ev = ledger.evaluate("sys-1", 10)
    assert ev.integrity_ok is False


def test_evaluate_posture_ladder_and_precedence() -> None:
    ledger = fresh()
    # unassessed system unknown -> raises; build ladder per system
    a = ledger.assess("s-threat", 1, verdict="active")
    assert ledger.evaluate("s-threat", 2).posture == "threatening"
    ledger.mitigate(a.assessment_id, 3)
    assert ledger.evaluate("s-threat", 4).posture == "mitigated"
    ledger.assess("s-suspect", 5, verdict="suspected")
    assert ledger.evaluate("s-suspect", 6).posture == "suspect"
    ledger.assess("s-inc", 7, verdict="inconclusive")
    assert ledger.evaluate("s-inc", 8).posture == "suspect"
    for i, k in enumerate(("sys-c1", "sys-c2")):
        ledger.assess(k, 9 + i, verdict="contained")
    assert ledger.evaluate("sys-c1", 11).posture == "contained"
    assert ledger.evaluate("sys-c2", 12).posture == "contained"
    # threatening outranks suspect
    ledger.assess("s-mix", 13, verdict="suspected")
    ledger.assess("s-mix", 14, verdict="active")
    assert ledger.evaluate("s-mix", 15).posture == "threatening"
    ev = ledger.evaluate("s-mix", 16)
    assert ev.n_assessments == 2
    assert ev.n_threatening == 1
    assert ev.n_suspected == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # read purity: reads add no audit rows
    n_rows = len(ledger.audit_log(0))
    ledger.evaluate("s-mix", 16)
    ledger.verify("rht-1", 16)
    assert len(ledger.audit_log(0)) == n_rows
    with pytest.raises(m.UnknownSystemError):
        ledger.evaluate("nope", 17)


def test_retire_terminality() -> None:
    ledger = fresh()
    ledger.assess("sys-1", 1, verdict="active")
    with pytest.raises(m.BadReasonError):
        ledger.retire("sys-1", 2, reason="nonsense")
    with pytest.raises(m.UnknownSystemError):
        ledger.retire("ghost", 3)
    ret = ledger.retire("sys-1", 4, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    assert ledger.retired_ids(0) == ("sys-1",)
    with pytest.raises(m.RetiredSystemError):
        ledger.retire("sys-1", 5)  # double retire
    with pytest.raises(m.RetiredSystemError):
        ledger.assess("sys-1", 6)  # post-retire mutation refused
    # reads still work after retire
    assert ledger.assessments_for("sys-1", 0) != ()
    assert ledger.evaluate("sys-1", 7).posture == "threatening"
    # ids never recycled: new system gets fresh counters
    rec = ledger.assess("sys-2", 8)
    assert rec.assessment_id == "rht-2"
    rows = ledger.audit_log(0)
    assert [r["kind"] for r in rows].count("retired") == 1
    assert sum(1 for r in rows if r["kind"] == "rejected") == 4


def test_audit_shapes_and_leak_ban() -> None:
    row = ai_robustness_threat_audit_event("assessed", 1, assessment_id="rht-1")
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-robustness-threat"
    assert row["version"] == AI_ROBUSTNESS_THREAT_VERSION
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    # pinned vocabulary values remain emittable
    row2 = ai_robustness_threat_audit_event(
        "mitigated", 2, strategy="rate-limiting", verdict="active", severity=80
    )
    assert row2["details"]["strategy"] == "rate-limiting"
    # raw material keys banned
    for banned in (
        "adversarial_example",
        "attack_payload",
        "exploit_code",
        "poisoned_sample",
        "trigger_pattern",
        "extraction_queries",
        "redteam_transcript",
        "robustness_report",
        "prompt",
        "api_key",
    ):
        with pytest.raises(AIRobustnessThreatError):
            ai_robustness_threat_audit_event("assessed", 3, **{banned: "x"})
    with pytest.raises(m.AuditKindError):
        ai_robustness_threat_audit_event("nonsense", 4)
    with pytest.raises(m.SeqOrderError):
        ai_robustness_threat_audit_event("assessed", True)


def test_views_stats_and_determinism() -> None:
    l1 = fresh()
    l2 = fresh()
    for ledger in (l1, l2):
        rec = ledger.assess("sys-1", 1, verdict="active", severity=50)
        ledger.mitigate(rec.assessment_id, 2, strategy="rate-limiting")
    assert l1.assessment_record("rht-1", 0).digest == l2.assessment_record(
        "rht-1", 0
    ).digest
    assert l1.mitigation_record("rhm-1", 0).digest == l2.mitigation_record(
        "rhm-1", 0
    ).digest
    st = l1.stats(0)
    assert st == {
        "seq": 2,
        "n_systems": 1,
        "n_assessments": 1,
        "n_mitigations": 1,
        "n_retired": 0,
        "n_audit_rows": 2,
    }
    with pytest.raises(m.UnknownAssessmentError):
        l1.assessment_record("rht-404", 0)
    with pytest.raises(m.UnknownMitigationError):
        l1.mitigation_record("rhm-404", 0)
    assert l1.assessments_for("ghost", 0) == ()
    assert l1.mitigations_for("rht-404", 0) == ()
    # 8-thread read smoke
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                l1.evaluate("sys-1", 3)
                l1.verify("rht-1", 3)
                l1.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_seq_discipline() -> None:
    ledger = fresh()
    with pytest.raises(m.SeqOrderError):
        ledger.assess("sys-1", 0)
    with pytest.raises(m.SeqOrderError):
        ledger.assess("sys-1", -3)
    with pytest.raises(m.SeqOrderError):
        ledger.assess("sys-1", "1")
    ledger.assess("sys-1", 5)
    with pytest.raises(m.SeqOrderError):
        ledger.assess("sys-1", 5)  # equal: rewind, bare
    assert ledger.stats(0)["seq"] == 5
    # rewinds are bare: no rejected rows booked, only the one assessed row
    rows = ledger.audit_log(0)
    assert len(rows) == 1 and rows[0]["kind"] == "assessed"


def test_main_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert (
        proc.stdout.strip()
        == "ai-robustness-threat OK: assess, mitigate, verify, evaluate, retire, pins, audit"
    )
