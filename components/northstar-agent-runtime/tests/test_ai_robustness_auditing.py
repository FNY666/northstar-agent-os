"""Targeted tests for ai_robustness_auditing (15 tests)."""

import ast
import dataclasses
import pathlib
import subprocess
import sys
import threading

import pytest

import ai_robustness_auditing as m
from ai_robustness_auditing import (
    AIRobustnessAuditing,
    AuditKeyError,
    AuditKindError,
    BadAuditKindError,
    BadDigestError,
    BadReasonError,
    BadSeqError,
    BadSeverityError,
    BadSystemError,
    BadVerdictError,
    RetiredSystemError,
    SeqOrderError,
    UnknownAuditError,
    UnknownSystemError,
    ai_robustness_auditing_audit_event,
)


def fresh():
    return AIRobustnessAuditing()


def test_pins_and_vocabularies():
    assert m.AI_ROBUSTNESS_AUDITING_VERSION == "ai-robustness-auditing.v1"
    assert m.SCHEMA_PIN == "northstar.ai-robustness-auditing.v1"
    assert m.AUDIT_KINDS == (
        "internal-robustness-audit",
        "external-robustness-audit",
        "adversarial-audit",
        "stress-test-audit",
        "fault-injection-audit",
        "chaos-audit",
        "redundancy-audit",
        "continuous-robustness-audit",
    )
    assert m.AUDIT_VERDICTS == (
        "robust",
        "partially-robust",
        "fragile",
        "inconclusive",
        "not-audited",
    )
    assert m.VERIFY_VERDICTS == ("verified", "tampered")
    assert m.POSTURES == (
        "unaudited",
        "fragile",
        "contested",
        "partially-robust",
        "robustness-audited",
    )
    assert m.RETIRE_REASONS == ("manual", "superseded", "completed", "withdrawn")


def test_stdlib_only_ast():
    assert m.stdlib_only() is True
    tree = ast.parse(pathlib.Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            assert name not in {"time", "sleep", "now", "utcnow", "monotonic"}, (
                f"wall-clock call suspected: {name}"
            )


def test_audit_roundtrip_rba_minting_frozen():
    ledger = fresh()
    rec = ledger.audit("sys-1", 1, audit_kind="adversarial-audit", verdict="robust", severity=10)
    assert rec.audit_id == "rba-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    assert rec.version == "ai-robustness-auditing.v1"
    assert rec.schema == "northstar.ai-robustness-auditing.v1"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "fragile"  # type: ignore[misc]
    # defaults
    rec2 = ledger.audit("sys-2", 2)
    assert rec2.audit_id == "rba-2"
    assert rec2.audit_kind == "internal-robustness-audit"
    assert rec2.verdict == "not-audited"


def test_bad_input_table_seq_burn_rejected_accounting():
    ledger = fresh()
    cases = [
        ({"system_id": ""}, BadSystemError),
        ({"system_id": "s", "audit_kind": "nope"}, BadAuditKindError),
        ({"system_id": "s", "verdict": "nope"}, BadVerdictError),
        ({"system_id": "s", "severity": -1}, BadSeverityError),
        ({"system_id": "s", "severity": 101}, BadSeverityError),
        ({"system_id": "s", "severity": True}, BadSeverityError),
        ({"system_id": "s", "audit_digest": "bogus"}, BadDigestError),
    ]
    for i, (kwargs, exc) in enumerate(cases, start=1):
        with pytest.raises(exc):
            ledger.audit(kwargs.pop("system_id", "s"), i, **kwargs)
    # every failed mutation burned its seq and booked a rejected row
    assert ledger.stats(0)["last_seq"] == len(cases)
    log = ledger.audit_log(0)
    rejected = [row for row in log if row["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    assert rejected[0]["details"]["reason"] == "BadSystemError"
    assert rejected[1]["details"]["reason"] == "BadAuditKindError"
    assert all(row["schema"] == "audit.ndjson/1" for row in rejected)
    # next good seq continues the burn chain
    rec = ledger.audit("s", len(cases) + 1)
    assert rec.audit_id == "rba-1"


def test_rewind_raises_bare_no_row():
    ledger = fresh()
    ledger.audit("s", 5)
    n_before = len(ledger.audit_log(0))
    with pytest.raises(SeqOrderError):
        ledger.audit("s", 5)
    with pytest.raises(SeqOrderError):
        ledger.audit("s", 3)
    assert ledger.stats(0)["last_seq"] == 5
    assert len(ledger.audit_log(0)) == n_before  # no rejected row on rewind
    for bad in (0, -1, True, "7", 7.0, None):
        with pytest.raises(BadSeqError):
            ledger.audit("s", bad)


def test_retired_refusal_burns_seq():
    ledger = fresh()
    ledger.audit("s", 1, verdict="robust")
    ledger.retire("s", 2, reason="completed")
    with pytest.raises(RetiredSystemError):
        ledger.audit("s", 3, verdict="robust")
    assert ledger.stats(0)["last_seq"] == 3
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert rejected and rejected[-1]["details"]["reason"] == "RetiredSystemError"


def test_full_audit_kind_vocabulary():
    ledger = fresh()
    for i, kind in enumerate(m.AUDIT_KINDS, start=1):
        rec = ledger.audit(f"sys-{i}", i, audit_kind=kind, verdict="robust")
        assert rec.audit_kind == kind
        assert rec.verify() is True


def test_full_verdict_vocabulary_and_tallies():
    ledger = fresh()
    for i, verdict in enumerate(m.AUDIT_VERDICTS, start=1):
        ledger.audit("s", i, verdict=verdict)
    ev = ledger.evaluate("s", 0)
    tallies = dict(ev.tallies)
    assert all(tallies[v] == 1 for v in m.AUDIT_VERDICTS)
    assert ev.integrity_ok is True


def test_evaluate_posture_ladder_and_precedence():
    # fragile outranks everything
    ledger = fresh()
    ledger.audit("a", 1, verdict="robust")
    ledger.audit("a", 2, verdict="fragile")
    ledger.audit("a", 3, verdict="inconclusive")
    assert ledger.evaluate("a", 0).posture == "fragile"
    # contested: inconclusive, no fragile
    ledger2 = fresh()
    ledger2.audit("b", 1, verdict="robust")
    ledger2.audit("b", 2, verdict="inconclusive")
    assert ledger2.evaluate("b", 0).posture == "contested"
    # partially-robust: partially-robust / not-audited present
    ledger3 = fresh()
    ledger3.audit("c", 1, verdict="robust")
    ledger3.audit("c", 2, verdict="partially-robust")
    assert ledger3.evaluate("c", 0).posture == "partially-robust"
    ledger4 = fresh()
    ledger4.audit("d", 1, verdict="robust")
    ledger4.audit("d", 2)  # not-audited default
    assert ledger4.evaluate("d", 0).posture == "partially-robust"
    # robustness-audited: all robust
    ledger5 = fresh()
    ledger5.audit("e", 1, verdict="robust")
    ledger5.audit("e", 2, verdict="robust")
    ev = ledger5.evaluate("e", 0)
    assert ev.posture == "robustness-audited"
    assert ev.verify() is True
    # unknown system refused
    with pytest.raises(UnknownSystemError):
        fresh().evaluate("ghost", 0)


def test_verify_semantics_tamper_as_data_and_read_purity():
    ledger = fresh()
    rec = ledger.audit("s", 1, verdict="robust")
    n_before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.audit_id, 0)
    assert rep.verdict == "verified"
    assert rep.record_id == rec.audit_id
    # read purity: same seq twice, no rows, seq unconsumed
    rep2 = ledger.verify(rec.audit_id, 0)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(0)) == n_before
    assert ledger.stats(0)["last_seq"] == 1
    # tamper as data: well-formed but wrong digest pin
    bad = ledger.audit("t", 2, verdict="robust", audit_digest="sha256:" + "0" * 64)
    assert bad.verify() is False
    trep = ledger.verify(bad.audit_id, 0)
    assert trep.verdict == "tampered"
    # unknown audit refused
    with pytest.raises(UnknownAuditError):
        ledger.verify("rba-999", 0)
    with pytest.raises(BadSeqError):
        ledger.verify(rec.audit_id, -1)


def test_evaluate_purity_and_integrity_flip():
    ledger = fresh()
    ledger.audit("s", 1, verdict="robust")
    n_before = len(ledger.audit_log(0))
    ev = ledger.evaluate("s", 0)
    assert ev.integrity_ok is True
    assert len(ledger.audit_log(0)) == n_before
    assert ledger.stats(0)["last_seq"] == 1
    # tampered record flips integrity_ok
    ledger2 = fresh()
    ledger2.audit("x", 1, verdict="robust", audit_digest="sha256:" + "f" * 64)
    ev2 = ledger2.evaluate("x", 0)
    assert ev2.integrity_ok is False
    assert ev2.posture == "robustness-audited"  # posture is ledger-rule, independent


def test_retire_terminality():
    ledger = fresh()
    ledger.audit("s", 1, verdict="robust")
    # bad reason burns seq
    with pytest.raises(BadReasonError):
        ledger.retire("s", 2, reason="nope")
    assert ledger.stats(0)["last_seq"] == 2
    # unknown system burns seq
    with pytest.raises(UnknownSystemError):
        ledger.retire("ghost", 3)
    rec = ledger.retire("s", 4, reason="superseded")
    assert rec.system_id == "s" and rec.reason == "superseded"
    assert rec.verify() is True
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("s", 5)
    # ids never recycled: next audit on another system keeps counting
    rec2 = ledger.audit("s2", 6, verdict="robust")
    assert rec2.audit_id == "rba-2"
    # post-retire reads still work
    assert ledger.retire_record("s", 0).reason == "superseded"
    assert ledger.evaluate("s", 0).posture == "robustness-audited"
    assert ledger.verify("rba-1", 0).verdict == "verified"
    assert ledger.retired_ids(0) == ("s",)


def test_seq_discipline_malformed_and_gaps():
    ledger = fresh()
    for bad in (0, -2, True, False, "1", 1.5, None, [1]):
        with pytest.raises(BadSeqError):
            ledger.audit("s", bad)
    assert ledger.stats(0)["last_seq"] == 0
    # gap seqs allowed (strictly increasing, not necessarily +1)
    ledger.audit("s", 10)
    ledger.audit("s", 100)
    assert ledger.stats(0)["last_seq"] == 100
    # read seqs: 0 ok, negatives refused
    ledger.verify("rba-1", 0)
    with pytest.raises(BadSeqError):
        ledger.verify("rba-1", -1)


def test_audit_shapes_and_leak_ban():
    ev = ai_robustness_auditing_audit_event("audited", 1, {"audit_id": "rba-1"})
    assert ev["module"] == "ai_robustness_auditing"
    assert ev["version"] == "ai-robustness-auditing.v1"
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "audited" and ev["seq"] == 1
    ev2 = ai_robustness_auditing_audit_event("rejected", 2, {"reason": "x"})
    assert ev2["kind"] == "rejected"
    # banned robustness-specific keys
    for key in ("adversarial_examples", "chaos_results", "fault_injection_log",
                "stress_test_results", "redundancy_config", "fuzz_corpus"):
        with pytest.raises(AuditKeyError):
            ai_robustness_auditing_audit_event("audited", 3, {key: "raw"})
    # banned standard keys
    for key in ("evidence", "pii", "api_key", "workpapers"):
        with pytest.raises(AuditKeyError):
            ai_robustness_auditing_audit_event("audited", 3, {key: "raw"})
    # pinned vocab values remain emittable
    ok = ai_robustness_auditing_audit_event(
        "audited", 4, {"audit_kind": "adversarial-audit", "verdict": "robust", "severity": 5}
    )
    assert ok["details"]["verdict"] == "robust"
    # bad kind / bad seq / non-dict details
    with pytest.raises(AuditKindError):
        ai_robustness_auditing_audit_event("nope", 1, {})
    with pytest.raises(BadSeqError):
        ai_robustness_auditing_audit_event("audited", -1, {})
    with pytest.raises(AuditKeyError):
        ai_robustness_auditing_audit_event("audited", 1, ["not", "a", "dict"])  # type: ignore[arg-type]


def test_views_stats_determinism_threads_and_main():
    ledger = fresh()
    r1 = ledger.audit("s1", 1, audit_kind="chaos-audit", verdict="robust", severity=7)
    r2 = ledger.audit("s2", 2, audit_kind="redundancy-audit", verdict="fragile", severity=90)
    assert ledger.audit_record("rba-1", 0) == r1
    assert ledger.audits_for("s1", 0) == ("rba-1",)
    assert ledger.audits_for("ghost", 0) == ()
    assert ledger.system_ids(0) == ("s1", "s2")
    assert ledger.audit_ids(0) == ("rba-1", "rba-2")
    assert ledger.retired_ids(0) == ()
    st = ledger.stats(0)
    assert st == {
        "module": "ai-robustness-auditing.v1",
        "n_audits": 2,
        "n_systems": 2,
        "n_retired": 0,
        "last_seq": 2,
    }
    with pytest.raises(UnknownAuditError):
        ledger.audit_record("rba-9", 0)
    with pytest.raises(UnknownSystemError):
        ledger.retire_record("s1", 0)
    # cross-instance digest determinism
    other = fresh()
    o1 = other.audit("s1", 1, audit_kind="chaos-audit", verdict="robust", severity=7)
    assert o1.audit_digest == r1.audit_digest
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.verify("rba-1", 0)
                ledger.evaluate("s1", 0)
                ledger.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() subprocess check
    proc = subprocess.run(
        [sys.executable, m.__file__],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-robustness-auditing OK" in proc.stdout
