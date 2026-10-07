"""Tests for ai_counterfactual: the declared what-if decision ledger.

House loader pattern: standalone import via sys.modules registration so
frozen-dataclass string annotations resolve under
``from __future__ import annotations``.
"""

import importlib.util
import pathlib
import subprocess
import sys
import threading

import pytest

MODULE_PATH = pathlib.Path(__file__).resolve().parent.parent / "ai_counterfactual.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_counterfactual", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_counterfactual"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()
AICounterfactual = mod.AICounterfactual
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _book(
    ledger,
    system_id="sys-1",
    seq=1,
    generation_kind="input-perturbation",
    verdict="plausible",
    severity=10,
    digest=PIN,
):
    return ledger.counterfactual(
        system_id,
        seq,
        generation_kind=generation_kind,
        verdict=verdict,
        severity=severity,
        counterfactual_digest=digest,
    )


# 1. pins and vocabularies ---------------------------------------------------


def test_pins_and_vocabularies():
    assert mod.AI_COUNTERFACTUAL_VERSION == "ai-counterfactual.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-counterfactual.v1"
    assert len(mod.GENERATION_KINDS) == 8
    assert set(mod.GENERATION_KINDS) == {
        "input-perturbation",
        "instance-retrieval",
        "optimization-search",
        "rule-template",
        "generative-rewrite",
        "boundary-sampling",
        "importance-flip",
        "human-authored",
    }
    assert tuple(mod.VERDICTS) == (
        "plausible",
        "implausible",
        "inconclusive",
        "unverifiable",
        "not-assessed",
    )
    assert set(mod.AUDIT_KINDS) == {"counterfactualled", "retired", "rejected"}


# 2. stdlib-only AST self-check ----------------------------------------------


def test_stdlib_only_ast_check():
    assert AICounterfactual.stdlib_only() is True


# 3. counterfactual roundtrip ------------------------------------------------


def test_counterfactual_roundtrip_and_frozen():
    ac = AICounterfactual()
    rec = _book(ac)
    assert rec.counterfactual_id == "cfn-1"
    assert rec.system_id == "sys-1"
    assert rec.generation_kind == "input-perturbation"
    assert rec.verdict == "plausible"
    assert rec.severity == 10
    assert rec.counterfactual_digest == PIN
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == mod.SCHEMA_PIN
    got = ac.counterfactual_record("cfn-1", 2)
    assert got == rec
    with pytest.raises(Exception):
        rec.verdict = "implausible"  # frozen dataclass
    audit = ac.audit_log(3)
    assert audit[0]["schema"] == "audit.ndjson/1"
    assert audit[0]["kind"] == "counterfactualled"
    assert audit[0]["details"]["counterfactual_id"] == "cfn-1"


# 4. bad-input table + seq burn + rejected rows -------------------------------


def test_bad_input_table_seq_burn_and_rejected_rows():
    ac = AICounterfactual()
    bad_cases = [
        ("bad-kind", dict(generation_kind="nope")),
        ("bad-verdict", dict(verdict="nope")),
        ("bad-digest", dict(digest="not-a-pin")),
        ("bad-severity-low", dict(severity=-1)),
        ("bad-severity-high", dict(severity=101)),
        ("bad-severity-bool", dict(severity=True)),
        ("bad-system-id", dict(system_id="")),
    ]
    seq = 1
    for label, kw in bad_cases:
        kw = dict(kw)
        digest = kw.pop("digest", PIN)
        with pytest.raises(mod.AICounterfactualError):
            _book(ac, seq=seq, digest=digest, **kw)
        seq += 1
    stats = ac.stats(seq)
    assert stats["rejected"] == len(bad_cases)
    assert stats["counterfactuals"] == 0
    rejected_rows = [r for r in ac.audit_log(seq + 1) if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad_cases)
    # rewind raises bare with zero new rows
    n_before = len(ac.audit_log(seq + 2))
    with pytest.raises(mod.SeqOrderError):
        _book(ac, seq=1)
    assert len(ac.audit_log(seq + 3)) == n_before


# 5. full 8-kind vocabulary ----------------------------------------------------


def test_full_generation_kind_vocabulary():
    ac = AICounterfactual()
    for i, kind in enumerate(mod.GENERATION_KINDS):
        rec = _book(ac, seq=i + 1, generation_kind=kind)
        assert rec.generation_kind == kind
        assert rec.counterfactual_id == f"cfn-{i + 1}"
    assert ac.stats(9)["counterfactuals"] == 8


# 6. full verdict vocabulary + severity bounds ---------------------------------


def test_full_verdict_vocabulary_and_severity_bounds():
    ac = AICounterfactual()
    for i, verdict in enumerate(mod.VERDICTS):
        rec = _book(ac, seq=i + 1, verdict=verdict)
        assert rec.verdict == verdict
    lo = _book(ac, seq=6, severity=0)
    assert lo.severity == 0
    hi = _book(ac, seq=7, severity=100)
    assert hi.severity == 100
    with pytest.raises(mod.BadSeverityError):
        _book(ac, seq=8, severity=False)
    rep = ac.evaluate("sys-1", 9)
    assert rep.n_counterfactuals == 7
    assert rep.posture == "implausible"
    assert rep.verify() is True


# 7. verify semantics ----------------------------------------------------------


def test_verify_semantics_and_read_purity():
    ac = AICounterfactual()
    _book(ac)
    rep = ac.verify("cfn-1", 2)
    assert rep.verdict == "verified"
    assert rep.record_kind == "counterfactual"
    assert rep.verify() is True
    n_before = len(ac.audit_log(3))
    rep2 = ac.verify("cfn-1", 2)  # same seq twice: pure read, no burn
    assert rep2.verdict == "verified"
    assert len(ac.audit_log(3)) == n_before
    with pytest.raises(mod.UnknownCounterfactualError):
        ac.verify("cfn-999", 4)
    with pytest.raises(mod.SeqOrderError):
        ac.verify("cfn-1", 0)


# 8. tamper-as-data -------------------------------------------------------------


def test_tamper_reported_as_data():
    ac = AICounterfactual()
    rec = _book(ac)
    object.__setattr__(rec, "verdict", "implausible")  # simulate store tamper
    rep = ac.verify("cfn-1", 2)
    assert rep.verdict == "tampered"
    evl = ac.evaluate("sys-1", 3)
    assert evl.integrity_ok is False
    assert evl.verify() is True  # the report itself is still well-formed


# 9. evaluate posture math -------------------------------------------------------


def test_evaluate_posture_math_and_precedence():
    ac = AICounterfactual()
    _book(ac, system_id="s-covered", seq=1, verdict="plausible")
    _book(ac, system_id="s-covered", seq=2, verdict="plausible")
    assert ac.evaluate("s-covered", 3).posture == "covered"

    _book(ac, system_id="s-implausible", seq=4, verdict="plausible")
    _book(ac, system_id="s-implausible", seq=5, verdict="inconclusive")
    _book(ac, system_id="s-implausible", seq=6, verdict="implausible")
    rep = ac.evaluate("s-implausible", 7)
    assert rep.posture == "implausible"  # implausible outranks contested
    assert rep.n_plausible == 1
    assert rep.n_inconclusive == 1
    assert rep.n_implausible == 1
    assert rep.integrity_ok is True

    _book(ac, system_id="s-contested", seq=8, verdict="unverifiable")
    assert ac.evaluate("s-contested", 9).posture == "contested"

    _book(ac, system_id="s-unassessed", seq=10, verdict="plausible")
    _book(ac, system_id="s-unassessed", seq=11, verdict="not-assessed")
    assert ac.evaluate("s-unassessed", 12).posture == "unassessed"

    _book(ac, system_id="s-empty-src", seq=13, verdict="plausible")
    ac2 = AICounterfactual()
    with pytest.raises(mod.UnknownSystemError):
        ac2.evaluate("never-registered", 1)

    # evaluate is pure: no audit rows, seq not consumed
    n_before = len(ac.audit_log(14))
    ac.evaluate("s-covered", 15)
    ac.evaluate("s-covered", 15)
    assert len(ac.audit_log(16)) == n_before


# 10. retire terminality ----------------------------------------------------------


def test_retire_terminality():
    ac = AICounterfactual()
    _book(ac, seq=1)
    rtr = ac.retire("sys-1", 2, reason="decommissioned")
    assert rtr.verify() is True
    assert ac.retired_ids(3) == ("sys-1",)
    with pytest.raises(mod.RetiredSystemError):
        ac.retire("sys-1", 4)  # double-retire
    with pytest.raises(mod.RetiredSystemError):
        _book(ac, seq=5)  # post-retire mutation refused
    assert ac.counterfactual_record("cfn-1", 6) == ac.counterfactual_record("cfn-1", 7)
    evl = ac.evaluate("sys-1", 8)  # reads still work
    assert evl.posture == "covered"
    with pytest.raises(mod.BadReasonError):
        _book(ac, system_id="sys-2", seq=9)
        ac.retire("sys-2", 10, reason="nope")
    with pytest.raises(mod.UnknownSystemError):
        ac.retire("ghost", 11)
    # ids never recycled: counter keeps minting, retire id not reused
    assert ac.stats(12)["retired"] == 1


# 11. seq discipline ----------------------------------------------------------------


def test_seq_discipline():
    ac = AICounterfactual()
    with pytest.raises(mod.SeqOrderError):
        _book(ac, seq=0)  # genesis rewind: bare, zero rows
    assert len(ac.audit_log(1)) == 0
    for bad in (True, 1.5, "2", -3):
        with pytest.raises(mod.SeqOrderError):
            ac.counterfactual("sys-1", bad, counterfactual_digest=PIN)
    _book(ac, seq=1)
    with pytest.raises(mod.SeqOrderError):
        _book(ac, seq=1)  # genuine rewind raises bare
    stats = ac.stats(2)
    assert stats["counterfactuals"] == 1
    assert stats["rejected"] == 0
    # failed mutation consumes seq + books rejected row
    with pytest.raises(mod.BadVerdictError):
        _book(ac, seq=2, verdict="nope")
    stats = ac.stats(3)
    assert stats["rejected"] == 1
    with pytest.raises(mod.SeqOrderError):
        _book(ac, seq=2)  # burned seq is gone
    assert len([r for r in ac.audit_log(4) if r["kind"] == "rejected"]) == 1


# 12. audit shapes + leak ban --------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    ac = AICounterfactual()
    _book(ac, seq=1)
    row = ac.audit_log(2)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "counterfactualled"
    details = row["details"]
    assert details["generation_kind"] == "input-perturbation"  # pinned data ok
    assert details["verdict"] == "plausible"
    assert details["severity"] == 10
    assert "counterfactual_text" not in details
    with pytest.raises(mod.AuditKindError):
        mod.ai_counterfactual_audit_event("bogus", 1)
    with pytest.raises(mod.AuditKindError):
        mod.ai_counterfactual_audit_event(
            "counterfactualled", 1, counterfactual_text="raw what-if"
        )
    with pytest.raises(mod.AuditKindError):
        mod.ai_counterfactual_audit_event(
            "counterfactualled", 1, original_input="raw input"
        )
    ok = mod.ai_counterfactual_audit_event(
        "counterfactualled",
        1,
        counterfactual_id="cfn-1",
        generation_kind="rule-template",
        verdict="implausible",
    )
    assert ok["kind"] == "counterfactualled"
    assert ok["details"]["generation_kind"] == "rule-template"


# 13. determinism, views, unknown lookups ------------------------------------------------


def test_cross_instance_determinism_and_views():
    def scenario():
        ac = AICounterfactual()
        _book(ac, system_id="a", seq=1, generation_kind="rule-template", digest=PIN2)
        _book(ac, system_id="b", seq=2, generation_kind="boundary-sampling")
        return ac

    ac1, ac2 = scenario(), scenario()
    assert ac1.counterfactual_record("cfn-1", 3).digest == ac2.counterfactual_record(
        "cfn-1", 3
    ).digest
    assert ac1.evaluate("a", 4).digest == ac2.evaluate("a", 4).digest
    assert ac1.system_ids(5) == ("a", "b")
    assert ac1.counterfactual_ids(6) == ("cfn-1", "cfn-2")
    assert ac1.counterfactuals_for("a", 7) == ("cfn-1",)
    assert ac1.counterfactuals_for("b", 8) == ("cfn-2",)
    with pytest.raises(mod.UnknownCounterfactualError):
        ac1.counterfactual_record("cfn-999", 9)
    with pytest.raises(mod.UnknownSystemError):
        ac1.counterfactuals_for("ghost", 10)
    assert ac1.stats(11)["systems"] == 2


# 14. thread-safety smoke ------------------------------------------------------------------


def test_threaded_reads_and_frozen_records():
    ac = AICounterfactual()
    for i in range(4):
        _book(ac, system_id=f"sys-{i}", seq=i + 1)
    errors = []

    def reader(n):
        try:
            for _ in range(50):
                ac.evaluate(f"sys-{n % 4}", 100)
                ac.verify("cfn-1", 101)
                ac.stats(102)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert ac.stats(103)["counterfactuals"] == 4


# 15. main() self-check via subprocess -------------------------------------------------------


def test_main_self_check_subprocess():
    out = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert "ai-counterfactual OK: counterfactual, verify, evaluate, retire, pins, audit" in out.stdout
