"""Tests for dpo.py (Direct Preference Optimization bookkeeping ledger)."""

import ast
import math
import subprocess
import sys
from pathlib import Path

import pytest

import dpo
from dpo import (
    DPO,
    dpo_audit_event,
    DPO_VERSION,
    DPO_SCHEMA,
    AUDIT_SCHEMA,
    KIND_PREFERRED,
    KIND_OPTIMIZED,
    KIND_REJECTED,
    DPOError,
    BadDigestError,
    IdenticalResponsesError,
    UnknownPreferenceError,
    BadBetaError,
    BadLogProbError,
    UnknownOptimizationError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(dpo.__file__)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


def fresh():
    return DPO()


def ledger_with_pair():
    m = fresh()
    pref = m.prefer(DIGEST_A, DIGEST_B, DIGEST_C, 1)
    return m, pref


def ledger_with_opt(beta=0.5):
    m, pref = ledger_with_pair()
    opt = m.optimize(
        pref.pref_id,
        2,
        beta=beta,
        logp_policy_chosen=-0.5,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-1.5,
    )
    return m, pref, opt


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert DPO_VERSION == "dpo.v1"
    assert DPO_SCHEMA == "northstar.dpo.v1"
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
        "math",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
        "__future__",
    }
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"


def test_prefer_roundtrip_and_verify():
    m = fresh()
    rec = m.prefer(DIGEST_A, DIGEST_B, DIGEST_C, 1)
    assert rec.pref_id == "pref-1"
    assert rec.prompt_digest == DIGEST_A
    assert rec.chosen_digest == DIGEST_B
    assert rec.rejected_digest == DIGEST_C
    assert rec.schema == DPO_SCHEMA
    assert rec.verify()
    # raw text never enters the record
    assert "a" * 64 not in repr(rec) or DIGEST_A in repr(rec)
    # second pair mints pref-2
    rec2 = m.prefer("", DIGEST_C, DIGEST_D, 2)
    assert rec2.pref_id == "pref-2"
    assert rec2.verify()


def test_prefer_identical_responses_refused():
    m = fresh()
    with pytest.raises(IdenticalResponsesError):
        m.prefer(DIGEST_A, DIGEST_B, DIGEST_B, 1)
    # failed mutation consumed its seq and booked a rejected row
    assert m.stats(1)["preferences"] == 0
    kinds = [e["kind"] for e in m.audit_log(1)]
    assert kinds == [KIND_REJECTED]
    assert m.audit_log(1)[0]["detail"]["error"] == "IdenticalResponsesError"


def test_prefer_bad_inputs_burn_seq_and_book_rejected():
    m = fresh()
    bad = [
        (123, DIGEST_B, DIGEST_C),  # non-str prompt
        (DIGEST_A, "nope", DIGEST_C),  # chosen not a digest pin
        (DIGEST_A, DIGEST_B, ""),  # rejected empty
        (DIGEST_A, DIGEST_B, DIGEST_B),  # identical responses
        (DIGEST_A, True, DIGEST_C),  # bool digest
    ]
    seq = 1
    for args in bad:
        with pytest.raises(DPOError):
            m.prefer(*args, seq)
        seq += 1
    assert m.stats(seq)["preferences"] == 0
    rejected = [e for e in m.audit_log(seq) if e["kind"] == KIND_REJECTED]
    assert len(rejected) == len(bad)
    assert all("error" in e["detail"] for e in rejected)


def test_seq_discipline():
    m, pref = ledger_with_pair()
    # rewind raises bare without consuming: next legal seq is still 2
    with pytest.raises(SeqOrderError):
        m.prefer(DIGEST_A, DIGEST_B, DIGEST_C, 1)
    rec = m.prefer(DIGEST_A, DIGEST_B, DIGEST_C, 2)
    assert rec.pref_id == "pref-2"
    for bad_seq in (True, "2", 2.0, None, -1):
        with pytest.raises(SeqOrderError):
            m.prefer(DIGEST_A, DIGEST_B, DIGEST_C, bad_seq)
    # negative seq: _check_seq passes ints, _claim rejects non-increasing
    assert m.stats(3)["preferences"] == 2


def test_optimize_roundtrip_and_loss_math():
    m, pref = ledger_with_pair()
    opt = m.optimize(
        pref.pref_id,
        2,
        beta=0.5,
        logp_policy_chosen=-0.5,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-1.5,
    )
    assert opt.opt_id == "opt-1"
    assert opt.pref_id == pref.pref_id
    assert opt.beta == 0.5
    assert opt.policy_margin == pytest.approx(1.5)
    assert opt.ref_margin == pytest.approx(0.5)
    assert opt.margin == pytest.approx(1.0)
    # x = 0.5 * 1.0 = 0.5 -> -log sigma(0.5) = 0.4740769841801067
    assert opt.loss == pytest.approx(0.4740769841801067, rel=1e-12)
    assert opt.verify()
    # zero margin -> loss = ln(2)
    opt2 = m.optimize(
        pref.pref_id,
        3,
        beta=0.5,
        logp_policy_chosen=-1.0,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.5,
        logp_ref_rejected=-2.5,
    )
    assert opt2.loss == pytest.approx(math.log(2), rel=1e-12)
    assert opt2.verify()


def test_optimize_loss_properties():
    m, pref = ledger_with_pair()
    # policy clearly better than reference -> margin > 0 -> loss < ln(2)
    good = m.optimize(
        pref.pref_id,
        2,
        beta=0.1,
        logp_policy_chosen=-0.1,
        logp_policy_rejected=-5.0,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-1.0,
    )
    assert good.margin > 0
    assert 0.0 < good.loss < math.log(2)
    # policy worse than reference -> margin < 0 -> loss > ln(2)
    bad = m.optimize(
        pref.pref_id,
        3,
        beta=0.1,
        logp_policy_chosen=-5.0,
        logp_policy_rejected=-0.1,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-1.0,
    )
    assert bad.margin < 0
    assert bad.loss > math.log(2)
    # extreme margins never overflow / stay finite
    extreme = m.optimize(
        pref.pref_id,
        4,
        beta=1.0,
        logp_policy_chosen=0.0,
        logp_policy_rejected=-1e6,
        logp_ref_chosen=-1e6,
        logp_ref_rejected=0.0,
    )
    assert math.isfinite(extreme.loss)


def test_optimize_bad_inputs():
    m, pref = ledger_with_pair()
    with pytest.raises(UnknownPreferenceError):
        m.optimize(
            "pref-99",
            2,
            logp_policy_chosen=-1.0,
            logp_policy_rejected=-2.0,
            logp_ref_chosen=-1.0,
            logp_ref_rejected=-2.0,
        )
    bad_betas = [0.0, -0.1, 1.5, True, "0.5", float("nan"), float("inf")]
    seq = 3
    for beta in bad_betas:
        with pytest.raises(BadBetaError):
            m.optimize(
                pref.pref_id,
                seq,
                beta=beta,
                logp_policy_chosen=-1.0,
                logp_policy_rejected=-2.0,
                logp_ref_chosen=-1.0,
                logp_ref_rejected=-2.0,
            )
        seq += 1
    bad_lps = [0.5, float("nan"), float("inf"), True, "x", None]
    for lp in bad_lps:
        with pytest.raises(BadLogProbError):
            m.optimize(
                pref.pref_id,
                seq,
                logp_policy_chosen=lp,
                logp_policy_rejected=-2.0,
                logp_ref_chosen=-1.0,
                logp_ref_rejected=-2.0,
            )
        seq += 1
    assert m.stats(seq)["optimizations"] == 0
    rejected = [e for e in m.audit_log(seq) if e["kind"] == KIND_REJECTED]
    assert len(rejected) == 1 + len(bad_betas) + len(bad_lps)


def test_loss_report_pure_read():
    m, pref, opt = ledger_with_opt()
    rep1 = m.loss(opt.opt_id, 3)
    rep2 = m.loss(opt.opt_id, 3)  # same seq twice is fine for a pure read
    assert rep1.loss == opt.loss
    assert rep1.margin == opt.margin
    assert rep1.pref_id == pref.pref_id
    assert rep1.verify()
    assert rep1 == rep2
    # no seq consumed, no audit rows booked by reads
    stats = m.stats(3)
    assert stats["optimizations"] == 1
    kinds = [e["kind"] for e in m.audit_log(3)]
    assert kinds == [KIND_PREFERRED, KIND_OPTIMIZED]
    # reads also work at lower seqs (shape validation only)
    m.loss(opt.opt_id, 1)


def test_loss_unknown_opt_raises_without_consuming():
    m, pref = ledger_with_pair()
    with pytest.raises(UnknownOptimizationError):
        m.loss("opt-99", 1)
    with pytest.raises(UnknownPreferenceError):
        m.preference("pref-99", 1)
    with pytest.raises(UnknownOptimizationError):
        m.optimization("opt-99", 1)
    # nothing consumed: next legal mutation seq is still 2
    opt = m.optimize(
        pref.pref_id,
        2,
        logp_policy_chosen=-1.0,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-2.0,
    )
    assert opt.opt_id == "opt-1"


def test_audit_shapes_leak_ban_and_bad_kind():
    m, pref, opt = ledger_with_opt()
    events = m.audit_log(3)
    assert [e["kind"] for e in events] == [KIND_PREFERRED, KIND_OPTIMIZED]
    for e in events:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "dpo"
        assert "digest" in e
        # raw text never crosses the audit boundary; only digest pins
        for banned in ("prompt", "chosen", "rejected", "response", "text", "value"):
            assert banned not in e["detail"]
    with pytest.raises(AuditKindError):
        dpo_audit_event("dpo.nope", 1)
    with pytest.raises(AuditKindError):
        dpo_audit_event(KIND_PREFERRED, 1, prompt="raw text leak")
    with pytest.raises(AuditKindError):
        dpo_audit_event(KIND_OPTIMIZED, 1, value=123)


def test_cross_instance_determinism():
    kwargs = dict(
        beta=0.5,
        logp_policy_chosen=-0.5,
        logp_policy_rejected=-2.0,
        logp_ref_chosen=-1.0,
        logp_ref_rejected=-1.5,
    )
    m1, p1, o1 = ledger_with_opt()
    m2 = fresh()
    p2 = m2.prefer(DIGEST_A, DIGEST_B, DIGEST_C, 1)
    o2 = m2.optimize(p2.pref_id, 2, **kwargs)
    assert o1.digest == o2.digest
    assert o1.loss == o2.loss
    assert m1.loss(o1.opt_id, 3).digest == m2.loss(o2.opt_id, 3).digest
    # tampering breaks verify
    import dataclasses

    tampered = dataclasses.replace(o1, loss=o1.loss + 1.0)
    assert not tampered.verify()


def test_stats_and_views():
    m, pref, opt = ledger_with_opt()
    stats = m.stats(9)
    assert stats["preferences"] == 1
    assert stats["optimizations"] == 1
    assert stats["audit_rows"] == 2
    assert stats["schema"] == DPO_SCHEMA
    assert m.preference(pref.pref_id, 9) == pref
    assert m.optimization(opt.opt_id, 9) == opt
    rep = m.loss(opt.opt_id, 9)
    assert rep.opt_id == opt.opt_id


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "dpo OK: prefer, optimize, loss, pins, audit" in proc.stdout
