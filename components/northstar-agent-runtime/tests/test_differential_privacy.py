"""Targeted tests for differential_privacy (privacy-budget bookkeeping)."""

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import differential_privacy
from differential_privacy import (
    DifferentialPrivacy,
    differential_privacy_audit_event,
    VERSION,
    SCHEMA,
    MECHANISMS,
    SCALE,
    BudgetRecord,
    NoiseRecord,
    CompositionRecord,
    DifferentialPrivacyError,
    BadBudgetError,
    DuplicateBudgetError,
    UnknownBudgetError,
    BadMechanismError,
    BadEpsilonError,
    BadSensitivityError,
    BadDeltaError,
    BadDigestError,
    BudgetExhaustedError,
    SeqOrderError,
    AuditKindError,
)

MODULE_PATH = Path(differential_privacy.__file__)
STDLIB_OK = {
    "__future__", "hashlib", "json", "math", "threading", "dataclasses",
    "typing", "canonical_json",
}


def new_dp():
    dp = DifferentialPrivacy()
    dp.budget("b1", 1.0, 1)
    return dp


# 1. pins
def test_version_schema_pins():
    assert VERSION == "differential-privacy.v1"
    assert SCHEMA == "northstar.differential-privacy.v1"
    assert DifferentialPrivacy().stats()["schema"] == SCHEMA
    assert MECHANISMS == ("laplace", "gaussian", "exponential")


# 2. stdlib only
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_OK, imports - STDLIB_OK


# 3. budget roundtrip + verify
def test_budget_roundtrip_and_verify():
    dp = DifferentialPrivacy()
    rec = dp.budget("analytics", 2.5, 1)
    assert isinstance(rec, BudgetRecord)
    assert rec.epsilon_num == 2_500_000 and rec.epsilon_den == SCALE
    assert rec.verify()
    assert dp.budget_record("analytics") is rec
    assert dp.budget_ids() == ("analytics",)
    assert dp.budget_spent("analytics") == (0, SCALE)
    # tamper breaks verify
    object.__setattr__(rec, "epsilon_num", 1)
    assert not rec.verify()


# 4. budget bad inputs + seq-burn + rejected rows
def test_budget_bad_inputs():
    dp = DifferentialPrivacy()
    dp.budget("ok", 1.0, 1)
    bad = [
        (("ok", 1.0, 2), DuplicateBudgetError),      # duplicate
        (("", 1.0, 2), BadBudgetError),              # empty id
        (("  ", 1.0, 2), BadBudgetError),            # whitespace id
        ((None, 1.0, 2), BadBudgetError),            # non-str id
        (("x", 0.0, 2), BadEpsilonError),            # zero epsilon
        (("x", -1.0, 2), BadEpsilonError),           # negative epsilon
        (("x", float("nan"), 2), BadEpsilonError),   # nan
        (("x", float("inf"), 2), BadEpsilonError),   # inf
        (("x", True, 2), BadEpsilonError),           # bool
        (("x", "1.0", 2), BadEpsilonError),          # str
    ]
    rejected = 0
    seq = 2
    for args, exc in bad:
        args = (args[0], args[1], seq)
        with pytest.raises(exc):
            dp.budget(*args)
        rejected += 1
        seq += 1
    assert len(dp.audit_log()) == 1 + rejected  # 1 declared + rejected rows
    assert dp.stats()["budgets"] == 1
    # next good call must use a fresh seq (failed mutations burn theirs)
    dp.budget("ok2", 1.0, seq)
    assert dp.stats()["budgets"] == 2


# 5. laplace noise roundtrip + exact scale math
def test_noise_laplace_scale_math():
    dp = new_dp()
    nz = dp.noise("b1", "laplace", 2, 0.5, sensitivity=1.0)
    assert isinstance(nz, NoiseRecord)
    assert nz.noise_id == "nz-1"
    assert nz.epsilon_num == 500_000
    assert nz.sensitivity_num == 1_000_000
    assert (nz.scale_num, nz.scale_den) == (2 * SCALE, SCALE)  # b = 1.0/0.5
    assert isinstance(nz.noised_value, float)
    assert nz.verify()
    assert dp.budget_spent("b1") == (500_000, SCALE)


# 6. gaussian requires delta + bad delta table
def test_noise_gaussian_delta():
    dp = new_dp()
    seq = 2
    with pytest.raises(BadDeltaError):
        dp.noise("b1", "gaussian", seq, 0.5)  # delta required
    seq += 1
    for bad_delta in (0.0, 1.0, -0.1, 2.0, float("nan"), True, "x"):
        with pytest.raises(BadDeltaError):
            dp.noise("b1", "gaussian", seq, 0.1, delta=bad_delta)
        seq += 1
    nz = dp.noise("b1", "gaussian", seq, 0.5, sensitivity=1.0, delta=1e-5)
    assert nz.verify()
    assert isinstance(nz.noised_value, float)
    # sigma = 1.0 * sqrt(2 ln(1.25/1e-5)) / 0.5 > laplace scale 2
    assert nz.scale_num > 2 * SCALE


# 7. exponential books no numeric scale/sample
def test_noise_exponential_no_sample():
    dp = new_dp()
    nz = dp.noise("b1", "exponential", 2, 0.25)
    assert nz.noised_value is None
    assert (nz.scale_num, nz.scale_den) == (0, 1)
    assert nz.verify()
    assert dp.budget_spent("b1") == (250_000, SCALE)


# 8. budget exhaustion is fail-closed
def test_budget_exhaustion():
    dp = new_dp()
    dp.noise("b1", "laplace", 2, 0.6)
    assert dp.budget_spent("b1") == (600_000, SCALE)
    with pytest.raises(BudgetExhaustedError):
        dp.noise("b1", "laplace", 3, 0.5)  # 0.6 + 0.5 > 1.0
    # failed spend burned seq 3 and booked a rejected row; spent unchanged
    assert dp.budget_spent("b1") == (600_000, SCALE)
    rows = dp.audit_log()
    assert rows[-1]["kind"] == "rejected"
    # exact boundary still works
    nz = dp.noise("b1", "laplace", 4, 0.4)
    assert nz.verify()
    assert dp.budget_spent("b1") == (1_000_000, SCALE)


# 9. unknown budget / bad mechanism / bad query digest
def test_noise_bad_targets():
    dp = new_dp()
    with pytest.raises(UnknownBudgetError):
        dp.noise("nope", "laplace", 2, 0.1)
    with pytest.raises(BadMechanismError):
        dp.noise("b1", "fourier", 3, 0.1)
    with pytest.raises(BadMechanismError):
        dp.noise("b1", None, 4, 0.1)
    with pytest.raises(BadDigestError):
        dp.noise("b1", "laplace", 5, 0.1, query_digest="SELECT *")  # raw text refused
    with pytest.raises(BadDigestError):
        dp.noise("b1", "laplace", 6, 0.1, query_digest="sha256:zzz")
    nz = dp.noise("b1", "laplace", 7, 0.1, query_digest="sha256:" + "ab" * 32)
    assert nz.verify()
    with pytest.raises(BadSensitivityError):
        dp.noise("b1", "laplace", 8, 0.1, sensitivity=0.0)


# 10. deterministic noise across instances
def test_noise_deterministic_across_instances():
    def book():
        dp = DifferentialPrivacy()
        dp.budget("b1", 2.0, 1)
        a = dp.noise("b1", "laplace", 2, 0.5, sensitivity=2.0)
        b = dp.noise("b1", "gaussian", 3, 0.5, delta=1e-5)
        return a, b
    a1, b1 = book()
    a2, b2 = book()
    assert a1.noised_value == a2.noised_value
    assert b1.noised_value == b2.noised_value
    assert a1.digest == a2.digest
    assert b1.digest == b2.digest


# 11. compose math + report roundtrip
def test_compose_math():
    dp = DifferentialPrivacy()
    dp.budget("a", 1.0, 1)
    dp.budget("b", 2.0, 2)
    dp.noise("a", "laplace", 3, 0.2)
    dp.noise("b", "laplace", 4, 0.3)
    rep = dp.compose(5, ("a", "b"))
    assert isinstance(rep, CompositionRecord)
    assert rep.composition_id == "cmp-1"
    assert (rep.total_spent_num, rep.total_spent_den) == (500_000, SCALE)  # 0.5
    assert rep.total_remaining_num == 2_500_000  # (1+2) - 0.5
    assert rep.per_budget == (("a", 200_000, 800_000), ("b", 300_000, 1_700_000))
    assert rep.verify()
    # compose-all default
    rep2 = dp.compose(6)
    assert rep2.budget_ids == ("a", "b")
    assert rep2.verify()
    with pytest.raises(UnknownBudgetError):
        dp.compose(7, ("a", "zzz"))
    with pytest.raises(BadBudgetError):
        dp.compose(8, "a")


# 12. seq discipline
def test_seq_discipline():
    dp = new_dp()
    with pytest.raises(SeqOrderError):
        dp.budget("x", 1.0, 1)  # rewind: seq 1 already claimed
    n_rejected_before = len([r for r in dp.audit_log() if r["kind"] == "rejected"])
    for bad_seq in (True, "2", 2.5, -1, None):
        with pytest.raises(SeqOrderError):
            dp.noise("b1", "laplace", bad_seq, 0.1)
    # bare rewinds raise without consuming and without rejected rows
    n_rejected_after = len([r for r in dp.audit_log() if r["kind"] == "rejected"])
    assert n_rejected_before == n_rejected_after
    # good seq still advances
    dp.noise("b1", "laplace", 2, 0.1)
    assert dp.noise_ids() == ("nz-1",)


# 13. audit shapes + banned keys + bad kind
def test_audit_shapes_and_ban():
    dp = new_dp()
    dp.noise("b1", "laplace", 2, 0.2, query_digest="sha256:" + "cd" * 32)
    dp.compose(3)
    kinds = [row["kind"] for row in dp.audit_log()]
    assert kinds == ["budget-declared", "noise-booked", "composition-reported"]
    for row in dp.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        for banned in ("query", "value", "scores", "payload", "raw", "text"):
            assert banned not in row["detail"]
    with pytest.raises(AuditKindError):
        differential_privacy_audit_event("nope")
    assert differential_privacy_audit_event("rejected")["schema"] == "audit.ndjson/1"


# 14. views + stats
def test_views_and_stats():
    dp = DifferentialPrivacy()
    dp.budget("b2", 1.0, 1)
    dp.budget("b1", 1.0, 2)
    assert dp.budget_ids() == ("b1", "b2")  # sorted
    dp.noise("b1", "laplace", 3, 0.1)
    assert dp.noise_record("nz-1").budget_id == "b1"
    assert dp.noise_ids() == ("nz-1",)
    with pytest.raises(UnknownBudgetError):
        dp.noise_record("nz-99")
    st = dp.stats()
    assert st == {
        "version": VERSION,
        "schema": SCHEMA,
        "budgets": 2,
        "noise_queries": 1,
        "compositions": 0,
    }
    # frozen records
    rec = dp.budget_record("b1")
    with pytest.raises(Exception):
        rec.budget_id = "hacked"  # noqa: B018


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MODULE_PATH.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "differential-privacy OK: budget, noise, compose, pins, audit" in proc.stdout
