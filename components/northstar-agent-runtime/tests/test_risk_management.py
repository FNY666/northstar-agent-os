"""15 tests for risk_management.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "risk_management.py"


def _load():
    spec = importlib.util.spec_from_file_location("risk_management", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["risk_management"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


rm_mod = _load()

PIN = "sha256:" + "a" * 64


def _rm():
    return rm_mod.RiskManagement()


# 1. version/schema pins
def test_pins():
    assert rm_mod.RISK_MANAGEMENT_VERSION == "risk-management.v1"
    assert rm_mod.SCHEMA_PIN == "northstar.risk-management.v1"
    assert set(rm_mod.RISK_CATEGORIES) >= {
        "strategic", "operational", "financial", "compliance",
        "reputational", "technology", "third-party", "environmental",
    }
    assert set(rm_mod.TREATMENT_STRATEGIES) == {"avoid", "reduce", "transfer", "accept"}
    assert set(rm_mod.REVIEW_OUTCOMES) == {"improving", "stable", "deteriorating", "closed"}


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. identify roundtrip + verify()
def test_identify_roundtrip():
    rm = _rm()
    rec = rm.identify("risk-1", "technology", 1,
                      description_digest=PIN, likelihood=4, impact=5)
    assert rec.risk_id == "risk-1"
    assert rec.rating == 20 and rec.band == "critical"
    assert rec.verify()
    back = rm.risk("risk-1", 2)
    assert back.digest == rec.digest


# 4. duplicate + bad-input table + seq-burn + rejected-row accounting
def test_identify_bad_inputs():
    rm = _rm()
    rm.identify("risk-1", "technology", 1)
    with pytest.raises(rm_mod.DuplicateRiskError):
        rm.identify("risk-1", "technology", 2)
    cases = [
        ("", "technology", 3, PIN, 1, 1),                       # bad id
        ("risk-x", "nope", 4, PIN, 1, 1),                       # bad category
        ("risk-x", "technology", 5, "not-a-pin", 1, 1),         # bad digest
        ("risk-x", "technology", 6, PIN, 0, 1),                 # likelihood too low
        ("risk-x", "technology", 7, PIN, 6, 1),                 # likelihood too high
        ("risk-x", "technology", 8, PIN, True, 1),              # bool rating
        ("risk-x", "technology", 9, PIN, 1, "3"),               # str impact
        ("risk-x", "technology", 10, PIN, 1, 2.5),              # float impact
    ]
    for rid, cat, seq, dig, lik, imp in cases:
        with pytest.raises(rm_mod.RiskManagementError):
            rm.identify(rid, cat, seq, description_digest=dig,
                        likelihood=lik, impact=imp)
    assert rm._n_rejected == 1 + len(cases)
    assert rm.stats(11)["risks"] == 1


# 5. full category vocabulary accepted + rating bands
def test_category_vocabulary_and_bands():
    rm = _rm()
    expectations = {
        "strategic": (1, 1, 1, "low"),
        "operational": (2, 2, 4, "low"),
        "financial": (3, 2, 6, "medium"),
        "compliance": (3, 3, 9, "medium"),
        "reputational": (4, 3, 12, "high"),
        "technology": (5, 3, 15, "high"),
        "third-party": (5, 4, 20, "critical"),
        "environmental": (5, 5, 25, "critical"),
    }
    for i, (cat, (lik, imp, rating, band)) in enumerate(expectations.items(), start=1):
        rec = rm.identify(f"risk-{cat}", cat, i, likelihood=lik, impact=imp)
        assert rec.rating == rating and rec.band == band
        assert rec.verify()
    assert rm.summary(9).risks == 8


# 6. treat roundtrip + verify() + minted ids
def test_treat_roundtrip():
    rm = _rm()
    rm.identify("risk-1", "operational", 1, likelihood=5, impact=4)
    trt = rm.treat("risk-1", "reduce", 2, owner="sec-team",
                   residual_likelihood=2, residual_impact=3)
    assert trt.treatment_id == "trt-1"
    assert trt.residual_rating == 6 and trt.residual_band == "medium"
    assert trt.verify()
    trt2 = rm.treat("risk-1", "transfer", 3, owner="vendor-x",
                    residual_likelihood=1, residual_impact=2)
    assert trt2.treatment_id == "trt-2"
    assert rm.treatments_for("risk-1", 4) == ("trt-1", "trt-2")
    assert rm.latest_treatment("risk-1", 4).treatment_id == "trt-2"


# 7. treat bad-input table + seq-burn + rejected rows
def test_treat_bad_inputs():
    rm = _rm()
    rm.identify("risk-1", "financial", 1)
    cases = [
        ("risk-?", "reduce", 2),                 # unknown risk
        ("risk-1", "destroy", 3),                # bad strategy
        ("risk-1", "reduce", 4, "x" * 129),      # bad owner (too long)
        ("risk-1", "reduce", 5, "sec", 0, 1),    # residual too low
        ("risk-1", "reduce", 6, "sec", 1, 6),    # residual too high
        ("risk-1", "reduce", 7, "sec", True, 1), # bool residual
    ]
    for rid, strat, seq, *rest in cases:
        owner = rest[0] if len(rest) > 0 else ""
        rl = rest[1] if len(rest) > 1 else 1
        ri = rest[2] if len(rest) > 2 else 1
        with pytest.raises(rm_mod.RiskManagementError):
            rm.treat(rid, strat, seq, owner=owner,
                     residual_likelihood=rl, residual_impact=ri)
    assert rm._n_rejected == len(cases)
    kinds = {r["kind"] for r in rm.audit_log(8)}
    assert "risk-management.rejected" in kinds


# 8. all treatment strategies accepted
def test_strategy_vocabulary():
    rm = _rm()
    strategies = sorted(rm_mod.TREATMENT_STRATEGIES)
    for i, strat in enumerate(strategies, start=1):
        rm.identify(f"risk-{i}", "strategic", i)
    for i, strat in enumerate(strategies, start=11):
        trt = rm.treat(f"risk-{i - 10}", strat, i, owner="owner")
        assert trt.strategy == strat and trt.verify()
    assert rm.stats(20)["treatments"] == 4


# 9. monitor roundtrip + review chain + verify()
def test_monitor_chain():
    rm = _rm()
    rm.identify("risk-1", "compliance", 1, likelihood=3, impact=3)
    rm.treat("risk-1", "accept", 2, owner="ciso")
    r1 = rm.monitor("risk-1", 3, outcome="deteriorating", review_digest=PIN)
    r2 = rm.monitor("risk-1", 4, outcome="stable")
    assert r1.review_id == "rvw-1" and r2.review_id == "rvw-2"
    assert r1.verify() and r2.verify()
    assert rm.reviews_for("risk-1", 5) == ("rvw-1", "rvw-2")
    assert rm.latest_review("risk-1", 5).outcome == "stable"
    assert rm.is_closed("risk-1", 5) is False
    with pytest.raises(rm_mod.BadOutcomeError):
        rm.monitor("risk-1", 6, outcome="vanished")
    with pytest.raises(rm_mod.UnknownRiskError):
        rm.monitor("risk-?", 7)
    with pytest.raises(rm_mod.BadDigestError):
        rm.monitor("risk-1", 8, review_digest="bad")


# 10. closed is terminal: later treat/monitor refused
def test_closed_terminal():
    rm = _rm()
    rm.identify("risk-1", "reputational", 1)
    rm.monitor("risk-1", 2, outcome="closed")
    assert rm.is_closed("risk-1", 3) is True
    with pytest.raises(rm_mod.ClosedRiskError):
        rm.treat("risk-1", "reduce", 4)
    with pytest.raises(rm_mod.ClosedRiskError):
        rm.monitor("risk-1", 5, outcome="stable")
    assert rm.summary(6).closed == 1
    with pytest.raises(rm_mod.UnknownRiskError):
        rm.is_closed("risk-?", 6)


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    rm = _rm()
    rm.identify("risk-1", "technology", 1)
    with pytest.raises(rm_mod.SeqOrderError):
        rm.identify("risk-2", "technology", 1)          # rewind: bare
    with pytest.raises(rm_mod.SeqOrderError):
        rm.identify("risk-2", "technology", True)       # bool seq
    with pytest.raises(rm_mod.SeqOrderError):
        rm.identify("risk-2", "technology", "2")        # str seq
    with pytest.raises(rm_mod.SeqOrderError):
        rm.identify("risk-2", "technology", -5)         # negative seq
    assert rm._n_rejected == 0                           # bare raises: no rows
    with pytest.raises(rm_mod.DuplicateRiskError):
        rm.identify("risk-1", "technology", 2)           # consumes seq
    assert rm._n_rejected == 1
    with pytest.raises(rm_mod.SeqOrderError):
        rm.identify("risk-2", "technology", 2)           # seq 2 is gone


# 12. view read-purity: same seq reuse, no audit rows, unknown lookups
def test_view_read_purity():
    rm = _rm()
    rm.identify("risk-1", "technology", 1, likelihood=2, impact=2)
    before = rm.stats(2)["audit_rows"]
    assert rm.risk_ids(3) == ("risk-1",)
    assert rm.treatments_for("risk-1", 3) == ()
    assert rm.reviews_for("risk-1", 3) == ()
    assert rm.latest_treatment("risk-1", 3) is None
    assert rm.latest_review("risk-1", 3) is None
    summ = rm.summary(3)
    assert summ.risks == 1 and summ.verify()
    assert rm.stats(3)["audit_rows"] == before
    with pytest.raises(rm_mod.UnknownRiskError):
        rm.risk("risk-?", 3)
    with pytest.raises(rm_mod.UnknownRiskError):
        rm.treatment("trt-9", 3)
    with pytest.raises(rm_mod.SeqOrderError):
        rm.summary(0)
    with pytest.raises(rm_mod.SeqOrderError):
        rm.summary(True)


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    rm = _rm()
    rm.identify("risk-1", "technology", 1, description_digest=PIN)
    rm.treat("risk-1", "reduce", 2, owner="sec-team")
    rm.monitor("risk-1", 3, outcome="stable")
    kinds = [e["kind"] for e in rm.audit_log(4)]
    assert kinds == [
        "risk-management.identified",
        "risk-management.treated",
        "risk-management.reviewed",
    ]
    ev = rm_mod.risk_management_audit_event("identified", {"risk_id": "x"})
    assert ev["kind"] == "risk-management.identified"
    with pytest.raises(rm_mod.AuditKindError):
        rm_mod.risk_management_audit_event("pwned", {})
    with pytest.raises(rm_mod.AuditKindError):
        rm_mod.risk_management_audit_event("identified", {"description": "raw"})
    with pytest.raises(rm_mod.AuditKindError):
        rm_mod.risk_management_audit_event("identified", {"evidence": "raw"})
    for banned in ("text", "content", "notes", "payload", "raw", "secret"):
        with pytest.raises(rm_mod.AuditKindError):
            rm_mod.risk_management_audit_event("treated", {banned: "x"})


# 14. cross-instance digest determinism + tamper rejection + frozen-ness
def test_digest_determinism_and_tamper():
    a, b = _rm(), _rm()
    ra = a.identify("risk-1", "financial", 1, description_digest=PIN,
                    likelihood=3, impact=4)
    rb = b.identify("risk-1", "financial", 1, description_digest=PIN,
                    likelihood=3, impact=4)
    assert ra.digest == rb.digest
    ra2 = a.identify("risk-2", "financial", 2, description_digest=PIN,
                     likelihood=3, impact=4)
    assert ra2.digest != ra.digest  # risk_id is in the pin
    object.__setattr__(ra, "rating", 99)
    assert ra.verify() is False
    with pytest.raises(Exception):
        ra.band = "low"  # frozen dataclass


# 15. concurrency smoke + main() subprocess check
def test_concurrency_and_main():
    rm = _rm()
    rm.identify("risk-1", "technology", 1)
    rm.treat("risk-1", "reduce", 2)
    rm.monitor("risk-1", 3, outcome="stable")
    errs = []

    def read():
        try:
            for _ in range(200):
                rm.summary(4)
                rm.risk("risk-1", 4)
                rm.audit_log(4)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=read) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs

    out = subprocess.run(
        [sys.executable, str(MOD_PATH)], capture_output=True, text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "risk-management OK" in out.stdout
