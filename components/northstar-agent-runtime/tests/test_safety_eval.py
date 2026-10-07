"""Tests for safety_eval: safety-benchmark decision ledger."""

import ast
import subprocess
import sys

import pytest

import safety_eval as sev
from safety_eval import SafetyEval


def _module_path():
    return sev.__file__


# ---------------------------------------------------------------------------
# pins & stdlib-only
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert sev.SAFETY_EVAL_VERSION == "safety-eval.v1"
    assert sev.SAFETY_EVAL_SCHEMA == "northstar.safety-eval.v1"
    assert sev.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(_module_path(), encoding="utf-8").read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "fractions",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# register_case
# ---------------------------------------------------------------------------


def test_register_case_roundtrip_and_digest():
    se = SafetyEval()
    rec = se.register_case("inj-001", "prompt-injection", 1)
    assert rec.case_id == "inj-001"
    assert rec.category == "prompt-injection"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify("inj-001", "prompt-injection")
    assert not rec.verify("inj-001", "jailbreak")
    assert se.case_record("inj-001") == rec
    assert se.case_record("nope") is None
    assert se.case_ids() == ("inj-001",)


def test_register_duplicate_and_bad_inputs_consume_seq_and_audit_rejected():
    se = SafetyEval()
    se.register_case("a1", "prompt-injection", 1)
    with pytest.raises(sev.DuplicateCaseError):
        se.register_case("a1", "prompt-injection", 2)
    with pytest.raises(sev.BadCaseError):
        se.register_case("", "prompt-injection", 3)
    with pytest.raises(sev.BadCaseError):
        se.register_case("has space", "prompt-injection", 4)
    with pytest.raises(sev.BadCaseError):
        se.register_case("x" * 257, "prompt-injection", 5)
    with pytest.raises(sev.BadCategoryError):
        se.register_case("a2", "hallucination", 6)
    with pytest.raises(sev.SeqOrderError):
        se.register_case("a3", "jailbreak", 6)  # rewind: bare
    kinds = [r["kind"] for r in se.audit_log()]
    assert kinds.count("rejected") == 5
    assert len(se.audit_log()) == 1 + 5
    # frozen records
    with pytest.raises(Exception):
        se.case_record("a1").case_id = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


def test_check_roundtrip_and_digest():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    ev = "sha256:" + "ab" * 32
    rec = se.check("inj-001", "fail", 2, evidence_digest=ev)
    assert rec.check_id == "check-1"
    assert rec.outcome == "fail"
    assert rec.evidence_digest == ev
    assert rec.digest.startswith("sha256:")
    assert rec.verify("inj-001", "fail", ev)
    assert not rec.verify("inj-001", "pass", ev)
    assert se.check_record("check-1") == rec
    assert se.check_record("nope") is None
    assert se.check_ids() == ("check-1",)


def test_check_refusals_and_inconclusive_is_data():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    # inconclusive is data, never raised
    inc = se.check("inj-001", "inconclusive", 2)
    assert inc.outcome == "inconclusive" and inc.evidence_digest == ""
    with pytest.raises(sev.UnknownCaseError):
        se.check("ghost", "pass", 3)
    with pytest.raises(sev.BadOutcomeError):
        se.check("inj-001", "maybe", 4)
    with pytest.raises(sev.BadEvidenceError):
        se.check("inj-001", "pass", 5, evidence_digest="not-a-digest")
    kinds = [r["kind"] for r in se.audit_log()]
    assert kinds.count("rejected") == 3


# ---------------------------------------------------------------------------
# score (pure read)
# ---------------------------------------------------------------------------


def test_score_report_counts_and_exact_rate():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    se.register_case("jail-001", "jailbreak", 2)
    se.check("inj-001", "pass", 3)
    se.check("inj-001", "fail", 4)
    se.check("jail-001", "inconclusive", 5)
    rep = se.score(5)
    by_cat = {c.category: c for c in rep.categories}
    assert by_cat["prompt-injection"].passed == 1
    assert by_cat["prompt-injection"].failed == 1
    assert by_cat["jailbreak"].inconclusive == 1
    assert (rep.total_passed, rep.total_failed, rep.total_inconclusive) == (1, 1, 1)
    assert rep.pass_rate == "1/3"  # exact Fraction text, no floats
    assert rep.verify(rep.categories,
                      (rep.total_passed, rep.total_failed,
                       rep.total_inconclusive), rep.pass_rate)
    assert len(rep.categories) == len(sev.CATEGORIES)


def test_score_is_pure_read():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    se.check("inj-001", "pass", 2)
    before = len(se.audit_log())
    r1 = se.score(2)
    r2 = se.score(2)  # same seq reuse OK: nothing consumed
    assert r1.digest == r2.digest
    assert len(se.audit_log()) == before
    empty = SafetyEval()
    rep = empty.score(1)
    assert rep.total_passed == 0 and rep.pass_rate == "0/1"


# ---------------------------------------------------------------------------
# certify
# ---------------------------------------------------------------------------


def test_certify_true_path():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    se.check("inj-001", "pass", 2)
    rec = se.certify(0.9, 3)
    assert rec.certify_id == "certify-1"
    assert rec.certified is True
    assert rec.passed == 1 and rec.total == 1
    assert rec.score_digest.startswith("sha256:")
    assert rec.verify(0.9, 1, 1, True)
    assert not rec.verify(0.5, 1, 1, True)
    assert se.certify_record("certify-1") == rec
    assert se.certify_record("nope") is None


def test_certify_false_path_is_data():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    se.register_case("jail-001", "jailbreak", 2)
    se.check("inj-001", "pass", 3)
    se.check("jail-001", "fail", 4)
    rec = se.certify(0.9, 5)  # 1/2 < 0.9: verdict as data, never raised
    assert rec.certified is False
    assert rec.passed == 1 and rec.total == 2
    row = se.audit_log()[-1]
    assert row["kind"] == "certified" and row["detail"]["certified"] is False


def test_certify_refusals_consume_seq():
    se = SafetyEval()
    with pytest.raises(sev.NoEvidenceError):
        se.certify(0.9, 1)  # zero booked checks: fail-closed
    se.register_case("inj-001", "prompt-injection", 2)
    se.check("inj-001", "pass", 3)
    with pytest.raises(sev.BadThresholdError):
        se.certify(1.5, 4)  # out of range
    with pytest.raises(sev.BadThresholdError):
        se.certify(True, 5)  # bool refused
    with pytest.raises(sev.BadThresholdError):
        se.certify(float("nan"), 6)
    kinds = [r["kind"] for r in se.audit_log()]
    assert kinds.count("rejected") == 4


# ---------------------------------------------------------------------------
# seq discipline
# ---------------------------------------------------------------------------


def test_seq_ordering_rewind_bare_malformed():
    se = SafetyEval()
    se.register_case("a", "jailbreak", 1)
    with pytest.raises(sev.SeqOrderError):
        se.register_case("b", "jailbreak", 1)  # rewind: bare, no consumption
    with pytest.raises(sev.SeqOrderError):
        se.register_case("b", "jailbreak", 0)  # negative/rewind
    with pytest.raises(sev.SeqOrderError):
        se.register_case("b", "jailbreak", True)  # bool refused
    with pytest.raises(sev.SeqOrderError):
        se.register_case("b", "jailbreak", "2")  # str refused
    # no rejected rows for bare rewinds
    assert len(se.audit_log()) == 1
    rec = se.register_case("b", "jailbreak", 2)
    assert rec.seq == 2


# ---------------------------------------------------------------------------
# audit boundary & cross-instance determinism
# ---------------------------------------------------------------------------


def test_audit_shapes_and_banned_keys_and_bad_kind():
    se = SafetyEval()
    se.register_case("inj-001", "prompt-injection", 1)
    rows = se.audit_log()
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "safety-eval.v1"
    assert rows[0]["kind"] == "case-registered"
    assert rows[0]["seq"] == 1
    # banned keys refused by the builder
    with pytest.raises(sev.AuditKindError):
        sev.safety_eval_audit_event("checked", {"evidence": "raw"}, 2)
    with pytest.raises(sev.AuditKindError):
        sev.safety_eval_audit_event("nope", {}, 2)
    with pytest.raises(sev.SeqOrderError):
        sev.safety_eval_audit_event("checked", {}, True)  # bool seq refused


def test_cross_instance_digest_determinism():
    def build():
        se = SafetyEval()
        se.register_case("inj-001", "prompt-injection", 1)
        se.check("inj-001", "pass", 2,
                 evidence_digest="sha256:" + "ff" * 32)
        return se

    a, b = build(), build()
    assert a.score(2).digest == b.score(2).digest
    assert a.certify(1.0, 3).digest == b.certify(1.0, 3).digest
    # different content -> different pins
    c = build()
    c.check("inj-001", "fail", 3)
    assert c.score(3).digest != a.score(3).digest


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def test_main_subprocess():
    out = subprocess.run([sys.executable, _module_path()],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "safety-eval OK: register, check, score, certify"
