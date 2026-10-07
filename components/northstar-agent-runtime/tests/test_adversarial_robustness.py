"""Tests for adversarial_robustness: attack-test / harden / certify ledger."""

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "adversarial_robustness.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "adversarial_robustness_under_test", MOD_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ar = load_module()


def fresh():
    return ar.AdversarialRobustness()


# 1. version / schema pins
def test_version_and_schema_pins():
    assert ar.ADVERSARIAL_ROBUSTNESS_VERSION == "adversarial-robustness.v1"
    assert ar.SCHEMA_PIN == "northstar.adversarial-robustness.v1"


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "hashlib", "json", "math", "threading", "dataclasses", "fractions",
        "typing", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed or \
                    alias.name == "canonical_json", alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed or node.module == "canonical_json", \
                node.module


# 3. register roundtrip + verify
def test_register_roundtrip():
    ledger = fresh()
    record = ledger.register("m1", 1)
    assert record.model_id == "m1"
    assert record.seq == 1
    assert record.verify()
    assert ledger.model_record("m1") == record
    assert ledger.model_ids() == ("m1",)
    assert record.as_dict()["schema"] == ar.SCHEMA_PIN


# 4. register duplicate + bad ids with seq-burn + rejected rows
def test_register_duplicate_and_bad_ids():
    ledger = fresh()
    ledger.register("m1", 1)
    with pytest.raises(ar.DuplicateModelError):
        ledger.register("m1", 2)
    assert ledger.stats()["seq"] == 2
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]
    assert len(rejected) == 1
    seq = 3
    for bad in ("", 123, None):
        with pytest.raises(ar.BadIdError):
            ledger.register(bad, seq)
        seq += 1
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]
    assert len(rejected) == 4


# 5. test roundtrip for all attacks + verify
def test_test_all_attacks():
    ledger = fresh()
    ledger.register("m1", 1)
    seq = 1
    for attack in ar.ATTACKS:
        seq += 1
        record = ledger.test("m1", attack, seq, success_rate=0.1)
        assert record.attack == attack
        assert record.verify()
    assert len(ledger.tests_for("m1")) == len(ar.ATTACKS)
    assert ledger.test_record("atk-1").attack == ar.ATTACKS[0]


# 6. test bad-input table + seq-burn
def test_test_bad_inputs():
    ledger = fresh()
    ledger.register("m1", 1)
    seq = 2
    for bad in (True, 1.5, float("nan"), float("inf"), -0.1, "high"):
        with pytest.raises(ar.BadRateError):
            ledger.test("m1", "pgd", seq, success_rate=bad)
        seq += 1
    with pytest.raises(ar.BadAttackError):
        ledger.test("m1", "brute-force", seq)
    seq += 1
    with pytest.raises(ar.BadDigestError):
        ledger.test("m1", "pgd", seq, budget_digest="not-a-pin")
    seq += 1
    with pytest.raises(ar.UnknownModelError):
        ledger.test("nope", "pgd", seq)
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]
    assert len(rejected) == 9
    assert ledger.stats()["seq"] == seq


# 7. harden roundtrip for all techniques + verify
def test_harden_all_techniques():
    ledger = fresh()
    ledger.register("m1", 1)
    seq = 1
    for technique in ar.TECHNIQUES:
        seq += 1
        record = ledger.harden("m1", technique, seq)
        assert record.technique == technique
        assert record.verify()
    assert len(ledger.hardening_for("m1")) == len(ar.TECHNIQUES)
    assert ledger.hardening_record("hrd-1").technique == ar.TECHNIQUES[0]


# 8. harden bad technique / unknown model
def test_harden_bad_inputs():
    ledger = fresh()
    ledger.register("m1", 1)
    with pytest.raises(ar.BadTechniqueError):
        ledger.harden("m1", "hope", 2)
    with pytest.raises(ar.UnknownModelError):
        ledger.harden("nope", "adversarial-training", 3)
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]
    assert len(rejected) == 2


# 9. certify certified-as-data
def test_certify_certified():
    ledger = fresh()
    ledger.register("m1", 1)
    ledger.test("m1", "pgd", 2, success_rate=0.1)
    ledger.harden("m1", "randomized-smoothing", 3)
    report = ledger.certify("m1", 4)
    assert report.tests == 1
    assert report.attacks == ("pgd",)
    assert report.max_success_rate == 0.1
    assert report.hardening == ("randomized-smoothing",)
    assert report.epsilon == "1/10"
    assert report.certified is True
    assert report.verify()


# 10. certify not-certified cases as data
def test_certify_not_certified_cases():
    ledger = fresh()
    ledger.register("m1", 1)
    ledger.register("m2", 2)
    # no tests, no hardening
    report = ledger.certify("m1", 3)
    assert report.certified is False
    assert report.tests == 0
    assert report.epsilon == "1/10"
    # hardening only, no tests
    ledger.harden("m2", "adversarial-training", 4)
    report = ledger.certify("m2", 5)
    assert report.certified is False
    # tests only, no hardening
    ledger.test("m1", "fgsm", 6, success_rate=0.0)
    report = ledger.certify("m1", 7)
    assert report.certified is False
    # high success rate
    ledger.harden("m1", "adversarial-training", 8)
    ledger.test("m1", "autoattack", 9, success_rate=0.9)
    report = ledger.certify("m1", 10, eps_num=2, eps_den=4)
    assert report.certified is False
    assert report.epsilon == "1/2"  # fraction reduced
    assert report.max_success_rate == 0.9


# 11. certify read purity (no seq consumption, no audit rows)
def test_certify_read_purity():
    ledger = fresh()
    ledger.register("m1", 1)
    before = len(ledger.audit_log())
    report1 = ledger.certify("m1", 9)
    report2 = ledger.certify("m1", 9)
    assert report1.digest == report2.digest
    assert ledger.stats()["seq"] == 1
    assert len(ledger.audit_log()) == before
    with pytest.raises(ar.UnknownModelError):
        ledger.certify("nope", 2)
    with pytest.raises(ar.BadEpsilonError):
        ledger.certify("m1", 2, eps_num=0)
    with pytest.raises(ar.BadEpsilonError):
        ledger.certify("m1", 2, eps_num=1, eps_den=-3)


# 12. retire terminality + id non-recycling
def test_retire_terminality():
    ledger = fresh()
    ledger.register("m1", 1)
    record = ledger.retire("m1", 2, reason="superseded")
    assert record.verify()
    assert ledger.retired_ids() == ("m1",)
    with pytest.raises(ar.RetiredModelError):
        ledger.test("m1", "pgd", 3)
    with pytest.raises(ar.RetiredModelError):
        ledger.harden("m1", "adversarial-training", 4)
    with pytest.raises(ar.RetiredModelError):
        ledger.certify("m1", 5)
    with pytest.raises(ar.DuplicateRetireError):
        ledger.retire("m1", 6)
    with pytest.raises(ar.RetiredModelError):
        ledger.register("m1", 7)
    ledger.register("m2", 8)
    with pytest.raises(ar.BadReasonError):
        ledger.retire("m2", 9, reason="deleted")


# 13. seq discipline (rewind bare, malformed seqs)
def test_seq_discipline():
    ledger = fresh()
    ledger.register("m1", 5)
    with pytest.raises(ar.SeqOrderError):
        ledger.register("m2", 5)
    with pytest.raises(ar.SeqOrderError):
        ledger.register("m2", 4)
    with pytest.raises(ar.SeqOrderError):
        ledger.register("m2", True)
    with pytest.raises(ar.SeqOrderError):
        ledger.register("m2", -1)
    # bare rewinds consume nothing and book no rejected rows
    assert ledger.stats()["seq"] == 5
    rejected = [r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]
    assert rejected == []
    # a failed mutation still consumes its seq
    with pytest.raises(ar.BadIdError):
        ledger.register("", 6)
    assert ledger.stats()["seq"] == 6
    assert len([r for r in ledger.audit_log()
                if r["kind"] == "adversarial-robustness.rejected"]) == 1


# 14. audit shapes + banned keys + bad kind
def test_audit_shapes_and_ban():
    ledger = fresh()
    ledger.register("m1", 1)
    ledger.test("m1", "pgd", 2)
    kinds = {r["kind"] for r in ledger.audit_log()}
    assert "adversarial-robustness.registered" in kinds
    assert "adversarial-robustness.tested" in kinds
    for row in ledger.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "adversarial-robustness"
        for key in row["detail"]:
            assert key not in ar._BANNED_AUDIT_KEYS
    with pytest.raises(ar.AuditKindError):
        ar.adversarial_robustness_audit_event("bogus-kind")
    with pytest.raises(ar.AuditKindError):
        ar.adversarial_robustness_audit_event(
            "adversarial-robustness.registered", weights="raw"
        )


# 15. frozen-ness, determinism, tamper, views, main
def test_frozen_determinism_and_main():
    ledger = fresh()
    record = ledger.register("m1", 1)
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        record.model_id = "m2"  # type: ignore[misc]
    ledger2 = fresh()
    record2 = ledger2.register("m1", 1)
    assert record.digest == record2.digest
    object.__setattr__(record2, "model_id", "tampered")
    assert not record2.verify()
    stats = ledger.stats()
    assert stats["models"] == 1 and stats["tests"] == 0
    assert ledger.model_record("m1").model_id == "m1"
    with pytest.raises(ar.UnknownModelError):
        ledger.model_record("nope")
    with pytest.raises(ar.AdversarialRobustnessError):
        ledger.test_record("atk-99")
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)], capture_output=True, text=True
    )
    assert proc.returncode == 0
    assert "adversarial-robustness OK" in proc.stdout
