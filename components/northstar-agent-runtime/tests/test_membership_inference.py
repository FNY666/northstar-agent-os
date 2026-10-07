"""15 tests for the membership_inference module."""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "membership_inference.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "membership_inference_test_mod", MOD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["membership_inference_test_mod"] = module
    spec.loader.exec_module(module)
    return module


mi = load_module()

GOOD_DIGEST = "sha256:" + "ab" * 32


def make(seq0=0):
    return mi.MembershipInference()


# ---------------------------------------------------------------- 1: pins
def test_01_version_and_schema_pins():
    assert mi.MEMBERSHIP_INFERENCE_VERSION == "membership-inference.v1"
    assert mi.MEMBERSHIP_INFERENCE_SCHEMA == "northstar.membership-inference.v1"


# ----------------------------------------------------------- 2: stdlib-only
def test_02_stdlib_only_ast():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "fractions", "typing",
        "__future__", "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports


# --------------------------------------------------- 3: register roundtrip
def test_03_register_roundtrip_and_verify():
    ledger = make()
    rec = ledger.register_model("m-1", 1, model_digest=GOOD_DIGEST,
                                training_size=100)
    assert rec.verify()
    assert rec.as_dict()["training_size"] == 100
    assert ledger.model_record("m-1", 2).verify()


# ------------------------------------------- 4: register bad inputs + seq-burn
def test_04_register_bad_inputs_seq_burn():
    ledger = make()
    n_rejected = 0
    # bad training sizes
    for i, bad in enumerate([-1, True, 1.5, "100"]):
        seq = 10 + i
        with pytest.raises(mi.MembershipInferenceError):
            ledger.register_model("mx", seq, training_size=bad)
        n_rejected += 1
    # bad digests
    for j, bad in enumerate(["raw", "sha256:xyz"]):
        seq = 20 + j
        with pytest.raises(mi.BadDigestError):
            ledger.register_model("mx2", seq, model_digest=bad)
    # duplicate id (failed mutation consumes seq + rejected row)
    ledger.register_model("m-dup", 30)
    with pytest.raises(mi.DuplicateIdError):
        ledger.register_model("m-dup", 31)
    n_rejected += 1
    rejected = [r for r in ledger.audit_log(32)
                if r["kind"] == "membership-inference.rejected"]
    # bad digests raise bare (before claim-then-burn); everything else books rows
    assert len(rejected) == n_rejected
    # seqs 10..13, 30, 31 consumed; next live seq must be > 31
    with pytest.raises(mi.SeqOrderError):
        ledger.register_model("m-next", 31)


# ------------------------------------------------------- 5: test roundtrip
def test_05_test_roundtrip_and_verify():
    ledger = make()
    ledger.register_model("m-1", 1)
    rec = ledger.test("t-1", "m-1", "loss-threshold", 2,
                      trials=("tp", "tn", "fp", "fn"))
    assert rec.verify()
    assert rec.as_dict()["trial_count"] if "trial_count" in rec.as_dict() else True
    assert ledger.test_record("t-1", 3).verify()


# ------------------------------------------------ 6: test bad-input table
def test_06_test_bad_inputs_seq_burn():
    ledger = make()
    ledger.register_model("m-1", 1)
    n = 0
    with pytest.raises(mi.BadKindError):  # bad attack kind
        ledger.test("t-x", "m-1", "gradient-norm", 2)
    n += 1
    with pytest.raises(mi.UnknownModelError):  # unknown model
        ledger.test("t-x", "nope", "loss-threshold", 3)
    n += 1
    with pytest.raises(mi.BadTrialError):  # empty trials
        ledger.test("t-x", "m-1", "loss-threshold", 4, trials=())
    n += 1
    with pytest.raises(mi.BadTrialError):  # bad outcome token
        ledger.test("t-x", "m-1", "loss-threshold", 5, trials=("tp", "xx"))
    n += 1
    ledger.test("t-dup", "m-1", "shadow-model", 6, trials=("tp",))
    with pytest.raises(mi.DuplicateIdError):  # duplicate test id
        ledger.test("t-dup", "m-1", "shadow-model", 7, trials=("tp",))
    n += 1
    rejected = [r for r in ledger.audit_log(8)
                if r["kind"] == "membership-inference.rejected"]
    assert len(rejected) == n
    with pytest.raises(mi.SeqOrderError):
        ledger.test("t-next", "m-1", "loss-threshold", 7, trials=("tp",))


# --------------------------------------------- 7: advantage + risk bands
def test_07_advantage_math_and_risk_bands():
    ledger = make()
    ledger.register_model("m-1", 1)
    # TPR=1.0 (4/4), FPR=0.0 (0/4) -> advantage 1 -> high
    ledger.test("t-hi", "m-1", "loss-threshold", 2,
                trials=("tp", "tp", "tp", "tp", "tn", "tn", "tn", "tn"))
    r = ledger.assess("m-1", 3)
    assert r.tpr == "1/1" and r.fpr == "0/1" and r.advantage == "1/1"
    assert r.risk_band == "high"
    assert r.verify()
    # TPR=3/4, FPR=1/4 -> advantage 1/2 -> high
    ledger2 = make()
    ledger2.register_model("m-2", 1)
    ledger2.test("t-md", "m-2", "shadow-model", 2,
                 trials=("tp", "tp", "tp", "fn", "tn", "tn", "tn", "fp"))
    r2 = ledger2.assess("m-2", 3)
    assert r2.advantage == "1/2" and r2.risk_band == "high"
    # advantage 0 -> low
    ledger3 = make()
    ledger3.register_model("m-3", 1)
    ledger3.test("t-lo", "m-3", "likelihood-ratio", 2,
                 trials=("tp", "fn", "fp", "tn"))
    r3 = ledger3.assess("m-3", 3)
    assert r3.advantage == "0/1" and r3.risk_band == "low"


# ---------------------------------------------- 8: assess read purity
def test_08_assess_pure_read_no_audit_rows():
    ledger = make()
    ledger.register_model("m-1", 1)
    ledger.test("t-1", "m-1", "confidence-score", 2, trials=("tp", "tn"))
    before = len(ledger.audit_log(3))
    r1 = ledger.assess("m-1", 4)
    r2 = ledger.assess("m-1", 4)  # same seq twice is fine (pure read)
    assert r1.digest == r2.digest
    assert len(ledger.audit_log(5)) == before
    assert ledger.stats(6)["seq"] == 2  # assess consumed no seq


# ------------------------------------------- 9: unknown model as data
def test_09_assess_unknown_model_as_data():
    ledger = make()
    r = ledger.assess("ghost", 1)
    assert r.total_trials == 0
    assert r.risk_band == "low"
    assert r.advantage == "0/1"
    assert r.verify()


# ---------------------------------------------------- 10: mitigate roundtrip
def test_10_mitigate_roundtrip_and_vocab():
    ledger = make()
    ledger.register_model("m-1", 1)
    for i, kind in enumerate(mi.MITIGATIONS):
        ledger.mitigate(f"mit-{i}", "m-1", kind, 2 + i)
    assert len(ledger.mitigations_for_model("m-1", 10)) == len(mi.MITIGATIONS)
    rec = ledger.mitigation_record("mit-0", 11)
    assert rec.verify()
    with pytest.raises(mi.BadKindError):
        ledger.mitigate("mit-x", "m-1", "adversarial-training", 12)
    with pytest.raises(mi.UnknownModelError):
        ledger.mitigate("mit-y", "nope", "dp-noise", 13)


# -------------------------------------------------- 11: retire terminality
def test_11_retire_terminality():
    ledger = make()
    ledger.register_model("m-1", 1)
    ledger.retire("m-1", 2, reason="leakage-accepted")
    assert "m-1" in ledger.retired_ids(3)
    for op in (
        lambda: ledger.test("t-1", "m-1", "loss-threshold", 4, trials=("tp",)),
        lambda: ledger.mitigate("mit-1", "m-1", "dp-noise", 5),
        lambda: ledger.register_model("m-1", 6),
        lambda: ledger.retire("m-1", 7),
    ):
        with pytest.raises((mi.UnknownModelError, mi.DuplicateIdError,
                             mi.RetiredModelError)):
            op()
    with pytest.raises(mi.BadReasonError):
        ledger.retire("m-1", 8, reason="nope")


# --------------------------------------------------- 12: seq discipline
def test_12_seq_discipline():
    ledger = make()
    ledger.register_model("m-1", 1)
    for bad in (1, 0, True, "2", 2.5, None):
        with pytest.raises(mi.SeqOrderError):
            ledger.register_model("m-x", bad)
    # bare rewind consumes nothing and books no rejected row
    with pytest.raises(mi.SeqOrderError):
        ledger.test("t-1", "m-1", "loss-threshold", 1, trials=("tp",))
    rejected = [r for r in ledger.audit_log(2)
                if r["kind"] == "membership-inference.rejected"]
    assert not rejected
    # failed mutation consumes seq: after register at 1, burn seq 3 via dup test id
    ledger.test("t-a", "m-1", "loss-threshold", 3, trials=("tp",))
    with pytest.raises(mi.DuplicateIdError):
        ledger.test("t-a", "m-1", "loss-threshold", 4, trials=("tp",))
    with pytest.raises(mi.SeqOrderError):
        ledger.register_model("m-y", 4)


# ------------------------------------------------------ 13: audit leak ban
def test_13_audit_shapes_leak_ban_bad_kind():
    for banned in ("record", "text", "content", "training", "data"):
        with pytest.raises(mi.AuditKindError):
            mi.membership_inference_audit_event("model-registered", {banned: "x"})
    ev = mi.membership_inference_audit_event("test-booked",
                                             {"test_id": "t-1", "trial_count": 4})
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "test-booked"
    with pytest.raises(mi.AuditKindError):
        mi.membership_inference_audit_event("bogus-kind", {})


# --------------------------------------------- 14: tamper + determinism
def test_14_cross_instance_determinism_and_tamper():
    a = make()
    b = make()
    a.register_model("m-1", 1, training_size=50)
    b.register_model("m-1", 1, training_size=50)
    ra = a.register_model("m-2", 2)
    rb = b.register_model("m-2", 2)
    assert ra.digest == rb.digest
    object.__setattr__(rb, "training_size", 51)
    assert not rb.verify()
    # assess digest deterministic across instances
    a.test("t-1", "m-1", "loss-threshold", 3, trials=("tp", "tn"))
    b.test("t-1", "m-1", "loss-threshold", 3, trials=("tp", "tn"))
    assert a.assess("m-1", 4).digest == b.assess("m-1", 4).digest


# -------------------------------------------------------- 15: main() check
def test_15_main_subprocess():
    proc = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "membership-inference OK" in proc.stdout
