"""Tests for the ai-safety-validation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_safety_validation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_safety_validation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_safety_validation"] = module
    spec.loader.exec_module(module)
    return module


sv = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sv.AI_SAFETY_VALIDATION_VERSION == "ai-safety-validation.v1"
    assert sv.SCHEMA_PIN == "northstar.ai-safety-validation.v1"
    assert sv.VALIDATION_KINDS == (
        "pre-deployment-validation",
        "post-deployment-validation",
        "regression-validation",
        "red-team-validation",
        "formal-check-validation",
        "behavioral-audit-validation",
        "scenario-validation",
        "incident-driven-validation",
    )
    assert sv.VALIDATION_VERDICTS == (
        "safe-to-deploy",
        "safe-with-conditions",
        "unsafe",
        "inconclusive",
        "not-validated",
    )
    assert sv.VERIFY_VERDICTS == ("verified", "tampered")
    assert sv.POSTURES == (
        "unvalidated",
        "unsafe",
        "contested",
        "conditionally-safe",
        "validated",
    )
    assert sv.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert sv.AUDIT_KINDS == ("validated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert sv.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast", "pathlib", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. validate roundtrip + val-N minting + verify() + frozen-ness
def test_validate_roundtrip():
    ledger = sv.AISafetyValidation()
    rec = ledger.validate("sys-1", 1, validation_kind="pre-deployment-validation",
                          verdict="safe-to-deploy", validation_digest=PIN)
    assert rec.validation_id == "val-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.validation_kind == "pre-deployment-validation"
    assert rec.verdict == "safe-to-deploy"
    assert rec.validation_digest == PIN
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        object.__getattribute__(rec, "__setattr__")("verdict", "unsafe")
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "unsafe"
    got = ledger.validation_record("val-1", 2)
    assert got == rec
    rows = ledger.audit_log(3)
    assert rows[0]["kind"] == "validated"
    assert rows[0]["module"] == "ai-safety-validation"
    assert rows[0]["version"] == "ai-safety-validation.v1"


# 4. bad-input table + seq-burn + rejected-row accounting + rewind-bare
def test_bad_inputs_burn_seq_and_book_rejected():
    ledger = sv.AISafetyValidation()
    bad_cases = [
        dict(validation_kind="not-a-kind"),
        dict(verdict="not-a-verdict"),
        dict(validation_digest="bad-digest"),
        dict(system_id=""),
        dict(system_id=123),
        dict(system_id="x" * 300),
    ]
    seq = 1
    for case in bad_cases:
        case = dict(case)
        system_id = case.pop("system_id", "sys-1")
        with pytest.raises(sv.AISafetyValidationError):
            ledger.validate(system_id, seq, **case)
        seq += 1
    rows = ledger.audit_log(seq)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_cases)
    # rewind raises bare with no new row
    before = len(ledger.audit_log(100))
    with pytest.raises(sv.SeqOrderError):
        ledger.validate("sys-1", 1)
    assert len(ledger.audit_log(101)) == before
    # genesis rewind (seq 0 after seq advanced) raises bare too
    ledger2 = sv.AISafetyValidation()
    ledger2.validate("sys-1", 5)
    with pytest.raises(sv.SeqOrderError):
        ledger2.validate("sys-1", 4)
    assert all(r["kind"] == "validated" for r in ledger2.audit_log(6))


# 5. full 8-kind vocabulary
def test_full_validation_kind_vocabulary():
    ledger = sv.AISafetyValidation()
    seq = 1
    for kind in sv.VALIDATION_KINDS:
        rec = ledger.validate("sys-k", seq, validation_kind=kind)
        assert rec.validation_kind == kind
        assert rec.verify()
        seq += 1
    ids = ledger.validation_ids(seq)
    assert len(ids) == 8


# 6. full 5-verdict vocabulary + tallies
def test_full_verdict_vocabulary_and_tallies():
    ledger = sv.AISafetyValidation()
    seq = 1
    for verdict in sv.VALIDATION_VERDICTS:
        rec = ledger.validate("sys-v", seq, verdict=verdict)
        assert rec.verdict == verdict
        seq += 1
    ev = ledger.evaluate("sys-v", seq)
    assert ev.n_validations == 5
    assert ev.n_safe_to_deploy == 1
    assert ev.n_safe_with_conditions == 1
    assert ev.n_unsafe == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_validated == 1
    # unsafe outranks everything
    assert ev.posture == "unsafe"
    assert ev.integrity_ok
    assert ev.verify()


# 7. verify semantics: tamper-as-data, read purity, unknown refusal
def test_verify_semantics():
    ledger = sv.AISafetyValidation()
    rec = ledger.validate("sys-1", 1, verdict="safe-to-deploy", validation_digest=PIN)
    rep = ledger.verify("val-1", 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    # tamper reported, never raised; purity: same seq twice, no audit rows
    n_before = len(ledger.audit_log(3))
    object.__setattr__(rec, "verdict", "unsafe")
    rep2 = ledger.verify("val-1", 2)
    assert rep2.verdict == "tampered"
    assert not rep2.integrity_ok
    assert ledger.verify("val-1", 2).verdict == "tampered"
    assert len(ledger.audit_log(4)) == n_before
    with pytest.raises(sv.UnknownValidationError):
        ledger.verify("val-999", 5)
    with pytest.raises(sv.SeqOrderError):
        ledger.verify("val-1", True)


# 8. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    ledger = sv.AISafetyValidation()
    # unvalidated
    ev = ledger.evaluate("ghost", 1)
    assert ev.posture == "unvalidated"
    assert ev.n_validations == 0
    seq = 2
    # validated: all safe-to-deploy
    ledger.validate("s-a", seq, verdict="safe-to-deploy"); seq += 1
    ledger.validate("s-a", seq, verdict="safe-to-deploy"); seq += 1
    assert ledger.evaluate("s-a", seq).posture == "validated"; seq += 1
    # conditionally-safe: safe-with-conditions present
    ledger.validate("s-b", seq, verdict="safe-to-deploy"); seq += 1
    ledger.validate("s-b", seq, verdict="safe-with-conditions"); seq += 1
    assert ledger.evaluate("s-b", seq).posture == "conditionally-safe"; seq += 1
    # conditionally-safe: not-validated present
    ledger.validate("s-c", seq, verdict="safe-to-deploy"); seq += 1
    ledger.validate("s-c", seq, verdict="not-validated"); seq += 1
    assert ledger.evaluate("s-c", seq).posture == "conditionally-safe"; seq += 1
    # contested: inconclusive outranks conditionally-safe
    ledger.validate("s-d", seq, verdict="safe-with-conditions"); seq += 1
    ledger.validate("s-d", seq, verdict="inconclusive"); seq += 1
    assert ledger.evaluate("s-d", seq).posture == "contested"; seq += 1
    # unsafe outranks everything
    ledger.validate("s-e", seq, verdict="safe-to-deploy"); seq += 1
    ledger.validate("s-e", seq, verdict="safe-with-conditions"); seq += 1
    ledger.validate("s-e", seq, verdict="inconclusive"); seq += 1
    ledger.validate("s-e", seq, verdict="unsafe"); seq += 1
    assert ledger.evaluate("s-e", seq).posture == "unsafe"
    # tamper flips integrity_ok as data
    ledger2 = sv.AISafetyValidation()
    rec = ledger2.validate("s-f", 1, verdict="safe-to-deploy")
    assert ledger2.evaluate("s-f", 2).integrity_ok
    object.__setattr__(rec, "verdict", "unsafe")
    assert not ledger2.evaluate("s-f", 3).integrity_ok


# 9. evaluate read purity + unknown-system refusal + views
def test_evaluate_read_purity_and_views():
    ledger = sv.AISafetyValidation()
    ledger.validate("sys-1", 1, validation_kind="red-team-validation", verdict="unsafe")
    ledger.validate("sys-1", 2, validation_kind="regression-validation", verdict="safe-to-deploy")
    n_before = len(ledger.audit_log(3))
    ev1 = ledger.evaluate("sys-1", 3)
    ev2 = ledger.evaluate("sys-1", 3)
    assert ev1 == ev2
    assert len(ledger.audit_log(4)) == n_before
    assert ev1.posture == "unsafe"
    # views
    assert ledger.system_ids(5) == ("sys-1",)
    assert ledger.validation_ids(6) == ("val-1", "val-2")
    recs = ledger.validations_for("sys-1", 7)
    assert [r.validation_id for r in recs] == ["val-1", "val-2"]
    assert ledger.validations_for("ghost", 8) == ()
    stats = ledger.stats(9)
    assert stats["n_validations"] == 2
    assert stats["n_systems"] == 1
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    with pytest.raises(sv.UnknownValidationError):
        ledger.validation_record("val-999", 10)


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = sv.AISafetyValidation()
    ledger.validate("sys-1", 1, verdict="safe-to-deploy")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify()
    assert ledger.retired_ids(3) == ("sys-1",)
    # id never recycled: mutating a retired system fails
    with pytest.raises(sv.RetiredSystemError):
        ledger.validate("sys-1", 4, verdict="safe-to-deploy")
    # reads still work after retire
    assert ledger.evaluate("sys-1", 5).posture == "validated"
    assert ledger.validation_record("val-1", 6).verify()
    # double retire fails
    with pytest.raises(sv.RetiredSystemError):
        ledger.retire("sys-1", 7)
    # unknown system retire fails
    with pytest.raises(sv.UnknownSystemError):
        ledger.retire("ghost", 8)
    # bad reason fails
    ledger.validate("sys-2", 9)
    with pytest.raises(sv.BadReasonError):
        ledger.retire("sys-2", 10, reason="bogus")
    # all four reasons accepted
    ledger2 = sv.AISafetyValidation()
    seq = 1
    for reason in sv.RETIRE_REASONS:
        ledger2.validate(f"sys-{reason}", seq); seq += 1
        ledger2.retire(f"sys-{reason}", seq, reason=reason); seq += 1
    assert ledger2.retired_ids(seq) == tuple(sorted(f"sys-{r}" for r in sv.RETIRE_REASONS))


# 11. seq discipline: genesis rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sv.AISafetyValidation()
    # genesis rewind: seq 0 claim after seq advanced
    ledger.validate("sys-1", 3)
    with pytest.raises(sv.SeqOrderError):
        ledger.validate("sys-1", 0)
    n = len(ledger.audit_log(10))
    # malformed seqs raise bare, burn nothing
    for bad in (True, "1", 1.5, None):
        with pytest.raises(sv.SeqOrderError):
            ledger.validate("sys-1", bad)
    assert len(ledger.audit_log(11)) == n
    # failed mutation consumes seq (bad kind burns 4, then 4 is gone)
    with pytest.raises(sv.BadValidationKindError):
        ledger.validate("sys-1", 4, validation_kind="bogus")
    with pytest.raises(sv.SeqOrderError):
        ledger.validate("sys-1", 4)
    # gap seqs allowed
    rec = ledger.validate("sys-1", 100)
    assert rec.validation_id == "val-2"
    # read seqs accept any int shape, bool refused
    assert ledger.stats(200)["n_validations"] == 2
    with pytest.raises(sv.SeqOrderError):
        ledger.stats(True)


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sv.AISafetyValidation()
    rec = ledger.validate("sys-1", 1, verdict="safe-to-deploy", validation_digest=PIN)
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-safety-validation"
    assert row["version"] == "ai-safety-validation.v1"
    assert row["kind"] == "validated"
    assert row["seq"] == 1
    assert row["details"]["validation_id"] == "val-1"
    # the declared validation_digest travels as a digest pin in the record,
    # never raw in audit details
    # banned raw-material keys cannot cross the audit boundary
    for banned in ("validation_report", "test_transcript", "behavior_trace",
                   "weights", "prompt", "evidence", "api_key", "pii"):
        with pytest.raises(sv.AISafetyValidationError):
            sv.ai_safety_validation_audit_event("validated", 3, **{banned: "raw"})
    # pinned vocab + digest pins remain emittable
    ok = sv.ai_safety_validation_audit_event(
        "validated", 4, validation_kind="scenario-validation",
        verdict="safe-to-deploy", validation_digest=PIN)
    assert ok["details"]["verdict"] == "safe-to-deploy"
    # bad audit kind
    with pytest.raises(sv.AuditKindError):
        sv.ai_safety_validation_audit_event("bogus", 5)
    # retire row shape
    ledger.retire("sys-1", 6)
    rows = ledger.audit_log(7)
    assert rows[-1]["kind"] == "retired"
    assert rows[-1]["details"]["reason"] == "manual"


# 13. cross-instance digest determinism + unknown lookups
def test_cross_instance_digest_determinism():
    def build():
        mod = _load()
        led = mod.AISafetyValidation()
        rec = led.validate("sys-x", 1, validation_kind="scenario-validation",
                           verdict="safe-with-conditions", validation_digest=PIN)
        return mod, led, rec
    mod1, led1, rec1 = build()
    mod2, led2, rec2 = build()
    assert rec1.digest == rec2.digest
    assert led1.evaluate("sys-x", 2).digest == led2.evaluate("sys-x", 2).digest
    assert led1.verify("val-1", 3).digest == led2.verify("val-1", 3).digest
    # digest format
    assert rec1.digest.startswith("sha256:")
    assert len(rec1.digest) == len("sha256:") + 64
    # empty digest pin allowed and deterministic
    r1 = led1.validate("sys-y", 4)
    r2 = led2.validate("sys-y", 4)
    assert r1.digest == r2.digest
    assert r1.validation_digest == ""


# 14. 8-thread read smoke + frozen-ness of all record types
def test_threaded_read_smoke_and_frozenness():
    ledger = sv.AISafetyValidation()
    for i in range(4):
        ledger.validate("sys-1", i + 1, verdict="safe-to-deploy")
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 5)
                ledger.verify("val-1", 6)
                ledger.stats(7)
                ledger.system_ids(8)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # frozen-ness across record types
    rec = ledger.validation_record("val-1", 9)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.seq = 999
    rep = ledger.verify("val-1", 10)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rep.verdict = "verified"
    ev = ledger.evaluate("sys-1", 11)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.posture = "unsafe"
    ret = ledger.retire("sys-1", 12)
    with pytest.raises(dataclasses.FrozenInstanceError):
        ret.reason = "manual"


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-safety-validation OK: validate, verify, evaluate, retire, pins, audit" in proc.stdout
