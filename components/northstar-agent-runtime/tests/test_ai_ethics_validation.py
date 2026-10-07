"""Tests for ai_ethics_validation.py (AI ethics validation decision ledger)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "ai_ethics_validation.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "ai_ethics_validation", MODULE_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_ethics_validation"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def m():
    return load_module()


# ---------------------------------------------------------------------------
# 1. pins and vocabularies
# ---------------------------------------------------------------------------


def test_pins_and_vocabularies(m):
    assert m.AI_ETHICS_VALIDATION_VERSION == "ai-ethics-validation.v1"
    assert m.SCHEMA_PIN == "northstar.ai-ethics-validation.v1"
    assert len(m.VALIDATION_KINDS) == 8
    assert len(m.VALIDATION_VERDICTS) == 5
    assert set(m.VERIFY_VERDICTS) == {"verified", "tampered"}
    assert set(m.POSTURES) == {
        "unvalidated",
        "ethically-invalid",
        "inconclusive",
        "partially-valid",
        "ethically-valid",
    }
    assert set(m.RETIRE_REASONS) == {
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    }
    assert set(m.EMIT_KINDS) == {"validated", "retired", "rejected"}
    assert "validations" in m._BANNED_AUDIT_KEYS
    assert "evidence" in m._BANNED_AUDIT_KEYS
    assert "ethics_review" in m._BANNED_AUDIT_KEYS
    assert "deliberation" in m._BANNED_AUDIT_KEYS


# ---------------------------------------------------------------------------
# 2. stdlib-only AST self-check
# ---------------------------------------------------------------------------


def test_stdlib_only(m):
    assert m.stdlib_only() is True


# ---------------------------------------------------------------------------
# 3. validate roundtrip, minting, verify(), frozen-ness
# ---------------------------------------------------------------------------


def test_validate_roundtrip(m):
    ledger = m.AIEthicsValidation()
    rec = ledger.validate(
        "sys-1", 1, validation_kind="fairness-validation", verdict="ethically-valid"
    )
    assert rec.validation_id == "evl-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    with pytest.raises(Exception):
        rec.verdict = "ethically-invalid"  # frozen
    rec2 = ledger.validate("sys-1", 2, verdict="ethically-invalid")
    assert rec2.validation_id == "evl-2"
    assert ledger.system_ids(0) == ("sys-1",)


# ---------------------------------------------------------------------------
# 4. bad-input table + seq-burn + rejected-row accounting + rewind-bare
# ---------------------------------------------------------------------------


def test_bad_input_table(m):
    ledger = m.AIEthicsValidation()
    n_rejected = 0
    bad = [
        ("", 1, "fairness-validation", "ethically-valid", ""),  # bad system
        (None, 2, "fairness-validation", "ethically-valid", ""),  # bad system
        ("sys-1", 3, "no-such-kind", "ethically-valid", ""),  # bad kind
        ("sys-1", 4, "fairness-validation", "no-such-verdict", ""),  # bad verdict
        ("sys-1", 5, "fairness-validation", "ethically-valid", "sha256:zzz"),  # bad digest
        ("sys-1", 6, "fairness-validation", "ethically-valid", "not-a-digest"),  # bad digest
    ]
    for system_id, seq, kind, verdict, digest in bad:
        with pytest.raises(m.AIEthicsValidationError):
            ledger.validate(system_id, seq, kind, verdict, digest)
        n_rejected += 1
        rows = ledger.audit_log(0)
        assert rows[-1]["kind"] == "rejected"
        assert rows[-1]["seq"] == seq
    assert ledger.stats(0)["n_validations"] == 0
    assert len(ledger.audit_log(0)) == n_rejected
    # first valid write after the burns
    rec = ledger.validate("sys-1", 7, verdict="ethically-valid")
    assert rec.validation_id == "evl-1"
    with pytest.raises(m.SeqOrderError):
        ledger.validate("sys-1", 3)
    rows = ledger.audit_log(0)
    assert rows[-1]["seq"] == 7  # no new row from the bare rewind
    assert ledger.stats(0)["n_validations"] == 1


# ---------------------------------------------------------------------------
# 5. full 8-kind vocabulary sweep
# ---------------------------------------------------------------------------


def test_full_kind_vocabulary(m):
    ledger = m.AIEthicsValidation()
    seq = 0
    for i, kind in enumerate(m.VALIDATION_KINDS):
        seq += 1
        rec = ledger.validate(f"sys-{i}", seq, validation_kind=kind)
        assert rec.validation_kind == kind
        assert rec.verify() is True


# ---------------------------------------------------------------------------
# 6. full 5-verdict vocabulary + tallies
# ---------------------------------------------------------------------------


def test_full_verdict_vocabulary_and_tallies(m):
    ledger = m.AIEthicsValidation()
    seq = 0
    for verdict in m.VALIDATION_VERDICTS:
        seq += 1
        ledger.validate("sys-1", seq, verdict=verdict)
    ev = ledger.evaluate("sys-1", 99)
    assert ev.n_validations == 5
    assert ev.n_ethically_valid == 1
    assert ev.n_partially_valid == 1
    assert ev.n_ethically_invalid == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_validated == 1
    assert ev.posture == "ethically-invalid"  # invalid outranks everything else
    assert ev.verify() is True


# ---------------------------------------------------------------------------
# 7. verify semantics: verified + tamper-as-data + read purity + unknown refusal
# ---------------------------------------------------------------------------


def test_verify_semantics(m):
    ledger = m.AIEthicsValidation()
    rec = ledger.validate("sys-1", 1, verdict="ethically-valid")
    rows_before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.validation_id, 42)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same seq twice, no audit rows added, seq untouched
    rep2 = ledger.verify(rec.validation_id, 42)
    assert rep2.digest == rep.digest
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == 1
    # tamper reported as data, never raised
    tampered = m.ValidationRecord(
        validation_id=rec.validation_id,
        system_id=rec.system_id,
        seq=rec.seq,
        validation_kind=rec.validation_kind,
        verdict="ethically-invalid",  # tampered verdict
        validation_digest=rec.validation_digest,
        digest=rec.digest,
    )
    ledger._validations[rec.validation_id] = tampered
    rep3 = ledger.verify(rec.validation_id, 43)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(m.UnknownRecordError):
        ledger.verify("evl-999", 44)


# ---------------------------------------------------------------------------
# 8. evaluate posture math (all 5 postures + precedence)
# ---------------------------------------------------------------------------


def test_evaluate_posture_math(m):
    def posture_for(verdicts):
        ledger = m.AIEthicsValidation()
        seq = 0
        for v in verdicts:
            seq += 1
            ledger.validate("s", seq, verdict=v)
        return ledger.evaluate("s", 1000).posture

    assert posture_for(["ethically-valid", "ethically-valid"]) == "ethically-valid"
    assert posture_for(["ethically-valid", "partially-valid"]) == "partially-valid"
    assert posture_for(["ethically-valid", "not-validated"]) == "partially-valid"
    assert posture_for(["inconclusive"]) == "inconclusive"
    assert posture_for(["ethically-valid", "inconclusive"]) == "inconclusive"
    assert posture_for(["ethically-invalid"]) == "ethically-invalid"
    # precedence: ethically-invalid > inconclusive > partially-valid
    assert posture_for(["partially-valid", "inconclusive"]) == "inconclusive"
    assert (
        posture_for(["partially-valid", "ethically-invalid", "inconclusive"])
        == "ethically-invalid"
    )
    # evaluate on a system with no validations is not possible; unknown raises
    ledger = m.AIEthicsValidation()
    with pytest.raises(m.UnknownSystemError):
        ledger.evaluate("ghost", 0)


# ---------------------------------------------------------------------------
# 9. evaluate read purity + integrity flip on tamper
# ---------------------------------------------------------------------------


def test_evaluate_read_purity(m):
    ledger = m.AIEthicsValidation()
    ledger.validate("sys-1", 1, verdict="ethically-valid")
    rows_before = len(ledger.audit_log(0))
    ev1 = ledger.evaluate("sys-1", 50)
    ev2 = ledger.evaluate("sys-1", 50)
    assert ev1.digest == ev2.digest
    assert ev1.integrity_ok is True
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == 1
    # tamper flips integrity_ok as data
    rec = ledger.validation_record("evl-1", 0)
    tampered = m.ValidationRecord(
        validation_id=rec.validation_id,
        system_id=rec.system_id,
        seq=rec.seq,
        validation_kind=rec.validation_kind,
        verdict="ethically-invalid",
        validation_digest=rec.validation_digest,
        digest=rec.digest,
    )
    ledger._validations[rec.validation_id] = tampered
    ev3 = ledger.evaluate("sys-1", 51)
    assert ev3.integrity_ok is False
    assert ev3.posture == "ethically-invalid"


# ---------------------------------------------------------------------------
# 10. retire terminality + id non-recycling + post-retire reads + bad reason
# ---------------------------------------------------------------------------


def test_retire_terminality(m):
    ledger = m.AIEthicsValidation()
    ledger.validate("sys-1", 1, verdict="ethically-valid")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    assert ledger.retired_ids(0) == ("sys-1",)
    # post-retire mutations refused
    with pytest.raises(m.RetiredSystemError):
        ledger.validate("sys-1", 3)
    # double retire refused
    with pytest.raises(m.RetiredSystemError):
        ledger.retire("sys-1", 4)
    # ids never recycled: a new system keeps incrementing evl-N
    rec = ledger.validate("sys-2", 5, verdict="ethically-valid")
    assert rec.validation_id == "evl-2"
    # post-retire reads still work
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "ethically-valid"
    assert ledger.validation_record("evl-1", 0).verify() is True
    # bad reason burns seq + rejected row
    with pytest.raises(m.BadReasonError):
        ledger.retire("sys-2", 7, reason="nope")
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"
    # retire unknown system refused
    with pytest.raises(m.UnknownSystemError):
        ledger.retire("ghost", 8)


# ---------------------------------------------------------------------------
# 11. seq discipline: genesis rewind, malformed seqs, failed-mutation-consumes-seq
# ---------------------------------------------------------------------------


def test_seq_discipline(m):
    ledger = m.AIEthicsValidation()
    # genesis rewind: seq 0 <= initial 0 -> bare SeqOrderError, no rows
    with pytest.raises(m.SeqOrderError):
        ledger.validate("sys-1", 0)
    assert len(ledger.audit_log(0)) == 0
    # malformed seqs raise bare, never booked
    for bad_seq in ("1", 1.5, True, None):
        with pytest.raises(m.SeqOrderError):
            ledger.validate("sys-1", bad_seq)
    assert len(ledger.audit_log(0)) == 0
    # failed mutation consumes its seq: next valid seq must exceed the burned one
    with pytest.raises(m.BadValidationKindError):
        ledger.validate("sys-1", 1, validation_kind="bogus")
    assert ledger.stats(0)["seq"] == 1
    rec = ledger.validate("sys-1", 2, verdict="ethically-valid")
    assert rec.validation_id == "evl-1"


# ---------------------------------------------------------------------------
# 12. audit shapes + leak ban + bad-kind (builder)
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban(m):
    ledger = m.AIEthicsValidation()
    rec = ledger.validate("sys-1", 1, verdict="ethically-valid")
    rows = ledger.audit_log(0)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-ethics-validation"
    assert row["version"] == "ai-ethics-validation.v1"
    assert row["kind"] == "validated"
    assert row["seq"] == 1
    assert row["details"]["validation_id"] == rec.validation_id
    # banned raw keys rejected at the builder boundary
    with pytest.raises(m.AIEthicsValidationError):
        m.ai_ethics_validation_audit_event("validated", 2, evidence="raw stuff")
    with pytest.raises(m.AIEthicsValidationError):
        m.ai_ethics_validation_audit_event("validated", 2, weights="raw stuff")
    with pytest.raises(m.AIEthicsValidationError):
        m.ai_ethics_validation_audit_event("validated", 2, validations="raw stuff")
    with pytest.raises(m.AIEthicsValidationError):
        m.ai_ethics_validation_audit_event("validated", 2, ethics_review="raw stuff")
    with pytest.raises(m.AIEthicsValidationError):
        m.ai_ethics_validation_audit_event("validated", 2, deliberation="raw stuff")
    # pinned vocab values and digest pins remain emittable
    ok = m.ai_ethics_validation_audit_event(
        "validated", 2, validation_kind="fairness-validation", verdict="ethically-valid"
    )
    assert ok["details"]["verdict"] == "ethically-valid"
    # bad kind refused
    with pytest.raises(m.AuditKindError):
        m.ai_ethics_validation_audit_event("nope", 3)


# ---------------------------------------------------------------------------
# 13. cross-instance digest determinism + views/stats + unknown lookups
# ---------------------------------------------------------------------------


def test_cross_instance_determinism_and_views(m):
    a = m.AIEthicsValidation()
    b = m.AIEthicsValidation()
    ra = a.validate(
        "sys-1", 1, validation_kind="fairness-validation", verdict="ethically-valid"
    )
    rb = b.validate(
        "sys-1", 1, validation_kind="fairness-validation", verdict="ethically-valid"
    )
    assert ra.digest == rb.digest
    ea = a.evaluate("sys-1", 2)
    eb = b.evaluate("sys-1", 2)
    assert ea.digest == eb.digest
    assert a.validation_ids(0) == ("evl-1",)
    assert len(a.validations_for("sys-1", 0)) == 1
    assert a.validations_for("ghost", 0) == ()
    stats = a.stats(0)
    assert stats["n_systems"] == 1
    assert stats["n_validations"] == 1
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 1
    with pytest.raises(m.UnknownValidationError):
        a.validation_record("evl-999", 0)


# ---------------------------------------------------------------------------
# 14. 8-thread read smoke + frozen-ness
# ---------------------------------------------------------------------------


def test_thread_read_smoke(m):
    ledger = m.AIEthicsValidation()
    rec = ledger.validate("sys-1", 1, verdict="ethically-valid")
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.verify(rec.validation_id, 0)
                ledger.evaluate("sys-1", 0)
                ledger.audit_log(0)
                ledger.stats(0)
                assert rec.verify() is True
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


# ---------------------------------------------------------------------------
# 15. main() subprocess self-check
# ---------------------------------------------------------------------------


def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert (
        "ai-ethics-validation OK: validate, verify, evaluate, retire, pins, audit"
        in result.stdout
    )
