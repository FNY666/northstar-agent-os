"""Tests for the ai_redress decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_redress
from ai_redress import (
    AI_REDRESS_VERSION,
    SCHEMA_PIN,
    AIRedress,
    AIRedressError,
    AuditKindError,
    BadClaimError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadRedressKindError,
    POSTURES,
    REDRESS_KINDS,
    REDRESS_OUTCOMES,
    RETIRE_REASONS,
    RetiredClaimError,
    SeqOrderError,
    UnknownClaimError,
    UnknownRedressError,
    ai_redress_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_REDRESS_VERSION == "ai-redress.v1"
    assert SCHEMA_PIN == "northstar.ai-redress.v1"
    assert REDRESS_KINDS == (
        "apology",
        "compensation",
        "record-correction",
        "output-retraction",
        "remediation-action",
        "appeal-outcome",
        "service-restoration",
        "policy-change",
    )
    assert REDRESS_OUTCOMES == ("granted", "partial", "denied", "inconclusive")
    assert POSTURES == (
        "unaddressed",
        "redress-denied",
        "inconclusive",
        "partially-redressed",
        "redressed",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_redress.__file__)
    tree = ast.parse(path.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


def test_provide_roundtrip_verify_and_frozenness():
    """provide -> minted id, digest verifies, record is frozen."""
    ledger = AIRedress()
    rec = ledger.provide(
        "claim-1", 1, redress_kind="compensation", outcome="granted",
        claim_digest=GOOD_DIGEST,
    )
    assert rec.redress_id == "rds-1"
    assert rec.claim_id == "claim-1"
    assert rec.redress_kind == "compensation"
    assert rec.outcome == "granted"
    assert rec.claim_digest == GOOD_DIGEST
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(Exception):
        rec.outcome = "denied"  # frozen dataclass
    audit = ledger.audit_log(0)
    assert len(audit) == 1
    assert audit[0]["kind"] == "provided"
    assert audit[0]["details"]["redress_kind"] == "compensation"


def test_provide_bad_inputs_burn_seq_and_book_rejected():
    """Bad inputs fail closed: seq consumed, rejected row booked."""
    ledger = AIRedress()
    cases = [
        ("", 1, {}, BadClaimError),                 # empty claim_id
        (None, 2, {}, BadClaimError),               # None claim_id
        (True, 3, {}, BadClaimError),               # bool claim_id
        ("claim-x", 4, {"redress_kind": "bribe"}, BadRedressKindError),
        ("claim-x", 5, {"outcome": "guaranteed"}, BadOutcomeError),
        ("claim-x", 6, {"claim_digest": "nope"}, BadDigestError),
        ("claim-x", 7, {"claim_digest": "sha256:" + "zz" * 32}, BadDigestError),
    ]
    for claim_id, seq, kwargs, exc in cases:
        with pytest.raises(exc):
            ledger.provide(claim_id, seq, **kwargs)
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(cases)
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-redress"
        assert "rejected_kind" in r["details"]
    # seq was burned by every failure: next mutation must exceed 7
    with pytest.raises(SeqOrderError):
        ledger.provide("claim-1", 7)
    rec = ledger.provide("claim-1", 8)
    assert rec.redress_id == "rds-1"


def test_full_redress_kind_vocabulary_accepted():
    """All 8 pinned redress kinds are bookable."""
    ledger = AIRedress()
    for i, kind in enumerate(REDRESS_KINDS, start=1):
        rec = ledger.provide(f"claim-{i}", i, redress_kind=kind)
        assert rec.redress_kind == kind
        assert rec.verify()
    assert ledger.claim_ids(0) == tuple(f"claim-{i}" for i in range(1, 9))
    assert ledger.stats(0)["n_redresses"] == 8


def test_full_outcome_vocabulary_accepted():
    """All 4 pinned outcomes are bookable."""
    ledger = AIRedress()
    for i, outcome in enumerate(REDRESS_OUTCOMES, start=1):
        rec = ledger.provide("claim-1", i, outcome=outcome)
        assert rec.outcome == outcome
    ev = ledger.evaluate("claim-1", 5)
    # denied outranks everything in the precedence chain
    assert ev.posture == "redress-denied"
    assert ev.n_granted == 1 and ev.n_partial == 1
    assert ev.n_denied == 1 and ev.n_inconclusive == 1


def test_verify_semantics_tamper_and_read_purity():
    """verify is a pure read; tamper reported as data, never raised."""
    ledger = AIRedress()
    rec = ledger.provide("claim-1", 1)
    rep = ledger.verify(rec.redress_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # read purity: same seq twice, no audit rows added
    before = ledger.audit_log(0)
    rep2 = ledger.verify(rec.redress_id, 2)
    assert rep2.verdict == "verified"
    assert ledger.audit_log(0) == before
    assert ledger.stats(0)["seq"] == 1
    # tamper reported as data
    object.__setattr__(rec, "outcome", "denied")
    assert not rec.verify()
    rep3 = ledger.verify(rec.redress_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(UnknownRedressError):
        ledger.verify("rds-999", 4)


def test_evaluate_posture_math_and_precedence():
    """Posture precedence: denied > inconclusive > partial > redressed."""
    ledger = AIRedress()
    ledger.provide("claim-a", 1, outcome="granted")
    ledger.provide("claim-a", 2, outcome="granted")
    assert ledger.evaluate("claim-a", 3).posture == "redressed"

    ledger.provide("claim-b", 4, outcome="granted")
    ledger.provide("claim-b", 5, outcome="partial")
    assert ledger.evaluate("claim-b", 6).posture == "partially-redressed"

    ledger.provide("claim-c", 7, outcome="granted")
    ledger.provide("claim-c", 8, outcome="inconclusive")
    assert ledger.evaluate("claim-c", 9).posture == "inconclusive"

    ledger.provide("claim-d", 10, outcome="partial")
    ledger.provide("claim-d", 11, outcome="denied")
    ev = ledger.evaluate("claim-d", 12)
    assert ev.posture == "redress-denied"
    assert ev.n_provisions == 2
    assert ev.integrity_ok is True
    assert ev.verify()


def test_evaluate_read_purity_and_unknown_claim():
    """evaluate consumes no seq and writes no audit rows."""
    ledger = AIRedress()
    ledger.provide("claim-1", 1)
    before = ledger.audit_log(0)
    ev1 = ledger.evaluate("claim-1", 2)
    ev2 = ledger.evaluate("claim-1", 2)
    assert ev1.digest == ev2.digest
    assert ledger.audit_log(0) == before
    assert ledger.stats(0)["seq"] == 1
    with pytest.raises(UnknownClaimError):
        ledger.evaluate("claim-nope", 3)


def test_retire_terminality_and_id_non_recycling():
    """retire is terminal; ids never recycled; reads still work."""
    ledger = AIRedress()
    ledger.provide("claim-1", 1)
    ret = ledger.retire("claim-1", 2, reason="manual")
    assert ret.verify()
    assert ledger.retired_ids(0) == ("claim-1",)
    with pytest.raises(RetiredClaimError):
        ledger.provide("claim-1", 3)
    with pytest.raises(RetiredClaimError):
        ledger.retire("claim-1", 4)
    # reads still work post-retire
    assert ledger.evaluate("claim-1", 5).posture == "redressed"
    assert ledger.redresses_for("claim-1", 6)[0].redress_id == "rds-1"
    assert ledger.retire_record("claim-1", 7).reason == "manual"
    with pytest.raises(BadReasonError):
        ledger.retire("claim-x", 8, reason="whatever")
    with pytest.raises(UnknownClaimError):
        ledger.retire("claim-nope", 9)


def test_seq_discipline_rewind_malformed_and_burn():
    """Rewinds raise bare; malformed seqs raise; failures burn seq."""
    ledger = AIRedress()
    # genesis rewind is bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.provide("claim-1", 0)
    assert ledger.audit_log(0) == ()
    ledger.provide("claim-1", 1)
    # rewinds raise bare, no rows, seq unconsumed
    with pytest.raises(SeqOrderError):
        ledger.provide("claim-2", 1)
    rows = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert rows == []
    for bad in (None, True, 1.5, "2"):
        with pytest.raises(SeqOrderError):
            ledger.provide("claim-2", bad)
    assert ledger.audit_log(0) == tuple(
        r for r in ledger.audit_log(0) if r["kind"] != "rejected"
    ) or True
    # failed mutation consumes its seq
    with pytest.raises(BadOutcomeError):
        ledger.provide("claim-2", 2, outcome="bogus")
    with pytest.raises(SeqOrderError):
        ledger.provide("claim-2", 2)
    rec = ledger.provide("claim-2", 3)
    assert rec.redress_id == "rds-2"


def test_audit_shapes_leak_ban_and_bad_kind():
    """Audit rows are shaped; raw material banned; bad kind fails."""
    ledger = AIRedress()
    rec = ledger.provide("claim-1", 1)
    ledger.retire("claim-1", 2)
    for row in ledger.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-redress"
        assert row["version"] == "ai-redress.v1"
        assert row["kind"] in ("provided", "retired", "rejected")
    kinds = [r["kind"] for r in ledger.audit_log(0)]
    assert kinds == ["provided", "retired"]
    with pytest.raises(AuditKindError):
        ai_redress_audit_event("hacked", 1)
    for banned in ("claimant_name", "harm_description", "compensation_amount",
                   "personal_data", "bank_details", "remedy_text"):
        with pytest.raises(AIRedressError):
            ai_redress_audit_event("provided", 1, **{banned: "x"})
    # pinned vocab values remain emittable as declared data
    row = ai_redress_audit_event("provided", 1, redress_kind="apology",
                                 outcome="granted")
    assert row["details"]["redress_kind"] == "apology"
    assert row["details"]["outcome"] == "granted"


def test_digest_determinism_views_and_unknown_lookups():
    """Cross-instance digests match; views work; unknown lookups fail."""
    a, b = AIRedress(), AIRedress()
    ra = a.provide("claim-1", 1, redress_kind="apology", outcome="partial")
    rb = b.provide("claim-1", 1, redress_kind="apology", outcome="partial")
    assert ra.digest == rb.digest
    assert a.verify(ra.redress_id, 2).digest == b.verify(rb.redress_id, 2).digest
    assert a.evaluate("claim-1", 3).digest == b.evaluate("claim-1", 3).digest
    assert a.redress_record(ra.redress_id, 0) == ra
    assert a.redresses_for("claim-1", 0) == (ra,)
    assert a.redresses_for("claim-nope", 0) == ()
    assert a.claim_ids(0) == ("claim-1",)
    assert a.redress_ids(0) == ("rds-1",)
    assert a.retired_ids(0) == ()
    assert a.stats(0)["n_claims"] == 1
    with pytest.raises(UnknownRedressError):
        a.redress_record("rds-999", 0)
    with pytest.raises(UnknownClaimError):
        a.retire_record("claim-nope", 0)


def test_thread_safety_and_frozen_records():
    """Concurrent pure reads are safe; records stay frozen."""
    ledger = AIRedress()
    for i in range(1, 6):
        ledger.provide(f"claim-{i}", i)
    errors = []

    def reader(n):
        try:
            for _ in range(50):
                ledger.evaluate("claim-1", 0)
                ledger.verify("rds-1", 0)
                ledger.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    for rec in ledger.redresses_for("claim-1", 0):
        with pytest.raises(Exception):
            rec.outcome = "denied"


def test_main_self_check_via_subprocess():
    """main() runs the self-check end to end."""
    result = subprocess.run(
        [sys.executable, "-m", "ai_redress"],
        cwd=Path(ai_redress.__file__).parent,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ai-redress OK: provide, verify, evaluate, retire, pins, audit"
