"""Spec-API tests for insurance.py: Insurance assess() / claim() / renew().

Additive extension coverage: the denial-receipt half (issue_denial_receipt,
proxy probes, high-risk gate, ...) is tested in test_insurance.py; these
tests cover the spec's assess -> claim -> renew lifecycle workflow layer.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from insurance import (  # noqa: E402
    INSURANCE_LIFECYCLE_SCHEMA,
    INSURANCE_LIFECYCLE_VERSION,
    AssessmentRecord,
    AuditKindError,
    BadAmountError,
    BadDigestError,
    BadIdError,
    BadRiskClassError,
    BadTermError,
    ClaimRecord,
    DuplicateClaimError,
    DuplicatePolicyError,
    DuplicateRenewalError,
    Insurance,
    InsuranceSpecError,
    ProhibitedPolicyError,
    RenewalRecord,
    RISK_CLASSES,
    SeqOrderError,
    UnknownPolicyError,
    insurance_lifecycle_audit_event,
)

_VALID_DIGEST = "sha256:" + "ab" * 32


def _assessed(seq_start: int = 1, policy_id: str = "pol-1",
              risk_class: str = "standard"):
    ins = Insurance()
    ins.assess(policy_id, seq_start, risk_class=risk_class)
    return ins, seq_start + 1


def test_spec_api_presence():
    ins = Insurance()
    assert callable(ins.assess)
    assert callable(ins.claim)
    assert callable(ins.renew)
    assert callable(ins.assessment_record)
    assert callable(ins.claims_for)
    assert callable(ins.renewals_for)
    assert callable(ins.policy_ids)
    assert callable(ins.stats)
    assert callable(ins.audit_log)
    assert INSURANCE_LIFECYCLE_VERSION == "insurance-lifecycle.v1"
    assert INSURANCE_LIFECYCLE_SCHEMA == "northstar.insurance-lifecycle.v1"
    assert RISK_CLASSES == ("low", "standard", "elevated", "high", "prohibited")
    for kind in ("assessed", "claimed", "renewed", "rejected"):
        evt = insurance_lifecycle_audit_event(kind, seq=1)
        assert evt["schema"] == "audit.ndjson/1"
        assert evt["kind"] == f"insurance-lifecycle.{kind}"


def test_assess_roundtrip_verify_and_frozen():
    ins = Insurance()
    rec = ins.assess("pol-1", 1, risk_class="low",
                     coverage_digest=_VALID_DIGEST, premium_cents=1000)
    assert isinstance(rec, AssessmentRecord)
    assert rec.policy_id == "pol-1"
    assert rec.seq == 1
    assert rec.risk_class == "low"
    assert rec.verify() is True
    assert rec.as_dict()["schema"] == INSURANCE_LIFECYCLE_SCHEMA
    with pytest.raises(Exception):
        rec.policy_id = "pol-2"  # frozen
    # Read back through the view.
    back = ins.assessment_record("pol-1", 2)
    assert back is rec


def test_assess_bad_inputs_seq_burn_and_rejected_rows():
    ins = Insurance()
    seq = 1
    bad_cases = [
        ("", 2, "standard"),           # empty id
        (None, 3, "standard"),         # non-str id
        ("pol-1", 4, "unknown-class"),  # bad risk class
        ("pol-1", 5, "standard", "not-a-digest"),  # bad digest
        ("pol-1", 6, "standard", _VALID_DIGEST, -1),  # negative amount
        ("pol-1", 7, "standard", _VALID_DIGEST, True),  # bool amount
    ]
    errors = (BadIdError, BadRiskClassError, BadDigestError, BadAmountError)
    for case in bad_cases:
        pid, s, rc = case[0], case[1], case[2]
        kwargs = {}
        if len(case) > 3:
            kwargs["coverage_digest"] = case[3]
        if len(case) > 4:
            kwargs["premium_cents"] = case[4]
        with pytest.raises(errors):
            ins.assess(pid, s, risk_class=rc, **kwargs)
        seq = s
    # All failed mutations burned their seq and booked rejected rows.
    rows = ins.audit_log(seq + 1)
    rejected = [r for r in rows if r["kind"] == "insurance-lifecycle.rejected"]
    assert len(rejected) == len(bad_cases)
    # seq is now consumed: replaying the last seq is a bare rewind.
    with pytest.raises(SeqOrderError):
        ins.assess("pol-9", seq)
    # A valid assess at the next seq succeeds.
    rec = ins.assess("pol-1", seq + 1)
    assert rec.policy_id == "pol-1"
    # Duplicate policy refused.
    with pytest.raises(DuplicatePolicyError):
        ins.assess("pol-1", seq + 2)


def test_claim_roundtrip_verify():
    ins, seq = _assessed(policy_id="pol-1")
    rec = ins.claim("pol-1", "clm-1", seq, loss_digest=_VALID_DIGEST,
                    amount_cents=500)
    assert isinstance(rec, ClaimRecord)
    assert rec.claim_id == "clm-1"
    assert rec.policy_id == "pol-1"
    assert rec.verify() is True
    claims = ins.claims_for("pol-1", seq + 1)
    assert claims == (rec,)


def test_claim_refusals():
    ins, seq = _assessed(policy_id="pol-1")
    # Unknown policy.
    with pytest.raises(UnknownPolicyError):
        ins.claim("pol-9", "clm-1", seq)
    # Bad digest.
    with pytest.raises(BadDigestError):
        ins.claim("pol-1", "clm-1", seq + 1, loss_digest="raw-text")
    # Bad amount (bool / negative / str).
    for bad, s in [(True, seq + 2), (-5, seq + 3), ("500", seq + 4)]:
        with pytest.raises(BadAmountError):
            ins.claim("pol-1", "clm-1", s, amount_cents=bad)
    # Valid claim, then duplicate id refused.
    ins.claim("pol-1", "clm-1", seq + 5)
    with pytest.raises(DuplicateClaimError):
        ins.claim("pol-1", "clm-1", seq + 6)


def test_claim_against_prohibited_policy_refused():
    ins, seq = _assessed(policy_id="pol-x", risk_class="prohibited")
    assert ins.assessment_record("pol-x", seq).risk_class == "prohibited"
    with pytest.raises(ProhibitedPolicyError):
        ins.claim("pol-x", "clm-1", seq + 1)
    # The rejected claim booked a rejected row, consumed its seq.
    rows = ins.audit_log(seq + 2)
    assert any(r["kind"] == "insurance-lifecycle.rejected" for r in rows)
    assert ins.claims_for("pol-x", seq + 3) == ()


def test_renew_roundtrip_verify():
    ins, seq = _assessed(policy_id="pol-1")
    rec = ins.renew("pol-1", "rnw-1", seq, terms_digest=_VALID_DIGEST,
                    term_months=12)
    assert isinstance(rec, RenewalRecord)
    assert rec.renewal_id == "rnw-1"
    assert rec.term_months == 12
    assert rec.verify() is True
    renewals = ins.renewals_for("pol-1", seq + 1)
    assert renewals == (rec,)


def test_renew_refusals():
    ins, seq = _assessed(policy_id="pol-1")
    # Unknown policy.
    with pytest.raises(UnknownPolicyError):
        ins.renew("pol-9", "rnw-1", seq)
    # Bad term (zero / negative / bool / str).
    for bad, s in [(0, seq + 1), (-1, seq + 2), (True, seq + 3),
                   ("12", seq + 4)]:
        with pytest.raises(BadTermError):
            ins.renew("pol-1", "rnw-1", s, term_months=bad)
    # Bad terms digest.
    with pytest.raises(BadDigestError):
        ins.renew("pol-1", "rnw-1", seq + 5, terms_digest="x" * 64)
    # Valid renewal, then duplicate id refused.
    ins.renew("pol-1", "rnw-1", seq + 6)
    with pytest.raises(DuplicateRenewalError):
        ins.renew("pol-1", "rnw-1", seq + 7)


def test_seq_discipline():
    ins = Insurance()
    ins.assess("pol-1", 1)
    # Rewind raises bare: no rejected row, seq still free.
    n_rows_before = len(ins.audit_log(2))
    with pytest.raises(SeqOrderError):
        ins.assess("pol-2", 1)
    assert len(ins.audit_log(2)) == n_rows_before
    # Malformed seqs raise bare.
    for bad in (True, "2", 0, -3, 2.5, None):
        with pytest.raises(SeqOrderError):
            ins.assess("pol-2", bad)
    # Failed mutation consumes its seq and books a rejected row.
    with pytest.raises(BadRiskClassError):
        ins.assess("pol-2", 2, risk_class="nope")
    rows = ins.audit_log(3)
    assert rows[-1]["kind"] == "insurance-lifecycle.rejected"
    assert rows[-1]["details"]["error"] == "BadRiskClassError"
    # Views validate seq shape but never consume: same seq twice is fine,
    # and writes no audit rows.
    n = len(ins.audit_log(4))
    ins.assessment_record("pol-1", 5)
    ins.stats(5)
    assert len(ins.audit_log(5)) == n
    with pytest.raises(SeqOrderError):
        ins.stats("x")


def test_view_read_purity_and_errors():
    ins, seq = _assessed(policy_id="pol-1")
    ins.claim("pol-1", "clm-1", seq)
    ins.renew("pol-1", "rnw-1", seq + 1)
    n = len(ins.audit_log(seq + 2))
    assert ins.policy_ids(seq + 2) == ("pol-1",)
    stats = ins.stats(seq + 2)
    assert stats == {"policies": 1, "claims": 1, "renewals": 1,
                    "prohibited": 0}
    assert len(ins.audit_log(seq + 2)) == n  # no audit rows from views
    with pytest.raises(UnknownPolicyError):
        ins.assessment_record("pol-9", seq + 2)
    with pytest.raises(UnknownPolicyError):
        ins.claims_for("pol-9", seq + 2)
    with pytest.raises(UnknownPolicyError):
        ins.renewals_for("pol-9", seq + 2)


def test_audit_shapes_leak_ban_and_bad_kind():
    ins, seq = _assessed(policy_id="pol-1")
    ins.claim("pol-1", "clm-1", seq)
    ins.renew("pol-1", "rnw-1", seq + 1)
    kinds = [r["kind"] for r in ins.audit_log(seq + 2)]
    assert kinds == ["insurance-lifecycle.assessed",
                     "insurance-lifecycle.claimed",
                     "insurance-lifecycle.renewed"]
    for row in ins.audit_log(seq + 2):
        assert row["schema"] == "audit.ndjson/1"
        assert row["seq"] >= 1
        assert "digest" in row["details"]
    # Raw keys are banned at the builder level.
    for raw_key in ("policy_terms", "coverage", "loss", "notes", "text",
                    "description", "evidence", "secret", "key", "payload",
                    "raw", "message"):
        with pytest.raises(AuditKindError):
            insurance_lifecycle_audit_event("assessed", **{raw_key: "x"})
    with pytest.raises(AuditKindError):
        insurance_lifecycle_audit_event("bogus-kind")


def test_cross_instance_digest_determinism_and_tamper():
    ins = Insurance()
    rec = ins.assess("pol-1", 1, risk_class="elevated",
                     coverage_digest=_VALID_DIGEST, premium_cents=2500)
    ins2 = Insurance()
    rec2 = ins2.assess("pol-1", 1, risk_class="elevated",
                       coverage_digest=_VALID_DIGEST, premium_cents=2500)
    assert rec.digest_pin == rec2.digest_pin
    assert rec2.verify() is True
    # Tampering a frozen record breaks verify().
    object.__setattr__(rec2, "premium_cents", 9999)
    assert rec2.verify() is False


def test_full_lifecycle_chain():
    ins = Insurance()
    ins.assess("pol-1", 1, risk_class="standard", premium_cents=2000)
    ins.claim("pol-1", "clm-1", 2, amount_cents=800)
    ins.claim("pol-1", "clm-2", 3, amount_cents=300)
    ins.renew("pol-1", "rnw-1", 4, term_months=6)
    ins.renew("pol-1", "rnw-2", 5, term_months=12)
    assert len(ins.claims_for("pol-1", 6)) == 2
    assert len(ins.renewals_for("pol-1", 6)) == 2
    assert ins.stats(6)["claims"] == 2
    kinds = [r["kind"] for r in ins.audit_log(6)]
    assert kinds == ["insurance-lifecycle.assessed",
                     "insurance-lifecycle.claimed",
                     "insurance-lifecycle.claimed",
                     "insurance-lifecycle.renewed",
                     "insurance-lifecycle.renewed"]


def test_error_taxonomy_subclasses():
    for cls in (BadIdError, DuplicatePolicyError, UnknownPolicyError,
                DuplicateClaimError, DuplicateRenewalError,
                BadRiskClassError, BadDigestError, BadAmountError,
                BadTermError, ProhibitedPolicyError, SeqOrderError,
                AuditKindError):
        assert issubclass(cls, InsuranceSpecError)
    assert issubclass(InsuranceSpecError, ValueError)


def test_main_subprocess():
    module = str(Path(__file__).resolve().parent.parent / "insurance.py")
    proc = subprocess.run([sys.executable, module], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "insurance-lifecycle OK: assess, claim, renew, pins, audit" in \
        proc.stdout
