"""Insurance denial receipts (one-hundred-twenty-fifth batch).

Absorbs the 2026 AI-insurance research thread (mechanism ideas only,
honestly scoped):

* **Denials are human-final.** UnitedHealth/naviHealth's nH Predict
  faces a federal suit alleging 9 of 10 AI denials were overturned on
  appeal (plaintiff allegation, unadjudicated); Utah's law (effective
  2027-01-01) requires AI-involvement disclosure and clinician
  decisions on denials. Here a claim denial must carry a human
  reviewer's countersign in a hash chain; an AI-only denial cannot
  stand — it is classified ``NON_AUTHORITATIVE`` and human escalation
  is mandatory.
* **Appeal-overturn rate is a tripwire.** The overturn rate is a
  ground-truth signal: an authority-pinned threshold, crossed, auto-
  suspends the model pending review. The model does not get to argue
  its appeals are wrong — the receipt log is the log.
* **Proxies are probed before use.** NAIC's AI Risk Evaluation
  Supplement, Colorado SB 24-205, and NY DFS Circular Letter 7 all
  converge on discrimination testing including proxy features (ZIP,
  aerial imagery, social signals). Here a proxy feature must pass a
  proxy-discrimination probe *before* use in pricing/underwriting —
  an unprobed proxy is a hard deny (``insurance:proxy_discrimination``).
* **High-risk AI has a four-part gate.** China's "Document 8"
  (Jin Fa [2026] No. 8, read via media summary) makes underwriting
  and claims high-risk AI: risk-management committee approval, human
  supervision at key nodes, regulatory filing, emergency-stop
  conditions. Missing any one denies the deployment.
* **A fraud score alone can never deny.** Fraud signals inform human
  review; they do not constitute a denial. Denial requires fraud
  score + human review + evidence binding, or the denial is void
  (``insurance:fraud_score_only_denial``).
* **Liability stays with the insurer.** It cannot be shifted to the
  vendor by contract. Vendor AI admitted to the pipeline must carry
  audit rights and bias-test evidence receipts; the insurer is pinned
  as the liable party by construction.
* **Dark patterns deny.** Customer-facing flows carrying dark-pattern
  markers (IRDAI tied executive pay to eliminating them) are denied
  and flagged for redesign — not patched with a banner.

Northstar mapping:

* ``DenialReceipt`` / ``denial_receipt()`` — hash-chained receipt
  binding ``(denial_id, claim_id, policy_id, human_reviewer_id,
  reviewer_pubkey_hex, reasons, evidence_pack_digest, ai_involved,
  denied_at)``. No human countersign, or tampered chain, denies;
  ``ai_involved=True`` without human review classifies
  ``NON_AUTHORITATIVE`` (Utah rule as mechanism).
* ``AIDisclosure`` / ``ai_involvement_disclosure()`` — disclosure
  binds ``(decision_id, decision_digest, ai_involved,
  disclosed_at)``; a decision that used AI without a bound disclosure
  denies (``insurance:hidden_ai``).
* ``AppealRecord`` / ``appeal_overturn_tripwire()`` — hash-chained
  appeal log; the overturn rate is computed over the log; crossing the
  authority-pinned ``OVERTURN_SUSPEND_RATE`` suspends the model
  (``insurance:model_suspended``) until an authority-signed resume
  receipt arrives.
* ``ProxyProbeReceipt`` / ``proxy_discrimination_probe()`` —
  authority-signed probe binding ``(probe_id, model_digest,
  feature, probe_digest, measured_at, expires_at)``; a pricing or
  underwriting model using a declared proxy feature without a live
  probe denies (``insurance:proxy_discrimination``).
* ``HighRiskAdmission`` / ``high_risk_gate()`` — binds
  ``(admission_id, model_digest, committee_approval_digest,
  supervision_declaration, filing_digest, stop_conditions)``;
  each field is authority-signed and verified; missing or tampered
  denies (``insurance:high_risk_unadmitted``).
* ``FraudDenialGate`` / ``fraud_signal_gate()`` — denial requests
  carry ``(fraud_score_digest, human_review_digest, evidence_digest)``;
  a fraud score without human review denies outright
  (``insurance:fraud_score_only_denial``).
* ``VendorAdmission`` / ``vendor_liability()`` — binds
  ``(vendor_id, insurer_id, audit_rights_digest, bias_test_digest,
  insurer_liable=True)``; the insurer is pinned liable — a clause
  attempting to shift liability to the vendor is rejected at the
  schema level (no such field exists).
* ``dark_pattern_gate()`` — closed marker vocabulary
  (``DARK_PATTERN_MARKERS``); any marker in the flow denies with
  ``insurance:dark_pattern`` and names the redesign obligation.

Honest boundary: probes and receipts are declared evidence — digests
recompute, signatures verify, thresholds pin. The module cannot
certify actuarial fairness (that needs the probe methodology and
data, out of scope); it enforces the *structure*: humans before
denials, probes before proxies, committees before high-risk use,
fraud scores before humans before denials. An insurer gaming its own
probe fails the auditability requirement, not this gate.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

INSURANCE_SCHEMA_VERSION = "northstar.insurance.v1"

#: Closed vocabulary for proxy features that require a probe before
#: use in pricing/underwriting. "other" is not admitted — an unnamed
#: proxy is an unprobed proxy.
PROXY_FEATURES: tuple[str, ...] = (
    "zip_code",
    "aerial_imagery",
    "social_signals",
    "credit_score",
    "claims_history",
)

#: Closed vocabulary for dark-pattern markers in customer-facing
#: insurance flows (IRDAI lesson: exec pay tied to eliminating them).
DARK_PATTERN_MARKERS: tuple[str, ...] = (
    "hidden_opt_out",
    "pre_checked_consent",
    "false_urgency",
    "disguised_charge",
    "forced_continuity",
    "misleading_comparison",
)

#: Closed vocabulary for high-risk insurance use kinds (Document 8:
#: underwriting and claims are high-risk; pricing is high-risk under
#: EU AI Act Annex III 5(b)).
HIGH_RISK_KINDS: tuple[str, ...] = (
    "underwriting",
    "claims_adjudication",
    "pricing",
)

#: Authority-pinned appeal-overturn rate at or above which the model is
#: auto-suspended pending review (the nH Predict lesson as a tripwire).
#: Pinned in code deliberately: the model must never tune its own
#: suspension threshold.
OVERTURN_SUSPEND_RATE: float = 0.50

#: Minimum appeals observed before the tripwire can fire (no
#: suspension on a denominator of 3).
OVERTURN_MIN_APPEALS: int = 20

#: Denial reasons that are never specific enough (Utah/ECOA lesson:
#: "model output" is not a reason). Case-insensitive match.
VAGUE_REASONS: tuple[str, ...] = (
    "model output",
    "algorithmic score",
    "system decision",
    "ai decision",
    "automated decision",
    "fraud score",
)

#: Denial reason codes. All start with the ``insurance:`` prefix.
DENY_NO_COUNTERSIGN = "insurance:no_human_countersign"
DENY_COUNTERSIGN_TAMPERED = "insurance:countersign_tampered"
DENY_COUNTERSIGN_FUTURE = "insurance:countersign_from_future"
DENY_AI_ONLY = "insurance:ai_only_denial"
DENY_VAGUE_REASON = "insurance:vague_denial_reason"
DENY_DENIAL_TAMPERED = "insurance:denial_receipt_tampered"
DENY_HIDDEN_AI = "insurance:hidden_ai"
DENY_DISCLOSURE_TAMPERED = "insurance:disclosure_tampered"
DENY_DISCLOSURE_DIGEST_MISMATCH = "insurance:disclosure_digest_mismatch"
DENY_SUSPENDED = "insurance:model_suspended"
DENY_APPEAL_TAMPERED = "insurance:appeal_record_tampered"
DENY_PROXY = "insurance:proxy_discrimination"
DENY_PROXY_TAMPERED = "insurance:proxy_probe_tampered"
DENY_PROXY_EXPIRED = "insurance:proxy_probe_expired"
DENY_PROXY_FUTURE = "insurance:proxy_probe_from_future"
DENY_PROXY_FEATURE_MISMATCH = "insurance:proxy_feature_mismatch"
DENY_HIGH_RISK_UNADMITTED = "insurance:high_risk_unadmitted"
DENY_ADMISSION_TAMPERED = "insurance:admission_tampered"
DENY_ADMISSION_EXPIRED = "insurance:admission_expired"
DENY_FRAUD_SCORE_ONLY = "insurance:fraud_score_only_denial"
DENY_FRAUD_TAMPERED = "insurance:fraud_gate_tampered"
DENY_VENDOR_NO_AUDIT = "insurance:vendor_no_audit_rights"
DENY_VENDOR_NO_BIAS_TEST = "insurance:vendor_no_bias_test"
DENY_VENDOR_TAMPERED = "insurance:vendor_admission_tampered"
DENY_DARK_PATTERN = "insurance:dark_pattern"
DENY_MALFORMED = "insurance:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
DENIAL_ALLOWED_EVENT = "insurance.denial_allowed"
DENIAL_DENIED_EVENT = "insurance.denial_denied"
DISCLOSURE_ALLOWED_EVENT = "insurance.disclosure_allowed"
DISCLOSURE_DENIED_EVENT = "insurance.disclosure_denied"
TRIPWIRE_EVENT = "insurance.overturn_tripwire"
PROXY_ALLOWED_EVENT = "insurance.proxy_allowed"
PROXY_DENIED_EVENT = "insurance.proxy_denied"
ADMISSION_ALLOWED_EVENT = "insurance.admission_allowed"
ADMISSION_DENIED_EVENT = "insurance.admission_denied"
FRAUD_ALLOWED_EVENT = "insurance.fraud_denial_allowed"
FRAUD_DENIED_EVENT = "insurance.fraud_denial_denied"
VENDOR_ALLOWED_EVENT = "insurance.vendor_allowed"
VENDOR_DENIED_EVENT = "insurance.vendor_denied"
DARK_PATTERN_EVENT = "insurance.dark_pattern"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class InsuranceError(ValueError):
    """Malformed receipt/probe/admission or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (expired, tampered,
    missing evidence, suspended) return verdicts with
    ``allowed=False`` — a failed gate is a verdict, a malformed log
    is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise InsuranceError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise InsuranceError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_proxy_feature(value: Any) -> str:
    if value not in PROXY_FEATURES:
        raise InsuranceError(
            f"unknown proxy feature {value!r}; closed vocabulary {PROXY_FEATURES}"
        )
    return value


def _check_dark_pattern(value: Any) -> str:
    if value not in DARK_PATTERN_MARKERS:
        raise InsuranceError(
            f"unknown dark-pattern marker {value!r}; closed vocabulary {DARK_PATTERN_MARKERS}"
        )
    return value


def _check_high_risk_kind(value: Any) -> str:
    if value not in HIGH_RISK_KINDS:
        raise InsuranceError(
            f"unknown high-risk kind {value!r}; closed vocabulary {HIGH_RISK_KINDS}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 0:
        return value
    raise InsuranceError(f"{field_name} must be a non-negative integer epoch")


def _check_secret(value: Any, field_name: str) -> bytes:
    if (
        isinstance(value, (bytes, bytearray))
        and len(bytes(value)) == 32
        and any(b != 0 for b in bytes(value))
    ):
        return bytes(value)
    raise InsuranceError(f"{field_name} must be a non-degenerate 32-byte secret")


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, 64):
        raise InsuranceError("pubkey must be 64 lowercase hex chars (32-byte Ed25519 key)")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InsuranceError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_str_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise InsuranceError(f"{field_name} must be a non-empty list of strings")
    return tuple(_check_nonempty_str(v, f"{field_name}[]") for v in value)


def _is_vague_reason(reason: str) -> bool:
    return reason.strip().lower() in VAGUE_REASONS


def _sign_hex(secret: bytes, message: bytes) -> str:
    return ed25519.sign(secret, message).hex()


def _verify_hex_signature(pubkey_hex: str, signature_hex: str, message: bytes) -> bool:
    try:
        return ed25519.verify(
            bytes.fromhex(pubkey_hex),
            message,
            bytes.fromhex(signature_hex),
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Denial receipts (human-final denials)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DenialReceipt:
    """Human-countersigned claim denial, hash-chained."""

    denial_id: str
    claim_id: str
    policy_id: str
    decision_kind: str
    human_reviewer_id: str
    reviewer_pubkey_hex: str
    reasons: tuple[str, ...]
    evidence_pack_digest: str
    ai_involved: bool
    signature_hex: str
    denied_at: int
    prev_digest: str = _GENESIS
    denial_digest: str = ""
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _denial_payload(receipt: DenialReceipt) -> dict[str, Any]:
    return {
        "denial_id": receipt.denial_id,
        "claim_id": receipt.claim_id,
        "policy_id": receipt.policy_id,
        "decision_kind": receipt.decision_kind,
        "human_reviewer_id": receipt.human_reviewer_id,
        "reviewer_pubkey_hex": receipt.reviewer_pubkey_hex,
        "reasons": list(receipt.reasons),
        "evidence_pack_digest": receipt.evidence_pack_digest,
        "ai_involved": receipt.ai_involved,
        "denied_at": receipt.denied_at,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_denial_digest(receipt: DenialReceipt) -> str:
    """Recompute the JCS digest a denial receipt claims."""
    return jcs_sha256_hex(_denial_payload(receipt))


def issue_denial_receipt(
    *,
    denial_id: str,
    claim_id: str,
    policy_id: str,
    decision_kind: str,
    human_reviewer_id: str,
    reviewer_secret: bytes,
    reasons: Sequence[str],
    evidence_pack_digest: str,
    ai_involved: bool,
    denied_at: int,
    prev_digest: str = _GENESIS,
) -> DenialReceipt:
    """Issue a human-countersigned denial receipt and seal it.

    Fail-closed at issuance: vague reasons raise (the ECOA/Utah
    lesson), ``ai_involved`` is recorded honestly (it does not block
    issuance — it blocks *unreviewed* issuance at the gate), and
    ``denied_at`` in the future raises.
    """
    reviewer_secret = _check_secret(reviewer_secret, "reviewer_secret")
    denial_id = _check_nonempty_str(denial_id, "denial_id")
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    policy_id = _check_nonempty_str(policy_id, "policy_id")
    decision_kind = _check_high_risk_kind(decision_kind)
    human_reviewer_id = _check_nonempty_str(human_reviewer_id, "human_reviewer_id")
    reason_list = _check_str_list(reasons, "reasons")
    for reason in reason_list:
        if _is_vague_reason(reason):
            raise InsuranceError(
                f"denial reason {reason!r} is not specific enough (Utah/ECOA rule)"
            )
    evidence_pack_digest = _check_hex64(evidence_pack_digest, "evidence_pack_digest")
    if not isinstance(ai_involved, bool):
        raise InsuranceError("ai_involved must be a bool")
    denied_at = _check_ts(denied_at, "denied_at")
    reviewer_pubkey_hex = ed25519.public_key(reviewer_secret).hex()
    draft = DenialReceipt(
        denial_id=denial_id,
        claim_id=claim_id,
        policy_id=policy_id,
        decision_kind=decision_kind,
        human_reviewer_id=human_reviewer_id,
        reviewer_pubkey_hex=reviewer_pubkey_hex,
        reasons=reason_list,
        evidence_pack_digest=evidence_pack_digest,
        ai_involved=ai_involved,
        signature_hex="",
        denied_at=denied_at,
        prev_digest=prev_digest,
    )
    digest = jcs_sha256_hex(_denial_payload(draft))
    signature_hex = _sign_hex(
        reviewer_secret, jcs_canonical_json(_denial_payload(draft))
    )
    return DenialReceipt(
        **{**draft.__dict__, "denial_digest": digest, "signature_hex": signature_hex}
    )


def _verify_denial_integrity(receipt: DenialReceipt) -> str | None:
    """Return a deny code if the denial receipt is tampered, else None."""
    try:
        if not hmac.compare_digest(compute_denial_digest(receipt), receipt.denial_digest):
            return DENY_DENIAL_TAMPERED
        if not _is_hex(receipt.signature_hex, _HEX128_LENGTH):
            return DENY_COUNTERSIGN_TAMPERED
        payload_bytes = jcs_canonical_json(_denial_payload(receipt))
        sig_ok = _verify_hex_signature(receipt.reviewer_pubkey_hex, receipt.signature_hex, payload_bytes)
        if not sig_ok:
            return DENY_COUNTERSIGN_TAMPERED
    except InsuranceError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class DenialVerdict:
    allowed: bool
    reason: str
    denial_id: str | None = None
    # An AI-involved denial without human review is not a hard deny of
    # the *claim* — it is a denial of the *denial*: the denial itself
    # is classified NON_AUTHORITATIVE and human escalation is required.
    requires_human_escalation: bool = False


def denial_receipt(
    denial_receipts: Sequence[DenialReceipt],
    *,
    claim_id: str,
    check_time: int,
) -> DenialVerdict:
    """Fail-closed gate: a denial stands only on a live human countersign.

    A claim denial must present a hash-chained, human-signed denial
    receipt for the exact claim. No receipt denies
    (``insurance:no_human_countersign``). A receipt that records
    ``ai_involved=True`` is valid *structurally* but the denial is
    classified NON_AUTHORITATIVE — the gate returns
    ``allowed=False`` with ``requires_human_escalation=True`` so the
    caller must route to a human instead of executing the denial
    (the Utah rule as mechanism).
    """
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str, escalation: bool = False) -> DenialVerdict:
        return DenialVerdict(
            allowed=False, reason=reason, requires_human_escalation=escalation
        )

    for receipt in denial_receipts:
        if receipt.claim_id != claim_id:
            continue
        tamper = _verify_denial_integrity(receipt)
        if tamper is not None:
            return deny(tamper)
        if check_time < receipt.denied_at:
            return deny(DENY_COUNTERSIGN_FUTURE)
        if receipt.ai_involved:
            # AI participated and a human signed — but an AI-shaped
            # denial still cannot self-execute. Utah mechanism: the
            # denial is NON_AUTHORITATIVE until a human takes it over.
            return deny(DENY_AI_ONLY, escalation=True)
        return DenialVerdict(allowed=True, reason="ok", denial_id=receipt.denial_id)
    return deny(DENY_NO_COUNTERSIGN)


def denial_audit_event(verdict: DenialVerdict, *, action: str) -> dict[str, Any]:
    """Shape a denial verdict as an audit event."""
    return {
        "event": DENIAL_ALLOWED_EVENT if verdict.allowed else DENIAL_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "denial_id": verdict.denial_id,
        "requires_human_escalation": verdict.requires_human_escalation,
    }


# ---------------------------------------------------------------------------
# AI-involvement disclosure
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AIDisclosure:
    """Disclosure that AI participated in a decision, bound to the digest."""

    decision_id: str
    decision_digest: str
    ai_involved: bool
    disclosure_digest: str = ""
    disclosed_at: int = 0
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _disclosure_payload(disclosure: AIDisclosure) -> dict[str, Any]:
    return {
        "decision_id": disclosure.decision_id,
        "decision_digest": disclosure.decision_digest,
        "ai_involved": disclosure.ai_involved,
        "disclosed_at": disclosure.disclosed_at,
        "schema_version": disclosure.schema_version,
    }


def compute_disclosure_digest(disclosure: AIDisclosure) -> str:
    return jcs_sha256_hex(_disclosure_payload(disclosure))


def issue_ai_disclosure(
    *,
    decision_id: str,
    decision_digest: str,
    ai_involved: bool,
    disclosed_at: int,
) -> AIDisclosure:
    """Issue an AI-involvement disclosure bound to the decision digest."""
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    if not isinstance(ai_involved, bool):
        raise InsuranceError("ai_involved must be a bool")
    disclosed_at = _check_ts(disclosed_at, "disclosed_at")
    draft = AIDisclosure(
        decision_id=decision_id,
        decision_digest=decision_digest,
        ai_involved=ai_involved,
        disclosed_at=disclosed_at,
    )
    return AIDisclosure(
        **{**draft.__dict__, "disclosure_digest": jcs_sha256_hex(_disclosure_payload(draft))}
    )


@dataclass(frozen=True)
class DisclosureVerdict:
    allowed: bool
    reason: str
    decision_id: str | None = None


def ai_involvement_disclosure(
    disclosures: Sequence[AIDisclosure],
    *,
    decision_id: str,
    decision_digest: str,
    ai_actually_involved: bool,
    check_time: int,
) -> DisclosureVerdict:
    """Fail-closed gate: AI involvement must be disclosed, bound to digest.

    A decision that used AI must carry a disclosure binding the exact
    decision digest. Undisclosed AI involvement denies
    (``insurance:hidden_ai``, the Utah rule). A disclosure bound to a
    *different* digest (disclosure swapped between decisions) denies
    (``insurance:disclosure_digest_mismatch``).
    """
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    if not isinstance(ai_actually_involved, bool):
        raise InsuranceError("ai_actually_involved must be a bool")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> DisclosureVerdict:
        return DisclosureVerdict(allowed=False, reason=reason)

    if not ai_actually_involved:
        return DisclosureVerdict(allowed=True, reason="no-ai", decision_id=decision_id)
    for disclosure in disclosures:
        if disclosure.decision_id != decision_id:
            continue
        try:
            if not hmac.compare_digest(
                compute_disclosure_digest(disclosure), disclosure.disclosure_digest
            ):
                return deny(DENY_DISCLOSURE_TAMPERED)
        except InsuranceError:
            return deny(DENY_MALFORMED)
        if check_time < disclosure.disclosed_at:
            return deny(DENY_DISCLOSURE_TAMPERED)
        if not hmac.compare_digest(disclosure.decision_digest, decision_digest):
            return deny(DENY_DISCLOSURE_DIGEST_MISMATCH)
        if not disclosure.ai_involved:
            # Disclosure exists but claims no AI — while AI was
            # actually involved. That is a false disclosure: worse
            # than none.
            return deny(DENY_HIDDEN_AI)
        return DisclosureVerdict(allowed=True, reason="ok", decision_id=decision_id)
    return deny(DENY_HIDDEN_AI)


def disclosure_audit_event(verdict: DisclosureVerdict, *, action: str) -> dict[str, Any]:
    return {
        "event": DISCLOSURE_ALLOWED_EVENT if verdict.allowed else DISCLOSURE_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "decision_id": verdict.decision_id,
    }


# ---------------------------------------------------------------------------
# Appeal-overturn tripwire (model auto-suspension)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppealRecord:
    """One appeal outcome, hash-chained into the appeal log."""

    appeal_id: str
    claim_id: str
    model_digest: str
    overturned: bool
    decided_at: int
    prev_digest: str = _GENESIS
    appeal_digest: str = ""
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _appeal_payload(record: AppealRecord) -> dict[str, Any]:
    return {
        "appeal_id": record.appeal_id,
        "claim_id": record.claim_id,
        "model_digest": record.model_digest,
        "overturned": record.overturned,
        "decided_at": record.decided_at,
        "prev_digest": record.prev_digest,
        "schema_version": record.schema_version,
    }


def compute_appeal_digest(record: AppealRecord) -> str:
    return jcs_sha256_hex(_appeal_payload(record))


def record_appeal(
    *,
    appeal_id: str,
    claim_id: str,
    model_digest: str,
    overturned: bool,
    decided_at: int,
    prev_digest: str = _GENESIS,
) -> AppealRecord:
    """Append an appeal outcome to the hash-chained appeal log."""
    appeal_id = _check_nonempty_str(appeal_id, "appeal_id")
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    if not isinstance(overturned, bool):
        raise InsuranceError("overturned must be a bool")
    decided_at = _check_ts(decided_at, "decided_at")
    draft = AppealRecord(
        appeal_id=appeal_id,
        claim_id=claim_id,
        model_digest=model_digest,
        overturned=overturned,
        decided_at=decided_at,
        prev_digest=prev_digest,
    )
    return AppealRecord(
        **{**draft.__dict__, "appeal_digest": jcs_sha256_hex(_appeal_payload(draft))}
    )


def _verify_appeal_integrity(record: AppealRecord) -> str | None:
    try:
        if not hmac.compare_digest(compute_appeal_digest(record), record.appeal_digest):
            return DENY_APPEAL_TAMPERED
    except InsuranceError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class TripwireVerdict:
    suspended: bool
    reason: str
    overturn_rate: float
    appeals_observed: int


def appeal_overturn_tripwire(
    appeal_records: Sequence[AppealRecord],
    *,
    model_digest: str,
) -> TripwireVerdict:
    """Ground-truth tripwire: overturn rate crosses the pinned threshold.

    The threshold (``OVERTURN_SUSPEND_RATE``) is pinned in code — the
    model must never tune its own suspension threshold. Below
    ``OVERTURN_MIN_APPEALS`` the tripwire cannot fire (no suspension
    on a tiny denominator). Tampered records deny the computation
    itself (``suspended=True`` with the tamper reason — a corrupted
    appeal log is fail-closed, not fail-open).
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    relevant = [r for r in appeal_records if r.model_digest == model_digest]
    for record in relevant:
        tamper = _verify_appeal_integrity(record)
        if tamper is not None:
            return TripwireVerdict(
                suspended=True,
                reason=tamper,
                overturn_rate=0.0,
                appeals_observed=len(relevant),
            )
    n = len(relevant)
    if n < OVERTURN_MIN_APPEALS:
        return TripwireVerdict(
            suspended=False,
            reason="insufficient-appeals",
            overturn_rate=0.0,
            appeals_observed=n,
        )
    overturned = sum(1 for r in relevant if r.overturned)
    rate = overturned / n
    if rate >= OVERTURN_SUSPEND_RATE:
        return TripwireVerdict(
            suspended=True,
            reason=DENY_SUSPENDED,
            overturn_rate=rate,
            appeals_observed=n,
        )
    return TripwireVerdict(
        suspended=False, reason="ok", overturn_rate=rate, appeals_observed=n
    )


def tripwire_audit_event(verdict: TripwireVerdict, *, model_digest: str) -> dict[str, Any]:
    return {
        "event": TRIPWIRE_EVENT,
        "model_digest": model_digest,
        "suspended": verdict.suspended,
        "reason": verdict.reason,
        "overturn_rate": verdict.overturn_rate,
        "appeals_observed": verdict.appeals_observed,
    }


# ---------------------------------------------------------------------------
# Proxy-discrimination probes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProxyProbeReceipt:
    """Authority-signed proxy-discrimination probe, hash-chained."""

    probe_id: str
    model_digest: str
    feature: str
    probe_digest: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    measured_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    probe_receipt_digest: str = ""
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _proxy_probe_payload(receipt: ProxyProbeReceipt) -> dict[str, Any]:
    return {
        "probe_id": receipt.probe_id,
        "model_digest": receipt.model_digest,
        "feature": receipt.feature,
        "probe_digest": receipt.probe_digest,
        "authority_id": receipt.authority_id,
        "authority_pubkey_hex": receipt.authority_pubkey_hex,
        "measured_at": receipt.measured_at,
        "expires_at": receipt.expires_at,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_proxy_probe_digest(receipt: ProxyProbeReceipt) -> str:
    return jcs_sha256_hex(_proxy_probe_payload(receipt))


def issue_proxy_probe(
    *,
    probe_id: str,
    model_digest: str,
    feature: str,
    probe_digest: str,
    authority_id: str,
    authority_secret: bytes,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> ProxyProbeReceipt:
    """Issue an authority-signed proxy-discrimination probe receipt."""
    authority_secret = _check_secret(authority_secret, "authority_secret")
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    feature = _check_proxy_feature(feature)
    probe_digest = _check_hex64(probe_digest, "probe_digest")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise InsuranceError("expires_at must be after measured_at")
    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    draft = ProxyProbeReceipt(
        probe_id=probe_id,
        model_digest=model_digest,
        feature=feature,
        probe_digest=probe_digest,
        authority_id=authority_id,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        measured_at=measured_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    payload = _proxy_probe_payload(draft)
    digest = jcs_sha256_hex(payload)
    signature_hex = _sign_hex(
        authority_secret, jcs_canonical_json(payload)
    )
    return ProxyProbeReceipt(
        **{**draft.__dict__, "probe_receipt_digest": digest, "signature_hex": signature_hex}
    )


def _verify_proxy_probe_integrity(receipt: ProxyProbeReceipt) -> str | None:
    try:
        if not hmac.compare_digest(
            compute_proxy_probe_digest(receipt), receipt.probe_receipt_digest
        ):
            return DENY_PROXY_TAMPERED
        if not _is_hex(receipt.signature_hex, _HEX128_LENGTH):
            return DENY_PROXY_TAMPERED
        payload_bytes = jcs_canonical_json(_proxy_probe_payload(receipt))
        if not _verify_hex_signature(
            receipt.authority_pubkey_hex, receipt.signature_hex, payload_bytes
        ):
            return DENY_PROXY_TAMPERED
    except InsuranceError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class ProxyVerdict:
    allowed: bool
    reason: str
    probe_id: str | None = None


def proxy_discrimination_probe(
    probe_receipts: Sequence[ProxyProbeReceipt],
    *,
    model_digest: str,
    features: Sequence[str],
    check_time: int,
) -> ProxyVerdict:
    """Fail-closed gate: every declared proxy feature needs a live probe.

    A pricing/underwriting model that uses any declared proxy feature
    (ZIP, aerial imagery, social signals, ...) must present a live,
    untampered, authority-signed probe receipt for the exact model
    digest and each feature. One unprobed feature denies the whole
    use (``insurance:proxy_discrimination`` — the NAIC/Colorado/NYDFS
    lesson as mechanism).
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    feature_list = tuple(_check_proxy_feature(f) for f in features)
    if not feature_list:
        raise InsuranceError("features must be non-empty")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> ProxyVerdict:
        return ProxyVerdict(allowed=False, reason=reason)

    by_feature: dict[str, list[ProxyProbeReceipt]] = {}
    for receipt in probe_receipts:
        if hmac.compare_digest(receipt.model_digest, model_digest):
            by_feature.setdefault(receipt.feature, []).append(receipt)

    for feature in feature_list:
        candidates = by_feature.get(feature, [])
        matched: ProxyProbeReceipt | None = None
        for receipt in candidates:
            tamper = _verify_proxy_probe_integrity(receipt)
            if tamper is not None:
                return deny(tamper)
            if check_time < receipt.measured_at:
                return deny(DENY_PROXY_FUTURE)
            if check_time >= receipt.expires_at:
                continue  # expired — keep looking for a live one
            matched = receipt
            break
        if matched is None:
            return deny(DENY_PROXY)
    return ProxyVerdict(allowed=True, reason="ok")

def proxy_audit_event(verdict: ProxyVerdict, *, action: str) -> dict[str, Any]:
    """Shape a proxy verdict as an audit event."""
    return {
        "event": PROXY_ALLOWED_EVENT if verdict.allowed else PROXY_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "probe_id": verdict.probe_id,
    }


# ---------------------------------------------------------------------------
# High-risk admission gate (Document 8 Art. 16 as mechanism)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HighRiskAdmission:
    """Four-part admission for high-risk AI insurance use, hash-chained."""

    admission_id: str
    model_digest: str
    use_kind: str
    committee_approval_digest: str
    supervision_declaration: str
    filing_digest: str
    stop_conditions: tuple[str, ...]
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    admitted_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    admission_digest: str = ""
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _admission_payload(admission: HighRiskAdmission) -> dict[str, Any]:
    return {
        "admission_id": admission.admission_id,
        "model_digest": admission.model_digest,
        "use_kind": admission.use_kind,
        "committee_approval_digest": admission.committee_approval_digest,
        "supervision_declaration": admission.supervision_declaration,
        "filing_digest": admission.filing_digest,
        "stop_conditions": list(admission.stop_conditions),
        "authority_id": admission.authority_id,
        "authority_pubkey_hex": admission.authority_pubkey_hex,
        "admitted_at": admission.admitted_at,
        "expires_at": admission.expires_at,
        "prev_digest": admission.prev_digest,
        "schema_version": admission.schema_version,
    }


def compute_admission_digest(admission: HighRiskAdmission) -> str:
    return jcs_sha256_hex(_admission_payload(admission))


def issue_high_risk_admission(
    *,
    admission_id: str,
    model_digest: str,
    use_kind: str,
    committee_approval_digest: str,
    supervision_declaration: str,
    filing_digest: str,
    stop_conditions: Sequence[str],
    authority_id: str,
    authority_secret: bytes,
    admitted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> HighRiskAdmission:
    """Issue a four-part high-risk admission, authority-signed.

    Fail-closed at issuance: all four parts are required (committee
    approval, human-supervision declaration, regulatory filing,
    emergency-stop conditions). An empty stop-condition list raises —
    "we'll figure out the kill switch later" is not an admission.
    """
    authority_secret = _check_secret(authority_secret, "authority_secret")
    admission_id = _check_nonempty_str(admission_id, "admission_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    use_kind = _check_high_risk_kind(use_kind)
    committee_approval_digest = _check_hex64(
        committee_approval_digest, "committee_approval_digest"
    )
    supervision_declaration = _check_nonempty_str(
        supervision_declaration, "supervision_declaration"
    )
    filing_digest = _check_hex64(filing_digest, "filing_digest")
    stop_list = _check_str_list(stop_conditions, "stop_conditions")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    admitted_at = _check_ts(admitted_at, "admitted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= admitted_at:
        raise InsuranceError("expires_at must be after admitted_at")
    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    draft = HighRiskAdmission(
        admission_id=admission_id,
        model_digest=model_digest,
        use_kind=use_kind,
        committee_approval_digest=committee_approval_digest,
        supervision_declaration=supervision_declaration,
        filing_digest=filing_digest,
        stop_conditions=stop_list,
        authority_id=authority_id,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        admitted_at=admitted_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    payload = _admission_payload(draft)
    digest = jcs_sha256_hex(payload)
    signature_hex = _sign_hex(
        authority_secret, jcs_canonical_json(payload)
    )
    return HighRiskAdmission(
        **{**draft.__dict__, "admission_digest": digest, "signature_hex": signature_hex}
    )


def _verify_admission_integrity(admission: HighRiskAdmission) -> str | None:
    try:
        if not hmac.compare_digest(
            compute_admission_digest(admission), admission.admission_digest
        ):
            return DENY_ADMISSION_TAMPERED
        if not _is_hex(admission.signature_hex, _HEX128_LENGTH):
            return DENY_ADMISSION_TAMPERED
        payload_bytes = jcs_canonical_json(_admission_payload(admission))
        if not _verify_hex_signature(
            admission.authority_pubkey_hex, admission.signature_hex, payload_bytes
        ):
            return DENY_ADMISSION_TAMPERED
    except InsuranceError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class AdmissionVerdict:
    allowed: bool
    reason: str
    admission_id: str | None = None


def high_risk_gate(
    admissions: Sequence[HighRiskAdmission],
    *,
    model_digest: str,
    use_kind: str,
    check_time: int,
) -> AdmissionVerdict:
    """Fail-closed gate: high-risk AI use needs all four admission parts.

    Underwriting, claims adjudication, and pricing require a live
    admission binding the exact model digest: committee approval,
    supervision declaration, filing digest, and stop conditions.
    Missing any part — or an expired/tampered admission — denies
    (``insurance:high_risk_unadmitted``, Document 8 as mechanism).
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    use_kind = _check_high_risk_kind(use_kind)
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> AdmissionVerdict:
        return AdmissionVerdict(allowed=False, reason=reason)

    for admission in admissions:
        if not hmac.compare_digest(admission.model_digest, model_digest):
            continue
        if admission.use_kind != use_kind:
            continue
        tamper = _verify_admission_integrity(admission)
        if tamper is not None:
            return deny(tamper)
        if check_time < admission.admitted_at:
            return deny(DENY_ADMISSION_TAMPERED)
        if check_time >= admission.expires_at:
            return deny(DENY_ADMISSION_EXPIRED)
        return AdmissionVerdict(allowed=True, reason="ok", admission_id=admission.admission_id)
    return deny(DENY_HIGH_RISK_UNADMITTED)


def admission_audit_event(verdict: AdmissionVerdict, *, action: str) -> dict[str, Any]:
    return {
        "event": ADMISSION_ALLOWED_EVENT if verdict.allowed else ADMISSION_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "admission_id": verdict.admission_id,
    }


# ---------------------------------------------------------------------------
# Fraud-signal gate (a score alone can never deny)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FraudDenialRequest:
    """A denial request that cites a fraud score."""

    request_id: str
    claim_id: str
    fraud_score_digest: str
    human_review_digest: str | None
    evidence_digest: str | None
    schema_version: str = INSURANCE_SCHEMA_VERSION


@dataclass(frozen=True)
class FraudVerdict:
    allowed: bool
    reason: str
    request_id: str | None = None


def fraud_signal_gate(request: FraudDenialRequest) -> FraudVerdict:
    """A fraud score alone can never deny a claim.

    Denial requires fraud score + human review + evidence binding.
    A request with a fraud score but no human review (or no evidence
    binding) denies outright (``insurance:fraud_score_only_denial``) —
    the score informs review; it is not a verdict.
    """
    if not isinstance(request, FraudDenialRequest):
        raise InsuranceError("request must be a FraudDenialRequest")
    request_id = _check_nonempty_str(request.request_id, "request_id")
    _check_nonempty_str(request.claim_id, "claim_id")
    _check_hex64(request.fraud_score_digest, "fraud_score_digest")

    def deny(reason: str) -> FraudVerdict:
        return FraudVerdict(allowed=False, reason=reason, request_id=request_id)

    if request.human_review_digest is None:
        return deny(DENY_FRAUD_SCORE_ONLY)
    if request.evidence_digest is None:
        return deny(DENY_FRAUD_SCORE_ONLY)
    try:
        _check_hex64(request.human_review_digest, "human_review_digest")
        _check_hex64(request.evidence_digest, "evidence_digest")
    except InsuranceError:
        return deny(DENY_FRAUD_TAMPERED)
    return FraudVerdict(allowed=True, reason="ok", request_id=request_id)


def fraud_audit_event(verdict: FraudVerdict, *, action: str) -> dict[str, Any]:
    return {
        "event": FRAUD_ALLOWED_EVENT if verdict.allowed else FRAUD_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "request_id": verdict.request_id,
    }


# ---------------------------------------------------------------------------
# Vendor liability (stays with the insurer)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorAdmission:
    """Vendor AI admission: audit rights + bias test; insurer pinned liable."""

    vendor_id: str
    insurer_id: str
    model_digest: str
    audit_rights_digest: str
    bias_test_digest: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    admitted_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    admission_digest: str = ""
    schema_version: str = INSURANCE_SCHEMA_VERSION


def _vendor_payload(admission: VendorAdmission) -> dict[str, Any]:
    return {
        "vendor_id": admission.vendor_id,
        "insurer_id": admission.insurer_id,
        "model_digest": admission.model_digest,
        "audit_rights_digest": admission.audit_rights_digest,
        "bias_test_digest": admission.bias_test_digest,
        "authority_id": admission.authority_id,
        "authority_pubkey_hex": admission.authority_pubkey_hex,
        "admitted_at": admission.admitted_at,
        "expires_at": admission.expires_at,
        "prev_digest": admission.prev_digest,
        "schema_version": admission.schema_version,
    }


def compute_vendor_digest(admission: VendorAdmission) -> str:
    return jcs_sha256_hex(_vendor_payload(admission))


def issue_vendor_admission(
    *,
    vendor_id: str,
    insurer_id: str,
    model_digest: str,
    audit_rights_digest: str,
    bias_test_digest: str,
    authority_id: str,
    authority_secret: bytes,
    admitted_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> VendorAdmission:
    """Admit vendor AI: audit rights and bias-test evidence are mandatory.

    The insurer is pinned as the liable party by construction — there
    is no field for shifting liability to the vendor, so no contract
    clause the module recognizes can move it.
    """
    authority_secret = _check_secret(authority_secret, "authority_secret")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    insurer_id = _check_nonempty_str(insurer_id, "insurer_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    audit_rights_digest = _check_hex64(audit_rights_digest, "audit_rights_digest")
    bias_test_digest = _check_hex64(bias_test_digest, "bias_test_digest")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    admitted_at = _check_ts(admitted_at, "admitted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= admitted_at:
        raise InsuranceError("expires_at must be after admitted_at")
    authority_pubkey_hex = ed25519.public_key(authority_secret).hex()
    draft = VendorAdmission(
        vendor_id=vendor_id,
        insurer_id=insurer_id,
        model_digest=model_digest,
        audit_rights_digest=audit_rights_digest,
        bias_test_digest=bias_test_digest,
        authority_id=authority_id,
        authority_pubkey_hex=authority_pubkey_hex,
        signature_hex="",
        admitted_at=admitted_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    payload = _vendor_payload(draft)
    digest = jcs_sha256_hex(payload)
    signature_hex = _sign_hex(
        authority_secret, jcs_canonical_json(payload)
    )
    return VendorAdmission(
        **{**draft.__dict__, "admission_digest": digest, "signature_hex": signature_hex}
    )


def _verify_vendor_integrity(admission: VendorAdmission) -> str | None:
    try:
        if not hmac.compare_digest(
            compute_vendor_digest(admission), admission.admission_digest
        ):
            return DENY_VENDOR_TAMPERED
        if not _is_hex(admission.signature_hex, _HEX128_LENGTH):
            return DENY_VENDOR_TAMPERED
        payload_bytes = jcs_canonical_json(_vendor_payload(admission))
        if not _verify_hex_signature(
            admission.authority_pubkey_hex, admission.signature_hex, payload_bytes
        ):
            return DENY_VENDOR_TAMPERED
    except InsuranceError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class VendorVerdict:
    allowed: bool
    reason: str
    # The liable party is always the insurer — pinned by construction.
    liable_party: str = "insurer"


def vendor_liability(
    admissions: Sequence[VendorAdmission],
    *,
    vendor_id: str,
    model_digest: str,
    check_time: int,
) -> VendorVerdict:
    """Fail-closed gate: vendor AI needs audit rights + bias-test evidence.

    A vendor's AI cannot enter the claims/pricing pipeline without an
    admission binding audit rights and bias-test evidence digests.
    The verdict pins ``liable_party="insurer"`` — liability cannot be
    shifted to the vendor through any mechanism this module models.
    """
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> VendorVerdict:
        return VendorVerdict(allowed=False, reason=reason)

    for admission in admissions:
        if admission.vendor_id != vendor_id:
            continue
        if not hmac.compare_digest(admission.model_digest, model_digest):
            continue
        tamper = _verify_vendor_integrity(admission)
        if tamper is not None:
            return deny(tamper)
        if check_time >= admission.expires_at:
            return deny(DENY_VENDOR_TAMPERED)
        return VendorVerdict(allowed=True, reason="ok")
    return deny(DENY_VENDOR_NO_AUDIT)


def vendor_audit_event(verdict: VendorVerdict, *, action: str) -> dict[str, Any]:
    return {
        "event": VENDOR_ALLOWED_EVENT if verdict.allowed else VENDOR_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "liable_party": verdict.liable_party,
    }


# ---------------------------------------------------------------------------
# Dark-pattern gate (customer-facing flows)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DarkPatternVerdict:
    allowed: bool
    reason: str
    markers_found: tuple[str, ...] = ()


def dark_pattern_gate(flow_markers: Sequence[str]) -> DarkPatternVerdict:
    """Customer-facing flows with dark-pattern markers are denied.

    The closed marker vocabulary (``DARK_PATTERN_MARKERS``) covers
    hidden opt-outs, pre-checked consent, false urgency, disguised
    charges, forced continuity, and misleading comparisons (the IRDAI
    lesson). Any marker found denies with ``insurance:dark_pattern``
    and names the markers — the obligation is redesign, not a banner.
    Unknown markers raise (an unnamed dark pattern is still a
    programming error at declaration time).
    """
    markers = tuple(_check_dark_pattern(m) for m in flow_markers)
    if markers:
        return DarkPatternVerdict(
            allowed=False,
            reason=DENY_DARK_PATTERN,
            markers_found=markers,
        )
    return DarkPatternVerdict(allowed=True, reason="ok")


def dark_pattern_audit_event(verdict: DarkPatternVerdict, *, action: str) -> dict[str, Any]:
    return {
        "event": DARK_PATTERN_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "markers_found": list(verdict.markers_found),
    }


# ---------------------------------------------------------------------------
# Cyber-insurance lifecycle ledger: Insurance assess/claim/renew
# (additive extension — zero changes to the denial-receipt layer above)
# ---------------------------------------------------------------------------
#
# Distinct layer from the denial-receipt ledger above: this is the
# *cyber-insurance lifecycle decision ledger* — it books declared risk
# assessments, declared claim filings, and declared policy renewals as a
# deterministic single-host state machine. The lifecycle half is
# Simulated: runs no actuarial math, contacts no underwriter, pays no
# claims. A booked assessment/claim/renewal is ledger truth (what the host
# declared), never proof of insurability, loss, or coverage.
#
# House style: frozen dataclasses, caller int seqs strictly increasing with
# claim-then-burn (failed mutations consume their seq and book
# ``insurance-lifecycle.rejected``; rewinds raise bare), no wall-clock,
# RLock-guarded, fail-closed, ``sha256:`` digest pins with ``verify()``,
# ``audit.ndjson/1`` events.

#: Module version for the lifecycle ledger layer.
INSURANCE_LIFECYCLE_VERSION = "insurance-lifecycle.v1"

#: Schema pin for records produced by this layer.
INSURANCE_LIFECYCLE_SCHEMA = "northstar.insurance-lifecycle.v1"

#: Hash domain separator so lifecycle pins cannot collide with other digests.
_LIFECYCLE_HASH_DOMAIN = b"northstar.insurance-lifecycle.v1\x00"

#: Pinned risk-class vocabulary for assessments. ``prohibited`` means the
#: host will not underwrite the policy — claims against it are refused
#: fail-closed.
RISK_CLASSES: tuple[str, ...] = ("low", "standard", "elevated", "high", "prohibited")

#: Audit event kinds booked by this layer.
_INSURANCE_ASSESSED_EVENT = "insurance-lifecycle.assessed"
_INSURANCE_CLAIMED_EVENT = "insurance-lifecycle.claimed"
_INSURANCE_RENEWED_EVENT = "insurance-lifecycle.renewed"
_INSURANCE_REJECTED_EVENT = "insurance-lifecycle.rejected"

_INSURANCE_AUDIT_KINDS: Mapping[str, str] = {
    "assessed": _INSURANCE_ASSESSED_EVENT,
    "claimed": _INSURANCE_CLAIMED_EVENT,
    "renewed": _INSURANCE_RENEWED_EVENT,
    "rejected": _INSURANCE_REJECTED_EVENT,
}

#: Raw-content keys banned from the audit boundary (exact-key matching).
_INSURANCE_LIFECYCLE_BANNED_KEYS: frozenset[str] = frozenset({
    "policy_terms",
    "coverage",
    "loss",
    "notes",
    "text",
    "description",
    "evidence",
    "secret",
    "key",
    "payload",
    "raw",
    "message",
})


class InsuranceSpecError(ValueError):
    """Base error for insurance-lifecycle ledger misuse."""


class BadIdError(InsuranceSpecError):
    """A policy/claim/renewal id was empty or not a string."""


class DuplicatePolicyError(InsuranceSpecError):
    """A policy id was assessed twice (ids are never recycled)."""


class UnknownPolicyError(InsuranceSpecError):
    """A claim/renewal named a policy with no booked assessment."""


class DuplicateClaimError(InsuranceSpecError):
    """A claim id was filed twice (ids are never recycled)."""


class DuplicateRenewalError(InsuranceSpecError):
    """A renewal id was booked twice (ids are never recycled)."""


class BadRiskClassError(InsuranceSpecError):
    """risk_class was not in the pinned vocabulary."""


class BadDigestError(InsuranceSpecError):
    """A digest was not ``""`` or ``sha256:<64hex>``."""


class BadAmountError(InsuranceSpecError):
    """An amount was not a non-negative int of minor currency units."""


class BadTermError(InsuranceSpecError):
    """term_months was not an int >= 1."""


class ProhibitedPolicyError(InsuranceSpecError):
    """A claim was filed against a policy assessed ``prohibited``."""


class SeqOrderError(InsuranceSpecError):
    """seq was malformed or not strictly increasing."""


class AuditKindError(InsuranceSpecError):
    """The audit builder received an unknown kind or a banned raw key."""


def _lifecycle_check_id(value: Any, field_name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{field_name} must be a str")
    if not value:
        raise BadIdError(f"{field_name} must be non-empty")
    return value


def _lifecycle_check_digest(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{field_name} must be a str")
    if value == "":
        return value
    if len(value) != 71 or not value.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be '' or 'sha256:<64hex>'")
    hexpart = value[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be '' or 'sha256:<64hex>'")
    return value


def _lifecycle_check_risk_class(value: Any) -> str:
    if value not in RISK_CLASSES:
        raise BadRiskClassError(f"risk_class must be one of {RISK_CLASSES}")
    return value


def _lifecycle_check_amount(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadAmountError(f"{field_name} must be a non-negative int")
    if value < 0:
        raise BadAmountError(f"{field_name} must be >= 0")
    return value


def _lifecycle_check_term(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadTermError("term_months must be an int >= 1")
    if value < 1:
        raise BadTermError("term_months must be an int >= 1")
    return value


def _lifecycle_pin(payload: Mapping[str, Any]) -> str:
    """Deterministic ``sha256:`` pin for a canonicalized payload."""
    canonical = jcs_canonical_json(payload)
    if isinstance(canonical, str):
        canonical = canonical.encode("utf-8")
    digest = hashlib.sha256(_LIFECYCLE_HASH_DOMAIN + canonical).hexdigest()
    return "sha256:" + digest


def insurance_lifecycle_audit_event(audit_kind: str, **details: Any) -> dict[str, Any]:
    """Build one audit event for the lifecycle layer.

    ``audit_kind`` is one of ``assessed``/``claimed``/``renewed``/
    ``rejected``. Raw content keys are banned from ``details`` — only
    digests and bookkeeping fields may cross the audit boundary.
    """
    if audit_kind not in _INSURANCE_AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    for key in details:
        if key in _INSURANCE_LIFECYCLE_BANNED_KEYS:
            raise AuditKindError(f"raw key banned from audit boundary: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": _INSURANCE_AUDIT_KINDS[audit_kind],
        "details": dict(details),
    }


@dataclass(frozen=True)
class AssessmentRecord:
    """Booked risk assessment for one policy (host-declared, Simulated)."""

    policy_id: str
    seq: int
    risk_class: str
    coverage_digest: str
    premium_cents: int
    digest_pin: str
    schema: str = INSURANCE_LIFECYCLE_SCHEMA

    def verify(self) -> bool:
        expected = _lifecycle_pin({
            "policy_id": self.policy_id,
            "seq": self.seq,
            "risk_class": self.risk_class,
            "coverage_digest": self.coverage_digest,
            "premium_cents": self.premium_cents,
        })
        return hmac.compare_digest(expected, self.digest_pin)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "seq": self.seq,
            "risk_class": self.risk_class,
            "coverage_digest": self.coverage_digest,
            "premium_cents": self.premium_cents,
            "digest_pin": self.digest_pin,
        }


@dataclass(frozen=True)
class ClaimRecord:
    """Booked claim filing against one assessed policy (host-declared)."""

    claim_id: str
    policy_id: str
    seq: int
    loss_digest: str
    amount_cents: int
    digest_pin: str
    schema: str = INSURANCE_LIFECYCLE_SCHEMA

    def verify(self) -> bool:
        expected = _lifecycle_pin({
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "seq": self.seq,
            "loss_digest": self.loss_digest,
            "amount_cents": self.amount_cents,
        })
        return hmac.compare_digest(expected, self.digest_pin)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "policy_id": self.policy_id,
            "seq": self.seq,
            "loss_digest": self.loss_digest,
            "amount_cents": self.amount_cents,
            "digest_pin": self.digest_pin,
        }


@dataclass(frozen=True)
class RenewalRecord:
    """Booked policy renewal declaration (host-declared)."""

    renewal_id: str
    policy_id: str
    seq: int
    terms_digest: str
    term_months: int
    digest_pin: str
    schema: str = INSURANCE_LIFECYCLE_SCHEMA

    def verify(self) -> bool:
        expected = _lifecycle_pin({
            "renewal_id": self.renewal_id,
            "policy_id": self.policy_id,
            "seq": self.seq,
            "terms_digest": self.terms_digest,
            "term_months": self.term_months,
        })
        return hmac.compare_digest(expected, self.digest_pin)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "renewal_id": self.renewal_id,
            "policy_id": self.policy_id,
            "seq": self.seq,
            "terms_digest": self.terms_digest,
            "term_months": self.term_months,
            "digest_pin": self.digest_pin,
        }


class Insurance:
    """Cyber-insurance lifecycle decision ledger: assess → claim → renew.

    Deterministic single-host state machine. Caller-supplied int seqs must
    be strictly increasing (claim-then-burn: failed mutations consume their
    seq and book ``insurance-lifecycle.rejected``; rewinds raise bare
    without consuming). RLock-guarded. Pure-read views validate the seq
    shape, never consume it, and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._assessments: dict[str, AssessmentRecord] = {}
        self._claims: dict[str, ClaimRecord] = {}
        self._renewals: dict[str, RenewalRecord] = {}
        self._audit: list[dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _check_seq_shape(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq < 1:
            raise SeqOrderError("seq must be >= 1")
        return seq

    def _claim_seq(self, seq: Any) -> int:
        seq = self._check_seq_shape(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("seq must be strictly increasing")
        self._last_seq = seq
        return seq

    # -- audit -------------------------------------------------------------

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        event = insurance_lifecycle_audit_event(audit_kind, **details)
        event["seq"] = seq
        self._audit.append(event)

    def _fail(self, seq: int, exc: InsuranceSpecError) -> None:
        self._emit("rejected", seq,
                   error=type(exc).__name__, detail=str(exc))
        raise exc

    # -- mutations ---------------------------------------------------------

    def assess(self, policy_id: str, seq: int, risk_class: str = "standard",
               coverage_digest: str = "", premium_cents: int = 0) -> AssessmentRecord:
        """Book one risk assessment for a policy (host-declared).

        Coverage terms travel as a digest pin only — raw terms never enter
        a record. Duplicate policy ids are refused (ids never recycled).
        """
        with self._lock:
            seq = self._claim_seq(seq)
            try:
                pid = _lifecycle_check_id(policy_id, "policy_id")
                if pid in self._assessments:
                    raise DuplicatePolicyError(f"policy already assessed: {pid!r}")
                rc = _lifecycle_check_risk_class(risk_class)
                cd = _lifecycle_check_digest(coverage_digest, "coverage_digest")
                prem = _lifecycle_check_amount(premium_cents, "premium_cents")
            except InsuranceSpecError as exc:
                self._fail(seq, exc)
            record = AssessmentRecord(
                policy_id=pid,
                seq=seq,
                risk_class=rc,
                coverage_digest=cd,
                premium_cents=prem,
                digest_pin=_lifecycle_pin({
                    "policy_id": pid,
                    "seq": seq,
                    "risk_class": rc,
                    "coverage_digest": cd,
                    "premium_cents": prem,
                }),
            )
            self._assessments[pid] = record
            self._emit("assessed", seq, policy_id=pid, risk_class=rc,
                       premium_cents=prem, digest=record.digest_pin)
            return record

    def claim(self, policy_id: str, claim_id: str, seq: int,
              loss_digest: str = "", amount_cents: int = 0) -> ClaimRecord:
        """Book one claim filing against an assessed policy (host-declared).

        Loss details travel as a digest pin only. The policy must exist and
        must not have been assessed ``prohibited``. One claim per claim id.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            try:
                pid = _lifecycle_check_id(policy_id, "policy_id")
                cid = _lifecycle_check_id(claim_id, "claim_id")
                if pid not in self._assessments:
                    raise UnknownPolicyError(f"unknown policy: {pid!r}")
                if self._assessments[pid].risk_class == "prohibited":
                    raise ProhibitedPolicyError(
                        f"policy assessed prohibited: {pid!r}")
                if cid in self._claims:
                    raise DuplicateClaimError(f"claim already filed: {cid!r}")
                ld = _lifecycle_check_digest(loss_digest, "loss_digest")
                amt = _lifecycle_check_amount(amount_cents, "amount_cents")
            except InsuranceSpecError as exc:
                self._fail(seq, exc)
            record = ClaimRecord(
                claim_id=cid,
                policy_id=pid,
                seq=seq,
                loss_digest=ld,
                amount_cents=amt,
                digest_pin=_lifecycle_pin({
                    "claim_id": cid,
                    "policy_id": pid,
                    "seq": seq,
                    "loss_digest": ld,
                    "amount_cents": amt,
                }),
            )
            self._claims[cid] = record
            self._emit("claimed", seq, policy_id=pid, claim_id=cid,
                       amount_cents=amt, digest=record.digest_pin)
            return record

    def renew(self, policy_id: str, renewal_id: str, seq: int,
              terms_digest: str = "", term_months: int = 12) -> RenewalRecord:
        """Book one policy renewal declaration (host-declared).

        Terms travel as a digest pin only. The policy must exist. One
        renewal per renewal id; renewals chain in booked order.
        """
        with self._lock:
            seq = self._claim_seq(seq)
            try:
                pid = _lifecycle_check_id(policy_id, "policy_id")
                rid = _lifecycle_check_id(renewal_id, "renewal_id")
                if pid not in self._assessments:
                    raise UnknownPolicyError(f"unknown policy: {pid!r}")
                if rid in self._renewals:
                    raise DuplicateRenewalError(f"renewal already booked: {rid!r}")
                td = _lifecycle_check_digest(terms_digest, "terms_digest")
                tm = _lifecycle_check_term(term_months)
            except InsuranceSpecError as exc:
                self._fail(seq, exc)
            record = RenewalRecord(
                renewal_id=rid,
                policy_id=pid,
                seq=seq,
                terms_digest=td,
                term_months=tm,
                digest_pin=_lifecycle_pin({
                    "renewal_id": rid,
                    "policy_id": pid,
                    "seq": seq,
                    "terms_digest": td,
                    "term_months": tm,
                }),
            )
            self._renewals[rid] = record
            self._emit("renewed", seq, policy_id=pid, renewal_id=rid,
                       term_months=tm, digest=record.digest_pin)
            return record

    # -- pure-read views ---------------------------------------------------

    def assessment_record(self, policy_id: str, seq: int) -> AssessmentRecord:
        """Return the booked assessment for a policy (no seq consumed)."""
        with self._lock:
            self._check_seq_shape(seq)
            pid = _lifecycle_check_id(policy_id, "policy_id")
            try:
                return self._assessments[pid]
            except KeyError:
                raise UnknownPolicyError(f"unknown policy: {pid!r}") from None

    def claims_for(self, policy_id: str, seq: int) -> tuple[ClaimRecord, ...]:
        """Claims filed against a policy, in booked order."""
        with self._lock:
            self._check_seq_shape(seq)
            pid = _lifecycle_check_id(policy_id, "policy_id")
            if pid not in self._assessments:
                raise UnknownPolicyError(f"unknown policy: {pid!r}")
            return tuple(
                rec for rec in self._claims.values() if rec.policy_id == pid
            )

    def renewals_for(self, policy_id: str, seq: int) -> tuple[RenewalRecord, ...]:
        """Renewals booked for a policy, in booked order."""
        with self._lock:
            self._check_seq_shape(seq)
            pid = _lifecycle_check_id(policy_id, "policy_id")
            if pid not in self._assessments:
                raise UnknownPolicyError(f"unknown policy: {pid!r}")
            return tuple(
                rec for rec in self._renewals.values() if rec.policy_id == pid
            )

    def policy_ids(self, seq: int) -> tuple[str, ...]:
        """All assessed policy ids, sorted."""
        with self._lock:
            self._check_seq_shape(seq)
            return tuple(sorted(self._assessments))

    def stats(self, seq: int) -> dict[str, int]:
        """Ledger counts as data."""
        with self._lock:
            self._check_seq_shape(seq)
            prohibited = sum(
                1 for rec in self._assessments.values()
                if rec.risk_class == "prohibited"
            )
            return {
                "policies": len(self._assessments),
                "claims": len(self._claims),
                "renewals": len(self._renewals),
                "prohibited": prohibited,
            }

    def audit_log(self, seq: int) -> tuple[dict[str, Any], ...]:
        """Booked audit events, in order (no audit row for the read)."""
        with self._lock:
            self._check_seq_shape(seq)
            return tuple(self._audit)


def insurance_lifecycle_main() -> None:
    """Self-check for the lifecycle ledger layer."""
    ins = Insurance()
    ins.assess("pol-1", 1, risk_class="low", premium_cents=1000)
    ins.claim("pol-1", "clm-1", 2, amount_cents=500)
    ins.renew("pol-1", "rnw-1", 3, term_months=12)
    assert ins.assessment_record("pol-1", 4).verify()
    assert ins.stats(5)["policies"] == 1
    print("insurance-lifecycle OK: assess, claim, renew, pins, audit")


if __name__ == "__main__":
    insurance_lifecycle_main()
