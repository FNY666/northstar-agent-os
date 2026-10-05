"""Underwriting & claims discipline gates (one-hundred-fortieth batch).

Absorbs the 2026 AI-insurance research thread (mechanism ideas only,
honestly scoped), extending the 125th-batch ``insurance.py`` denial
receipts into the underwriting/claims AI pipeline:

* **Claim engines may only approve or route to human.** Lemonade's
  "approve engine" (55% claims fully automated, 96% FNOL touchless)
  is the model: the engine's action vocabulary has no ``deny``.
  Hesper AI's 2026-09 analysis of NAIC data found *zero* large auto
  insurers reporting AI for claim denials — the denial narrative is
  mostly health insurance. Here a direct AI claim denial is a hard
  deny (``underwriting.ai_denial``), not a configurable policy.
* **Human-review circuit breakers on key content.** China's
  "Generative AI Insurance Compliance Guidance (trial)" (2026-06)
  requires human-review circuit breakers on key content and
  fairness stress tests on script templates. Here denials and
  large payouts must bind a live human-review breaker receipt;
  underwriting templates must bind a fairness stress-test receipt.
* **EU AI Act timing is a clock, not a vibe.** Omnibus 2026/1744
  defers Annex III high-risk obligations to 2027-12-02, but
  Art. 50 transparency stays 2026-08-02. Here each insurance-AI
  deployment binds its obligation set to those pinned dates; a
  past-deadline unmet obligation is a compliance lapse.
* **Assistive AI that decides has crossed a line.** Aviva's AI
  medical-report summaries (99.7% self-reported accuracy) are
  explicitly assist-not-decide. Here a system declared
  assistive whose output was a decision raises
  ``underwriting.decision_creep``.
* **Synthetic fraud probes route to humans.** AI-generated fake
  claims probe fraud detection, but the probe verdict itself may
  never auto-deny — false positives at scale are a denial pipeline.
* **NAIC Evaluation Tool is a pre-deployment checklist.** The
  12-state pilot (2026-01~09) review items map to deployment
  gates; high-risk uses without a mapped item are
  NON_AUTHORITATIVE.
* **Vendor accuracy claims bind evidence.** "99.7% accuracy",
  "<2% hallucination", "triage time -80%" (Zurich×Cytora,
  Prudential HK×Alibaba Cloud — all vendor/PR, unaudited) are
  self-reported until bound to a trial-evidence digest.

Honest boundary: receipts bind declared underwriting discipline —
digests recompute, signatures verify, thresholds pin. The module
cannot certify actuarial fairness (that needs the probe methodology
and data, out of scope); it enforces the *structure*: approvals or
human routing, breakers on key content, clocks on obligations,
checklists before deployment. An insurer gaming its own stress
test fails the auditability requirement, not this gate.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

UNDERWRITING_SCHEMA_VERSION = "northstar.underwriting.v1"

#: Claim-engine action vocabulary. "deny" is deliberately absent:
#: a claim engine may approve or route to a human — nothing else.
CLAIM_ENGINE_ACTIONS: tuple[str, ...] = (
    "approve",
    "route_to_human",
    "request_info",
)

#: Closed vocabulary for human-review circuit-breaker kinds (key
#: content under the 2026-06 China compliance guidance).
BREAKER_KINDS: tuple[str, ...] = (
    "claim_denial",
    "large_payout",
    "underwriting_rejection",
)

#: Closed vocabulary for NAIC AI Evaluation Tool review items,
#: mapped as pre-deployment bench checklist entries (2026 spring
#: meeting split claims AI from pricing/underwriting review).
NAIC_REVIEW_ITEMS: tuple[str, ...] = (
    "governance_disclosure",
    "data_quality",
    "proxy_discrimination_test",
    "model_validation",
    "human_oversight",
    "claims_specific_review",
    "third_party_oversight",
    "consumer_notification",
    "adverse_action_explanation",
    "incident_response",
)

#: High-risk insurance-AI kinds that require full NAIC mapping.
HIGH_RISK_UNDERWRITING_KINDS: tuple[str, ...] = (
    "underwriting",
    "claims_adjudication",
    "pricing",
)

#: Large-payout threshold in basis points of annual premium
#: (10_000 bps = 100%). Pinned in code deliberately: the payout
#: breaker must never be tuned by the model it gates.
LARGE_PAYOUT_BPS = 100_000

#: EU AI Act pinned obligation deadlines (seconds since epoch).
#: Art. 50 transparency: 2026-08-02. Annex III high-risk
#: obligations: 2027-12-02 (Omnibus 2026/1744 deferral).
ART50_TRANSPARENCY_EPOCH = 1785542400  # 2026-08-02T00:00:00Z
ANNEX3_OBLIGATIONS_EPOCH = 1830297600  # 2027-12-02T00:00:00Z

#: Denial reason codes. All start with the ``underwriting:`` prefix.
DENY_AI_DENIAL = "underwriting.ai_denial"
DENY_UNKNOWN_ACTION = "underwriting.unknown_engine_action"
DENY_BREAKER_MISSING = "underwriting.breaker_missing"
DENY_BREAKER_TAMPERED = "underwriting.breaker_tampered"
DENY_BREAKER_EXPIRED = "underwriting.breaker_expired"
DENY_BREAKER_FUTURE = "underwriting.breaker_from_future"
DENY_BREAKER_KIND_MISMATCH = "underwriting.breaker_kind_mismatch"
DENY_UNTESTED_TEMPLATE = "underwriting.untested_template"
DENY_STRESS_TAMPERED = "underwriting.stress_receipt_tampered"
DENY_STRESS_EXPIRED = "underwriting.stress_receipt_expired"
DENY_STRESS_FUTURE = "underwriting.stress_receipt_from_future"
DENY_STRESS_TEMPLATE_MISMATCH = "underwriting.stress_template_mismatch"
DENY_COMPLIANCE_LAPSE = "underwriting.compliance_lapse"
DENY_CLOCK_UNKNOWN_KIND = "underwriting.clock_unknown_kind"
DENY_FRAUD_AUTO_DENY = "underwriting.fraud_auto_deny"
DENY_FRAUD_UNKNOWN_ACTION = "underwriting.fraud_probe_unknown_action"
DENY_DECISION_CREEP = "underwriting.decision_creep"
DENY_UNMAPPED_HIGH_RISK = "underwriting.unmapped_high_risk"
DENY_ITEM_UNKNOWN = "underwriting.unknown_review_item"
DENY_VENDOR_SELF_REPORTED = "underwriting.vendor_self_reported"
DENY_VENDOR_TAMPERED = "underwriting.vendor_claim_tampered"
DENY_VENDOR_FUTURE = "underwriting.vendor_claim_from_future"
DENY_MALFORMED = "underwriting.malformed"

#: Non-authoritative classification reasons (soft fails).
NONAUTH_VENDER_NO_EVIDENCE = "underwriting.vendor_no_evidence"
NONAUTH_UNMAPPED_LOW_RISK = "underwriting.unmapped_low_risk"

#: Audit event names (shaped for ``audit_chain.chain_record``).
ENGINE_ALLOWED_EVENT = "underwriting.engine_allowed"
ENGINE_DENIED_EVENT = "underwriting.engine_denied"
BREAKER_ALLOWED_EVENT = "underwriting.breaker_allowed"
BREAKER_DENIED_EVENT = "underwriting.breaker_denied"
STRESS_ALLOWED_EVENT = "underwriting.stress_allowed"
STRESS_DENIED_EVENT = "underwriting.stress_denied"
CLOCK_EVENT = "underwriting.compliance_clock"
FRAUD_ALLOWED_EVENT = "underwriting.fraud_probe_allowed"
FRAUD_DENIED_EVENT = "underwriting.fraud_probe_denied"
CREEP_EVENT = "underwriting.decision_creep"
MAPPING_EVENT = "underwriting.evaluation_mapping"
VENDOR_EVENT = "underwriting.vendor_disclosure"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class UnderwritingError(DomainError):
    """Malformed receipt/probe/checklist or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (expired, tampered,
    missing evidence, lapsed) return verdicts with
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
        raise UnderwritingError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise UnderwritingError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_engine_action(value: Any) -> str:
    if value not in CLAIM_ENGINE_ACTIONS:
        raise UnderwritingError(
            f"unknown claim-engine action {value!r}; closed vocabulary "
            f"{CLAIM_ENGINE_ACTIONS}"
        )
    return value


def _check_breaker_kind(value: Any) -> str:
    if value not in BREAKER_KINDS:
        raise UnderwritingError(
            f"unknown breaker kind {value!r}; closed vocabulary {BREAKER_KINDS}"
        )
    return value


def _check_review_item(value: Any) -> str:
    if value not in NAIC_REVIEW_ITEMS:
        raise UnderwritingError(
            f"unknown review item {value!r}; closed vocabulary "
            f"{NAIC_REVIEW_ITEMS}"
        )
    return value


def _check_high_risk_kind(value: Any) -> str:
    if value not in HIGH_RISK_UNDERWRITING_KINDS:
        raise UnderwritingError(
            f"unknown high-risk kind {value!r}; closed vocabulary "
            f"{HIGH_RISK_UNDERWRITING_KINDS}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 0:
        return value
    raise UnderwritingError(f"{field_name} must be a non-negative integer epoch")


def _check_secret(value: Any, field_name: str) -> bytes:
    if (
        isinstance(value, (bytes, bytearray))
        and len(bytes(value)) == 32
        and any(b != 0 for b in bytes(value))
    ):
        return bytes(value)
    raise UnderwritingError(f"{field_name} must be a non-degenerate 32-byte secret")


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, 64):
        raise UnderwritingError("pubkey must be 64 lowercase hex chars (32-byte Ed25519 key)")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UnderwritingError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_bps(value: Any, field_name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 0:
        return value
    raise UnderwritingError(f"{field_name} must be a non-negative integer (basis points)")


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


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    return jcs_sha256_hex(payload)


# ---------------------------------------------------------------------------
# Claim engine actions (approve-only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngineVerdict:
    """Verdict for a claim-engine action request."""

    allowed: bool
    reason: str
    action: str


def approve_only_engine(action: str) -> EngineVerdict:
    """Claim engines may only approve or route to a human.

    The closed action vocabulary (``CLAIM_ENGINE_ACTIONS``) has no
    ``deny`` entry — the approve-engine pattern (Lemonade's 55%
    fully-automated claims) is enforced structurally, not by policy.
    A direct AI claim denial is a hard deny
    (``underwriting.ai_denial``); an unknown action raises (a new
    action kind is a programming decision, not runtime data).
    """
    if action == "deny":
        return EngineVerdict(
            allowed=False, reason=DENY_AI_DENIAL, action=action
        )
    action = _check_engine_action(action)
    return EngineVerdict(allowed=True, reason="ok", action=action)


def engine_audit_event(verdict: EngineVerdict) -> dict[str, Any]:
    """Shape an engine verdict as an audit event."""
    return {
        "event": ENGINE_ALLOWED_EVENT if verdict.allowed else ENGINE_DENIED_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "action": verdict.action,
    }


# ---------------------------------------------------------------------------
# Human-review circuit breakers (key content)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BreakerReceipt:
    """Human-review circuit breaker for key content, hash-chained."""

    break_id: str
    decision_id: str
    decision_digest: str
    breaker_kind: str
    human_reviewer_id: str
    reviewer_pubkey_hex: str
    payout_bps: int
    created_at: int
    expires_at: int
    signature_hex: str
    prev_digest: str = _GENESIS

    def digest(self) -> str:
        return _canonical_digest(
            {
                "schema": UNDERWRITING_SCHEMA_VERSION,
                "break_id": self.break_id,
                "decision_id": self.decision_id,
                "decision_digest": self.decision_digest,
                "breaker_kind": self.breaker_kind,
                "human_reviewer_id": self.human_reviewer_id,
                "reviewer_pubkey_hex": self.reviewer_pubkey_hex,
                "payout_bps": self.payout_bps,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "prev_digest": self.prev_digest,
            }
        )


@dataclass(frozen=True)
class BreakerVerdict:
    """Verdict for a breaker check."""

    allowed: bool
    reason: str
    break_id: str


def issue_breaker_receipt(
    *,
    break_id: str,
    decision_id: str,
    decision_digest: str,
    breaker_kind: str,
    human_reviewer_id: str,
    reviewer_pubkey_hex: str,
    reviewer_secret: bytes,
    payout_bps: int,
    created_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> BreakerReceipt:
    """Issue a human-review circuit-breaker receipt (reviewer-signed)."""
    break_id = _check_nonempty_str(break_id, "break_id")
    decision_id = _check_nonempty_str(decision_id, "decision_id")
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    breaker_kind = _check_breaker_kind(breaker_kind)
    human_reviewer_id = _check_nonempty_str(human_reviewer_id, "human_reviewer_id")
    reviewer_pubkey_hex = _check_pubkey_hex(reviewer_pubkey_hex)
    reviewer_secret = _check_secret(reviewer_secret, "reviewer_secret")
    payout_bps = _check_bps(payout_bps, "payout_bps")
    created_at = _check_ts(created_at, "created_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= created_at:
        raise UnderwritingError("expires_at must be after created_at")
    receipt = BreakerReceipt(
        break_id=break_id,
        decision_id=decision_id,
        decision_digest=decision_digest,
        breaker_kind=breaker_kind,
        human_reviewer_id=human_reviewer_id,
        reviewer_pubkey_hex=reviewer_pubkey_hex,
        payout_bps=payout_bps,
        created_at=created_at,
        expires_at=expires_at,
        signature_hex="",
        prev_digest=prev_digest,
    )
    signature_hex = _sign_hex(reviewer_secret, receipt.digest().encode())
    return BreakerReceipt(
        break_id=receipt.break_id,
        decision_id=receipt.decision_id,
        decision_digest=receipt.decision_digest,
        breaker_kind=receipt.breaker_kind,
        human_reviewer_id=receipt.human_reviewer_id,
        reviewer_pubkey_hex=receipt.reviewer_pubkey_hex,
        payout_bps=receipt.payout_bps,
        created_at=receipt.created_at,
        expires_at=receipt.expires_at,
        signature_hex=signature_hex,
        prev_digest=receipt.prev_digest,
    )


def human_circuit_breaker(
    receipt: BreakerReceipt,
    *,
    expected_kind: str,
    decision_digest: str,
    now: int,
) -> BreakerVerdict:
    """Verify a human-review circuit breaker is live and bound.

    Key content (denials, large payouts, underwriting rejections)
    must bind a live, reviewer-signed breaker receipt. Expired,
    future-dated, tampered, or kind-mismatched receipts deny with
    ``underwriting.breaker_*``.
    """
    expected_kind = _check_breaker_kind(expected_kind)
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    now = _check_ts(now, "now")
    break_id = receipt.break_id
    if not _verify_hex_signature(
        receipt.reviewer_pubkey_hex, receipt.signature_hex, receipt.digest().encode()
    ):
        return BreakerVerdict(allowed=False, reason=DENY_BREAKER_TAMPERED, break_id=break_id)
    if receipt.breaker_kind != expected_kind:
        return BreakerVerdict(
            allowed=False, reason=DENY_BREAKER_KIND_MISMATCH, break_id=break_id
        )
    if receipt.created_at > now:
        return BreakerVerdict(allowed=False, reason=DENY_BREAKER_FUTURE, break_id=break_id)
    if receipt.expires_at <= now:
        return BreakerVerdict(allowed=False, reason=DENY_BREAKER_EXPIRED, break_id=break_id)
    if not hmac.compare_digest(receipt.decision_digest, decision_digest):
        return BreakerVerdict(allowed=False, reason=DENY_BREAKER_TAMPERED, break_id=break_id)
    return BreakerVerdict(allowed=True, reason="ok", break_id=break_id)


def breaker_required(breaker_kind: str, *, payout_bps: int) -> bool:
    """Whether key content requires a human-review breaker.

    Denials and underwriting rejections always require one; payouts
    require one at or above ``LARGE_PAYOUT_BPS``.
    """
    breaker_kind = _check_breaker_kind(breaker_kind)
    payout_bps = _check_bps(payout_bps, "payout_bps")
    if breaker_kind in ("claim_denial", "underwriting_rejection"):
        return True
    return payout_bps >= LARGE_PAYOUT_BPS


def breaker_audit_event(verdict: BreakerVerdict, *, expected_kind: str) -> dict[str, Any]:
    """Shape a breaker verdict as an audit event."""
    return {
        "event": BREAKER_ALLOWED_EVENT if verdict.allowed else BREAKER_DENIED_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "break_id": verdict.break_id,
        "expected_kind": expected_kind,
    }


# ---------------------------------------------------------------------------
# Fairness stress-test receipts (templates)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StressReceipt:
    """Fairness stress-test receipt for an underwriting template."""

    template_id: str
    template_digest: str
    stress_test_digest: str
    fairness_threshold_bps: int
    measured_disparity_bps: int
    authority_id: str
    authority_pubkey_hex: str
    tested_at: int
    expires_at: int
    signature_hex: str
    prev_digest: str = _GENESIS

    def digest(self) -> str:
        return _canonical_digest(
            {
                "schema": UNDERWRITING_SCHEMA_VERSION,
                "template_id": self.template_id,
                "template_digest": self.template_digest,
                "stress_test_digest": self.stress_test_digest,
                "fairness_threshold_bps": self.fairness_threshold_bps,
                "measured_disparity_bps": self.measured_disparity_bps,
                "authority_id": self.authority_id,
                "authority_pubkey_hex": self.authority_pubkey_hex,
                "tested_at": self.tested_at,
                "expires_at": self.expires_at,
                "prev_digest": self.prev_digest,
            }
        )


@dataclass(frozen=True)
class StressVerdict:
    """Verdict for a template stress-test check."""

    allowed: bool
    reason: str
    template_id: str


def issue_stress_receipt(
    *,
    template_id: str,
    template_digest: str,
    stress_test_digest: str,
    fairness_threshold_bps: int,
    measured_disparity_bps: int,
    authority_id: str,
    authority_pubkey_hex: str,
    authority_secret: bytes,
    tested_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> StressReceipt:
    """Issue a fairness stress-test receipt (authority-signed)."""
    template_id = _check_nonempty_str(template_id, "template_id")
    template_digest = _check_hex64(template_digest, "template_digest")
    stress_test_digest = _check_hex64(stress_test_digest, "stress_test_digest")
    fairness_threshold_bps = _check_bps(fairness_threshold_bps, "fairness_threshold_bps")
    measured_disparity_bps = _check_bps(measured_disparity_bps, "measured_disparity_bps")
    authority_id = _check_nonempty_str(authority_id, "authority_id")
    authority_pubkey_hex = _check_pubkey_hex(authority_pubkey_hex)
    authority_secret = _check_secret(authority_secret, "authority_secret")
    tested_at = _check_ts(tested_at, "tested_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= tested_at:
        raise UnderwritingError("expires_at must be after tested_at")
    receipt = StressReceipt(
        template_id=template_id,
        template_digest=template_digest,
        stress_test_digest=stress_test_digest,
        fairness_threshold_bps=fairness_threshold_bps,
        measured_disparity_bps=measured_disparity_bps,
        authority_id=authority_id,
        authority_pubkey_hex=authority_pubkey_hex,
        tested_at=tested_at,
        expires_at=expires_at,
        signature_hex="",
        prev_digest=prev_digest,
    )
    signature_hex = _sign_hex(authority_secret, receipt.digest().encode())
    return StressReceipt(
        template_id=receipt.template_id,
        template_digest=receipt.template_digest,
        stress_test_digest=receipt.stress_test_digest,
        fairness_threshold_bps=receipt.fairness_threshold_bps,
        measured_disparity_bps=receipt.measured_disparity_bps,
        authority_id=receipt.authority_id,
        authority_pubkey_hex=receipt.authority_pubkey_hex,
        tested_at=receipt.tested_at,
        expires_at=receipt.expires_at,
        signature_hex=signature_hex,
        prev_digest=receipt.prev_digest,
    )


def fairness_stress_receipt(
    receipt: StressReceipt | None,
    *,
    template_digest: str,
    now: int,
) -> StressVerdict:
    """Verify an underwriting template binds a live stress receipt.

    A template with no receipt denies with
    ``underwriting.untested_template`` (the China 2026-06 guidance
    lesson). A template whose measured disparity exceeds its pinned
    threshold also denies — the threshold is the line, not the
    template's opinion of itself.
    """
    template_digest = _check_hex64(template_digest, "template_digest")
    now = _check_ts(now, "now")
    if receipt is None:
        return StressVerdict(allowed=False, reason=DENY_UNTESTED_TEMPLATE, template_id="?")
    template_id = receipt.template_id
    if not _verify_hex_signature(
        receipt.authority_pubkey_hex, receipt.signature_hex, receipt.digest().encode()
    ):
        return StressVerdict(allowed=False, reason=DENY_STRESS_TAMPERED, template_id=template_id)
    if receipt.tested_at > now:
        return StressVerdict(allowed=False, reason=DENY_STRESS_FUTURE, template_id=template_id)
    if receipt.expires_at <= now:
        return StressVerdict(allowed=False, reason=DENY_STRESS_EXPIRED, template_id=template_id)
    if not hmac.compare_digest(receipt.template_digest, template_digest):
        return StressVerdict(
            allowed=False, reason=DENY_STRESS_TEMPLATE_MISMATCH, template_id=template_id
        )
    if receipt.measured_disparity_bps > receipt.fairness_threshold_bps:
        return StressVerdict(allowed=False, reason=DENY_UNTESTED_TEMPLATE, template_id=template_id)
    return StressVerdict(allowed=True, reason="ok", template_id=template_id)


def stress_audit_event(verdict: StressVerdict) -> dict[str, Any]:
    """Shape a stress verdict as an audit event."""
    return {
        "event": STRESS_ALLOWED_EVENT if verdict.allowed else STRESS_DENIED_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "template_id": verdict.template_id,
    }


# ---------------------------------------------------------------------------
# EU AI Act compliance clock
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClockVerdict:
    """Verdict for the EU AI Act compliance clock."""

    allowed: bool
    reason: str
    deployment_id: str
    pending_obligations: tuple[str, ...] = ()


def ai_act_clock(
    deployment_id: str,
    *,
    deployment_kind: str,
    obligations_met: Mapping[str, bool],
    now: int,
) -> ClockVerdict:
    """Check EU AI Act obligation deadlines for an insurance-AI deployment.

    Pinned deadlines: Art. 50 transparency by 2026-08-02
    (``ART50_TRANSPARENCY_EPOCH``); Annex III high-risk obligations by
    2027-12-02 (``ANNEX3_OBLIGATIONS_EPOCH``, the Omnibus 2026/1744
    deferral). A past-deadline unmet obligation is a compliance
    lapse (``underwriting.compliance_lapse``); future deadlines are
    listed as pending.
    """
    deployment_id = _check_nonempty_str(deployment_id, "deployment_id")
    deployment_kind = _check_nonempty_str(deployment_kind, "deployment_kind")
    now = _check_ts(now, "now")
    deadlines = {
        "art50_transparency": ART50_TRANSPARENCY_EPOCH,
        "annex3_obligations": ANNEX3_OBLIGATIONS_EPOCH,
    }
    for name, met in obligations_met.items():
        if name not in deadlines:
            raise UnderwritingError(
                f"unknown obligation {name!r}; closed set {tuple(deadlines)}"
            )
        if not isinstance(met, bool):
            raise UnderwritingError(f"obligation {name!r} met flag must be a bool")
    lapsed: list[str] = []
    pending: list[str] = []
    for name, deadline in deadlines.items():
        met = obligations_met.get(name, False)
        if met:
            continue
        if now >= deadline:
            lapsed.append(name)
        else:
            pending.append(name)
    if lapsed:
        return ClockVerdict(
            allowed=False,
            reason=DENY_COMPLIANCE_LAPSE,
            deployment_id=deployment_id,
            pending_obligations=tuple(lapsed),
        )
    return ClockVerdict(
        allowed=True,
        reason="ok",
        deployment_id=deployment_id,
        pending_obligations=tuple(pending),
    )


def clock_audit_event(verdict: ClockVerdict, *, deployment_kind: str) -> dict[str, Any]:
    """Shape a clock verdict as an audit event."""
    return {
        "event": CLOCK_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "deployment_id": verdict.deployment_id,
        "deployment_kind": deployment_kind,
        "pending_obligations": list(verdict.pending_obligations),
    }


# ---------------------------------------------------------------------------
# Synthetic fraud probes (route to human, never auto-deny)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FraudProbeVerdict:
    """Verdict for a synthetic fraud-probe routing decision."""

    allowed: bool
    reason: str
    probe_id: str


def synthetic_fraud_probe(probe_id: str, *, routed_action: str) -> FraudProbeVerdict:
    """Route AI-generated fake-claim probes to humans only.

    Fraud probes inform human review; the probe verdict itself may
    never auto-deny — at scale, false positives become a denial
    pipeline. ``deny`` routes hard-deny
    (``underwriting.fraud_auto_deny``); unknown actions raise.
    """
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    if routed_action == "deny":
        return FraudProbeVerdict(
            allowed=False, reason=DENY_FRAUD_AUTO_DENY, probe_id=probe_id
        )
    if routed_action not in ("route_to_human", "flag_for_review"):
        raise UnderwritingError(
            f"unknown fraud-probe action {routed_action!r}; closed vocabulary "
            "('route_to_human', 'flag_for_review')"
        )
    return FraudProbeVerdict(allowed=True, reason="ok", probe_id=probe_id)


def fraud_probe_audit_event(verdict: FraudProbeVerdict, *, routed_action: str) -> dict[str, Any]:
    """Shape a fraud-probe verdict as an audit event."""
    return {
        "event": FRAUD_ALLOWED_EVENT if verdict.allowed else FRAUD_DENIED_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "probe_id": verdict.probe_id,
        "routed_action": routed_action,
    }


# ---------------------------------------------------------------------------
# Assist-not-decide (Aviva line)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreepVerdict:
    """Verdict for the assist-not-decide check."""

    allowed: bool
    reason: str
    system_id: str


def assist_not_decide(system_id: str, *, declared_assistive: bool, decision_made: bool) -> CreepVerdict:
    """An assistive AI that decides has crossed the line.

    A system declared assistive (Aviva's medical-report summaries:
    99.7% self-reported accuracy, explicitly assist-not-decide)
    whose output was used as a decision raises
    ``underwriting.decision_creep``. Systems declared decisive are
    checked elsewhere — this gate pins the *declaration boundary*.
    """
    system_id = _check_nonempty_str(system_id, "system_id")
    if declared_assistive and decision_made:
        return CreepVerdict(allowed=False, reason=DENY_DECISION_CREEP, system_id=system_id)
    return CreepVerdict(allowed=True, reason="ok", system_id=system_id)


def creep_audit_event(verdict: CreepVerdict) -> dict[str, Any]:
    """Shape a decision-creep verdict as an audit event."""
    return {
        "event": CREEP_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "system_id": verdict.system_id,
    }


# ---------------------------------------------------------------------------
# NAIC evaluation-tool mapping (pre-deployment checklist)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MappingVerdict:
    """Verdict for the NAIC evaluation-tool mapping check."""

    allowed: bool
    reason: str
    deployment_id: str
    non_authoritative: bool = False


def evaluation_tool_mapping(
    deployment_id: str,
    *,
    deployment_kind: str,
    mapped_items: Sequence[str],
) -> MappingVerdict:
    """Map an insurance-AI deployment against NAIC review items.

    Every deployment must map to at least one closed-vocabulary
    review item. High-risk kinds (underwriting, claims
    adjudication, pricing) with no mapped items deny
    (``underwriting.unmapped_high_risk``); low-risk uses with no
    items are NON_AUTHORITATIVE. Unknown items raise (an unnamed
    review item is a programming decision).
    """
    deployment_id = _check_nonempty_str(deployment_id, "deployment_id")
    deployment_kind = _check_nonempty_str(deployment_kind, "deployment_kind")
    items = tuple(_check_review_item(i) for i in mapped_items)
    if not items:
        if deployment_kind in HIGH_RISK_UNDERWRITING_KINDS:
            return MappingVerdict(
                allowed=False,
                reason=DENY_UNMAPPED_HIGH_RISK,
                deployment_id=deployment_id,
            )
        return MappingVerdict(
            allowed=True,
            reason=NONAUTH_UNMAPPED_LOW_RISK,
            deployment_id=deployment_id,
            non_authoritative=True,
        )
    return MappingVerdict(allowed=True, reason="ok", deployment_id=deployment_id)


def mapping_audit_event(verdict: MappingVerdict, *, deployment_kind: str) -> dict[str, Any]:
    """Shape a mapping verdict as an audit event."""
    return {
        "event": MAPPING_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "deployment_id": verdict.deployment_id,
        "deployment_kind": deployment_kind,
        "non_authoritative": verdict.non_authoritative,
    }


# ---------------------------------------------------------------------------
# Vendor accuracy claims (bind evidence)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorClaim:
    """A vendor accuracy claim bound to trial evidence."""

    claim_id: str
    vendor_id: str
    metric_name: str
    metric_value_bps: int
    evidence_digest: str
    vendor_pubkey_hex: str
    claimed_at: int
    signature_hex: str
    prev_digest: str = _GENESIS

    def digest(self) -> str:
        return _canonical_digest(
            {
                "schema": UNDERWRITING_SCHEMA_VERSION,
                "claim_id": self.claim_id,
                "vendor_id": self.vendor_id,
                "metric_name": self.metric_name,
                "metric_value_bps": self.metric_value_bps,
                "evidence_digest": self.evidence_digest,
                "vendor_pubkey_hex": self.vendor_pubkey_hex,
                "claimed_at": self.claimed_at,
                "prev_digest": self.prev_digest,
            }
        )


@dataclass(frozen=True)
class VendorVerdict:
    """Verdict for a vendor accuracy-claim check."""

    allowed: bool
    reason: str
    claim_id: str
    non_authoritative: bool = False


def issue_vendor_claim(
    *,
    claim_id: str,
    vendor_id: str,
    metric_name: str,
    metric_value_bps: int,
    evidence_digest: str | None,
    vendor_pubkey_hex: str,
    vendor_secret: bytes,
    claimed_at: int,
    prev_digest: str = _GENESIS,
) -> VendorClaim:
    """Issue a vendor accuracy claim (vendor-signed).

    ``evidence_digest=None`` marks the claim self-reported — the
    vendor signs the admission, and the gate classifies it
    NON_AUTHORITATIVE.
    """
    claim_id = _check_nonempty_str(claim_id, "claim_id")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    metric_name = _check_nonempty_str(metric_name, "metric_name")
    metric_value_bps = _check_bps(metric_value_bps, "metric_value_bps")
    if evidence_digest is not None:
        evidence_digest = _check_hex64(evidence_digest, "evidence_digest")
    vendor_pubkey_hex = _check_pubkey_hex(vendor_pubkey_hex)
    vendor_secret = _check_secret(vendor_secret, "vendor_secret")
    claimed_at = _check_ts(claimed_at, "claimed_at")
    claim = VendorClaim(
        claim_id=claim_id,
        vendor_id=vendor_id,
        metric_name=metric_name,
        metric_value_bps=metric_value_bps,
        evidence_digest=evidence_digest or "",
        vendor_pubkey_hex=vendor_pubkey_hex,
        claimed_at=claimed_at,
        signature_hex="",
        prev_digest=prev_digest,
    )
    signature_hex = _sign_hex(vendor_secret, claim.digest().encode())
    return VendorClaim(
        claim_id=claim.claim_id,
        vendor_id=claim.vendor_id,
        metric_name=claim.metric_name,
        metric_value_bps=claim.metric_value_bps,
        evidence_digest=claim.evidence_digest,
        vendor_pubkey_hex=claim.vendor_pubkey_hex,
        claimed_at=claim.claimed_at,
        signature_hex=signature_hex,
        prev_digest=claim.prev_digest,
    )


def vendor_disclosure_gate(claim: VendorClaim, *, now: int) -> VendorVerdict:
    """Verify a vendor accuracy claim binds trial evidence.

    "99.7% accuracy", "<2% hallucination", "-80% triage time" —
    vendor/PR, unaudited until bound to an evidence digest.
    Self-reported claims (no evidence digest) are
    NON_AUTHORITATIVE; tampered or future-dated claims deny.
    """
    now = _check_ts(now, "now")
    claim_id = claim.claim_id
    if not _verify_hex_signature(
        claim.vendor_pubkey_hex, claim.signature_hex, claim.digest().encode()
    ):
        return VendorVerdict(allowed=False, reason=DENY_VENDOR_TAMPERED, claim_id=claim_id)
    if claim.claimed_at > now:
        return VendorVerdict(allowed=False, reason=DENY_VENDOR_FUTURE, claim_id=claim_id)
    if not claim.evidence_digest:
        return VendorVerdict(
            allowed=True,
            reason=NONAUTH_VENDER_NO_EVIDENCE,
            claim_id=claim_id,
            non_authoritative=True,
        )
    return VendorVerdict(allowed=True, reason="ok", claim_id=claim_id)


def vendor_audit_event(verdict: VendorVerdict) -> dict[str, Any]:
    """Shape a vendor verdict as an audit event."""
    return {
        "event": VENDOR_EVENT,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "claim_id": verdict.claim_id,
        "non_authoritative": verdict.non_authoritative,
    }


__all__ = [
    "UNDERWRITING_SCHEMA_VERSION",
    "CLAIM_ENGINE_ACTIONS",
    "BREAKER_KINDS",
    "NAIC_REVIEW_ITEMS",
    "HIGH_RISK_UNDERWRITING_KINDS",
    "LARGE_PAYOUT_BPS",
    "ART50_TRANSPARENCY_EPOCH",
    "ANNEX3_OBLIGATIONS_EPOCH",
    "DENY_AI_DENIAL",
    "DENY_UNKNOWN_ACTION",
    "DENY_BREAKER_MISSING",
    "DENY_BREAKER_TAMPERED",
    "DENY_BREAKER_EXPIRED",
    "DENY_BREAKER_FUTURE",
    "DENY_BREAKER_KIND_MISMATCH",
    "DENY_UNTESTED_TEMPLATE",
    "DENY_STRESS_TAMPERED",
    "DENY_STRESS_EXPIRED",
    "DENY_STRESS_FUTURE",
    "DENY_STRESS_TEMPLATE_MISMATCH",
    "DENY_COMPLIANCE_LAPSE",
    "DENY_CLOCK_UNKNOWN_KIND",
    "DENY_FRAUD_AUTO_DENY",
    "DENY_FRAUD_UNKNOWN_ACTION",
    "DENY_DECISION_CREEP",
    "DENY_UNMAPPED_HIGH_RISK",
    "DENY_ITEM_UNKNOWN",
    "DENY_VENDOR_SELF_REPORTED",
    "DENY_VENDOR_TAMPERED",
    "DENY_VENDOR_FUTURE",
    "DENY_MALFORMED",
    "NONAUTH_VENDER_NO_EVIDENCE",
    "NONAUTH_UNMAPPED_LOW_RISK",
    "UnderwritingError",
    "EngineVerdict",
    "approve_only_engine",
    "engine_audit_event",
    "BreakerReceipt",
    "BreakerVerdict",
    "issue_breaker_receipt",
    "human_circuit_breaker",
    "breaker_required",
    "breaker_audit_event",
    "StressReceipt",
    "StressVerdict",
    "issue_stress_receipt",
    "fairness_stress_receipt",
    "stress_audit_event",
    "ClockVerdict",
    "ai_act_clock",
    "clock_audit_event",
    "FraudProbeVerdict",
    "synthetic_fraud_probe",
    "fraud_probe_audit_event",
    "CreepVerdict",
    "assist_not_decide",
    "creep_audit_event",
    "MappingVerdict",
    "evaluation_tool_mapping",
    "mapping_audit_event",
    "VendorClaim",
    "VendorVerdict",
    "issue_vendor_claim",
    "vendor_disclosure_gate",
    "vendor_audit_event",
]
