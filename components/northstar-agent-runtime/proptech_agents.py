"""Real-estate & proptech AI discipline gates (one-hundred-fifty-ninth batch).

Absorbs the 2026 proptech thread:

* **SafeRent** (Louis v. SafeRent, D. Mass.): $2.28-2.3M class
  settlement — for 5 years SafeRent shows no screening score and no
  accept/decline recommendation for housing-voucher applicants;
  landlords must certify applicant status before a score is shown.
  Screening tools can create FHA liability independent of landlord
  intent.
* **HUD**: May-2024 dual guidance (six screening principles +
  anti-discriminatory ad delivery); April-2026 withdrawal of the ad
  guidance; disparate-impact rule (24 CFR 100.500) comment window
  closes 2026-10-09. Practitioner rule: never let AI decide the
  specific applicant.
* **DOJ v. RealPage** (M.D.N.C.): settlement bars real-time
  nonpublic competitor data; pricing algorithms may train only on
  >=1-year-old data. Landlord settlements 2026: LivCor (Blackstone)
  $7M, Willow Bridge, Pinnacle — no fault admitted, all must stop
  algorithmic coordination.
* **NY algorithmic-rent ban** (Oct 2025): preliminarily enjoined
  Sept 2026 (Judge Caproni, First Amendment grounds) — the law is
  mid-flight.
* **BGH I ZR 129/25** (Jan 2026): the broker is the "Nadeloehr"
  (bottleneck) between tenants and landlords and is liable for
  discrimination damages — the human intermediary is the liability
  anchor for AI-assisted selection.
* **Dubai DLD**: Smart Rental Index as a public reference benchmark.
* **Colorado AI Act**: delayed to 2027-01-01 with
  anti-algorithmic-discrimination duties stripped.
* **Maryland Fair Chance Housing Act** (effective 2026-10-01):
  individualized assessment over blanket criminal-history bans.

Fail-closed gates over registries of signed receipts:

1. Voucher applicants are score-silent: no scores or accept/decline
   recommendations may be shown for voucher recipients.
2. Screening models bind current disparate-impact audits; a finding
   withdraws the model.
3. Every denial binds an adverse-action receipt: specific reasons
   (ECOA-style, "model output" is not a reason), report copy, and a
   challenge channel.
4. Screening criteria are published *before* any application;
   per-applicant deviation fails closed.
5. Pricing models train only on >=1-year-old data; real-time
   competitor data is a collusion input and fails closed.
6. Competitor nonpublic data in pricing inputs triggers an
   antitrust review gate, never an automated pass.
7. Deployments pin the local rent-law jurisdiction matrix digest;
   a mismatch refuses to operate.
8. AI may draft criteria and adverse-action templates but never
   decides a specific applicant.
9. Housing-ad delivery is audited for discriminatory skew; skew
   halts the campaign.
10. Every transaction binds a human broker liability anchor
    (BGH Nadeloehr) — liability is non-delegable and registered.
11. AVM outputs below the confidence floor are
    NON_AUTHORITATIVE; autonomous pricing on them is refused.
12. High-opacity markets must reference a public benchmark;
    deviation beyond tolerance without justification fails closed.

Honest scoping: receipts bind *declared* proptech discipline —
digests recompute, signatures verify, chains link. They do not end
housing discrimination or fix rent markets, and they cannot prove
the human understood what they signed.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th-batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`. Signature verification honors the
boolean return of ``ed25519.verify`` (which never raises).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()

try:
    import ed25519
except Exception:  # pragma: no cover - vendored module is always present
    ed25519 = None  # type: ignore[assignment]


PROPTECH_SCHEMA_VERSION = "northstar.proptech.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_DAY_S = 86_400
_YEAR_S = 365 * _DAY_S

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Receipt shelf lives.
RECEIPT_MAX_AGE_S = 365 * _DAY_S

#: DOJ-RealPage settlement rule generalized: pricing models may only
#: train on competitor data at least this old.
PRICING_DATA_MIN_AGE_S = _YEAR_S

#: AVM confidence floor (HouseCanary/ATTOM lesson: valuations ship
#: with confidence intervals; below this a human valuer is required).
VALUATION_CONFIDENCE_FLOOR = 0.70

#: Public-benchmark deviation tolerance (basis points). Beyond this,
#: a documented justification digest is required.
BENCHMARK_DEVIATION_TOL_BPS = 1_000

#: Decision roles: AI may draft, never decide a specific applicant.
DECIDER_AI = "ai"
DECIDER_HUMAN = "human"

#: Screening recommendation vocabulary.
RECOMMENDATIONS = frozenset({
    "accept",
    "decline",
    "conditional",
    "no_recommendation",
})

#: Vague denial reasons that fail the specific-and-understandable
#: test (ECOA lesson carried into rentals; "model output" is not a
#: reason).
VAGUE_REASONS = frozenset({
    "model output",
    "ai score",
    "algorithmic score",
    "risk score",
    "screening score",
    "background check",
})


class ProptechError(ValueError):
    """A malformed proptech-discipline receipt or a programming error.

    Raised for structural problems (bad digests, unknown registries,
    broken chains). Verification *failures* (voucher score shown, AI
    deciding an applicant, stale pricing data, disparate impact)
    return a :class:`ProptechVerdict` with ``allowed=False`` instead —
    a failed gate is a verdict, a malformed receipt is a bug.
    """


# ---------------------------------------------------------------------------
# Field checks
# ---------------------------------------------------------------------------


def _is_hex(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _check_hex64(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ProptechError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProptechError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProptechError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise ProptechError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProptechError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise ProptechError(f"{field_name} must be within [0, 1]")
    return float(value)


def _check_nonneg_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProptechError(f"{field_name} must be a non-negative int")
    return value


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    # The vendored ed25519.verify() returns a bool and never raises;
    # the return value must be honored (the old try/except-around-verify
    # pattern silently approved everything — the 147th-batch finding).
    try:
        return bool(
            ed25519.verify(
                bytes.fromhex(pubkey_hex),
                jcs_canonical_json(payload),
                bytes.fromhex(signature_hex),
            )
        )
    except Exception:
        return False


def _check_chain(log: list[Any], type_name: str) -> None:
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise ProptechError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise ProptechError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise ProptechError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class ProptechVerdict:
    """Outcome of one proptech-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> ProptechVerdict:
    return ProptechVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> ProptechVerdict:
    return ProptechVerdict(
        allowed=True,
        reason=detail,
        classification=CLASS_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


# ---------------------------------------------------------------------------
# Authority registry (shared lookup for signed receipts)
# ---------------------------------------------------------------------------


@dataclass
class AuthorityRegistry:
    """Maps authority ids to Ed25519 public keys (hex)."""

    _pubkeys: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self._pubkeys = {}

    def register(self, authority_id: str, pubkey_hex: str) -> None:
        _check_nonempty_str(authority_id, "authority_id")
        _check_pubkey_hex(pubkey_hex)
        self._pubkeys[authority_id] = pubkey_hex

    def pubkey(self, authority_id: str) -> str | None:
        return self._pubkeys.get(authority_id)


def _new_log(registry: Any) -> str:
    return registry.log[-1].receipt_digest if registry.log else _GENESIS


def _sealed_payload(payload: dict[str, Any], authority_secret: bytes) -> tuple[str, str]:
    """Sign ``payload``; returns (authority_pubkey_hex, signature_hex)."""
    if ed25519 is None:  # pragma: no cover
        raise ProptechError("vendored ed25519 module unavailable")
    sig_body = dict(payload)
    sig_body["signature_hex"] = "00" * 64
    signature = ed25519.sign(authority_secret, jcs_canonical_json(sig_body))
    return ed25519.public_key(authority_secret).hex(), signature.hex()


# ---------------------------------------------------------------------------
# 1. Screening criteria pins (HUD six principles: publish before applying)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreeningCriteriaReceipt:
    """Written screening criteria published *before* applications."""

    receipt_id: str
    owner_id: str
    criteria_digest: str
    published_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "screening_criteria",
            "receipt_id": self.receipt_id,
            "owner_id": self.owner_id,
            "criteria_digest": self.criteria_digest,
            "published_at": self.published_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ScreeningCriteriaRegistry:
    """Hash-chained log of screening-criteria pins."""

    authorities: AuthorityRegistry
    log: list[ScreeningCriteriaReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        owner_id: str,
        criteria_digest: str,
        published_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> ScreeningCriteriaReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(owner_id, "owner_id")
        _check_hex64(criteria_digest, "criteria_digest")
        _check_ts(published_at, "published_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "screening_criteria",
            "receipt_id": receipt_id,
            "owner_id": owner_id,
            "criteria_digest": criteria_digest,
            "published_at": published_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = ScreeningCriteriaReceipt(
            receipt_id=receipt_id,
            owner_id=owner_id,
            criteria_digest=criteria_digest,
            published_at=published_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "screening_criteria")
        return receipt

    def get(self, receipt_id: str) -> ScreeningCriteriaReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 2. Screening decisions (SafeRent lesson: voucher applicants go scoreless)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreeningDecisionReceipt:
    """One applicant screening decision."""

    receipt_id: str
    applicant_id: str
    voucher_recipient: bool
    score_shown: bool
    recommendation: str
    decider: str
    criteria_receipt_id: str
    decided_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "screening_decision",
            "receipt_id": self.receipt_id,
            "applicant_id": self.applicant_id,
            "voucher_recipient": self.voucher_recipient,
            "score_shown": self.score_shown,
            "recommendation": self.recommendation,
            "decider": self.decider,
            "criteria_receipt_id": self.criteria_receipt_id,
            "decided_at": self.decided_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ScreeningDecisionRegistry:
    """Hash-chained log of screening decisions."""

    authorities: AuthorityRegistry
    log: list[ScreeningDecisionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        applicant_id: str,
        voucher_recipient: bool,
        score_shown: bool,
        recommendation: str,
        decider: str,
        criteria_receipt_id: str,
        decided_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> ScreeningDecisionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(applicant_id, "applicant_id")
        if not isinstance(voucher_recipient, bool):
            raise ProptechError("voucher_recipient must be a bool")
        if not isinstance(score_shown, bool):
            raise ProptechError("score_shown must be a bool")
        _check_nonempty_str(recommendation, "recommendation")
        if recommendation not in RECOMMENDATIONS:
            raise ProptechError(f"recommendation must be one of {sorted(RECOMMENDATIONS)}")
        if decider not in (DECIDER_AI, DECIDER_HUMAN):
            raise ProptechError("decider must be 'ai' or 'human'")
        _check_nonempty_str(criteria_receipt_id, "criteria_receipt_id")
        _check_ts(decided_at, "decided_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "screening_decision",
            "receipt_id": receipt_id,
            "applicant_id": applicant_id,
            "voucher_recipient": voucher_recipient,
            "score_shown": score_shown,
            "recommendation": recommendation,
            "decider": decider,
            "criteria_receipt_id": criteria_receipt_id,
            "decided_at": decided_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = ScreeningDecisionReceipt(
            receipt_id=receipt_id,
            applicant_id=applicant_id,
            voucher_recipient=voucher_recipient,
            score_shown=score_shown,
            recommendation=recommendation,
            decider=decider,
            criteria_receipt_id=criteria_receipt_id,
            decided_at=decided_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "screening_decision")
        return receipt

    def get(self, receipt_id: str) -> ScreeningDecisionReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 3. Adverse-action receipts (ECOA-style: specific reasons, report, appeal)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdverseActionReceipt:
    """Binds a rental denial: specific reasons, report copy, challenge."""

    receipt_id: str
    applicant_id: str
    decision_receipt_id: str
    reasons: tuple[str, ...]
    report_copy_digest: str
    challenge_channel: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "adverse_action",
            "receipt_id": self.receipt_id,
            "applicant_id": self.applicant_id,
            "decision_receipt_id": self.decision_receipt_id,
            "reasons": list(self.reasons),
            "report_copy_digest": self.report_copy_digest,
            "challenge_channel": self.challenge_channel,
            "issued_at": self.issued_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class AdverseActionRegistry:
    """Hash-chained log of adverse-action receipts."""

    authorities: AuthorityRegistry
    log: list[AdverseActionReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        applicant_id: str,
        decision_receipt_id: str,
        reasons: list[str],
        report_copy_digest: str,
        challenge_channel: str,
        issued_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> AdverseActionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(applicant_id, "applicant_id")
        _check_nonempty_str(decision_receipt_id, "decision_receipt_id")
        if not reasons or not all(isinstance(r, str) and r.strip() for r in reasons):
            raise ProptechError("reasons must be a non-empty list of non-empty strings")
        _check_hex64(report_copy_digest, "report_copy_digest")
        _check_nonempty_str(challenge_channel, "challenge_channel")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "adverse_action",
            "receipt_id": receipt_id,
            "applicant_id": applicant_id,
            "decision_receipt_id": decision_receipt_id,
            "reasons": reasons,
            "report_copy_digest": report_copy_digest,
            "challenge_channel": challenge_channel,
            "issued_at": issued_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = AdverseActionReceipt(
            receipt_id=receipt_id,
            applicant_id=applicant_id,
            decision_receipt_id=decision_receipt_id,
            reasons=tuple(reasons),
            report_copy_digest=report_copy_digest,
            challenge_channel=challenge_channel,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "adverse_action")
        return receipt

    def get(self, receipt_id: str) -> AdverseActionReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 4. Disparate-impact audit receipts (HUD disparate-impact discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisparateImpactAuditReceipt:
    """A disparate-impact audit of a screening model."""

    receipt_id: str
    model_id: str
    selection_rate_ratio: float
    impact_found: bool
    audited_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "disparate_impact_audit",
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "selection_rate_ratio": self.selection_rate_ratio,
            "impact_found": self.impact_found,
            "audited_at": self.audited_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class DisparateImpactAuditRegistry:
    """Hash-chained log of disparate-impact audits."""

    authorities: AuthorityRegistry
    log: list[DisparateImpactAuditReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        model_id: str,
        selection_rate_ratio: float,
        impact_found: bool,
        audited_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> DisparateImpactAuditReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(model_id, "model_id")
        _check_ratio(selection_rate_ratio, "selection_rate_ratio")
        if not isinstance(impact_found, bool):
            raise ProptechError("impact_found must be a bool")
        _check_ts(audited_at, "audited_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "disparate_impact_audit",
            "receipt_id": receipt_id,
            "model_id": model_id,
            "selection_rate_ratio": selection_rate_ratio,
            "impact_found": impact_found,
            "audited_at": audited_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = DisparateImpactAuditReceipt(
            receipt_id=receipt_id,
            model_id=model_id,
            selection_rate_ratio=selection_rate_ratio,
            impact_found=impact_found,
            audited_at=audited_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "disparate_impact_audit")
        return receipt

    def latest_for(self, model_id: str) -> DisparateImpactAuditReceipt | None:
        for r in reversed(self.log):
            if r.model_id == model_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 5. Pricing-data firewall (DOJ-RealPage: >=1-year-old data only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PricingDataReceipt:
    """Binds a pricing model's training-data freshness declaration."""

    receipt_id: str
    model_id: str
    data_cutoff_epoch: int
    contains_competitor_nonpublic: bool
    competitor_data_freshest_at: int  # 0 = no competitor data
    pinned_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "pricing_data",
            "receipt_id": self.receipt_id,
            "model_id": self.model_id,
            "data_cutoff_epoch": self.data_cutoff_epoch,
            "contains_competitor_nonpublic": self.contains_competitor_nonpublic,
            "competitor_data_freshest_at": self.competitor_data_freshest_at,
            "pinned_at": self.pinned_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class PricingDataRegistry:
    """Hash-chained log of pricing-data declarations."""

    authorities: AuthorityRegistry
    log: list[PricingDataReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        model_id: str,
        data_cutoff_epoch: int,
        contains_competitor_nonpublic: bool,
        competitor_data_freshest_at: int,
        pinned_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> PricingDataReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(model_id, "model_id")
        _check_ts(data_cutoff_epoch, "data_cutoff_epoch")
        if not isinstance(contains_competitor_nonpublic, bool):
            raise ProptechError("contains_competitor_nonpublic must be a bool")
        _check_ts(competitor_data_freshest_at, "competitor_data_freshest_at")
        _check_ts(pinned_at, "pinned_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "pricing_data",
            "receipt_id": receipt_id,
            "model_id": model_id,
            "data_cutoff_epoch": data_cutoff_epoch,
            "contains_competitor_nonpublic": contains_competitor_nonpublic,
            "competitor_data_freshest_at": competitor_data_freshest_at,
            "pinned_at": pinned_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = PricingDataReceipt(
            receipt_id=receipt_id,
            model_id=model_id,
            data_cutoff_epoch=data_cutoff_epoch,
            contains_competitor_nonpublic=contains_competitor_nonpublic,
            competitor_data_freshest_at=competitor_data_freshest_at,
            pinned_at=pinned_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "pricing_data")
        return receipt

    def latest_for(self, model_id: str) -> PricingDataReceipt | None:
        for r in reversed(self.log):
            if r.model_id == model_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 6. Rent-jurisdiction matrix pins (NY ban, Colorado delay, MD Fair Chance)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RentJurisdictionPin:
    """A pinned digest of the algorithmic-rent rules for one jurisdiction."""

    receipt_id: str
    jurisdiction_id: str
    law_digest: str
    algorithmic_pricing_banned: bool
    pinned_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "rent_jurisdiction_pin",
            "receipt_id": self.receipt_id,
            "jurisdiction_id": self.jurisdiction_id,
            "law_digest": self.law_digest,
            "algorithmic_pricing_banned": self.algorithmic_pricing_banned,
            "pinned_at": self.pinned_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class RentJurisdictionRegistry:
    """Hash-chained log of jurisdiction matrix pins."""

    authorities: AuthorityRegistry
    log: list[RentJurisdictionPin]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        jurisdiction_id: str,
        law_digest: str,
        algorithmic_pricing_banned: bool,
        pinned_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> RentJurisdictionPin:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(jurisdiction_id, "jurisdiction_id")
        _check_hex64(law_digest, "law_digest")
        if not isinstance(algorithmic_pricing_banned, bool):
            raise ProptechError("algorithmic_pricing_banned must be a bool")
        _check_ts(pinned_at, "pinned_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "rent_jurisdiction_pin",
            "receipt_id": receipt_id,
            "jurisdiction_id": jurisdiction_id,
            "law_digest": law_digest,
            "algorithmic_pricing_banned": algorithmic_pricing_banned,
            "pinned_at": pinned_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = RentJurisdictionPin(
            receipt_id=receipt_id,
            jurisdiction_id=jurisdiction_id,
            law_digest=law_digest,
            algorithmic_pricing_banned=algorithmic_pricing_banned,
            pinned_at=pinned_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "rent_jurisdiction_pin")
        return receipt

    def latest_for(self, jurisdiction_id: str) -> RentJurisdictionPin | None:
        for r in reversed(self.log):
            if r.jurisdiction_id == jurisdiction_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 7. Broker liability pins (BGH Nadeloehr: the human anchor is registered)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BrokerLiabilityPin:
    """A registered non-delegable liability anchor for one transaction."""

    receipt_id: str
    transaction_id: str
    broker_id: str
    broker_pubkey_hex: str
    pinned_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "broker_liability_pin",
            "receipt_id": self.receipt_id,
            "transaction_id": self.transaction_id,
            "broker_id": self.broker_id,
            "broker_pubkey_hex": self.broker_pubkey_hex,
            "pinned_at": self.pinned_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class BrokerLiabilityRegistry:
    """Hash-chained log of broker liability pins."""

    authorities: AuthorityRegistry
    log: list[BrokerLiabilityPin]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        transaction_id: str,
        broker_id: str,
        broker_pubkey_hex: str,
        pinned_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> BrokerLiabilityPin:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(transaction_id, "transaction_id")
        _check_nonempty_str(broker_id, "broker_id")
        _check_pubkey_hex(broker_pubkey_hex)
        _check_ts(pinned_at, "pinned_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "broker_liability_pin",
            "receipt_id": receipt_id,
            "transaction_id": transaction_id,
            "broker_id": broker_id,
            "broker_pubkey_hex": broker_pubkey_hex,
            "pinned_at": pinned_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = BrokerLiabilityPin(
            receipt_id=receipt_id,
            transaction_id=transaction_id,
            broker_id=broker_id,
            broker_pubkey_hex=broker_pubkey_hex,
            pinned_at=pinned_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "broker_liability_pin")
        return receipt

    def latest_for(self, transaction_id: str) -> BrokerLiabilityPin | None:
        for r in reversed(self.log):
            if r.transaction_id == transaction_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 8. Valuation receipts (AVMs with confidence intervals)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValuationReceipt:
    """An automated valuation with a declared confidence level."""

    receipt_id: str
    property_id: str
    value_minor: int
    confidence: float
    valuer: str
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "valuation",
            "receipt_id": self.receipt_id,
            "property_id": self.property_id,
            "value_minor": self.value_minor,
            "confidence": self.confidence,
            "valuer": self.valuer,
            "issued_at": self.issued_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class ValuationRegistry:
    """Hash-chained log of valuation receipts."""

    authorities: AuthorityRegistry
    log: list[ValuationReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        property_id: str,
        value_minor: int,
        confidence: float,
        valuer: str,
        issued_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> ValuationReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(property_id, "property_id")
        _check_nonneg_int(value_minor, "value_minor")
        _check_ratio(confidence, "confidence")
        if valuer not in (DECIDER_AI, DECIDER_HUMAN):
            raise ProptechError("valuer must be 'ai' or 'human'")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "valuation",
            "receipt_id": receipt_id,
            "property_id": property_id,
            "value_minor": value_minor,
            "confidence": confidence,
            "valuer": valuer,
            "issued_at": issued_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = ValuationReceipt(
            receipt_id=receipt_id,
            property_id=property_id,
            value_minor=value_minor,
            confidence=confidence,
            valuer=valuer,
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "valuation")
        return receipt

    def get(self, receipt_id: str) -> ValuationReceipt | None:
        for r in self.log:
            if r.receipt_id == receipt_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 9. Public benchmark references (Dubai DLD lesson)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkReferenceReceipt:
    """A deployment's binding to a public rental/price benchmark."""

    receipt_id: str
    market_id: str
    benchmark_digest: str
    benchmark_source: str
    deviation_bps: int
    justification_digest: str  # _HEX64 zeros when within tolerance
    referenced_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "benchmark_reference",
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "benchmark_digest": self.benchmark_digest,
            "benchmark_source": self.benchmark_source,
            "deviation_bps": self.deviation_bps,
            "justification_digest": self.justification_digest,
            "referenced_at": self.referenced_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class BenchmarkReferenceRegistry:
    """Hash-chained log of benchmark references."""

    authorities: AuthorityRegistry
    log: list[BenchmarkReferenceReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        market_id: str,
        benchmark_digest: str,
        benchmark_source: str,
        deviation_bps: int,
        justification_digest: str,
        referenced_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> BenchmarkReferenceReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(market_id, "market_id")
        _check_hex64(benchmark_digest, "benchmark_digest")
        _check_nonempty_str(benchmark_source, "benchmark_source")
        _check_nonneg_int(deviation_bps, "deviation_bps")
        _check_hex64(justification_digest, "justification_digest")
        _check_ts(referenced_at, "referenced_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "benchmark_reference",
            "receipt_id": receipt_id,
            "market_id": market_id,
            "benchmark_digest": benchmark_digest,
            "benchmark_source": benchmark_source,
            "deviation_bps": deviation_bps,
            "justification_digest": justification_digest,
            "referenced_at": referenced_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = BenchmarkReferenceReceipt(
            receipt_id=receipt_id,
            market_id=market_id,
            benchmark_digest=benchmark_digest,
            benchmark_source=benchmark_source,
            deviation_bps=deviation_bps,
            justification_digest=justification_digest,
            referenced_at=referenced_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "benchmark_reference")
        return receipt

    def latest_for(self, market_id: str) -> BenchmarkReferenceReceipt | None:
        for r in reversed(self.log):
            if r.market_id == market_id:
                return r
        return None


# ---------------------------------------------------------------------------
# 10. Housing-ad delivery audits (2024 HUD ad-guidance discipline)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdDeliveryAuditReceipt:
    """An audit of a housing ad's actual delivery composition."""

    receipt_id: str
    campaign_id: str
    audience_composition_digest: str
    skew_detected: bool
    audited_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str
    receipt_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "ad_delivery_audit",
            "receipt_id": self.receipt_id,
            "campaign_id": self.campaign_id,
            "audience_composition_digest": self.audience_composition_digest,
            "skew_detected": self.skew_detected,
            "audited_at": self.audited_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "prev_digest": self.prev_digest,
        }


@dataclass
class AdDeliveryAuditRegistry:
    """Hash-chained log of housing-ad delivery audits."""

    authorities: AuthorityRegistry
    log: list[AdDeliveryAuditReceipt]

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self.authorities = authorities
        self.log = []

    def issue(
        self,
        receipt_id: str,
        campaign_id: str,
        audience_composition_digest: str,
        skew_detected: bool,
        audited_at: int,
        authority_id: str,
        authority_secret: bytes
    ) -> AdDeliveryAuditReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(campaign_id, "campaign_id")
        _check_hex64(audience_composition_digest, "audience_composition_digest")
        if not isinstance(skew_detected, bool):
            raise ProptechError("skew_detected must be a bool")
        _check_ts(audited_at, "audited_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise ProptechError(f"unknown authority {authority_id!r}")
        prev = _new_log(self)
        payload = {
            "schema": PROPTECH_SCHEMA_VERSION,
            "type": "ad_delivery_audit",
            "receipt_id": receipt_id,
            "campaign_id": campaign_id,
            "audience_composition_digest": audience_composition_digest,
            "skew_detected": skew_detected,
            "audited_at": audited_at,
            "authority_id": authority_id,
            "authority_pubkey_hex": pubkey,
            "prev_digest": prev,
        }
        _, signature_hex = _sealed_payload(payload, authority_secret)
        receipt = AdDeliveryAuditReceipt(
            receipt_id=receipt_id,
            campaign_id=campaign_id,
            audience_composition_digest=audience_composition_digest,
            skew_detected=skew_detected,
            audited_at=audited_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature_hex,
            prev_digest=prev,
            receipt_digest=jcs_sha256_hex(payload),
        )
        self.log.append(receipt)
        _check_chain(self.log, "ad_delivery_audit")
        return receipt

    def latest_for(self, campaign_id: str) -> AdDeliveryAuditReceipt | None:
        for r in reversed(self.log):
            if r.campaign_id == campaign_id:
                return r
        return None


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def screening_score_silencing(
    decisions: ScreeningDecisionRegistry,
    receipt_id: str,
) -> ProptechVerdict:
    """Voucher applicants are score-silent (SafeRent settlement lesson).

    If a decision was made on a voucher recipient and a score was
    shown or a non-``no_recommendation`` recommendation was issued,
    the gate fails closed: ``proptech:voucher_score_shown``.
    """
    decision = decisions.get(receipt_id)
    if decision is None:
        return _deny(
            "proptech:no_screening_decision",
            f"screening decision {receipt_id!r} not found",
        )
    if not decision.voucher_recipient:
        return _allow(
            f"applicant {decision.applicant_id!r} is not a voucher recipient; "
            "score-silencing does not apply",
            decision.receipt_digest,
        )
    if decision.score_shown:
        return _deny(
            "proptech:voucher_score_shown",
            f"a score was shown for voucher applicant {decision.applicant_id!r} "
            "(SafeRent: no scores for voucher applicants)",
        )
    if decision.recommendation != "no_recommendation":
        return _deny(
            "proptech:voucher_score_shown",
            f"a {decision.recommendation!r} recommendation was issued for voucher "
            f"applicant {decision.applicant_id!r} (SafeRent: no recommendations)",
        )
    return _allow(
        f"voucher applicant {decision.applicant_id!r} received no score and no "
        "recommendation",
        decision.receipt_digest,
    )


def screening_criteria_pin(
    criteria: ScreeningCriteriaRegistry,
    decisions: ScreeningDecisionRegistry,
    receipt_id: str,
) -> ProptechVerdict:
    """Criteria must be published before the decision (HUD lesson).

    A decision bound to a criteria receipt that was published *after*
    the decision — or to no criteria at all — is
    ``proptech.unpinned_criteria``.
    """
    decision = decisions.get(receipt_id)
    if decision is None:
        return _deny(
            "proptech:no_screening_decision",
            f"screening decision {receipt_id!r} not found",
        )
    pin = criteria.get(decision.criteria_receipt_id)
    if pin is None:
        return _deny(
            "proptech.unpinned_criteria",
            f"decision {receipt_id!r} binds no published screening criteria",
        )
    if pin.published_at > decision.decided_at:
        return _deny(
            "proptech.unpinned_criteria",
            f"criteria {pin.receipt_id!r} were published after decision "
            f"{receipt_id!r} (criteria must pre-date the application)",
        )
    return _allow(
        f"decision {receipt_id!r} applied criteria {pin.receipt_id!r} published "
        "before the application",
        decision.receipt_digest,
    )


def human_final_gate_screening(
    decisions: ScreeningDecisionRegistry,
    receipt_id: str,
) -> ProptechVerdict:
    """AI drafts criteria; a specific applicant's decision is human
    (HUD practitioner lesson: never let AI decide the applicant).

    An AI-issued recommendation other than ``no_recommendation`` is
    ``proptech:ai_specific_decision``.
    """
    decision = decisions.get(receipt_id)
    if decision is None:
        return _deny(
            "proptech:no_screening_decision",
            f"screening decision {receipt_id!r} not found",
        )
    if decision.decider == DECIDER_AI and decision.recommendation != "no_recommendation":
        return _deny(
            "proptech:ai_specific_decision",
            f"AI issued a {decision.recommendation!r} recommendation for specific "
            f"applicant {decision.applicant_id!r} — AI may draft criteria, never "
            "decide the applicant",
        )
    return _allow(
        f"decision {receipt_id!r} on {decision.applicant_id!r} is human-final",
        decision.receipt_digest,
    )


def adverse_action_receipt(
    adverse_actions: AdverseActionRegistry,
    decisions: ScreeningDecisionRegistry,
    receipt_id: str,
) -> ProptechVerdict:
    """Denials bind specific, understandable reasons plus a report copy
    and a challenge channel (HUD six-principle lesson).

    Vague reasons ("model output", "ai score", ...) are
    ``proptech:vague_adverse_reason``; a denial without a bound
    adverse-action receipt is ``proptech:no_adverse_action``.
    """
    decision = decisions.get(receipt_id)
    if decision is None:
        return _deny(
            "proptech:no_screening_decision",
            f"screening decision {receipt_id!r} not found",
        )
    if decision.recommendation != "decline":
        return _allow(
            f"decision {receipt_id!r} is not a denial; no adverse-action "
            "receipt required",
            decision.receipt_digest,
        )
    action = None
    for r in adverse_actions.log:
        if r.decision_receipt_id == receipt_id:
            action = r
            break
    if action is None:
        return _deny(
            "proptech:no_adverse_action",
            f"denial {receipt_id!r} binds no adverse-action receipt "
            "(specific reasons + report copy + challenge channel required)",
        )
    vague = [r for r in action.reasons if r.strip().lower() in VAGUE_REASONS]
    if vague:
        return _deny(
            "proptech:vague_adverse_reason",
            f"denial {receipt_id!r} cites vague reason(s) {vague!r} — "
            "'model output' is not a specific reason",
        )
    return _allow(
        f"denial {receipt_id!r} binds adverse-action receipt {action.receipt_id!r} "
        f"with specific reasons and challenge channel {action.challenge_channel!r}",
        action.receipt_digest,
    )


def disparate_impact_audit_receipt(
    audits: DisparateImpactAuditRegistry,
    model_id: str,
    checked_at: int,
) -> ProptechVerdict:
    """Screening models bind current disparate-impact audits.

    A model whose latest audit found disparate impact is withdrawn:
    ``proptech:disparate_impact``. No current audit is
    ``proptech:no_impact_audit``. The HUD disparate-impact comment
    clock (2026-10-09) is tracked as context on the audit shelf life.
    """
    _check_ts(checked_at, "checked_at")
    audit = audits.latest_for(model_id)
    if audit is None:
        return _deny(
            "proptech:no_impact_audit",
            f"screening model {model_id!r} has no disparate-impact audit receipt",
        )
    if checked_at - audit.audited_at > RECEIPT_MAX_AGE_S:
        return _deny(
            "proptech:no_impact_audit",
            f"disparate-impact audit for {model_id!r} is stale (>365 days)",
        )
    if audit.impact_found:
        return _deny(
            "proptech:disparate_impact",
            f"screening model {model_id!r} found disparate impact "
            f"(selection-rate ratio {audit.selection_rate_ratio}) — "
            "model withdrawn from deployment",
        )
    return _allow(
        f"screening model {model_id!r} has a current disparate-impact audit "
        "with no finding",
        audit.receipt_digest,
    )


def pricing_data_firewall(
    pricing: PricingDataRegistry,
    model_id: str,
    checked_at: int,
) -> ProptechVerdict:
    """Pricing models train only on >=1-year-old data (DOJ-RealPage).

    Any competitor data fresher than a year in the training inputs is
    ``proptech.stale_data_violation``; no bound data declaration is
    ``proptech:no_pricing_declaration``.
    """
    _check_ts(checked_at, "checked_at")
    declaration = pricing.latest_for(model_id)
    if declaration is None:
        return _deny(
            "proptech:no_pricing_declaration",
            f"pricing model {model_id!r} binds no training-data declaration",
        )
    cutoff = declaration.data_cutoff_epoch
    if cutoff > checked_at - PRICING_DATA_MIN_AGE_S:
        return _deny(
            "proptech.stale_data_violation",
            f"pricing model {model_id!r} trained on data newer than 1 year "
            f"(cutoff {cutoff}, checked {checked_at})",
        )
    fresh = declaration.competitor_data_freshest_at
    if fresh and fresh > checked_at - PRICING_DATA_MIN_AGE_S:
        return _deny(
            "proptech.stale_data_violation",
            f"pricing model {model_id!r} ingested competitor data at {fresh} — "
            "real-time competitor data is a collusion input (DOJ-RealPage)",
        )
    return _allow(
        f"pricing model {model_id!r} training data is >=1 year old with no "
        "fresh competitor data",
        declaration.receipt_digest,
    )


def competitor_data_probe(
    pricing: PricingDataRegistry,
    model_id: str,
) -> ProptechVerdict:
    """Competitor nonpublic data triggers an antitrust review gate.

    Any pricing input declared as competitor nonpublic data is
    ``proptech:collusion_input``: it may not flow into automated
    pricing and must be routed to human antitrust review.
    """
    declaration = pricing.latest_for(model_id)
    if declaration is None:
        return _deny(
            "proptech:no_pricing_declaration",
            f"pricing model {model_id!r} binds no training-data declaration",
        )
    if declaration.contains_competitor_nonpublic:
        return _deny(
            "proptech:collusion_input",
            f"pricing model {model_id!r} ingested competitor nonpublic data — "
            "antitrust review gate required, automated pricing refused",
        )
    return _allow(
        f"pricing model {model_id!r} declares no competitor nonpublic data",
        declaration.receipt_digest,
    )


def rent_jurisdiction_matrix(
    pins: RentJurisdictionRegistry,
    jurisdiction_id: str,
    algorithmic_pricing: bool,
    checked_at: int,
) -> ProptechVerdict:
    """Deployments pin the local rent-law matrix; a mismatch refuses.

    In a jurisdiction whose pinned matrix bans algorithmic pricing,
    operating algorithmic pricing is ``proptech:jurisdiction_ban``
    (NY-ban lesson — the ban's enforcement is stayed on First
    Amendment grounds, but the matrix still binds the deployment's
    declared posture). A stale pin is
    ``proptech:stale_jurisdiction_pin``.
    """
    _check_ts(checked_at, "checked_at")
    pin = pins.latest_for(jurisdiction_id)
    if pin is None:
        return _deny(
            "proptech:no_jurisdiction_pin",
            f"no rent-jurisdiction matrix pinned for {jurisdiction_id!r}",
        )
    if checked_at - pin.pinned_at > RECEIPT_MAX_AGE_S:
        return _deny(
            "proptech:stale_jurisdiction_pin",
            f"jurisdiction pin for {jurisdiction_id!r} is stale (>365 days)",
        )
    if algorithmic_pricing and pin.algorithmic_pricing_banned:
        return _deny(
            "proptech:jurisdiction_ban",
            f"algorithmic pricing is banned under the pinned matrix for "
            f"{jurisdiction_id!r}",
        )
    return _allow(
        f"deployment posture matches the pinned rent-law matrix for "
        f"{jurisdiction_id!r}",
        pin.receipt_digest,
    )


def target_ad_delivery_audit(
    audits: AdDeliveryAuditRegistry,
    campaign_id: str,
    checked_at: int,
) -> ProptechVerdict:
    """Housing-ad delivery is audited for discriminatory skew.

    A skew finding halts the campaign: ``proptech:ad_delivery_skew``
    (2024 HUD ad-guidance discipline). No audit is
    ``proptech:no_ad_audit``.
    """
    _check_ts(checked_at, "checked_at")
    audit = audits.latest_for(campaign_id)
    if audit is None:
        return _deny(
            "proptech:no_ad_audit",
            f"housing campaign {campaign_id!r} has no delivery audit receipt",
        )
    if checked_at - audit.audited_at > RECEIPT_MAX_AGE_S:
        return _deny(
            "proptech:no_ad_audit",
            f"delivery audit for campaign {campaign_id!r} is stale (>365 days)",
        )
    if audit.skew_detected:
        return _deny(
            "proptech:ad_delivery_skew",
            f"housing campaign {campaign_id!r} shows discriminatory delivery "
            "skew — campaign halted",
        )
    return _allow(
        f"housing campaign {campaign_id!r} delivery audit shows no skew",
        audit.receipt_digest,
    )


def broker_liability_pin(
    pins: BrokerLiabilityRegistry,
    transaction_id: str,
    broker_id: str,
) -> ProptechVerdict:
    """Every transaction binds a registered human liability anchor.

    The BGH "Nadeloehr" (bottleneck) lesson: the human intermediary's
    liability for AI-assisted selection is non-delegable and must be
    registered per transaction. No pin is
    ``proptech.no_liability_anchor``; a pin for the wrong broker is
    ``proptech:liability_mismatch``.
    """
    pin = pins.latest_for(transaction_id)
    if pin is None:
        return _deny(
            "proptech.no_liability_anchor",
            f"transaction {transaction_id!r} has no registered broker "
            "liability anchor (BGH Nadeloehr)",
        )
    if pin.broker_id != broker_id:
        return _deny(
            "proptech:liability_mismatch",
            f"transaction {transaction_id!r} pins broker {pin.broker_id!r}, "
            f"not {broker_id!r}",
        )
    return _allow(
        f"transaction {transaction_id!r} liability anchored to broker "
        f"{broker_id!r}",
        pin.receipt_digest,
    )


def valuation_confidence_floor(
    valuations: ValuationRegistry,
    receipt_id: str,
) -> ProptechVerdict:
    """AVM outputs below the confidence floor are NON_AUTHORITATIVE
    (HouseCanary/ATTOM lesson: valuations ship confidence intervals).

    Below-floor AI valuations are ``proptech:low_confidence_valuation``:
    autonomous pricing on them is refused; a human valuer is required.
    """
    valuation = valuations.get(receipt_id)
    if valuation is None:
        return _deny(
            "proptech:no_valuation",
            f"valuation receipt {receipt_id!r} not found",
        )
    if valuation.valuer == DECIDER_AI and valuation.confidence < VALUATION_CONFIDENCE_FLOOR:
        return _deny(
            "proptech:low_confidence_valuation",
            f"AI valuation {receipt_id!r} for property {valuation.property_id!r} "
            f"has confidence {valuation.confidence:.2f} below floor "
            f"{VALUATION_CONFIDENCE_FLOOR:.2f} — NON_AUTHORITATIVE, human valuer "
            "required",
        )
    return _allow(
        f"valuation {receipt_id!r} meets the confidence floor "
        f"(confidence {valuation.confidence:.2f})",
        valuation.receipt_digest,
    )


def public_benchmark_reference(
    refs: BenchmarkReferenceRegistry,
    market_id: str,
    checked_at: int,
) -> ProptechVerdict:
    """High-opacity markets must reference a public benchmark (Dubai
    DLD Smart Rental Index lesson).

    No bound reference is ``proptech:no_benchmark``; deviation beyond
    tolerance without a justification digest is
    ``proptech:unjustified_deviation``.
    """
    _check_ts(checked_at, "checked_at")
    ref = refs.latest_for(market_id)
    if ref is None:
        return _deny(
            "proptech:no_benchmark",
            f"market {market_id!r} binds no public benchmark reference",
        )
    if checked_at - ref.referenced_at > RECEIPT_MAX_AGE_S:
        return _deny(
            "proptech:no_benchmark",
            f"benchmark reference for market {market_id!r} is stale (>365 days)",
        )
    if (
        ref.deviation_bps > BENCHMARK_DEVIATION_TOL_BPS
        and ref.justification_digest == "00" * 32
    ):
        return _deny(
            "proptech:unjustified_deviation",
            f"market {market_id!r} deviates {ref.deviation_bps} bps from public "
            f"benchmark {ref.benchmark_source!r} without justification",
        )
    return _allow(
        f"market {market_id!r} references public benchmark "
        f"{ref.benchmark_source!r} (deviation {ref.deviation_bps} bps)",
        ref.receipt_digest,
    )
