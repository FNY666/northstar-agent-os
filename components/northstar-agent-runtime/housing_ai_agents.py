"""Housing-market AI discipline (one-hundred-forty-second batch).

Absorbs the 2026 AI-real-estate research thread (mechanism ideas only,
honestly scoped):

* **Voucher applicants are explicitly protected.** *Louis v. SafeRent*
  settled for $2.275M; SafeRent agreed to 5 years of court supervision
  and to stop scoring housing-voucher applicants before fairness was
  verified. Here a tenant-screening model must present a fairness-probe
  receipt whose demographic slices EXPLICITLY include ``voucher_holders``
  (plus ``race_ethnicity`` and ``familial_status``); a probe that never
  measured voucher applicants cannot authorize scoring them
  (``housing:voucher_slice_missing``). The probe must also be
  independently audited — a vendor-signed probe without an independent
  auditor binding is self-certification (``housing:probe_self_audited``).
* **No-appeal decisions are the red line.** The decisive SafeRent fact
  was the property manager's line: "the algorithm can't be appealed".
  Here every AI-influenced screening decision binds an appeal-window
  receipt (contact channel, >= 30-day window, named human reviewer);
  a decision with no bound appeal denies (``housing:no_appeal``).
* **Rent-coordination training data is pinned.** DOJ v. RealPage is
  ongoing (2026-10-02 motion to dismiss denied); the DOJ–RealPage
  settlement bars competitor non-public data in pricing models,
  removes auto-accept recommendations, and limits training data to
  1+ year old. Here a rent-pricing model binds its training sources:
  any competitor non-public source denies
  (``housing:rent_coordination``), any source younger than 365 days
  denies (``housing:recency_violation``), and an auto-accept
  recommendation denies (``housing:auto_accept``).
* **AVMs bind confidence + recency.** Fannie/Freddie's early-2026 AI
  governance frameworks and UAD 3.6 (mandatory 2026-11-02) push
  valuation discipline into structure: an automated valuation binds a
  confidence score and a data-as-of timestamp; low-confidence or stale
  valuations for high-stakes use refuse automated reliance and require
  human review (``housing:avm_human_review_required``).
* **Steering probes are sealed.** The 119th-batch ``housing.py``
  steering probe returns a boolean verdict; here probe executions are
  sealed into hash-chained, prober-signed receipts binding the
  listing-function digest, the persona digests, and the measured
  overlap — probe results become auditable evidence, not console
  output.
* **AI-edited photos disclose.** NYC A.11635 (AI photo-edit disclosure,
  pending) becomes structure: a listing photo that is AI-edited must
  carry a sealed edit-declaration receipt; an AI-edited photo with no
  receipt is a deceptive listing (``housing:deceptive_listing``).
* **Adverse actions bind appeal.** Beyond the 119th-batch adverse-action
  receipt (specific reasons + human countersign), the 142nd-batch
  adverse-action receipt additionally binds the appeal-window receipt:
  an adverse action with no live appeal path denies
  (``housing:adverse_action_no_appeal``).

Northstar mapping:

* ``ScreeningProbeVerdict`` / ``screening_fairness_probe()`` —
  fail-closed gate reusing the 119th-batch ``FairnessProbeReceipt``
  but enforcing voucher-slice coverage and auditor independence.
* ``AppealReceipt`` / ``issue_appeal_receipt()`` / ``check_appeal()`` —
  hash-chained appeal windows; ``appeal_window()`` is the
  fail-closed screening-decision check.
* ``TrainingDataReceipt`` / ``rent_coordination_probe()`` —
  training-source binding with recency and competitor-nonpublic flags;
  ``rent_recommendation_gate()`` refuses auto-accept.
* ``AVMVerdict`` / ``avm_confidence_gate()`` — confidence + recency
  thresholds pinned per use-kind.
* ``SteeringProbeReceipt`` / ``steering_probe()`` — sealed steering
  probe executions (reuses ``housing.steering_probe`` as the engine).
* ``PhotoEditReceipt`` / ``issue_photo_edit_receipt()`` /
  ``listing_truth_receipt()`` — edit-declaration binding for
  AI-edited listing photos.
* ``AdverseActionReceipt`` / ``adverse_action_receipt()`` /
  ``check_adverse_action()`` — adverse actions bound to appeal
  receipts (reuses the 119th-batch ``VAGUE_REASONS`` list).

Honest boundary: receipts bind declared market discipline — digests
recompute, signatures verify, appeal windows are checkable. The
module cannot certify statistical fairness, detect undisclosed
AI photo edits, or prove training data was truly isolated; it
enforces the *structure*: probes before scoring, appeal before
decisions, isolated-and-aged data before pricing, disclosure before
edited photos. Vendors self-declare; a lying vendor fails the
auditability requirement, not this gate.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations
from _domain_base import DomainError

import hmac
import inspect
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

import ed25519
import housing
from canonical_json import jcs_canonical_json, jcs_sha256_hex

HOUSING_AI_SCHEMA_VERSION = "northstar.housing_ai.v1"

#: Demographic slices a screening probe must explicitly cover. A probe
#: that never measured voucher applicants cannot authorize scoring
#: them (the SafeRent lesson).
REQUIRED_SCREENING_SLICES: tuple[str, ...] = (
    "voucher_holders",
    "race_ethnicity",
    "familial_status",
)

#: Closed appeal-channel vocabulary.
APPEAL_CHANNELS: tuple[str, ...] = (
    "email",
    "phone",
    "in_person",
    "web_portal",
)

#: Minimum appeal window in days (ECOA-style reasonable window).
MIN_APPEAL_WINDOW_DAYS = 30

#: Minimum training-data age in days for rent-pricing models
#: (DOJ-RealPage settlement: training data limited to 1+ year old).
MIN_TRAINING_DATA_AGE_DAYS = 365

#: Closed AVM use-kind vocabulary with (min_confidence, max_data_age_days).
AVM_USE_KINDS: dict[str, tuple[float, int]] = {
    "mortgage_lending": (0.90, 90),
    "sale_listing": (0.80, 180),
    "tax_assessment": (0.70, 365),
    "portfolio_valuation": (0.70, 365),
}

#: Closed photo-edit vocabulary for listing-truth receipts.
PHOTO_EDITS: tuple[str, ...] = (
    "none",
    "lighting",
    "staging",
    "object_removal",
    "view_enhancement",
    "floorplan_render",
)

#: Edits considered material (must be declared; "none"/"lighting" are
#: cosmetic and carry no disclosure duty).
MATERIAL_EDITS: tuple[str, ...] = (
    "staging",
    "object_removal",
    "view_enhancement",
    "floorplan_render",
)

#: Denial reason codes. All start with the ``housing:`` prefix.
DENY_NO_PROBE = "housing:no_screening_probe"
DENY_PROBE_EXPIRED = "housing:probe_expired"
DENY_PROBE_FUTURE = "housing:probe_from_future"
DENY_PROBE_TAMPERED = "housing:probe_tampered"
DENY_PROBE_SELF_AUDITED = "housing:probe_self_audited"
DENY_VOUCHER_SLICE_MISSING = "housing:voucher_slice_missing"
DENY_VOUCHER_INCOME = "housing:voucher_income_discrimination"
DENY_VOUCHER_POLICY_UNDECLARED = "housing:voucher_policy_undeclared"
DENY_NO_APPEAL = "housing:no_appeal"
DENY_APPEAL_TAMPERED = "housing:appeal_tampered"
DENY_APPEAL_EXPIRED = "housing:appeal_expired"
DENY_APPEAL_WINDOW_SHORT = "housing:appeal_window_too_short"
DENY_COORDINATION = "housing:rent_coordination"
DENY_RECENCY = "housing:recency_violation"
DENY_TRAINING_TAMPERED = "housing:training_data_tampered"
DENY_AUTO_ACCEPT = "housing:auto_accept"
DENY_AVM_REVIEW = "housing:avm_human_review_required"
DENY_STEERING = housing.DENY_STEERING
DENY_STEERING_TAMPERED = "housing:steering_probe_tampered"
DENY_DECEPTIVE_LISTING = "housing:deceptive_listing"
DENY_PHOTO_TAMPERED = "housing:photo_edit_tampered"
DENY_ACTION_NO_APPEAL = "housing:adverse_action_no_appeal"
DENY_ACTION_TAMPERED = "housing:adverse_action_tampered"
DENY_VAGUE_REASON = "housing:vague_adverse_action"
DENY_MALFORMED = "housing:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
PROBE_ALLOWED_EVENT = "housing_ai.probe_allowed"
PROBE_DENIED_EVENT = "housing_ai.probe_denied"
APPEAL_ALLOWED_EVENT = "housing_ai.appeal_allowed"
APPEAL_DENIED_EVENT = "housing_ai.appeal_denied"
COORD_ALLOWED_EVENT = "housing_ai.coordination_allowed"
COORD_DENIED_EVENT = "housing_ai.coordination_denied"
AVM_ALLOWED_EVENT = "housing_ai.avm_allowed"
AVM_DENIED_EVENT = "housing_ai.avm_denied"
STEERING_EVENT = "housing_ai.steering_checked"
LISTING_ALLOWED_EVENT = "housing_ai.listing_allowed"
LISTING_DENIED_EVENT = "housing_ai.listing_denied"
ACTION_ALLOWED_EVENT = "housing_ai.action_allowed"
ACTION_DENIED_EVENT = "housing_ai.action_denied"

_GENESIS = "genesis"
_HEX64_LENGTH = 64


class HousingAIError(DomainError):
    """Malformed receipt/claim or a programming error.

    Raised for structural problems (unknown vocabulary, bad digests,
    non-hex fields). Verification *failures* (expired, revoked,
    tampered, missing evidence) return verdicts with ``allowed=False``
    — a failed gate is a verdict, a malformed log is a bug.
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
        raise HousingAIError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, 128):
        raise HousingAIError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 0:
        return value
    raise HousingAIError(f"{field_name} must be a non-negative integer epoch")


def _check_secret(value: Any, field_name: str) -> bytes:
    if (
        isinstance(value, (bytes, bytearray))
        and len(bytes(value)) == 32
        and any(b != 0 for b in bytes(value))
    ):
        return bytes(value)
    raise HousingAIError(f"{field_name} must be a non-degenerate 32-byte secret")


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, 64):
        raise HousingAIError(
            "pubkey must be 64 lowercase hex chars (32-byte Ed25519 key)"
        )
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HousingAIError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_str_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise HousingAIError(f"{field_name} must be a non-empty list of strings")
    return tuple(_check_nonempty_str(v, f"{field_name}[]") for v in value)


def _check_channel(value: Any) -> str:
    if value not in APPEAL_CHANNELS:
        raise HousingAIError(
            f"unknown appeal channel {value!r}; closed vocabulary {APPEAL_CHANNELS}"
        )
    return value


def _check_use_kind(value: Any) -> str:
    if value not in AVM_USE_KINDS:
        raise HousingAIError(
            f"unknown AVM use kind {value!r}; closed vocabulary "
            f"{tuple(AVM_USE_KINDS)}"
        )
    return value


def _check_confidence(value: Any, field_name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise HousingAIError(f"{field_name} must be a number in [0.0, 1.0]")
    return float(value)


# ---------------------------------------------------------------------------
# Screening fairness probes (voucher-slice coverage + auditor independence)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScreeningProbeVerdict:
    allowed: bool
    reason: str
    probe_id: str | None = None


def _verify_screening_probe_integrity(
    receipt: housing.FairnessProbeReceipt,
) -> str | None:
    """Return a denial code if the probe receipt is tampered, else None."""
    try:
        if not hmac.compare_digest(
            housing.compute_probe_digest(receipt), receipt.probe_receipt_digest
        ):
            return DENY_PROBE_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(receipt.vendor_pubkey_hex),
                jcs_canonical_json(housing._probe_payload(receipt)),
                bytes.fromhex(receipt.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_PROBE_TAMPERED
    except HousingAIError:
        return DENY_MALFORMED
    return None


def screening_fairness_probe(
    probe_receipts: Sequence[housing.FairnessProbeReceipt],
    *,
    model_digest: str,
    auditor_id: str,
    check_time: int,
) -> ScreeningProbeVerdict:
    """Fail-closed gate: screening models need an independently-audited probe.

    Reuses the 119th-batch ``FairnessProbeReceipt`` but enforces two
    142nd-batch requirements the 119th gate does not: (1) the probe's
    demographic slices must explicitly include ``voucher_holders``
    (plus ``race_ethnicity`` and ``familial_status``) — a probe that
    never measured voucher applicants cannot authorize scoring them;
    (2) the auditor must differ from the vendor (no self-certification).
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    auditor_id = _check_nonempty_str(auditor_id, "auditor_id")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> ScreeningProbeVerdict:
        return ScreeningProbeVerdict(allowed=False, reason=reason)

    for receipt in probe_receipts:
        if not hmac.compare_digest(receipt.model_digest, model_digest):
            continue
        tamper = _verify_screening_probe_integrity(receipt)
        if tamper is not None:
            return deny(tamper)
        if check_time < receipt.measured_at:
            return deny(DENY_PROBE_FUTURE)
        if check_time >= receipt.expires_at:
            return deny(DENY_PROBE_EXPIRED)
        if hmac.compare_digest(receipt.vendor_id.lower(), auditor_id.lower()):
            return deny(DENY_PROBE_SELF_AUDITED)
        missing = [
            s for s in REQUIRED_SCREENING_SLICES if s not in receipt.demographic_slices
        ]
        if missing:
            return deny(DENY_VOUCHER_SLICE_MISSING)
        return ScreeningProbeVerdict(
            allowed=True, reason="ok", probe_id=receipt.probe_id
        )
    return deny(DENY_NO_PROBE)


def probe_audit_event(verdict: ScreeningProbeVerdict, *, action: str) -> dict[str, Any]:
    """Shape a screening-probe verdict as an audit event."""
    return {
        "event": PROBE_ALLOWED_EVENT if verdict.allowed else PROBE_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "probe_id": verdict.probe_id,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Voucher-income discrimination gate
# ---------------------------------------------------------------------------


#: Closed screening-rule treatment vocabulary for voucher income.
VOUCHER_TREATMENTS: tuple[str, ...] = ("accept", "downgrade", "exclude")


@dataclass(frozen=True)
class VoucherVerdict:
    allowed: bool
    reason: str
    offending_rules: tuple[str, ...] = ()


def voucher_income_gate(
    *,
    voucher_policy_declared: bool,
    accepts_vouchers: bool,
    screening_rules: Sequence[Mapping[str, Any]],
) -> VoucherVerdict:
    """Fail-closed voucher-income discrimination gate.

    The landlord's voucher policy must be declared (undeclared is a
    deny — the policy cannot be silently punitive). If vouchers are
    accepted, no screening rule may ``exclude`` or ``downgrade``
    voucher income; offending rules deny with their ids named.
    """
    if not isinstance(voucher_policy_declared, bool):
        raise HousingAIError("voucher_policy_declared must be a bool")
    if not isinstance(accepts_vouchers, bool):
        raise HousingAIError("accepts_vouchers must be a bool")
    if not voucher_policy_declared:
        return VoucherVerdict(
            allowed=False, reason=DENY_VOUCHER_POLICY_UNDECLARED
        )
    if not isinstance(screening_rules, (list, tuple)):
        raise HousingAIError("screening_rules must be a list of mappings")
    offending: list[str] = []
    for raw in screening_rules:
        if not isinstance(raw, Mapping):
            raise HousingAIError("screening_rules entries must be mappings")
        rule_id = _check_nonempty_str(raw.get("rule_id"), "rule_id")
        treatment = raw.get("treats_voucher_income")
        if treatment not in VOUCHER_TREATMENTS:
            raise HousingAIError(
                f"unknown voucher treatment {treatment!r}; closed vocabulary "
                f"{VOUCHER_TREATMENTS}"
            )
        if accepts_vouchers and treatment != "accept":
            offending.append(rule_id)
    if offending:
        return VoucherVerdict(
            allowed=False,
            reason=DENY_VOUCHER_INCOME,
            offending_rules=tuple(sorted(offending)),
        )
    return VoucherVerdict(allowed=True, reason="ok")


# ---------------------------------------------------------------------------
# Appeal windows
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppealReceipt:
    """Hash-chained appeal-window receipt for a screening decision."""

    appeal_id: str
    decision_digest: str
    channel: str
    contact: str
    window_days: int
    human_reviewer_id: str
    issued_at: int
    expires_at: int
    issuer_pubkey_hex: str
    signature_hex: str
    prev_digest: str = _GENESIS
    appeal_digest: str = ""
    schema_version: str = HOUSING_AI_SCHEMA_VERSION


def _appeal_payload(appeal: AppealReceipt) -> dict[str, Any]:
    return {
        "appeal_id": appeal.appeal_id,
        "decision_digest": appeal.decision_digest,
        "channel": appeal.channel,
        "contact": appeal.contact,
        "window_days": appeal.window_days,
        "human_reviewer_id": appeal.human_reviewer_id,
        "issued_at": appeal.issued_at,
        "expires_at": appeal.expires_at,
        "issuer_pubkey_hex": appeal.issuer_pubkey_hex,
        "prev_digest": appeal.prev_digest,
        "schema_version": appeal.schema_version,
    }


def compute_appeal_digest(appeal: AppealReceipt) -> str:
    """Recompute the JCS digest an appeal receipt claims."""
    return jcs_sha256_hex(_appeal_payload(appeal))


def issue_appeal_receipt(
    *,
    appeal_id: str,
    decision_digest: str,
    channel: str,
    contact: str,
    window_days: int,
    human_reviewer_id: str,
    issuer_secret: bytes,
    issued_at: int,
    prev_digest: str = _GENESIS,
) -> AppealReceipt:
    """Issue a signed appeal-window receipt for a screening decision.

    Fail-closed at issuance: windows shorter than
    ``MIN_APPEAL_WINDOW_DAYS`` raise — a 24-hour "appeal" is no appeal.
    """
    _check_secret(issuer_secret, "issuer_secret")
    appeal_id = _check_nonempty_str(appeal_id, "appeal_id")
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    channel = _check_channel(channel)
    contact = _check_nonempty_str(contact, "contact")
    if (
        not isinstance(window_days, bool)
        and isinstance(window_days, int)
        and window_days >= MIN_APPEAL_WINDOW_DAYS
    ):
        pass
    else:
        raise HousingAIError(
            f"window_days must be an integer >= {MIN_APPEAL_WINDOW_DAYS}"
        )
    human_reviewer_id = _check_nonempty_str(human_reviewer_id, "human_reviewer_id")
    issued_at = _check_ts(issued_at, "issued_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise HousingAIError("prev_digest must be a non-empty string")

    pubkey_hex = ed25519.public_key(issuer_secret).hex()
    expires_at = issued_at + window_days * 86_400
    bare = AppealReceipt(
        appeal_id=appeal_id,
        decision_digest=decision_digest,
        channel=channel,
        contact=contact,
        window_days=window_days,
        human_reviewer_id=human_reviewer_id,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        prev_digest=prev_digest,
    )
    payload = _appeal_payload(bare)
    signature_hex = ed25519.sign(
        issuer_secret, jcs_canonical_json(payload)
    ).hex()
    return AppealReceipt(
        appeal_id=bare.appeal_id,
        decision_digest=bare.decision_digest,
        channel=bare.channel,
        contact=bare.contact,
        window_days=bare.window_days,
        human_reviewer_id=bare.human_reviewer_id,
        issued_at=bare.issued_at,
        expires_at=bare.expires_at,
        issuer_pubkey_hex=bare.issuer_pubkey_hex,
        signature_hex=signature_hex,
        prev_digest=bare.prev_digest,
        appeal_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class AppealVerdict:
    allowed: bool
    reason: str
    appeal_id: str | None = None


def _verify_appeal_integrity(appeal: AppealReceipt) -> str | None:
    try:
        if not hmac.compare_digest(
            compute_appeal_digest(appeal), appeal.appeal_digest
        ):
            return DENY_APPEAL_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(appeal.issuer_pubkey_hex),
                jcs_canonical_json(_appeal_payload(appeal)),
                bytes.fromhex(appeal.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_APPEAL_TAMPERED
    except HousingAIError:
        return DENY_MALFORMED
    return None


def check_appeal(
    appeal: AppealReceipt | None,
    *,
    decision_digest: str,
    check_time: int,
) -> AppealVerdict:
    """Fail-closed check: a screening decision needs a live appeal window."""
    decision_digest = _check_hex64(decision_digest, "decision_digest")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> AppealVerdict:
        return AppealVerdict(allowed=False, reason=reason)

    if appeal is None:
        return deny(DENY_NO_APPEAL)
    tamper = _verify_appeal_integrity(appeal)
    if tamper is not None:
        return deny(tamper)
    if not hmac.compare_digest(appeal.decision_digest, decision_digest):
        return deny(DENY_APPEAL_TAMPERED)
    if check_time < appeal.issued_at or check_time >= appeal.expires_at:
        return deny(DENY_APPEAL_EXPIRED)
    if appeal.window_days < MIN_APPEAL_WINDOW_DAYS:
        return deny(DENY_APPEAL_WINDOW_SHORT)
    return AppealVerdict(allowed=True, reason="ok", appeal_id=appeal.appeal_id)


def appeal_window(
    appeal: AppealReceipt | None,
    *,
    decision_digest: str,
    check_time: int,
) -> AppealVerdict:
    """The SafeRent red line as a gate: no appeal window, no decision."""
    return check_appeal(appeal, decision_digest=decision_digest, check_time=check_time)


def appeal_audit_event(verdict: AppealVerdict, *, action: str) -> dict[str, Any]:
    """Shape an appeal verdict as an audit event."""
    return {
        "event": APPEAL_ALLOWED_EVENT if verdict.allowed else APPEAL_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "appeal_id": verdict.appeal_id,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Rent-coordination probes (training-data binding + auto-accept refusal)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrainingSource:
    """One declared training source for a rent-pricing model."""

    source_id: str
    source_digest: str
    min_age_days: int
    contains_competitor_nonpublic: bool


@dataclass(frozen=True)
class TrainingDataReceipt:
    """Sealed training-source binding for a rent-pricing model."""

    receipt_id: str
    model_digest: str
    sources: tuple[TrainingSource, ...]
    declared_by: str
    declared_at: int
    receipt_digest: str = ""
    schema_version: str = HOUSING_AI_SCHEMA_VERSION


def _training_payload(receipt: TrainingDataReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "model_digest": receipt.model_digest,
        "sources": [
            {
                "source_id": s.source_id,
                "source_digest": s.source_digest,
                "min_age_days": s.min_age_days,
                "contains_competitor_nonpublic": s.contains_competitor_nonpublic,
            }
            for s in receipt.sources
        ],
        "declared_by": receipt.declared_by,
        "declared_at": receipt.declared_at,
        "schema_version": receipt.schema_version,
    }


def declare_training_data(
    *,
    receipt_id: str,
    model_digest: str,
    sources: Sequence[Mapping[str, Any]],
    declared_by: str,
    declared_at: int,
) -> TrainingDataReceipt:
    """Declare the training sources of a rent-pricing model, sealed.

    Each source declares its minimum data age and whether it contains
    competitor non-public data. The declaration is sealed; a source
    cannot be quietly added later without breaking the digest.
    """
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    if not isinstance(sources, (list, tuple)) or not sources:
        raise HousingAIError("sources must be a non-empty list of mappings")
    parsed: list[TrainingSource] = []
    for raw in sources:
        if not isinstance(raw, Mapping):
            raise HousingAIError("sources entries must be mappings")
        source_id = _check_nonempty_str(raw.get("source_id"), "source_id")
        source_digest = _check_hex64(raw.get("source_digest"), "source_digest")
        age = raw.get("min_age_days")
        if not isinstance(age, bool) and isinstance(age, int) and age >= 0:
            pass
        else:
            raise HousingAIError("min_age_days must be a non-negative integer")
        flag = raw.get("contains_competitor_nonpublic")
        if not isinstance(flag, bool):
            raise HousingAIError("contains_competitor_nonpublic must be a bool")
        parsed.append(
            TrainingSource(
                source_id=source_id,
                source_digest=source_digest,
                min_age_days=age,
                contains_competitor_nonpublic=flag,
            )
        )
    if len({s.source_id for s in parsed}) != len(parsed):
        raise HousingAIError("duplicate training source id")
    declared_by = _check_nonempty_str(declared_by, "declared_by")
    declared_at = _check_ts(declared_at, "declared_at")
    bare = TrainingDataReceipt(
        receipt_id=receipt_id,
        model_digest=model_digest,
        sources=tuple(sorted(parsed, key=lambda s: s.source_id)),
        declared_by=declared_by,
        declared_at=declared_at,
    )
    return TrainingDataReceipt(
        receipt_id=bare.receipt_id,
        model_digest=bare.model_digest,
        sources=bare.sources,
        declared_by=bare.declared_by,
        declared_at=bare.declared_at,
        receipt_digest=jcs_sha256_hex(_training_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class CoordinationVerdict:
    allowed: bool
    reason: str
    receipt_id: str | None = None


def rent_coordination_probe(
    receipt: TrainingDataReceipt | None,
    *,
    model_digest: str,
) -> CoordinationVerdict:
    """Fail-closed rent-coordination gate over training data.

    Any training source containing competitor non-public data denies
    (``housing:rent_coordination`` — the DOJ-RealPage vector); any
    source younger than ``MIN_TRAINING_DATA_AGE_DAYS`` denies
    (``housing:recency_violation`` — the 1-year settlement rule).
    """
    model_digest = _check_hex64(model_digest, "model_digest")

    def deny(reason: str) -> CoordinationVerdict:
        return CoordinationVerdict(allowed=False, reason=reason)

    if receipt is None:
        return deny(DENY_COORDINATION)
    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_training_payload(receipt)), receipt.receipt_digest
        ):
            return deny(DENY_TRAINING_TAMPERED)
    except HousingAIError:
        return deny(DENY_MALFORMED)
    if not hmac.compare_digest(receipt.model_digest, model_digest):
        return deny(DENY_TRAINING_TAMPERED)
    for source in receipt.sources:
        if source.contains_competitor_nonpublic:
            return deny(DENY_COORDINATION)
        if source.min_age_days < MIN_TRAINING_DATA_AGE_DAYS:
            return deny(DENY_RECENCY)
    return CoordinationVerdict(allowed=True, reason="ok", receipt_id=receipt.receipt_id)


@dataclass(frozen=True)
class RentRecommendationVerdict:
    allowed: bool
    reason: str


def rent_recommendation_gate(
    *,
    rent_value: float,
    auto_accept: bool,
    basis_digest: str,
) -> RentRecommendationVerdict:
    """Refuse auto-accept rent recommendations.

    A pricing recommendation that would apply itself (``auto_accept``)
    denies (``housing:auto_accept`` — the DOJ-RealPage settlement
    removed auto-accept recommendations). Manual recommendations pass
    through with their basis digest pinned for audit.
    """
    if isinstance(rent_value, bool) or not isinstance(rent_value, (int, float)):
        raise HousingAIError("rent_value must be a number")
    if float(rent_value) <= 0:
        raise HousingAIError("rent_value must be positive")
    if not isinstance(auto_accept, bool):
        raise HousingAIError("auto_accept must be a bool")
    basis_digest = _check_hex64(basis_digest, "basis_digest")
    if auto_accept:
        return RentRecommendationVerdict(allowed=False, reason=DENY_AUTO_ACCEPT)
    return RentRecommendationVerdict(allowed=True, reason="ok")


def coordination_audit_event(
    verdict: CoordinationVerdict, *, action: str
) -> dict[str, Any]:
    """Shape a coordination verdict as an audit event."""
    return {
        "event": COORD_ALLOWED_EVENT if verdict.allowed else COORD_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "receipt_id": verdict.receipt_id,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# AVM confidence + recency gates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AVMVerdict:
    allowed: bool
    reason: str
    requires_human_review: bool = False


def avm_confidence_gate(
    *,
    model_digest: str,
    confidence: float,
    data_as_of: int,
    use_kind: str,
    check_time: int,
) -> AVMVerdict:
    """Fail-closed AVM gate: confidence and recency pinned per use-kind.

    Low-confidence or stale valuations for high-stakes use refuse
    automated reliance and require human review
    (``housing:avm_human_review_required``) — the UAD 3.6 / Fannie-Freddie
    AI-governance lesson made structural.
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    confidence = _check_confidence(confidence, "confidence")
    data_as_of = _check_ts(data_as_of, "data_as_of")
    use_kind = _check_use_kind(use_kind)
    check_time = _check_ts(check_time, "check_time")

    if data_as_of > check_time:
        return AVMVerdict(
            allowed=False, reason=DENY_AVM_REVIEW, requires_human_review=True
        )
    min_conf, max_age = AVM_USE_KINDS[use_kind]
    if confidence < min_conf or (check_time - data_as_of) > max_age * 86_400:
        return AVMVerdict(
            allowed=False, reason=DENY_AVM_REVIEW, requires_human_review=True
        )
    return AVMVerdict(allowed=True, reason="ok")


def avm_audit_event(verdict: AVMVerdict, *, action: str) -> dict[str, Any]:
    """Shape an AVM verdict as an audit event."""
    return {
        "event": AVM_ALLOWED_EVENT if verdict.allowed else AVM_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "requires_human_review": verdict.requires_human_review,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Sealed steering probes
# ---------------------------------------------------------------------------


def _listing_fn_digest(list_listings: Callable[..., Any]) -> str:
    """Bind a listing function's identity to a digest."""
    try:
        source = inspect.getsource(list_listings)
    except (OSError, TypeError):
        code = getattr(list_listings, "__code__", None)
        source = repr(code.co_code) if code is not None else repr(list_listings)
    return jcs_sha256_hex({"fn_source": source})


@dataclass(frozen=True)
class SteeringProbeReceipt:
    """Sealed steering-probe execution: hash-chained, prober-signed."""

    probe_id: str
    listing_fn_digest: str
    persona_a_digest: str
    persona_b_digest: str
    overlap: float
    prober_id: str
    prober_pubkey_hex: str
    signature_hex: str
    measured_at: int
    prev_digest: str = _GENESIS
    probe_receipt_digest: str = ""
    schema_version: str = HOUSING_AI_SCHEMA_VERSION


def _steering_payload(receipt: SteeringProbeReceipt) -> dict[str, Any]:
    return {
        "probe_id": receipt.probe_id,
        "listing_fn_digest": receipt.listing_fn_digest,
        "persona_a_digest": receipt.persona_a_digest,
        "persona_b_digest": receipt.persona_b_digest,
        "overlap": receipt.overlap,
        "prober_id": receipt.prober_id,
        "prober_pubkey_hex": receipt.prober_pubkey_hex,
        "measured_at": receipt.measured_at,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


@dataclass(frozen=True)
class SealedSteeringVerdict:
    allowed: bool
    reason: str
    receipt: SteeringProbeReceipt | None = None


def steering_probe(
    list_listings: Callable[[Mapping[str, str]], Sequence[str]],
    persona_a: Mapping[str, str],
    persona_b: Mapping[str, str],
    *,
    probe_id: str,
    prober_id: str,
    prober_secret: bytes,
    measured_at: int,
    prev_digest: str = _GENESIS,
) -> SealedSteeringVerdict:
    """Run the 119th-batch steering probe and seal the execution.

    The probe engine is ``housing.steering_probe`` (synthetic persona
    pairs differing only in ``protected:`` fields). The 142nd-batch
    addition seals the execution: the receipt binds the listing-function
    digest, both persona digests, and the measured overlap, signed by
    the prober and hash-chained. Probe results become auditable
    evidence; a fabricated "pass" breaks the signature.
    """
    _check_secret(prober_secret, "prober_secret")
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    prober_id = _check_nonempty_str(prober_id, "prober_id")
    measured_at = _check_ts(measured_at, "measured_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise HousingAIError("prev_digest must be a non-empty string")

    verdict = housing.steering_probe(list_listings, persona_a, persona_b)
    fn_digest = _listing_fn_digest(list_listings)
    persona_a_digest = jcs_sha256_hex(
        {k: persona_a[k] for k in sorted(persona_a)}
    )
    persona_b_digest = jcs_sha256_hex(
        {k: persona_b[k] for k in sorted(persona_b)}
    )
    overlap = verdict.overlap if verdict.overlap is not None else 1.0

    pubkey_hex = ed25519.public_key(prober_secret).hex()
    bare = SteeringProbeReceipt(
        probe_id=probe_id,
        listing_fn_digest=fn_digest,
        persona_a_digest=persona_a_digest,
        persona_b_digest=persona_b_digest,
        overlap=overlap,
        prober_id=prober_id,
        prober_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        measured_at=measured_at,
        prev_digest=prev_digest,
    )
    payload = _steering_payload(bare)
    signature_hex = ed25519.sign(
        prober_secret, jcs_canonical_json(payload)
    ).hex()
    receipt = SteeringProbeReceipt(
        probe_id=bare.probe_id,
        listing_fn_digest=bare.listing_fn_digest,
        persona_a_digest=bare.persona_a_digest,
        persona_b_digest=bare.persona_b_digest,
        overlap=bare.overlap,
        prober_id=bare.prober_id,
        prober_pubkey_hex=bare.prober_pubkey_hex,
        signature_hex=signature_hex,
        measured_at=bare.measured_at,
        prev_digest=bare.prev_digest,
        probe_receipt_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )
    return SealedSteeringVerdict(
        allowed=verdict.allowed, reason=verdict.reason, receipt=receipt
    )


def check_steering_probe_receipt(
    receipt: SteeringProbeReceipt,
) -> SealedSteeringVerdict:
    """Fail-closed integrity check of a sealed steering-probe receipt."""
    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_steering_payload(receipt)),
            receipt.probe_receipt_digest,
        ):
            return SealedSteeringVerdict(
                allowed=False, reason=DENY_STEERING_TAMPERED
            )
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(receipt.prober_pubkey_hex),
                jcs_canonical_json(_steering_payload(receipt)),
                bytes.fromhex(receipt.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return SealedSteeringVerdict(
                allowed=False, reason=DENY_STEERING_TAMPERED
            )
    except HousingAIError:
        return SealedSteeringVerdict(allowed=False, reason=DENY_MALFORMED)
    if receipt.overlap < 1.0:
        return SealedSteeringVerdict(
            allowed=False, reason=DENY_STEERING, receipt=receipt
        )
    return SealedSteeringVerdict(allowed=True, reason="ok", receipt=receipt)


def steering_audit_event(verdict: SealedSteeringVerdict, *, action: str) -> dict[str, Any]:
    """Shape a sealed steering verdict as an audit event."""
    return {
        "event": STEERING_EVENT,
        "action": action,
        "reason": verdict.reason,
        "probe_id": verdict.receipt.probe_id if verdict.receipt else None,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Listing-truth receipts (AI-edited photo disclosure)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhotoEditReceipt:
    """Sealed edit-declaration for an AI-edited listing photo."""

    receipt_id: str
    listing_id: str
    photo_digest: str
    edits: tuple[str, ...]
    publisher_id: str
    published_at: int
    receipt_digest: str = ""
    schema_version: str = HOUSING_AI_SCHEMA_VERSION


def _photo_payload(receipt: PhotoEditReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "listing_id": receipt.listing_id,
        "photo_digest": receipt.photo_digest,
        "edits": list(receipt.edits),
        "publisher_id": receipt.publisher_id,
        "published_at": receipt.published_at,
        "schema_version": receipt.schema_version,
    }


def issue_photo_edit_receipt(
    *,
    receipt_id: str,
    listing_id: str,
    photo_digest: str,
    edits: Sequence[str],
    publisher_id: str,
    published_at: int,
) -> PhotoEditReceipt:
    """Issue a sealed edit-declaration for a listing photo.

    Every edit in ``edits`` must come from the closed ``PHOTO_EDITS``
    vocabulary. Declaring ``"none"`` alongside other edits raises —
    the declaration is either clean or it names its edits.
    """
    receipt_id = _check_nonempty_str(receipt_id, "receipt_id")
    listing_id = _check_nonempty_str(listing_id, "listing_id")
    photo_digest = _check_hex64(photo_digest, "photo_digest")
    edit_list = _check_str_list(edits, "edits")
    for edit in edit_list:
        if edit not in PHOTO_EDITS:
            raise HousingAIError(
                f"unknown photo edit {edit!r}; closed vocabulary {PHOTO_EDITS}"
            )
    if "none" in edit_list and len(edit_list) > 1:
        raise HousingAIError('cannot declare "none" alongside other edits')
    publisher_id = _check_nonempty_str(publisher_id, "publisher_id")
    published_at = _check_ts(published_at, "published_at")
    bare = PhotoEditReceipt(
        receipt_id=receipt_id,
        listing_id=listing_id,
        photo_digest=photo_digest,
        edits=tuple(sorted(set(edit_list))),
        publisher_id=publisher_id,
        published_at=published_at,
    )
    return PhotoEditReceipt(
        receipt_id=bare.receipt_id,
        listing_id=bare.listing_id,
        photo_digest=bare.photo_digest,
        edits=bare.edits,
        publisher_id=bare.publisher_id,
        published_at=bare.published_at,
        receipt_digest=jcs_sha256_hex(_photo_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class ListingVerdict:
    allowed: bool
    reason: str
    receipt_id: str | None = None


def listing_truth_receipt(
    *,
    listing_id: str,
    photos: Sequence[Mapping[str, Any]],
    edit_receipts: Sequence[PhotoEditReceipt],
) -> ListingVerdict:
    """Fail-closed listing-truth check over a listing's photos.

    Each photo declares ``ai_edited``. An AI-edited photo must present
    a valid edit receipt binding its photo digest and listing id; a
    photo marked AI-edited with no receipt denies
    (``housing:deceptive_listing`` — the NYC A.11635 logic). A photo
    marked not-edited needs no receipt. Tampered receipts deny.
    """
    listing_id = _check_nonempty_str(listing_id, "listing_id")
    if not isinstance(photos, (list, tuple)) or not photos:
        raise HousingAIError("photos must be a non-empty list of mappings")

    def deny(reason: str) -> ListingVerdict:
        return ListingVerdict(allowed=False, reason=reason)

    receipts_by_digest: dict[str, PhotoEditReceipt] = {}
    for receipt in edit_receipts:
        try:
            if not hmac.compare_digest(
                jcs_sha256_hex(_photo_payload(receipt)), receipt.receipt_digest
            ):
                return deny(DENY_PHOTO_TAMPERED)
        except HousingAIError:
            return deny(DENY_MALFORMED)
        if not hmac.compare_digest(receipt.listing_id, listing_id):
            return deny(DENY_PHOTO_TAMPERED)
        receipts_by_digest[receipt.photo_digest] = receipt

    for raw in photos:
        if not isinstance(raw, Mapping):
            raise HousingAIError("photos entries must be mappings")
        photo_digest = _check_hex64(raw.get("photo_digest"), "photo_digest")
        ai_edited = raw.get("ai_edited")
        if not isinstance(ai_edited, bool):
            raise HousingAIError("ai_edited must be a bool")
        if ai_edited and photo_digest not in receipts_by_digest:
            return deny(DENY_DECEPTIVE_LISTING)
    return ListingVerdict(allowed=True, reason="ok")


def listing_audit_event(verdict: ListingVerdict, *, action: str) -> dict[str, Any]:
    """Shape a listing-truth verdict as an audit event."""
    return {
        "event": LISTING_ALLOWED_EVENT if verdict.allowed else LISTING_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "receipt_id": verdict.receipt_id,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Adverse-action receipts with bound appeal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdverseActionReceipt:
    """Adverse action bound to a live appeal-window receipt."""

    action_id: str
    subject_id: str
    reasons: tuple[str, ...]
    appeal_receipt_digest: str
    human_decision_digest: str
    acted_at: int
    action_digest: str = ""
    schema_version: str = HOUSING_AI_SCHEMA_VERSION


def _action_payload(action: AdverseActionReceipt) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "subject_id": action.subject_id,
        "reasons": list(action.reasons),
        "appeal_receipt_digest": action.appeal_receipt_digest,
        "human_decision_digest": action.human_decision_digest,
        "acted_at": action.acted_at,
        "schema_version": action.schema_version,
    }


def compute_action_digest(action: AdverseActionReceipt) -> str:
    """Recompute the JCS digest an adverse-action receipt claims."""
    return jcs_sha256_hex(_action_payload(action))


def adverse_action_receipt(
    *,
    action_id: str,
    subject_id: str,
    reasons: Sequence[str],
    appeal: AppealReceipt,
    human_decision_digest: str,
    acted_at: int,
) -> AdverseActionReceipt:
    """Issue an adverse-action receipt bound to an appeal receipt.

    Fail-closed at issuance: reasons matching the 119th-batch
    ``VAGUE_REASONS`` list raise (the ECOA lesson — "model output" is
    not a reason); the appeal receipt must bind the same subject
    decision context. The action is sealed to the appeal digest so the
    appeal path cannot be swapped out later.
    """
    action_id = _check_nonempty_str(action_id, "action_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    reason_list = _check_str_list(reasons, "reasons")
    if len(set(reason_list)) != len(reason_list):
        raise HousingAIError("duplicate reason")
    for reason in reason_list:
        if reason.strip().lower() in housing.VAGUE_REASONS:
            raise HousingAIError(
                f"reason {reason!r} is not specific enough for an adverse action"
            )
    human_decision_digest = _check_hex64(human_decision_digest, "human_decision_digest")
    acted_at = _check_ts(acted_at, "acted_at")
    tamper = _verify_appeal_integrity(appeal)
    if tamper is not None:
        raise HousingAIError(f"appeal receipt invalid: {tamper}")
    bare = AdverseActionReceipt(
        action_id=action_id,
        subject_id=subject_id,
        reasons=tuple(reason_list),
        appeal_receipt_digest=appeal.appeal_digest,
        human_decision_digest=human_decision_digest,
        acted_at=acted_at,
    )
    return AdverseActionReceipt(
        action_id=bare.action_id,
        subject_id=bare.subject_id,
        reasons=bare.reasons,
        appeal_receipt_digest=bare.appeal_receipt_digest,
        human_decision_digest=bare.human_decision_digest,
        acted_at=bare.acted_at,
        action_digest=jcs_sha256_hex(_action_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class ActionVerdict:
    allowed: bool
    reason: str
    action_id: str | None = None


def check_adverse_action(
    action: AdverseActionReceipt,
    appeal: AppealReceipt | None,
    *,
    check_time: int,
) -> ActionVerdict:
    """Fail-closed check of an adverse-action receipt at use time.

    The action must be digest-intact, its bound appeal receipt must be
    the exact one presented, and that appeal must be live at
    ``check_time``. An adverse action with no live appeal path denies
    (``housing:adverse_action_no_appeal``).
    """
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> ActionVerdict:
        return ActionVerdict(allowed=False, reason=reason)

    try:
        if not hmac.compare_digest(
            compute_action_digest(action), action.action_digest
        ):
            return deny(DENY_ACTION_TAMPERED)
    except HousingAIError:
        return deny(DENY_MALFORMED)
    if appeal is None:
        return deny(DENY_ACTION_NO_APPEAL)
    if not hmac.compare_digest(appeal.appeal_digest, action.appeal_receipt_digest):
        return deny(DENY_ACTION_TAMPERED)
    appeal_verdict = check_appeal(
        appeal, decision_digest=appeal.decision_digest, check_time=check_time
    )
    if not appeal_verdict.allowed:
        return deny(DENY_ACTION_NO_APPEAL)
    return ActionVerdict(allowed=True, reason="ok", action_id=action.action_id)


def action_audit_event(verdict: ActionVerdict, *, action: str) -> dict[str, Any]:
    """Shape an adverse-action verdict as an audit event."""
    return {
        "event": ACTION_ALLOWED_EVENT if verdict.allowed else ACTION_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "action_id": verdict.action_id,
        "schema_version": HOUSING_AI_SCHEMA_VERSION,
    }


__all__ = [
    "HOUSING_AI_SCHEMA_VERSION",
    "REQUIRED_SCREENING_SLICES",
    "APPEAL_CHANNELS",
    "MIN_APPEAL_WINDOW_DAYS",
    "MIN_TRAINING_DATA_AGE_DAYS",
    "AVM_USE_KINDS",
    "PHOTO_EDITS",
    "MATERIAL_EDITS",
    "VOUCHER_TREATMENTS",
    "HousingAIError",
    "ScreeningProbeVerdict",
    "screening_fairness_probe",
    "probe_audit_event",
    "VoucherVerdict",
    "voucher_income_gate",
    "AppealReceipt",
    "issue_appeal_receipt",
    "compute_appeal_digest",
    "AppealVerdict",
    "check_appeal",
    "appeal_window",
    "appeal_audit_event",
    "TrainingSource",
    "TrainingDataReceipt",
    "declare_training_data",
    "CoordinationVerdict",
    "rent_coordination_probe",
    "RentRecommendationVerdict",
    "rent_recommendation_gate",
    "coordination_audit_event",
    "AVMVerdict",
    "avm_confidence_gate",
    "avm_audit_event",
    "SteeringProbeReceipt",
    "SealedSteeringVerdict",
    "steering_probe",
    "check_steering_probe_receipt",
    "steering_audit_event",
    "PhotoEditReceipt",
    "issue_photo_edit_receipt",
    "ListingVerdict",
    "listing_truth_receipt",
    "listing_audit_event",
    "AdverseActionReceipt",
    "adverse_action_receipt",
    "compute_action_digest",
    "ActionVerdict",
    "check_adverse_action",
    "action_audit_event",
    "DENY_NO_PROBE",
    "DENY_PROBE_EXPIRED",
    "DENY_PROBE_FUTURE",
    "DENY_PROBE_TAMPERED",
    "DENY_PROBE_SELF_AUDITED",
    "DENY_VOUCHER_SLICE_MISSING",
    "DENY_VOUCHER_INCOME",
    "DENY_VOUCHER_POLICY_UNDECLARED",
    "DENY_NO_APPEAL",
    "DENY_APPEAL_TAMPERED",
    "DENY_APPEAL_EXPIRED",
    "DENY_APPEAL_WINDOW_SHORT",
    "DENY_COORDINATION",
    "DENY_RECENCY",
    "DENY_TRAINING_TAMPERED",
    "DENY_AUTO_ACCEPT",
    "DENY_AVM_REVIEW",
    "DENY_STEERING",
    "DENY_STEERING_TAMPERED",
    "DENY_DECEPTIVE_LISTING",
    "DENY_PHOTO_TAMPERED",
    "DENY_ACTION_NO_APPEAL",
    "DENY_ACTION_TAMPERED",
    "DENY_VAGUE_REASON",
    "DENY_MALFORMED",
]
