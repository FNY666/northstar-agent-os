"""Agriculture & food-system AI discipline (one-hundred-fifty-fourth batch).

Absorbs the 2026 AI-agrifood research thread:

* **India FASAL / MNCFC (PIB 2026-08-11)** — satellite yield forecasts
  for 11 crops in 20 states feed the Krishi Decision Support System
  and are used *directly* in crop-insurance claim settlement: an
  already-deployed "AI assessment -> money consequences" scenario.
* **China 伏羲农场 (CCTV 2026-03)** — soil-health robots and
  variable-rate fertilizing (~15% fertilizer-cost cut claimed by the
  project team); AI doses go straight to the field with no stated
  liability assignment when a wrong dose cuts yield.
* **John Deere (2026)** — autonomous 8R on general sale, See & Spray
  on 5M+ acres, and the "JD" conversational assistant for Latin
  America (only customer-authorized Operations Center data). Critic
  qu3ry.net (2026-03): autonomous tractors have no structured
  *capability envelope* — wet soil, obstacles, degraded hardware
  change what the machine can reliably do, but the system never
  re-evaluates whether it should run the configured job; it only
  stops when it detects something.
* **Japan ABC 株式会社 (2026-09)** — "AI に農業はできるか" social
  experiment: 100% of farming decisions made by AI, humans only
  execute — even when the judgment looks wrong. The counter-lesson:
  an AI judgment must be vetoable by a safety envelope.
* **Brazil (2026)** — drone+AI mapping turned into instant agronomic
  prescriptions (per-plant counts, pre-harvest multispectral yield
  estimates for futures planning).
* **LatAm paradox (McKinsey 2026 / IICA 2026)** — 26% of farmers use
  (free) generative AI, yet <5% of 2,500+ agri-tech solutions see
  real adoption: connectivity, cost, literacy, and local fit are the
  exclusion gate.
* **EU regulatory patchwork** — Data Act (2025-09: farmer data
  access/portability rights), CEADS agricultural data space, AI Act
  Art.12 (2026-08: automatic decision logging for high-risk AI),
  Reg 2023/564 (2026-01: digital pesticide-application records).
* **FDA FSMA 204 (2026-01)** — food traceability rule in force for
  high-risk foods; prov-core community demo shows one spray action
  satisfying AI Act + pesticide records + Farm-to-Fork via
  ``anchor_hash`` + ``record_transform`` chains.
* **phys.org 2026-06** — models trained on US/EU large-farm data give
  unreliable advice to African smallholders (mixed cropping,
  rain-fed, heterogeneous soils), *increasing* the risk for the most
  vulnerable farms.

Northstar mapping: agrifood AI discipline is a set of hash-chained
receipts. Insurance-bound assessments bind
``(assessment_id | claim_id | model_version | input_digest |
human_reviewer_id)``; anything with physical consequences must leave
a tamper-evident log; variable-input prescriptions deviating beyond
±30% from the regional recommendation need a named-human approval;
farm data is read only against a live authorization receipt
``(scope | principal | expiry | purpose)``; agronomic advice binds an
applicability-domain statement and degrades to "ask an agronomist"
outside it; smallholder deployments must prove an offline/low-
bandwidth fallback in the farmer's language; embodied field robots
bind a capability envelope and refuse out-of-envelope commands
(never just "stop on detect"); and sensor→AI→application→product
traceability forms one hash-anchored chain (FSMA 204 lesson).

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* Receipts bind the *declared* agrifood discipline; they do not make
  farms resilient, models locally valid, or insurance payouts fair.
* The ±30% prescription band, 90-day assessment-review shelf life,
  and 30-day envelope validity are bench parameters drawn from the
  2026 research sweep; confirm against the deployment's agronomic
  standards before field reliance.
* An applicability-domain statement records claimed training
  coverage; it cannot prove the model is actually safe in that
  domain — that needs field validation.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
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


AGRIFOOD_SCHEMA_VERSION = "northstar.agrifood.v1"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128
_DAY_S = 86_400

CLASS_AUTHORITATIVE = "authoritative"
CLASS_NON_AUTHORITATIVE = "non_authoritative"

#: Prescription deviation band: variable-input prescriptions deviating
#: beyond this fraction from the regional recommendation need a
#: named-human approval before execution (±30% rule, bench
#: parameter drawn from the 2026 agrifood sweep).
PRESCRIPTION_DEVIATION_MAX = 0.30

#: Assessment-review shelf life (FASAL lesson: insurance-bound
#: assessments must be recently reviewed by a named human).
ASSESSMENT_REVIEW_MAX_AGE_S = 90 * _DAY_S

#: Capability-envelope validity for field robots.
ENVELOPE_MAX_AGE_S = 30 * _DAY_S

#: Data-authorization receipts may not be issued longer than this.
DATA_AUTH_MAX_TTL_S = 365 * _DAY_S

#: Traceability chain stages in order (sensor → AI decision →
#: application → product provenance; FSMA 204 lesson).
TRACE_STAGES = ("sensor", "decision", "application", "provenance")


class AgrifoodError(ValueError):
    """A malformed agrifood receipt or a programming error.

    Raised for structural problems (bad digests, unknown checks,
    broken chains). Verification *failures* (unreceipted insurance
    assessments, out-of-envelope robot commands, broken traceability)
    return an :class:`AgrifoodVerdict` with ``allowed=False``
    instead — a failed gate is a verdict, a malformed receipt is a
    bug.
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
        raise AgrifoodError(f"{field_name} must be a 64-char lowercase hex digest")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgrifoodError(f"{field_name} must be a non-empty string")
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AgrifoodError(f"{field_name} must be a non-negative int epoch")
    return value


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, _HEX64_LENGTH):
        raise AgrifoodError("authority_pubkey_hex must be a 64-char lowercase hex digest")
    return value


def _check_sig_hex(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise AgrifoodError(f"{field_name} must be a 128-char lowercase hex signature")
    return value


def _check_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise AgrifoodError(f"{field_name} must be a bool")
    return value


def _check_nonneg_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise AgrifoodError(f"{field_name} must be a non-negative number")
    return float(value)


def _check_ratio(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AgrifoodError(f"{field_name} must be a number")
    if not 0.0 <= value <= 1.0:
        raise AgrifoodError(f"{field_name} must be in [0, 1]")
    return float(value)


def _check_str_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise AgrifoodError(f"{field_name} must be a non-empty list of strings")
    items = tuple(_check_nonempty_str(v, f"{field_name} item") for v in value)
    return items


# ---------------------------------------------------------------------------
# Signing and chain verification
# ---------------------------------------------------------------------------


def _verify_signature(
    pubkey_hex: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
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
    """Raise :class:`AgrifoodError` if a receipt log is tampered/broken.

    Every entry must expose ``receipt_digest`` and ``prev_digest`` and
    a ``_payload()`` method; the entries must form one chain from
    ``"genesis"`` with recomputing digests and valid authority
    signatures.
    """
    expected_prev = _GENESIS
    for entry in log:
        if not hmac.compare_digest(entry.receipt_digest, jcs_sha256_hex(entry._payload())):
            raise AgrifoodError(
                f"{type_name} receipt {entry.receipt_id!r} digest does not recompute"
            )
        if not hmac.compare_digest(entry.prev_digest, expected_prev):
            raise AgrifoodError(
                f"{type_name} receipt {entry.receipt_id!r} chain break: "
                f"expected prev {expected_prev!r}"
            )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(
            entry.authority_pubkey_hex, signed_body, entry.signature_hex
        ):
            raise AgrifoodError(
                f"{type_name} receipt {entry.receipt_id!r} authority signature invalid"
            )
        expected_prev = entry.receipt_digest


@dataclass(frozen=True)
class AgrifoodVerdict:
    """Outcome of one agrifood-discipline gate check."""

    allowed: bool
    reason: str
    classification: str = CLASS_NON_AUTHORITATIVE
    receipt_digest: str = ""


def _deny(code: str, detail: str) -> AgrifoodVerdict:
    return AgrifoodVerdict(
        allowed=False,
        reason=f"{code}: {detail}",
        classification=CLASS_NON_AUTHORITATIVE,
    )


def _allow(detail: str, receipt_digest: str = "") -> AgrifoodVerdict:
    return AgrifoodVerdict(
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

# ---------------------------------------------------------------------------
# 1. Insurance assessment receipts (India FASAL lesson)
# ---------------------------------------------------------------------------
#
# Remote-sensing yield assessments are already used directly for
# crop-insurance claim settlement (PIB 2026-08-11). An assessment that
# touches a claim must bind a receipt with the model version, the
# input digest, and a named-human review signature. Assessments
# without a live receipt are NON_AUTHORITATIVE:
# ``agrifood:unreceipted_assessment``.


@dataclass(frozen=True)
class AssessmentReceipt:
    """Binds an AI yield/damage assessment to an insurance claim."""

    receipt_id: str
    assessment_id: str
    claim_id: str
    model_version: str
    input_digest: str
    confidence_bps: int
    human_reviewer_id: str
    reviewed_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "assessment",
            "receipt_id": self.receipt_id,
            "assessment_id": self.assessment_id,
            "claim_id": self.claim_id,
            "model_version": self.model_version,
            "input_digest": self.input_digest,
            "confidence_bps": self.confidence_bps,
            "human_reviewer_id": self.human_reviewer_id,
            "reviewed_at": self.reviewed_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class AssessmentRegistry:
    """Hash-chained log of insurance assessment receipts."""

    authorities: AuthorityRegistry
    log: list[AssessmentReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        assessment_id: str,
        claim_id: str,
        model_version: str,
        input_digest: str,
        confidence_bps: int,
        human_reviewer_id: str,
        reviewed_at: int,
        authority_id: str,
        signature: bytes,
    ) -> AssessmentReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(assessment_id, "assessment_id")
        _check_nonempty_str(claim_id, "claim_id")
        _check_nonempty_str(model_version, "model_version")
        _check_hex64(input_digest, "input_digest")
        if (
            not isinstance(confidence_bps, int)
            or isinstance(confidence_bps, bool)
            or not 0 <= confidence_bps <= 10_000
        ):
            raise AgrifoodError("confidence_bps must be an int in [0, 10000]")
        _check_nonempty_str(human_reviewer_id, "human_reviewer_id")
        _check_ts(reviewed_at, "reviewed_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = AssessmentReceipt(
            receipt_id=receipt_id,
            assessment_id=assessment_id,
            claim_id=claim_id,
            model_version=model_version,
            input_digest=input_digest,
            confidence_bps=confidence_bps,
            human_reviewer_id=human_reviewer_id,
            reviewed_at=reviewed_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AgrifoodError("assessment receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, assessment_id: str) -> AssessmentReceipt | None:
        for entry in self.log:
            if entry.assessment_id == assessment_id:
                return entry
        return None


def assessment_claim_receipt(
    registry: AssessmentRegistry,
    assessment_id: str,
    now: int,
    max_review_age_s: int = ASSESSMENT_REVIEW_MAX_AGE_S,
) -> AgrifoodVerdict:
    """Insurance-bound AI assessments need a live, human-reviewed receipt.

    The receipt must exist, name a human reviewer, and the review
    must be fresh; expired receipts read as no receipt (FASAL lesson:
    AI assessment -> money consequences needs an auditable binding).
    """
    _check_nonempty_str(assessment_id, "assessment_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "assessment")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    entry = registry.find(assessment_id)
    if entry is None:
        return _deny(
            "agrifood:unreceipted_assessment",
            f"insurance assessment {assessment_id!r} binds no assessment "
            "receipt (model version / input digest / human review)",
        )
    if not entry.human_reviewer_id.strip():
        return _deny(
            "agrifood:no_reviewer",
            f"assessment receipt for {assessment_id!r} names no human reviewer",
        )
    if entry.reviewed_at > now:
        return _deny(
            "agrifood:future_review",
            f"assessment receipt for {assessment_id!r} is reviewed in the future",
        )
    if now - entry.reviewed_at > max_review_age_s:
        return _deny(
            "agrifood:stale_assessment",
            f"assessment receipt for {assessment_id!r} review is older than "
            f"{max_review_age_s}s",
        )
    return _allow(
        f"insurance assessment {assessment_id!r} bound: receipt {entry.receipt_id!r} "
        f"reviewed by {entry.human_reviewer_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 2. Physical-consequence logs (EU AI Act Art.12 generalization)
# ---------------------------------------------------------------------------
#
# From 2026-08, high-risk AI under the EU AI Act must automatically
# log decisions. Generalized: any AI decision with physical-world
# consequences (pesticide spray, variable-rate fertilizing, irrigation
# switching) must write a tamper-evident log entry binding the model
# version and input-sensor digest. A physical action with no log
# entry is refused as ``agrifood:no_consequence_log``.


@dataclass(frozen=True)
class ConsequenceLogEntry:
    """Tamper-evident log of one AI decision with physical consequences."""

    receipt_id: str
    action_id: str
    action_kind: str
    model_version: str
    input_digest: str
    decided_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "consequence_log",
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "action_kind": self.action_kind,
            "model_version": self.model_version,
            "input_digest": self.input_digest,
            "decided_at": self.decided_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ConsequenceLogRegistry:
    """Hash-chained log of physical-consequence decisions."""

    authorities: AuthorityRegistry
    log: list[ConsequenceLogEntry] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        action_id: str,
        action_kind: str,
        model_version: str,
        input_digest: str,
        decided_at: int,
        authority_id: str,
        signature: bytes,
    ) -> ConsequenceLogEntry:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(action_id, "action_id")
        _check_nonempty_str(action_kind, "action_kind")
        _check_nonempty_str(model_version, "model_version")
        _check_hex64(input_digest, "input_digest")
        _check_ts(decided_at, "decided_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        entry = ConsequenceLogEntry(
            receipt_id=receipt_id,
            action_id=action_id,
            action_kind=action_kind,
            model_version=model_version,
            input_digest=input_digest,
            decided_at=decided_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, entry.signature_hex):
            raise AgrifoodError("consequence-log authority signature invalid")
        self.log.append(entry)
        return entry

    def find(self, action_id: str) -> ConsequenceLogEntry | None:
        for entry in self.log:
            if entry.action_id == action_id:
                return entry
        return None


def physical_consequence_log(
    registry: ConsequenceLogRegistry,
    action_id: str,
    now: int,
) -> AgrifoodVerdict:
    """Physical AI actions must leave a tamper-evident decision log.

    Sprays, variable-rate doses, irrigation switches: the decision
    entry must exist before the action is treated as authorized (EU
    AI Act Art.12 lesson).
    """
    _check_nonempty_str(action_id, "action_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "consequence_log")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    entry = registry.find(action_id)
    if entry is None:
        return _deny(
            "agrifood:no_consequence_log",
            f"physical action {action_id!r} has no tamper-evident decision "
            "log entry (model version / input digest)",
        )
    if entry.decided_at > now:
        return _deny(
            "agrifood:future_decision",
            f"consequence log for {action_id!r} is decided in the future",
        )
    return _allow(
        f"physical action {action_id!r} logged: {entry.action_kind!r} "
        f"decided by {entry.model_version!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 3. Prescription human-final gate (伏羲农场 ±30% rule)
# ---------------------------------------------------------------------------
#
# AI variable-input prescriptions (fertilizer, pesticide, irrigation)
# go straight to actuators in 2026 deployments with no stated
# liability for wrong doses. Rule: a prescription deviating beyond
# ±30% from the regional recommendation needs a named-human approval
# bound to the exact prescribed values; in-band prescriptions pass
# without one.


@dataclass(frozen=True)
class PrescriptionReceipt:
    """Binds an AI variable-input prescription, with its approval."""

    receipt_id: str
    prescription_id: str
    field_id: str
    input_kind: str
    prescribed_value: float
    regional_recommendation: float
    approver_id: str
    approved_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "prescription",
            "receipt_id": self.receipt_id,
            "prescription_id": self.prescription_id,
            "field_id": self.field_id,
            "input_kind": self.input_kind,
            "prescribed_value": self.prescribed_value,
            "regional_recommendation": self.regional_recommendation,
            "approver_id": self.approver_id,
            "approved_at": self.approved_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class PrescriptionRegistry:
    """Hash-chained log of prescription receipts."""

    authorities: AuthorityRegistry
    log: list[PrescriptionReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        prescription_id: str,
        field_id: str,
        input_kind: str,
        prescribed_value: float,
        regional_recommendation: float,
        approver_id: str,
        approved_at: int,
        authority_id: str,
        signature: bytes,
    ) -> PrescriptionReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(prescription_id, "prescription_id")
        _check_nonempty_str(field_id, "field_id")
        _check_nonempty_str(input_kind, "input_kind")
        _check_nonneg_number(prescribed_value, "prescribed_value")
        _check_nonneg_number(regional_recommendation, "regional_recommendation")
        if not isinstance(approver_id, str):
            raise AgrifoodError("approver_id must be a string")
        _check_ts(approved_at, "approved_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = PrescriptionReceipt(
            receipt_id=receipt_id,
            prescription_id=prescription_id,
            field_id=field_id,
            input_kind=input_kind,
            prescribed_value=float(prescribed_value),
            regional_recommendation=float(regional_recommendation),
            approver_id=approver_id,
            approved_at=approved_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AgrifoodError("prescription receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, prescription_id: str) -> PrescriptionReceipt | None:
        for entry in self.log:
            if entry.prescription_id == prescription_id:
                return entry
        return None


def prescription_human_final_gate(
    registry: PrescriptionRegistry,
    prescription_id: str,
    now: int,
    deviation_max: float = PRESCRIPTION_DEVIATION_MAX,
) -> AgrifoodVerdict:
    """Out-of-band prescriptions need a named-human approval.

    Deviation = |prescribed - regional| / regional. In-band
    prescriptions pass on the receipt alone; out-of-band ones must
    name a human approver with an approval timestamp at or before
    ``now`` (伏羲农场 lesson: AI doses need human finality when they
    leave the agronomic band).
    """
    _check_nonempty_str(prescription_id, "prescription_id")
    _check_ts(now, "now")
    _check_ratio(deviation_max, "deviation_max")
    try:
        _check_chain(registry.log, "prescription")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    entry = registry.find(prescription_id)
    if entry is None:
        return _deny(
            "agrifood:unreceipted_prescription",
            f"prescription {prescription_id!r} binds no prescription receipt",
        )
    if entry.regional_recommendation <= 0:
        deviation = float("inf")
    else:
        deviation = abs(entry.prescribed_value - entry.regional_recommendation) / (
            entry.regional_recommendation
        )
    if deviation <= deviation_max:
        return _allow(
            f"prescription {prescription_id!r} within band "
            f"(deviation {deviation:.2%} <= {deviation_max:.0%})",
            entry.receipt_digest,
        )
    if not entry.approver_id.strip():
        return _deny(
            "agrifood:unapproved_prescription",
            f"prescription {prescription_id!r} deviates {deviation:.2%} from the "
            f"regional recommendation with no named-human approval",
        )
    if entry.approved_at > now:
        return _deny(
            "agrifood:future_approval",
            f"prescription {prescription_id!r} approval is in the future",
        )
    return _allow(
        f"prescription {prescription_id!r} out of band but approved by "
        f"{entry.approver_id!r}",
        entry.receipt_digest,
    )

# ---------------------------------------------------------------------------
# 4. Farm-data authorization receipts (EU Data Act lesson)
# ---------------------------------------------------------------------------
#
# The EU Data Act gives farmers access/portability rights and the
# power to authorize third parties; John Deere's 2026 statement says
# its AI assistant answers only from customer-authorized Operations
# Center data. Northstar rule: an agent reads farm data only against
# a live authorization receipt binding
# ``(scope | principal | expiry | purpose)``; out-of-scope, expired,
# or purpose-mismatched reads are
# ``agrifood:unauthorized_access``.


@dataclass(frozen=True)
class DataAuthReceipt:
    """Binds a farmer's authorization for data access."""

    receipt_id: str
    farm_id: str
    principal_id: str
    scope: str
    purpose: str
    valid_from: int
    expires_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "data_authorization",
            "receipt_id": self.receipt_id,
            "farm_id": self.farm_id,
            "principal_id": self.principal_id,
            "scope": self.scope,
            "purpose": self.purpose,
            "valid_from": self.valid_from,
            "expires_at": self.expires_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class DataAuthRegistry:
    """Hash-chained log of data-authorization receipts."""

    authorities: AuthorityRegistry
    log: list[DataAuthReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        farm_id: str,
        principal_id: str,
        scope: str,
        purpose: str,
        valid_from: int,
        expires_at: int,
        authority_id: str,
        signature: bytes,
    ) -> DataAuthReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(farm_id, "farm_id")
        _check_nonempty_str(principal_id, "principal_id")
        _check_nonempty_str(scope, "scope")
        _check_nonempty_str(purpose, "purpose")
        _check_ts(valid_from, "valid_from")
        _check_ts(expires_at, "expires_at")
        if expires_at <= valid_from:
            raise AgrifoodError("expires_at must be after valid_from")
        if expires_at - valid_from > DATA_AUTH_MAX_TTL_S:
            raise AgrifoodError("data authorization TTL exceeds one year")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = DataAuthReceipt(
            receipt_id=receipt_id,
            farm_id=farm_id,
            principal_id=principal_id,
            scope=scope,
            purpose=purpose,
            valid_from=valid_from,
            expires_at=expires_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AgrifoodError("data-authorization receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find_live(
        self, farm_id: str, principal_id: str, now: int
    ) -> list[DataAuthReceipt]:
        return [
            e
            for e in self.log
            if e.farm_id == farm_id
            and e.principal_id == principal_id
            and e.valid_from <= now < e.expires_at
        ]


def _scope_covers(granted: str, requested: str) -> bool:
    """Granted scope covers the requested scope.

    Scopes are dot-paths (e.g. ``soil.moisture``); ``all`` covers
    everything, and a granted prefix covers its children.
    """
    if granted == "all":
        return True
    return requested == granted or requested.startswith(granted + ".")


def data_authorization_receipt(
    registry: DataAuthRegistry,
    farm_id: str,
    principal_id: str,
    scope: str,
    purpose: str,
    now: int,
) -> AgrifoodVerdict:
    """Farm data reads need a live, purpose-bound authorization receipt.

    The receipt must be live at ``now``, grant the requested scope,
    and name the same purpose; anything else is
    ``agrifood:unauthorized_access`` (EU Data Act lesson: the farmer
    holds the authorization pen).
    """
    _check_nonempty_str(farm_id, "farm_id")
    _check_nonempty_str(principal_id, "principal_id")
    _check_nonempty_str(scope, "scope")
    _check_nonempty_str(purpose, "purpose")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "data_authorization")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    live = registry.find_live(farm_id, principal_id, now)
    if not live:
        return _deny(
            "agrifood:unauthorized_access",
            f"no live data authorization for principal {principal_id!r} "
            f"on farm {farm_id!r}",
        )
    for entry in live:
        if entry.purpose != purpose:
            continue
        if _scope_covers(entry.scope, scope):
            return _allow(
                f"data read {scope!r} authorized by receipt {entry.receipt_id!r} "
                f"for purpose {purpose!r}",
                entry.receipt_digest,
            )
    return _deny(
        "agrifood:unauthorized_access",
        f"principal {principal_id!r} has no live authorization covering "
        f"scope {scope!r} for purpose {purpose!r}",
    )


# ---------------------------------------------------------------------------
# 5. Applicability-domain statements (model water-mismatch lesson)
# ---------------------------------------------------------------------------
#
# phys.org 2026-06: models trained on US/EU large-farm data give
# unreliable advice to African smallholders. Rule: agronomic advice
# must bind an applicability-domain statement declaring the training
# coverage (regions, cropping patterns); a farm outside the declared
# domain gets ``agrifood:out_of_domain`` — degrade to "consult an
# agronomist", never a high-confidence dose.


@dataclass(frozen=True)
class DomainStatement:
    """Declares where an agronomic model is claimed to be valid."""

    receipt_id: str
    statement_id: str
    model_id: str
    covered_regions: tuple[str, ...]
    covered_patterns: tuple[str, ...]
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "applicability_domain",
            "receipt_id": self.receipt_id,
            "statement_id": self.statement_id,
            "model_id": self.model_id,
            "covered_regions": list(self.covered_regions),
            "covered_patterns": list(self.covered_patterns),
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class DomainRegistry:
    """Hash-chained log of applicability-domain statements."""

    authorities: AuthorityRegistry
    log: list[DomainStatement] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        statement_id: str,
        model_id: str,
        covered_regions: list[str] | tuple[str, ...],
        covered_patterns: list[str] | tuple[str, ...],
        authority_id: str,
        signature: bytes,
    ) -> DomainStatement:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(statement_id, "statement_id")
        _check_nonempty_str(model_id, "model_id")
        regions = _check_str_list(covered_regions, "covered_regions")
        patterns = _check_str_list(covered_patterns, "covered_patterns")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        stmt = DomainStatement(
            receipt_id=receipt_id,
            statement_id=statement_id,
            model_id=model_id,
            covered_regions=regions,
            covered_patterns=patterns,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(stmt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, stmt.signature_hex):
            raise AgrifoodError("domain statement authority signature invalid")
        self.log.append(stmt)
        return stmt

    def find(self, model_id: str) -> DomainStatement | None:
        for entry in self.log:
            if entry.model_id == model_id:
                return entry
        return None


def applicability_domain_statement(
    registry: DomainRegistry,
    model_id: str,
    region: str,
    cropping_pattern: str,
    now: int,
) -> AgrifoodVerdict:
    """Agronomic advice outside the declared domain is refused.

    The model must bind a domain statement covering both the farm's
    region and its cropping pattern; otherwise the advice degrades
    to "consult an agronomist" (``agrifood:out_of_domain``) instead
    of a high-confidence dose (model water-mismatch lesson).
    """
    _check_nonempty_str(model_id, "model_id")
    _check_nonempty_str(region, "region")
    _check_nonempty_str(cropping_pattern, "cropping_pattern")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "applicability_domain")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    stmt = registry.find(model_id)
    if stmt is None:
        return _deny(
            "agrifood:no_domain_statement",
            f"model {model_id!r} binds no applicability-domain statement",
        )
    if region not in stmt.covered_regions:
        return _deny(
            "agrifood:out_of_domain",
            f"farm region {region!r} is outside model {model_id!r}'s declared "
            "training coverage: degrade to human agronomist",
        )
    if cropping_pattern not in stmt.covered_patterns:
        return _deny(
            "agrifood:out_of_domain",
            f"cropping pattern {cropping_pattern!r} is outside model "
            f"{model_id!r}'s declared coverage: degrade to human agronomist",
        )
    return _allow(
        f"model {model_id!r} in-domain for {region!r}/{cropping_pattern!r}: "
        f"statement {stmt.statement_id!r}",
        stmt.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 6. Offline fallback (smallholder exclusion lesson)
# ---------------------------------------------------------------------------
#
# IICA 2026: 2,500+ agri-tech solutions, <5% real adoption — the
# blockers are connectivity, cost, literacy, local fit. McKinsey 2026:
# LatAm farmers lead in (free) generative-AI use. Rule: a deployment
# serving smallholders must bind a readiness receipt proving an
# offline/low-bandwidth fallback in the farmer's language. When the
# network is down and no fallback exists, the agent must say so
# loudly — never silently fail (``agrifood:silent_failure``).


@dataclass(frozen=True)
class ReadinessReceipt:
    """Binds a deployment's smallholder readiness (offline + language)."""

    receipt_id: str
    deployment_id: str
    supports_offline: bool
    local_languages: tuple[str, ...]
    offline_guidance_digest: str
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "readiness",
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "supports_offline": self.supports_offline,
            "local_languages": list(self.local_languages),
            "offline_guidance_digest": self.offline_guidance_digest,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class ReadinessRegistry:
    """Hash-chained log of deployment readiness receipts."""

    authorities: AuthorityRegistry
    log: list[ReadinessReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        deployment_id: str,
        supports_offline: bool,
        local_languages: list[str] | tuple[str, ...],
        offline_guidance_digest: str,
        authority_id: str,
        signature: bytes,
    ) -> ReadinessReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(deployment_id, "deployment_id")
        _check_bool(supports_offline, "supports_offline")
        languages = _check_str_list(local_languages, "local_languages")
        _check_hex64(offline_guidance_digest, "offline_guidance_digest")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = ReadinessReceipt(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            supports_offline=supports_offline,
            local_languages=languages,
            offline_guidance_digest=offline_guidance_digest,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AgrifoodError("readiness receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, deployment_id: str) -> ReadinessReceipt | None:
        for entry in self.log:
            if entry.deployment_id == deployment_id:
                return entry
        return None


def offline_fallback_mode(
    registry: ReadinessRegistry,
    deployment_id: str,
    network_available: bool,
    language: str,
    now: int,
) -> AgrifoodVerdict:
    """Offline smallholder scenarios need a proven fallback.

    When the network is down, the deployment must have bound an
    offline fallback supporting the farmer's language; otherwise the
    agent must refuse loudly rather than fail silently
    (``agrifood:silent_failure``).
    """
    _check_nonempty_str(deployment_id, "deployment_id")
    _check_bool(network_available, "network_available")
    _check_nonempty_str(language, "language")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "readiness")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    entry = registry.find(deployment_id)
    if entry is None:
        return _deny(
            "agrifood:no_readiness",
            f"deployment {deployment_id!r} binds no smallholder-readiness receipt",
        )
    if network_available:
        return _allow(
            f"deployment {deployment_id!r} online: readiness receipt "
            f"{entry.receipt_id!r} live",
            entry.receipt_digest,
        )
    if not entry.supports_offline:
        return _deny(
            "agrifood:silent_failure",
            f"deployment {deployment_id!r} has no offline fallback while the "
            "network is down: must refuse loudly, never silently fail",
        )
    if language not in entry.local_languages:
        return _deny(
            "agrifood:silent_failure",
            f"offline fallback for {deployment_id!r} lacks language "
            f"{language!r}: must refuse loudly, never silently fail",
        )
    return _allow(
        f"deployment {deployment_id!r} offline in {language!r}: fallback "
        f"guidance {entry.offline_guidance_digest[:16]}...",
        entry.receipt_digest,
    )

# ---------------------------------------------------------------------------
# 7. Capability envelope (John Deere critique lesson)
# ---------------------------------------------------------------------------
#
# qu3ry.net 2026-03: autonomous tractors lack a structured capability
# envelope — wet soil, obstacles, hardware degradation change what the
# machine can reliably do, but nothing re-evaluates whether the job
# should run. Japan's ABC social experiment (follow the AI even when
# it looks wrong) is the anti-pattern. Rule: a field robot binds a
# capability envelope (max slope, max soil moisture, max obstacle
# density, max speed); commands outside the envelope are
# ``agrifood:envelope_breach`` — refused up front, not "stop on
# detect".


@dataclass(frozen=True)
class EnvelopeReceipt:
    """Binds a field robot's capability envelope."""

    receipt_id: str
    envelope_id: str
    robot_id: str
    max_slope_deg: float
    max_soil_moisture: float
    max_obstacle_density: float
    max_speed_ms: float
    issued_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "capability_envelope",
            "receipt_id": self.receipt_id,
            "envelope_id": self.envelope_id,
            "robot_id": self.robot_id,
            "max_slope_deg": self.max_slope_deg,
            "max_soil_moisture": self.max_soil_moisture,
            "max_obstacle_density": self.max_obstacle_density,
            "max_speed_ms": self.max_speed_ms,
            "issued_at": self.issued_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class EnvelopeRegistry:
    """Hash-chained log of capability-envelope receipts."""

    authorities: AuthorityRegistry
    log: list[EnvelopeReceipt] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        envelope_id: str,
        robot_id: str,
        max_slope_deg: float,
        max_soil_moisture: float,
        max_obstacle_density: float,
        max_speed_ms: float,
        issued_at: int,
        authority_id: str,
        signature: bytes,
    ) -> EnvelopeReceipt:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(envelope_id, "envelope_id")
        _check_nonempty_str(robot_id, "robot_id")
        _check_nonneg_number(max_slope_deg, "max_slope_deg")
        _check_nonneg_number(max_soil_moisture, "max_soil_moisture")
        _check_nonneg_number(max_obstacle_density, "max_obstacle_density")
        _check_nonneg_number(max_speed_ms, "max_speed_ms")
        _check_ts(issued_at, "issued_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        receipt = EnvelopeReceipt(
            receipt_id=receipt_id,
            envelope_id=envelope_id,
            robot_id=robot_id,
            max_slope_deg=float(max_slope_deg),
            max_soil_moisture=float(max_soil_moisture),
            max_obstacle_density=float(max_obstacle_density),
            max_speed_ms=float(max_speed_ms),
            issued_at=issued_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(receipt._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, receipt.signature_hex):
            raise AgrifoodError("envelope receipt authority signature invalid")
        self.log.append(receipt)
        return receipt

    def find(self, robot_id: str) -> EnvelopeReceipt | None:
        for entry in reversed(self.log):
            if entry.robot_id == robot_id:
                return entry
        return None


def capability_envelope_gate(
    registry: EnvelopeRegistry,
    robot_id: str,
    conditions: Mapping[str, Any],
    now: int,
    envelope_max_age_s: int = ENVELOPE_MAX_AGE_S,
) -> AgrifoodVerdict:
    """Field-robot commands must stay inside the capability envelope.

    ``conditions`` carries the current field state
    (``soil_moisture``, ``slope_deg``, ``obstacle_density``,
    ``speed_ms``). Missing/expired envelopes are
    ``agrifood:no_envelope``; out-of-envelope conditions are
    ``agrifood:envelope_breach`` — the command is refused up front,
    never executed until "stop on detect".
    """
    _check_nonempty_str(robot_id, "robot_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "capability_envelope")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    entry = registry.find(robot_id)
    if entry is None:
        return _deny(
            "agrifood:no_envelope",
            f"robot {robot_id!r} binds no capability envelope",
        )
    if entry.issued_at > now:
        return _deny(
            "agrifood:future_envelope",
            f"envelope for robot {robot_id!r} is issued in the future",
        )
    if now - entry.issued_at > envelope_max_age_s:
        return _deny(
            "agrifood:stale_envelope",
            f"envelope for robot {robot_id!r} is older than "
            f"{envelope_max_age_s}s: re-validate before dispatch",
        )
    checks = (
        ("soil_moisture", entry.max_soil_moisture),
        ("slope_deg", entry.max_slope_deg),
        ("obstacle_density", entry.max_obstacle_density),
        ("speed_ms", entry.max_speed_ms),
    )
    for cond_name, bound in checks:
        value = _check_nonneg_number(conditions.get(cond_name), cond_name)
        if value > bound:
            return _deny(
                "agrifood:envelope_breach",
                f"robot {robot_id!r} command refused: {cond_name}={value} "
                f"exceeds envelope bound {bound} (refuse up front, not "
                "'stop on detect')",
            )
    return _allow(
        f"robot {robot_id!r} command inside envelope {entry.envelope_id!r}",
        entry.receipt_digest,
    )


# ---------------------------------------------------------------------------
# 8. Traceability chain (FSMA 204 lesson)
# ---------------------------------------------------------------------------
#
# FDA FSMA Section 204 (in force 2026-01) and the prov-core community
# demo (one spray action satisfying AI Act + pesticide records +
# Farm-to-Fork) converge on one shape: sensor → AI decision →
# application → product provenance as a single hash-anchored chain.
# Rule: a product lot must resolve to a complete, unbroken chain
# through all four stages; a missing or broken link is
# ``agrifood:traceability_breach``.


@dataclass(frozen=True)
class TraceEntry:
    """One link in a product lot's provenance chain."""

    receipt_id: str
    lot_id: str
    stage: str
    record_digest: str
    recorded_at: int
    authority_id: str
    authority_pubkey_hex: str
    signature_hex: str
    prev_digest: str

    def _payload(self) -> dict[str, Any]:
        return {
            "schema": AGRIFOOD_SCHEMA_VERSION,
            "type": "trace",
            "receipt_id": self.receipt_id,
            "lot_id": self.lot_id,
            "stage": self.stage,
            "record_digest": self.record_digest,
            "recorded_at": self.recorded_at,
            "authority_id": self.authority_id,
            "authority_pubkey_hex": self.authority_pubkey_hex,
            "signature_hex": "00" * 64,
            "prev_digest": self.prev_digest,
        }

    @property
    def receipt_digest(self) -> str:
        return jcs_sha256_hex(self._payload())


@dataclass
class TraceRegistry:
    """Hash-chained log of traceability entries."""

    authorities: AuthorityRegistry
    log: list[TraceEntry] | None = None

    def __post_init__(self) -> None:
        self.log = []

    def issue(
        self,
        receipt_id: str,
        lot_id: str,
        stage: str,
        record_digest: str,
        recorded_at: int,
        authority_id: str,
        signature: bytes,
    ) -> TraceEntry:
        _check_nonempty_str(receipt_id, "receipt_id")
        _check_nonempty_str(lot_id, "lot_id")
        if stage not in TRACE_STAGES:
            raise AgrifoodError(f"stage must be one of {TRACE_STAGES}")
        _check_hex64(record_digest, "record_digest")
        _check_ts(recorded_at, "recorded_at")
        pubkey = self.authorities.pubkey(authority_id)
        if pubkey is None:
            raise AgrifoodError(f"unknown authority {authority_id!r}")
        prev = self.log[-1].receipt_digest if self.log else _GENESIS
        entry = TraceEntry(
            receipt_id=receipt_id,
            lot_id=lot_id,
            stage=stage,
            record_digest=record_digest,
            recorded_at=recorded_at,
            authority_id=authority_id,
            authority_pubkey_hex=pubkey,
            signature_hex=signature.hex(),
            prev_digest=prev,
        )
        signed_body = dict(entry._payload())
        signed_body["signature_hex"] = "00" * 64
        if not _verify_signature(pubkey, signed_body, entry.signature_hex):
            raise AgrifoodError("trace entry authority signature invalid")
        self.log.append(entry)
        return entry

    def chain_for(self, lot_id: str) -> list[TraceEntry]:
        return [e for e in self.log if e.lot_id == lot_id]


def traceability_chain(
    registry: TraceRegistry,
    lot_id: str,
    now: int,
) -> AgrifoodVerdict:
    """A product lot must resolve to a complete hash-anchored chain.

    All four stages (sensor → decision → application → provenance)
    must be present in order for the lot, with each link's
    ``prev_digest`` pointing at the previous link's digest. A
    missing or broken link is ``agrifood:traceability_breach``
    (FSMA 204 lesson: recall must be able to walk the chain).
    """
    _check_nonempty_str(lot_id, "lot_id")
    _check_ts(now, "now")
    try:
        _check_chain(registry.log, "trace")
    except AgrifoodError as exc:
        return _deny("agrifood:chain_broken", str(exc))
    chain = registry.chain_for(lot_id)
    if not chain:
        return _deny(
            "agrifood:traceability_breach",
            f"lot {lot_id!r} has no traceability entries at all",
        )
    stages = [e.stage for e in chain]
    if stages != list(TRACE_STAGES):
        return _deny(
            "agrifood:traceability_breach",
            f"lot {lot_id!r} chain stages {stages} != "
            f"required {list(TRACE_STAGES)}: cannot walk sensor->AI->"
            "application->provenance",
        )
    for entry in chain:
        if entry.recorded_at > now:
            return _deny(
                "agrifood:future_trace",
                f"trace entry {entry.receipt_id!r} for lot {lot_id!r} is "
                "recorded in the future",
            )
    return _allow(
        f"lot {lot_id!r} resolves through all four stages: "
        f"{chain[-1].receipt_digest[:16]}...",
        chain[-1].receipt_digest,
    )


__all__ = [
    "AGRIFOOD_SCHEMA_VERSION",
    "PRESCRIPTION_DEVIATION_MAX",
    "ASSESSMENT_REVIEW_MAX_AGE_S",
    "ENVELOPE_MAX_AGE_S",
    "DATA_AUTH_MAX_TTL_S",
    "TRACE_STAGES",
    "CLASS_AUTHORITATIVE",
    "CLASS_NON_AUTHORITATIVE",
    "AgrifoodError",
    "AgrifoodVerdict",
    "AuthorityRegistry",
    "AssessmentReceipt",
    "AssessmentRegistry",
    "ConsequenceLogEntry",
    "ConsequenceLogRegistry",
    "PrescriptionReceipt",
    "PrescriptionRegistry",
    "DataAuthReceipt",
    "DataAuthRegistry",
    "DomainStatement",
    "DomainRegistry",
    "ReadinessReceipt",
    "ReadinessRegistry",
    "EnvelopeReceipt",
    "EnvelopeRegistry",
    "TraceEntry",
    "TraceRegistry",
    "assessment_claim_receipt",
    "physical_consequence_log",
    "prescription_human_final_gate",
    "data_authorization_receipt",
    "applicability_domain_statement",
    "offline_fallback_mode",
    "capability_envelope_gate",
    "traceability_chain",
]
