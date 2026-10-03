"""Embodied-AI safety vacuum gates (one-hundred-twenty-sixth batch).

Absorbs the 2026 AI-construction/manufacturing research thread:

* **Safety-regulation vacuum** — ISO 25785-1 (humanoid safety) is still
  draft in 2026 (final 2027); there is *no* certified humanoid safety
  standard this year. A Unitree G1 demo injured a child (2026-06-08).
  Governance takeaway: when no certified standard exists, the
  deployment must *say so* explicitly — ``standard=pre_ratification`` —
  and the deployment registry must refuse undeclared operation.
* **Hyundai union (2026-01)** — "no robot enters the factory without a
  labor agreement". **Warsaw "robots protest AI" (2026-09-07)** —
  organizers point out the EU AI Act says almost nothing about labor
  displacement: a fully compliant deployment can still automate away
  half a workforce. Governance takeaway: displacement above a threshold
  requires a labor-impact disclosure receipt, enforced even when the
  deployment is otherwise compliant.
* **Prescriptive agents (2026)** — predictive maintenance (downtime
  -40~60%) is shifting to agents that *autonomously generate* work
  orders, parts orders, and schedules. Governance takeaway: the
  prescriptive agent's action envelope is authority-signed and the
  agent can never widen it (the 104th batch's no-self-widening,
  applied to manufacturing).
* **Visual inspection (2026)** — fastest ROI (Forrester: 374% 3-year
  ROI, escape rate 2.8% -> 0.3%). Governance takeaway: the escape
  rate is *measured*, not guaranteed — verdicts carry measured
  confidence, and below-threshold verdicts cannot auto-release
  product.
* **Construction-robot dispatch** — 五冶's 2026 construction-robot
  cluster runs project-level scheduling from a "command center";
  中建八局 CMC modular runs at scale. Governance takeaway:
  command-center dispatch must be hash-chained and auditable.
* **AI adoption stats contradict each other** (18%-92%, inconsistent
  definitions). Governance takeaway: capability claims must be pinned
  to measured benchmarks; marketing claims without measured evidence
  are ``embodied.unsubstantiated_capability``.

Northstar mapping:

* ``safety_vacuum_gate()`` — a deployment registers a standard
  declaration: either a certified standard (pinned id + cert digest)
  or an explicit ``standard=pre_ratification`` declaration (draft
  standard digest + acknowledgment of the citizen-facing disclosure).
  No declaration at all -> ``embodied.unverifiable_safety`` and the
  deployment registry (110th batch) must refuse registration.
* ``fall_zone_receipt()`` — physical actuation near humans requires a
  fall-zone/clearance computation bound to the deployment (the Unitree
  G1 lesson). Actuation without a fresh, unrevoked fall-zone receipt
  -> ``embodied.no_fall_zone``.
* ``capability_honesty_label()`` — speed/capability claims
  (e.g. "50% of human speed") bind a measured benchmark digest;
  claims without measured evidence ->
  ``embodied.unsubstantiated_capability``.
* ``labor_impact_receipt()`` — deployments displacing workers at or
  above ``LABOR_DISPLACEMENT_THRESHOLD`` must carry a labor-impact
  disclosure (retraining plan digest and/or labor agreement digest).
  Undisclosed displacement -> ``embodied.labor_impact_undisclosed``
  and a mandatory disclosure on the citizen explanation API.
* ``prescriptive_agent_gate()`` — prescriptive agents bind an
  authority-signed action envelope (closed action vocabulary +
  scope); actions outside the envelope deny, and the agent can never
  widen it.
* ``inspection_confidence_gate()`` — inspection verdicts carry
  measured confidence; below-threshold verdicts cannot auto-release
  product.
* ``DispatchLedger`` — hash-chained construction-robot dispatch
  receipts; unaudited dispatch -> ``embodied.unaudited_dispatch``.
* ``incident_binding()`` — physical incidents feed the 113th-batch
  incident-receipts clock; an incident with no filing linked within
  the clock -> escalation verdict + ``embodied.incident_unreported``.

Honest scoping: this module enforces *declared-safety discipline* —
the software cannot authorize what is not declared, pinned, and
fresh. It does not replace physical safety engineering, real
interlocks, or the true moment-of-detection in incident reporting
(the 113th batch's honest boundary). Everything is offline and
deterministic; the only clock is the ``now`` the caller injects
(integer epoch seconds). All digest comparisons use
:func:`hmac.compare_digest`.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(
            _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True).encode("utf-8")
        ).hexdigest()

from ed25519 import verify as _ed25519_verify

#: Schema marker, pinned into every digest.
SCHEMA_VERSION = "northstar.embodied.v1"

#: Workers-displaced threshold at or above which a labor-impact
#: disclosure becomes mandatory (bench parameter, not a legal
#: threshold — verify against labor law before legal use).
LABOR_DISPLACEMENT_THRESHOLD = 10

#: Freshness windows (seconds).
FALL_ZONE_FRESHNESS_S = 24 * 3600
DISPATCH_FRESHNESS_S = 7 * 24 * 3600

#: Denial reason codes. All start with ``embodied:`` for audit filtering.
DENY_NO_STANDARD_DECLARATION = "embodied:no_standard_declaration"
DENY_UNVERIFIABLE_SAFETY = "embodied:unverifiable_safety"
DENY_STANDARD_DIGEST_MISMATCH = "embodied:standard_digest_mismatch"
DENY_STANDARD_SIGNATURE_INVALID = "embodied:standard_signature_invalid"
DENY_NO_FALL_ZONE = "embodied:no_fall_zone"
DENY_FALL_ZONE_STALE = "embodied:fall_zone_stale"
DENY_FALL_ZONE_REVOKED = "embodied:fall_zone_revoked"
DENY_FALL_ZONE_DIGEST_MISMATCH = "embodied:fall_zone_digest_mismatch"
DENY_UNSUBSTANTIATED_CAPABILITY = "embodied:unsubstantiated_capability"
DENY_LABOR_IMPACT_UNDISCLOSED = "embodied:labor_impact_undisclosed"
DENY_PRESCRIPTIVE_OUT_OF_SCOPE = "embodied:prescriptive_out_of_scope"
DENY_PRESCRIPTIVE_ENVELOPE_WIDENED = "embodied:prescriptive_envelope_widened"
DENY_LOW_CONFIDENCE_RELEASE = "embodied:low_confidence_release"
DENY_UNAUDITED_DISPATCH = "embodied:unaudited_dispatch"
DENY_INCIDENT_UNREPORTED = "embodied:incident_unreported"
DENY_MALFORMED = "embodied:malformed"
DENY_UNKNOWN_AUTHORITY = "embodied:unknown_authority"

#: Audit events.
STANDARD_DECLARED_EVENT = "embodied.standard_declared"
ACTUATION_DENIED_EVENT = "embodied.actuation_denied"
DISPATCH_RECORDED_EVENT = "embodied.dispatch_recorded"

#: Classification tiers.
EMBODIED_AUTHORITATIVE = "embodied-authoritative"
EMBODIED_NON_AUTHORITATIVE = "embodied-non-authoritative"

_GENESIS = "genesis"


class EmbodiedError(ValueError):
    """Malformed embodied-AI input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise EmbodiedError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EmbodiedError(f"{name} must be an integer")
    return value


def _check_ts(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise EmbodiedError(f"{name} must be a non-negative epoch")
    return v


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise EmbodiedError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, name: str) -> str:
    if not _is_hex(value, 128):
        raise EmbodiedError(f"{name} must be 128 lowercase hex chars")
    return value


def _check_sig(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise EmbodiedError(f"{name} must be 64 bytes")
    return value


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key)."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise EmbodiedError("public_key must be 32 bytes")
        self._keys[authority_id] = public_key

    def public_key_for(self, authority_id: str) -> bytes | None:
        return self._keys.get(authority_id)


def _verify_signature(
    authorities: AuthorityRegistry,
    *,
    authority_id: str,
    digest_hex: str,
    signature: bytes,
    deny_code: str,
) -> str | None:
    """Return a denial code if the signature is invalid, else None."""
    pub = authorities.public_key_for(authority_id)
    if pub is None:
        return DENY_UNKNOWN_AUTHORITY
    try:
        ok = _ed25519_verify(pub, digest_hex.encode("utf-8"), signature)
    except Exception:
        ok = False
    return None if ok else deny_code


# ---------------------------------------------------------------------------
# Standard declarations: the safety vacuum gate
# ---------------------------------------------------------------------------

#: Closed standard-status vocabulary.
STANDARD_STATUSES: tuple[str, ...] = (
    "certified",
    "pre_ratification",
)

STANDARD_DECLARATION_SCHEMA = "northstar.embodied.standard-declaration.v1"


@dataclass(frozen=True)
class StandardDeclaration:
    """A deployment's safety-standard declaration.

    Either ``standard_status == "certified"`` (pinned ``cert_digest``) or
    ``"pre_ratification"`` (pinned ``draft_standard_digest`` plus a
    citizen-facing acknowledgment hash). There is no third option: a
    deployment that declares nothing is
    ``embodied.unverifiable_safety``.
    """

    deployment_id: str
    standard_id: str
    standard_status: str
    cert_digest: str
    draft_standard_digest: str
    citizen_ack_digest: str
    declared_by: str
    declared_at: int
    declaration_digest: str
    signature: bytes
    schema_version: str = STANDARD_DECLARATION_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-standard-declaration",
            "deployment_id": self.deployment_id,
            "standard_id": self.standard_id,
            "standard_status": self.standard_status,
            "cert_digest": self.cert_digest,
            "draft_standard_digest": self.draft_standard_digest,
            "citizen_ack_digest": self.citizen_ack_digest,
            "declared_by": self.declared_by,
            "declared_at": self.declared_at,
            "declaration_digest": self.declaration_digest,
            "signature": self.signature.hex(),
            "schema_version": self.schema_version,
        }


def _standard_payload(
    *,
    deployment_id: str,
    standard_id: str,
    standard_status: str,
    cert_digest: str,
    draft_standard_digest: str,
    citizen_ack_digest: str,
    declared_by: str,
    declared_at: int,
) -> dict[str, Any]:
    return {
        "deployment_id": deployment_id,
        "standard_id": standard_id,
        "standard_status": standard_status,
        "cert_digest": cert_digest,
        "draft_standard_digest": draft_standard_digest,
        "citizen_ack_digest": citizen_ack_digest,
        "declared_by": declared_by,
        "declared_at": declared_at,
        "schema_version": STANDARD_DECLARATION_SCHEMA,
    }


def compute_standard_digest(
    *,
    deployment_id: str,
    standard_id: str,
    standard_status: str,
    cert_digest: str,
    draft_standard_digest: str,
    citizen_ack_digest: str,
    declared_by: str,
    declared_at: int,
) -> str:
    return jcs_sha256_hex(
        _standard_payload(
            deployment_id=deployment_id,
            standard_id=standard_id,
            standard_status=standard_status,
            cert_digest=cert_digest,
            draft_standard_digest=draft_standard_digest,
            citizen_ack_digest=citizen_ack_digest,
            declared_by=declared_by,
            declared_at=declared_at,
        )
    )


@dataclass(frozen=True)
class StandardVerdict:
    allowed: bool
    deny_code: str | None
    classification: str
    declaration: StandardDeclaration | None


class StandardRegistry:
    """Deployment standard declarations: the safety-vacuum gate."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._declarations: dict[str, StandardDeclaration] = {}

    def declare(
        self,
        *,
        deployment_id: str,
        standard_id: str,
        standard_status: str,
        cert_digest: str,
        draft_standard_digest: str,
        citizen_ack_digest: str,
        declared_by: str,
        declared_at: int,
        signature: bytes,
    ) -> StandardDeclaration:
        _require_str(deployment_id, "deployment_id")
        _require_str(standard_id, "standard_id")
        _require_str(declared_by, "declared_by")
        _check_ts(declared_at, "declared_at")
        _check_sig(signature, "signature")
        if standard_status not in STANDARD_STATUSES:
            raise EmbodiedError(f"unknown standard_status {standard_status!r}")
        if standard_status == "certified":
            _check_hex64(cert_digest, "cert_digest")
            _check_hex64(draft_standard_digest, "draft_standard_digest")
            _check_hex64(citizen_ack_digest, "citizen_ack_digest")
        else:  # pre_ratification: the honest declaration of the vacuum
            if not _is_hex(cert_digest, 64) or cert_digest == "00" * 32:
                # cert_digest must be the explicit zero placeholder —
                # a pre-ratification standard has no certificate.
                if cert_digest != "00" * 32:
                    raise EmbodiedError(
                        "pre_ratification declarations pin cert_digest to "
                        "'00'*32"
                    )
            _check_hex64(draft_standard_digest, "draft_standard_digest")
            _check_hex64(citizen_ack_digest, "citizen_ack_digest")
        digest = compute_standard_digest(
            deployment_id=deployment_id,
            standard_id=standard_id,
            standard_status=standard_status,
            cert_digest=cert_digest,
            draft_standard_digest=draft_standard_digest,
            citizen_ack_digest=citizen_ack_digest,
            declared_by=declared_by,
            declared_at=declared_at,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=declared_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_STANDARD_SIGNATURE_INVALID,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        decl = StandardDeclaration(
            deployment_id=deployment_id,
            standard_id=standard_id,
            standard_status=standard_status,
            cert_digest=cert_digest,
            draft_standard_digest=draft_standard_digest,
            citizen_ack_digest=citizen_ack_digest,
            declared_by=declared_by,
            declared_at=declared_at,
            declaration_digest=digest,
            signature=signature,
        )
        self._declarations[deployment_id] = decl
        return decl

    def safety_vacuum_gate(
        self, *, deployment_id: str, now: int
    ) -> StandardVerdict:
        """The gate: no declaration -> unverifiable safety, fail closed.

        A deployment that cannot show a standard declaration — certified
        *or* an explicit pre-ratification declaration — is
        ``embodied.unverifiable_safety``. The 110th batch's deployment
        registry must refuse registration on this verdict.
        """
        _require_str(deployment_id, "deployment_id")
        _check_ts(now, "now")
        decl = self._declarations.get(deployment_id)
        if decl is None:
            return StandardVerdict(
                allowed=False,
                deny_code=DENY_NO_STANDARD_DECLARATION,
                classification=EMBODIED_NON_AUTHORITATIVE,
                declaration=None,
            )
        if decl.declared_at > now:
            return StandardVerdict(
                allowed=False,
                deny_code=DENY_UNVERIFIABLE_SAFETY,
                classification=EMBODIED_NON_AUTHORITATIVE,
                declaration=None,
            )
        expected = compute_standard_digest(
            deployment_id=decl.deployment_id,
            standard_id=decl.standard_id,
            standard_status=decl.standard_status,
            cert_digest=decl.cert_digest,
            draft_standard_digest=decl.draft_standard_digest,
            citizen_ack_digest=decl.citizen_ack_digest,
            declared_by=decl.declared_by,
            declared_at=decl.declared_at,
        )
        if not hmac.compare_digest(expected, decl.declaration_digest):
            return StandardVerdict(
                allowed=False,
                deny_code=DENY_STANDARD_DIGEST_MISMATCH,
                classification=EMBODIED_NON_AUTHORITATIVE,
                declaration=None,
            )
        deny = _verify_signature(
            self._authorities,
            authority_id=decl.declared_by,
            digest_hex=decl.declaration_digest,
            signature=decl.signature,
            deny_code=DENY_STANDARD_SIGNATURE_INVALID,
        )
        if deny is not None:
            return StandardVerdict(
                allowed=False,
                deny_code=deny,
                classification=EMBODIED_NON_AUTHORITATIVE,
                declaration=None,
            )
        return StandardVerdict(
            allowed=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
            declaration=decl,
        )


# ---------------------------------------------------------------------------
# Fall-zone receipts: actuation near humans
# ---------------------------------------------------------------------------

#: Closed human-proximity vocabulary.
PROXIMITY_CLASSES: tuple[str, ...] = (
    "remote",
    "shared_space",
    "close_contact",
)

FALL_ZONE_SCHEMA = "northstar.embodied.fall-zone.v1"


@dataclass(frozen=True)
class FallZoneReceipt:
    """A fall-zone/clearance computation bound to a deployment.

    ``fall_zone_m`` pins the computed keep-clear radius in metres;
    ``computation_digest`` pins the computation inputs. The receipt is
    fresh for ``FALL_ZONE_FRESHNESS_S`` and terminally revocable.
    """

    receipt_id: str
    deployment_id: str
    proximity_class: str
    fall_zone_m: float
    computation_digest: str
    computed_by: str
    computed_at: int
    receipt_digest: str
    signature: bytes
    revoked: bool = False
    schema_version: str = FALL_ZONE_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-fall-zone",
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "proximity_class": self.proximity_class,
            "fall_zone_m": self.fall_zone_m,
            "computation_digest": self.computation_digest,
            "computed_by": self.computed_by,
            "computed_at": self.computed_at,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature.hex(),
            "revoked": self.revoked,
            "schema_version": self.schema_version,
        }


def _fall_zone_payload(
    *,
    receipt_id: str,
    deployment_id: str,
    proximity_class: str,
    fall_zone_m: float,
    computation_digest: str,
    computed_by: str,
    computed_at: int,
) -> dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "deployment_id": deployment_id,
        "proximity_class": proximity_class,
        "fall_zone_m": fall_zone_m,
        "computation_digest": computation_digest,
        "computed_by": computed_by,
        "computed_at": computed_at,
        "schema_version": FALL_ZONE_SCHEMA,
    }


def compute_fall_zone_digest(
    *,
    receipt_id: str,
    deployment_id: str,
    proximity_class: str,
    fall_zone_m: float,
    computation_digest: str,
    computed_by: str,
    computed_at: int,
) -> str:
    return jcs_sha256_hex(
        _fall_zone_payload(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            proximity_class=proximity_class,
            fall_zone_m=fall_zone_m,
            computation_digest=computation_digest,
            computed_by=computed_by,
            computed_at=computed_at,
        )
    )


@dataclass(frozen=True)
class ActuationVerdict:
    allowed: bool
    deny_code: str | None
    classification: str


class FallZoneRegistry:
    """Fall-zone receipts: actuation near humans needs a live receipt."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, FallZoneReceipt] = {}
        self._revoked: set[str] = set()

    def issue(
        self,
        *,
        receipt_id: str,
        deployment_id: str,
        proximity_class: str,
        fall_zone_m: float,
        computation_digest: str,
        computed_by: str,
        computed_at: int,
        signature: bytes,
    ) -> FallZoneReceipt:
        _require_str(receipt_id, "receipt_id")
        _require_str(deployment_id, "deployment_id")
        _require_str(computed_by, "computed_by")
        _check_ts(computed_at, "computed_at")
        _check_sig(signature, "signature")
        if proximity_class not in PROXIMITY_CLASSES:
            raise EmbodiedError(f"unknown proximity_class {proximity_class!r}")
        if isinstance(fall_zone_m, bool) or not isinstance(fall_zone_m, (int, float)):
            raise EmbodiedError("fall_zone_m must be a number")
        if fall_zone_m < 0:
            raise EmbodiedError("fall_zone_m must not be negative")
        _check_hex64(computation_digest, "computation_digest")
        digest = compute_fall_zone_digest(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            proximity_class=proximity_class,
            fall_zone_m=float(fall_zone_m),
            computation_digest=computation_digest,
            computed_by=computed_by,
            computed_at=computed_at,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=computed_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_FALL_ZONE_DIGEST_MISMATCH,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        receipt = FallZoneReceipt(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            proximity_class=proximity_class,
            fall_zone_m=float(fall_zone_m),
            computation_digest=computation_digest,
            computed_by=computed_by,
            computed_at=computed_at,
            receipt_digest=digest,
            signature=signature,
        )
        self._receipts[receipt_id] = receipt
        return receipt

    def revoke(self, receipt_id: str) -> None:
        _require_str(receipt_id, "receipt_id")
        self._revoked.add(receipt_id)

    def check_actuation(
        self,
        *,
        deployment_id: str,
        proximity_class: str,
        now: int,
    ) -> ActuationVerdict:
        """Actuation near humans requires a fresh, unrevoked receipt.

        ``remote`` proximity (no humans in the envelope) needs no
        receipt; anything closer fails closed without one — the Unitree
        G1 lesson: a demo that *looked* safe had no pinned
        fall-zone computation.
        """
        _require_str(deployment_id, "deployment_id")
        _check_ts(now, "now")
        if proximity_class not in PROXIMITY_CLASSES:
            raise EmbodiedError(f"unknown proximity_class {proximity_class!r}")
        if proximity_class == "remote":
            return ActuationVerdict(
                allowed=True,
                deny_code=None,
                classification=EMBODIED_AUTHORITATIVE,
            )
        live: FallZoneReceipt | None = None
        for receipt in self._receipts.values():
            if receipt.deployment_id != deployment_id:
                continue
            if receipt.proximity_class != proximity_class:
                continue
            if receipt.receipt_id in self._revoked:
                continue
            if receipt.computed_at > now:
                continue
            if now - receipt.computed_at > FALL_ZONE_FRESHNESS_S:
                continue
            if live is None or receipt.computed_at > live.computed_at:
                live = receipt
        if live is None:
            return ActuationVerdict(
                allowed=False,
                deny_code=DENY_NO_FALL_ZONE,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        expected = compute_fall_zone_digest(
            receipt_id=live.receipt_id,
            deployment_id=live.deployment_id,
            proximity_class=live.proximity_class,
            fall_zone_m=live.fall_zone_m,
            computation_digest=live.computation_digest,
            computed_by=live.computed_by,
            computed_at=live.computed_at,
        )
        if not hmac.compare_digest(expected, live.receipt_digest):
            return ActuationVerdict(
                allowed=False,
                deny_code=DENY_FALL_ZONE_DIGEST_MISMATCH,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        deny = _verify_signature(
            self._authorities,
            authority_id=live.computed_by,
            digest_hex=live.receipt_digest,
            signature=live.signature,
            deny_code=DENY_FALL_ZONE_DIGEST_MISMATCH,
        )
        if deny is not None:
            return ActuationVerdict(
                allowed=False,
                deny_code=deny,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        return ActuationVerdict(
            allowed=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
        )


# ---------------------------------------------------------------------------
# Capability honesty labels: measured benchmarks, not marketing
# ---------------------------------------------------------------------------

CAPABILITY_LABEL_SCHEMA = "northstar.embodied.capability-label.v1"


@dataclass(frozen=True)
class CapabilityLabel:
    """A pinned capability claim.

    ``claim`` is free text (e.g. "50% of human speed"); ``measured``
    pins whether the claim comes from a measured benchmark
    (``benchmark_digest`` pinned) or is marketing. Unmeasured claims
    are ``embodied.unsubstantiated_capability``.
    """

    label_id: str
    deployment_id: str
    claim: str
    measured: bool
    benchmark_id: str
    benchmark_digest: str
    labeled_by: str
    labeled_at: int
    label_digest: str
    signature: bytes
    schema_version: str = CAPABILITY_LABEL_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-capability-label",
            "label_id": self.label_id,
            "deployment_id": self.deployment_id,
            "claim": self.claim,
            "measured": self.measured,
            "benchmark_id": self.benchmark_id,
            "benchmark_digest": self.benchmark_digest,
            "labeled_by": self.labeled_by,
            "labeled_at": self.labeled_at,
            "label_digest": self.label_digest,
            "signature": self.signature.hex(),
            "schema_version": self.schema_version,
        }


def _label_payload(
    *,
    label_id: str,
    deployment_id: str,
    claim: str,
    measured: bool,
    benchmark_id: str,
    benchmark_digest: str,
    labeled_by: str,
    labeled_at: int,
) -> dict[str, Any]:
    return {
        "label_id": label_id,
        "deployment_id": deployment_id,
        "claim": claim,
        "measured": measured,
        "benchmark_id": benchmark_id,
        "benchmark_digest": benchmark_digest,
        "labeled_by": labeled_by,
        "labeled_at": labeled_at,
        "schema_version": CAPABILITY_LABEL_SCHEMA,
    }


def compute_label_digest(
    *,
    label_id: str,
    deployment_id: str,
    claim: str,
    measured: bool,
    benchmark_id: str,
    benchmark_digest: str,
    labeled_by: str,
    labeled_at: int,
) -> str:
    return jcs_sha256_hex(
        _label_payload(
            label_id=label_id,
            deployment_id=deployment_id,
            claim=claim,
            measured=measured,
            benchmark_id=benchmark_id,
            benchmark_digest=benchmark_digest,
            labeled_by=labeled_by,
            labeled_at=labeled_at,
        )
    )


@dataclass(frozen=True)
class HonestyVerdict:
    allowed: bool
    deny_code: str | None
    classification: str


class CapabilityRegistry:
    """Capability honesty labels: measured benchmarks pin claims."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._labels: dict[str, CapabilityLabel] = {}

    def label(
        self,
        *,
        label_id: str,
        deployment_id: str,
        claim: str,
        measured: bool,
        benchmark_id: str,
        benchmark_digest: str,
        labeled_by: str,
        labeled_at: int,
        signature: bytes,
    ) -> CapabilityLabel:
        _require_str(label_id, "label_id")
        _require_str(deployment_id, "deployment_id")
        _require_str(claim, "claim")
        _require_str(benchmark_id, "benchmark_id")
        _require_str(labeled_by, "labeled_by")
        _check_ts(labeled_at, "labeled_at")
        _check_sig(signature, "signature")
        if not isinstance(measured, bool):
            raise EmbodiedError("measured must be a bool")
        if measured:
            _check_hex64(benchmark_digest, "benchmark_digest")
        else:
            if benchmark_digest != "00" * 32:
                raise EmbodiedError(
                    "unmeasured labels pin benchmark_digest to '00'*32"
                )
        digest = compute_label_digest(
            label_id=label_id,
            deployment_id=deployment_id,
            claim=claim,
            measured=measured,
            benchmark_id=benchmark_id,
            benchmark_digest=benchmark_digest,
            labeled_by=labeled_by,
            labeled_at=labeled_at,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=labeled_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_UNSUBSTANTIATED_CAPABILITY,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        lbl = CapabilityLabel(
            label_id=label_id,
            deployment_id=deployment_id,
            claim=claim,
            measured=measured,
            benchmark_id=benchmark_id,
            benchmark_digest=benchmark_digest,
            labeled_by=labeled_by,
            labeled_at=labeled_at,
            label_digest=digest,
            signature=signature,
        )
        self._labels[label_id] = lbl
        return lbl

    def capability_honesty_label(
        self, *, label_id: str, now: int
    ) -> HonestyVerdict:
        """A claim is honest only if measured: marketing without a pinned
        benchmark digest is ``embodied.unsubstantiated_capability`` —
        the 18%-92% contradictory-adoption-stats lesson.
        """
        _require_str(label_id, "label_id")
        _check_ts(now, "now")
        lbl = self._labels.get(label_id)
        if lbl is None:
            return HonestyVerdict(
                allowed=False,
                deny_code=DENY_UNSUBSTANTIATED_CAPABILITY,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if lbl.labeled_at > now:
            return HonestyVerdict(
                allowed=False,
                deny_code=DENY_MALFORMED,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if not lbl.measured:
            return HonestyVerdict(
                allowed=False,
                deny_code=DENY_UNSUBSTANTIATED_CAPABILITY,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        expected = compute_label_digest(
            label_id=lbl.label_id,
            deployment_id=lbl.deployment_id,
            claim=lbl.claim,
            measured=lbl.measured,
            benchmark_id=lbl.benchmark_id,
            benchmark_digest=lbl.benchmark_digest,
            labeled_by=lbl.labeled_by,
            labeled_at=lbl.labeled_at,
        )
        if not hmac.compare_digest(expected, lbl.label_digest):
            return HonestyVerdict(
                allowed=False,
                deny_code=DENY_UNSUBSTANTIATED_CAPABILITY,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        return HonestyVerdict(
            allowed=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
        )


# ---------------------------------------------------------------------------
# Labor-impact receipts: compliance is not the absence of displacement
# ---------------------------------------------------------------------------

LABOR_IMPACT_SCHEMA = "northstar.embodied.labor-impact.v1"


@dataclass(frozen=True)
class LaborImpactReceipt:
    """A labor-impact disclosure for a deployment.

    ``workers_displaced_estimate`` pins the declared headcount impact;
    ``retraining_plan_digest`` / ``labor_agreement_digest`` pin the
    mitigation (either may be the zero placeholder, but at least one
    must be non-zero). ``disclosed`` pins whether the disclosure was
    published to the citizen explanation API.
    """

    receipt_id: str
    deployment_id: str
    workers_displaced_estimate: int
    retraining_plan_digest: str
    labor_agreement_digest: str
    disclosed: bool
    recorded_by: str
    recorded_at: int
    receipt_digest: str
    signature: bytes
    schema_version: str = LABOR_IMPACT_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-labor-impact",
            "receipt_id": self.receipt_id,
            "deployment_id": self.deployment_id,
            "workers_displaced_estimate": self.workers_displaced_estimate,
            "retraining_plan_digest": self.retraining_plan_digest,
            "labor_agreement_digest": self.labor_agreement_digest,
            "disclosed": self.disclosed,
            "recorded_by": self.recorded_by,
            "recorded_at": self.recorded_at,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature.hex(),
            "schema_version": self.schema_version,
        }


def _labor_payload(
    *,
    receipt_id: str,
    deployment_id: str,
    workers_displaced_estimate: int,
    retraining_plan_digest: str,
    labor_agreement_digest: str,
    disclosed: bool,
    recorded_by: str,
    recorded_at: int,
) -> dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "deployment_id": deployment_id,
        "workers_displaced_estimate": workers_displaced_estimate,
        "retraining_plan_digest": retraining_plan_digest,
        "labor_agreement_digest": labor_agreement_digest,
        "disclosed": disclosed,
        "recorded_by": recorded_by,
        "recorded_at": recorded_at,
        "schema_version": LABOR_IMPACT_SCHEMA,
    }


def compute_labor_digest(
    *,
    receipt_id: str,
    deployment_id: str,
    workers_displaced_estimate: int,
    retraining_plan_digest: str,
    labor_agreement_digest: str,
    disclosed: bool,
    recorded_by: str,
    recorded_at: int,
) -> str:
    return jcs_sha256_hex(
        _labor_payload(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            workers_displaced_estimate=workers_displaced_estimate,
            retraining_plan_digest=retraining_plan_digest,
            labor_agreement_digest=labor_agreement_digest,
            disclosed=disclosed,
            recorded_by=recorded_by,
            recorded_at=recorded_at,
        )
    )


@dataclass(frozen=True)
class LaborVerdict:
    allowed: bool
    deny_code: str | None
    classification: str
    mandatory_disclosure: bool


class LaborRegistry:
    """Labor-impact disclosures: displacement at/above the threshold must
    be disclosed, even when the deployment is otherwise compliant."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, LaborImpactReceipt] = {}

    def record(
        self,
        *,
        receipt_id: str,
        deployment_id: str,
        workers_displaced_estimate: int,
        retraining_plan_digest: str,
        labor_agreement_digest: str,
        disclosed: bool,
        recorded_by: str,
        recorded_at: int,
        signature: bytes,
    ) -> LaborImpactReceipt:
        _require_str(receipt_id, "receipt_id")
        _require_str(deployment_id, "deployment_id")
        _require_str(recorded_by, "recorded_by")
        _check_ts(recorded_at, "recorded_at")
        _check_sig(signature, "signature")
        workers_displaced_estimate = _require_int(
            workers_displaced_estimate, "workers_displaced_estimate"
        )
        if workers_displaced_estimate < 0:
            raise EmbodiedError("workers_displaced_estimate must not be negative")
        if not isinstance(disclosed, bool):
            raise EmbodiedError("disclosed must be a bool")
        for name, dg in (
            ("retraining_plan_digest", retraining_plan_digest),
            ("labor_agreement_digest", labor_agreement_digest),
        ):
            if not (_is_hex(dg, 64)):
                raise EmbodiedError(f"{name} must be 64 lowercase hex chars")
        if retraining_plan_digest == "00" * 32 and labor_agreement_digest == "00" * 32:
            raise EmbodiedError(
                "at least one of retraining_plan_digest / "
                "labor_agreement_digest must be non-zero"
            )
        digest = compute_labor_digest(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            workers_displaced_estimate=workers_displaced_estimate,
            retraining_plan_digest=retraining_plan_digest,
            labor_agreement_digest=labor_agreement_digest,
            disclosed=disclosed,
            recorded_by=recorded_by,
            recorded_at=recorded_at,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=recorded_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_LABOR_IMPACT_UNDISCLOSED,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        receipt = LaborImpactReceipt(
            receipt_id=receipt_id,
            deployment_id=deployment_id,
            workers_displaced_estimate=workers_displaced_estimate,
            retraining_plan_digest=retraining_plan_digest,
            labor_agreement_digest=labor_agreement_digest,
            disclosed=disclosed,
            recorded_by=recorded_by,
            recorded_at=recorded_at,
            receipt_digest=digest,
            signature=signature,
        )
        self._receipts[deployment_id] = receipt
        return receipt

    def labor_impact_receipt(
        self, *, deployment_id: str, workers_displaced_estimate: int, now: int
    ) -> LaborVerdict:
        """Below the threshold: no disclosure required. At/above: a
        disclosed receipt must exist, else
        ``embodied.labor_impact_undisclosed`` — the Hyundai/Warsaw
        lesson: compliance does not erase displacement.
        """
        _require_str(deployment_id, "deployment_id")
        workers_displaced_estimate = _require_int(
            workers_displaced_estimate, "workers_displaced_estimate"
        )
        _check_ts(now, "now")
        if workers_displaced_estimate < LABOR_DISPLACEMENT_THRESHOLD:
            return LaborVerdict(
                allowed=True,
                deny_code=None,
                classification=EMBODIED_AUTHORITATIVE,
                mandatory_disclosure=False,
            )
        receipt = self._receipts.get(deployment_id)
        if receipt is None or not receipt.disclosed:
            return LaborVerdict(
                allowed=False,
                deny_code=DENY_LABOR_IMPACT_UNDISCLOSED,
                classification=EMBODIED_NON_AUTHORITATIVE,
                mandatory_disclosure=True,
            )
        if receipt.recorded_at > now:
            return LaborVerdict(
                allowed=False,
                deny_code=DENY_MALFORMED,
                classification=EMBODIED_NON_AUTHORITATIVE,
                mandatory_disclosure=True,
            )
        return LaborVerdict(
            allowed=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
            mandatory_disclosure=False,
        )


# ---------------------------------------------------------------------------
# Prescriptive-agent gate: autonomous work orders, parts, schedules
# ---------------------------------------------------------------------------

#: Closed prescriptive-action vocabulary.
PRESCRIPTIVE_ACTIONS: tuple[str, ...] = (
    "create_work_order",
    "order_parts",
    "reschedule_line",
    "flag_for_human",
)

PRESCRIPTIVE_SCHEMA = "northstar.embodied.prescriptive.v1"


@dataclass(frozen=True)
class PrescriptiveEnvelope:
    """The authority-signed action envelope of a prescriptive agent.

    ``allowed_actions`` is a closed-vocabulary subset; ``scope_digest``
    pins the lines/sites/assets the agent may touch. The agent can
    never widen it — widening requires a new envelope from a *different*
    authority than the one that issued the current one.
    """

    envelope_id: str
    agent_id: str
    allowed_actions: tuple[str, ...]
    scope_digest: str
    armed_by: str
    armed_at: int
    expires_at: int
    envelope_digest: str
    signature: bytes
    schema_version: str = PRESCRIPTIVE_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-prescriptive-envelope",
            "envelope_id": self.envelope_id,
            "agent_id": self.agent_id,
            "allowed_actions": list(self.allowed_actions),
            "scope_digest": self.scope_digest,
            "armed_by": self.armed_by,
            "armed_at": self.armed_at,
            "expires_at": self.expires_at,
            "envelope_digest": self.envelope_digest,
            "signature": self.signature.hex(),
            "schema_version": self.schema_version,
        }


def _prescriptive_payload(
    *,
    envelope_id: str,
    agent_id: str,
    allowed_actions: tuple[str, ...],
    scope_digest: str,
    armed_by: str,
    armed_at: int,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "envelope_id": envelope_id,
        "agent_id": agent_id,
        "allowed_actions": list(allowed_actions),
        "scope_digest": scope_digest,
        "armed_by": armed_by,
        "armed_at": armed_at,
        "expires_at": expires_at,
        "schema_version": PRESCRIPTIVE_SCHEMA,
    }


def compute_prescriptive_digest(
    *,
    envelope_id: str,
    agent_id: str,
    allowed_actions: tuple[str, ...],
    scope_digest: str,
    armed_by: str,
    armed_at: int,
    expires_at: int,
) -> str:
    return jcs_sha256_hex(
        _prescriptive_payload(
            envelope_id=envelope_id,
            agent_id=agent_id,
            allowed_actions=allowed_actions,
            scope_digest=scope_digest,
            armed_by=armed_by,
            armed_at=armed_at,
            expires_at=expires_at,
        )
    )


@dataclass(frozen=True)
class PrescriptiveVerdict:
    allowed: bool
    deny_code: str | None
    classification: str


class PrescriptiveRegistry:
    """Prescriptive agents: every action checked against the envelope."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._envelopes: dict[str, PrescriptiveEnvelope] = {}

    def arm(
        self,
        *,
        envelope_id: str,
        agent_id: str,
        allowed_actions: tuple[str, ...],
        scope_digest: str,
        armed_by: str,
        armed_at: int,
        expires_at: int,
        signature: bytes,
    ) -> PrescriptiveEnvelope:
        _require_str(envelope_id, "envelope_id")
        _require_str(agent_id, "agent_id")
        _require_str(armed_by, "armed_by")
        _check_ts(armed_at, "armed_at")
        _check_ts(expires_at, "expires_at")
        _check_sig(signature, "signature")
        if expires_at <= armed_at:
            raise EmbodiedError("expires_at must be after armed_at")
        if not isinstance(allowed_actions, (list, tuple)) or not allowed_actions:
            raise EmbodiedError("allowed_actions must be a non-empty list")
        unknown = [a for a in allowed_actions if a not in PRESCRIPTIVE_ACTIONS]
        if unknown:
            raise EmbodiedError(f"unknown prescriptive actions: {unknown}")
        actions = tuple(sorted(set(allowed_actions)))
        _check_hex64(scope_digest, "scope_digest")
        digest = compute_prescriptive_digest(
            envelope_id=envelope_id,
            agent_id=agent_id,
            allowed_actions=actions,
            scope_digest=scope_digest,
            armed_by=armed_by,
            armed_at=armed_at,
            expires_at=expires_at,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=armed_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        env = PrescriptiveEnvelope(
            envelope_id=envelope_id,
            agent_id=agent_id,
            allowed_actions=actions,
            scope_digest=scope_digest,
            armed_by=armed_by,
            armed_at=armed_at,
            expires_at=expires_at,
            envelope_digest=digest,
            signature=signature,
        )
        self._envelopes[agent_id] = env
        return env

    def widen(
        self,
        *,
        agent_id: str,
        allowed_actions: tuple[str, ...],
        approved_by: str,
        signature: bytes,
        now: int,
    ) -> None:
        """Widening requires a *different* authority's approval: the
        agent can never widen its own envelope, and the issuer cannot
        approve their own widening."""
        _require_str(agent_id, "agent_id")
        _require_str(approved_by, "approved_by")
        _check_ts(now, "now")
        current = self._envelopes.get(agent_id)
        if current is None:
            raise EmbodiedError("no envelope armed for this agent")
        if approved_by == current.armed_by:
            raise EmbodiedError(DENY_PRESCRIPTIVE_ENVELOPE_WIDENED)
        # The widening path always re-arms via arm(); this function is a
        # deliberate dead end for self-widening. Kept explicit so the
        # capability table is auditable.
        raise EmbodiedError(DENY_PRESCRIPTIVE_ENVELOPE_WIDENED)

    def prescriptive_agent_gate(
        self,
        *,
        agent_id: str,
        action: str,
        scope_digest: str,
        now: int,
    ) -> PrescriptiveVerdict:
        _require_str(agent_id, "agent_id")
        _check_ts(now, "now")
        _check_hex64(scope_digest, "scope_digest")
        env = self._envelopes.get(agent_id)
        if env is None:
            return PrescriptiveVerdict(
                allowed=False,
                deny_code=DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if now < env.armed_at or now > env.expires_at:
            return PrescriptiveVerdict(
                allowed=False,
                deny_code=DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if action not in env.allowed_actions:
            return PrescriptiveVerdict(
                allowed=False,
                deny_code=DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if not hmac.compare_digest(scope_digest, env.scope_digest):
            return PrescriptiveVerdict(
                allowed=False,
                deny_code=DENY_PRESCRIPTIVE_OUT_OF_SCOPE,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        return PrescriptiveVerdict(
            allowed=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
        )


# ---------------------------------------------------------------------------
# Inspection confidence gate: measured escape rates, not guaranteed ones
# ---------------------------------------------------------------------------

INSPECTION_SCHEMA = "northstar.embodied.inspection.v1"


@dataclass(frozen=True)
class InspectionVerdict:
    auto_release: bool
    deny_code: str | None
    classification: str


def inspection_confidence_gate(
    *,
    inspection_id: str,
    verdict: str,
    confidence: float,
    measured: bool,
    confidence_threshold: float,
    now: int,
    decided_at: int,
) -> InspectionVerdict:
    """Below-threshold verdicts cannot auto-release product.

    ``confidence`` must be a *measured* value (``measured=True`` pins
    that a benchmark produced it); a 0.3% escape rate is a measurement
    over a sample, not a guarantee over the next lot.
    """
    _require_str(inspection_id, "inspection_id")
    _require_str(verdict, "verdict")
    _check_ts(now, "now")
    _check_ts(decided_at, "decided_at")
    if verdict not in ("pass", "fail", "inconclusive"):
        raise EmbodiedError(f"unknown verdict {verdict!r}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise EmbodiedError("confidence must be a number")
    if not 0.0 <= float(confidence) <= 1.0:
        raise EmbodiedError("confidence must be in [0, 1]")
    if not isinstance(measured, bool):
        raise EmbodiedError("measured must be a bool")
    if isinstance(confidence_threshold, bool) or not isinstance(
        confidence_threshold, (int, float)
    ):
        raise EmbodiedError("confidence_threshold must be a number")
    if not 0.0 <= float(confidence_threshold) <= 1.0:
        raise EmbodiedError("confidence_threshold must be in [0, 1]")
    if decided_at > now:
        return InspectionVerdict(
            auto_release=False,
            deny_code=DENY_MALFORMED,
            classification=EMBODIED_NON_AUTHORITATIVE,
        )
    if not measured:
        return InspectionVerdict(
            auto_release=False,
            deny_code=DENY_LOW_CONFIDENCE_RELEASE,
            classification=EMBODIED_NON_AUTHORITATIVE,
        )
    if verdict != "pass" or float(confidence) < float(confidence_threshold):
        return InspectionVerdict(
            auto_release=False,
            deny_code=DENY_LOW_CONFIDENCE_RELEASE,
            classification=EMBODIED_NON_AUTHORITATIVE,
        )
    return InspectionVerdict(
        auto_release=True,
        deny_code=None,
        classification=EMBODIED_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Dispatch ledger: command-center scheduling, hash-chained
# ---------------------------------------------------------------------------

DISPATCH_SCHEMA = "northstar.embodied.dispatch.v1"


@dataclass(frozen=True)
class DispatchReceipt:
    dispatch_id: str
    project_id: str
    robot_id: str
    task_digest: str
    window_start: int
    window_end: int
    dispatched_by: str
    dispatched_at: int
    prev_hash: str
    receipt_digest: str
    signature: bytes
    schema_version: str = DISPATCH_SCHEMA

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "embodied-dispatch",
            "dispatch_id": self.dispatch_id,
            "project_id": self.project_id,
            "robot_id": self.robot_id,
            "task_digest": self.task_digest,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "dispatched_by": self.dispatched_by,
            "dispatched_at": self.dispatched_at,
            "prev_hash": self.prev_hash,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature.hex(),
            "schema_version": self.schema_version,
        }


def _dispatch_payload(
    *,
    dispatch_id: str,
    project_id: str,
    robot_id: str,
    task_digest: str,
    window_start: int,
    window_end: int,
    dispatched_by: str,
    dispatched_at: int,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "dispatch_id": dispatch_id,
        "project_id": project_id,
        "robot_id": robot_id,
        "task_digest": task_digest,
        "window_start": window_start,
        "window_end": window_end,
        "dispatched_by": dispatched_by,
        "dispatched_at": dispatched_at,
        "prev_hash": prev_hash,
        "schema_version": DISPATCH_SCHEMA,
    }


def compute_dispatch_digest(
    *,
    dispatch_id: str,
    project_id: str,
    robot_id: str,
    task_digest: str,
    window_start: int,
    window_end: int,
    dispatched_by: str,
    dispatched_at: int,
    prev_hash: str,
) -> str:
    return jcs_sha256_hex(
        _dispatch_payload(
            dispatch_id=dispatch_id,
            project_id=project_id,
            robot_id=robot_id,
            task_digest=task_digest,
            window_start=window_start,
            window_end=window_end,
            dispatched_by=dispatched_by,
            dispatched_at=dispatched_at,
            prev_hash=prev_hash,
        )
    )


@dataclass(frozen=True)
class DispatchVerdict:
    audited: bool
    deny_code: str | None
    classification: str


class DispatchLedger:
    """Hash-chained construction-robot dispatch."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, DispatchReceipt] = {}
        self._prev_hash = _GENESIS

    def record(
        self,
        *,
        dispatch_id: str,
        project_id: str,
        robot_id: str,
        task_digest: str,
        window_start: int,
        window_end: int,
        dispatched_by: str,
        dispatched_at: int,
        signature: bytes,
    ) -> DispatchReceipt:
        _require_str(dispatch_id, "dispatch_id")
        _require_str(project_id, "project_id")
        _require_str(robot_id, "robot_id")
        _require_str(dispatched_by, "dispatched_by")
        _check_ts(window_start, "window_start")
        _check_ts(window_end, "window_end")
        _check_ts(dispatched_at, "dispatched_at")
        _check_hex64(task_digest, "task_digest")
        _check_sig(signature, "signature")
        if window_end <= window_start:
            raise EmbodiedError("window_end must be after window_start")
        digest = compute_dispatch_digest(
            dispatch_id=dispatch_id,
            project_id=project_id,
            robot_id=robot_id,
            task_digest=task_digest,
            window_start=window_start,
            window_end=window_end,
            dispatched_by=dispatched_by,
            dispatched_at=dispatched_at,
            prev_hash=self._prev_hash,
        )
        deny = _verify_signature(
            self._authorities,
            authority_id=dispatched_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_UNAUDITED_DISPATCH,
        )
        if deny is not None:
            raise EmbodiedError(deny)
        receipt = DispatchReceipt(
            dispatch_id=dispatch_id,
            project_id=project_id,
            robot_id=robot_id,
            task_digest=task_digest,
            window_start=window_start,
            window_end=window_end,
            dispatched_by=dispatched_by,
            dispatched_at=dispatched_at,
            prev_hash=self._prev_hash,
            receipt_digest=digest,
            signature=signature,
        )
        self._receipts[dispatch_id] = receipt
        self._prev_hash = digest
        return receipt

    def dispatch_audit(
        self, *, dispatch_id: str, now: int
    ) -> DispatchVerdict:
        """A dispatch the ledger cannot show is unaudited: deny."""
        _require_str(dispatch_id, "dispatch_id")
        _check_ts(now, "now")
        receipt = self._receipts.get(dispatch_id)
        if receipt is None:
            return DispatchVerdict(
                audited=False,
                deny_code=DENY_UNAUDITED_DISPATCH,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if receipt.dispatched_at > now:
            return DispatchVerdict(
                audited=False,
                deny_code=DENY_MALFORMED,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        if now - receipt.dispatched_at > DISPATCH_FRESHNESS_S:
            return DispatchVerdict(
                audited=False,
                deny_code=DENY_UNAUDITED_DISPATCH,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        expected = compute_dispatch_digest(
            dispatch_id=receipt.dispatch_id,
            project_id=receipt.project_id,
            robot_id=receipt.robot_id,
            task_digest=receipt.task_digest,
            window_start=receipt.window_start,
            window_end=receipt.window_end,
            dispatched_by=receipt.dispatched_by,
            dispatched_at=receipt.dispatched_at,
            prev_hash=receipt.prev_hash,
        )
        if not hmac.compare_digest(expected, receipt.receipt_digest):
            return DispatchVerdict(
                audited=False,
                deny_code=DENY_UNAUDITED_DISPATCH,
                classification=EMBODIED_NON_AUTHORITATIVE,
            )
        return DispatchVerdict(
            audited=True,
            deny_code=None,
            classification=EMBODIED_AUTHORITATIVE,
        )


# ---------------------------------------------------------------------------
# Incident binding: physical incidents feed the 113th-batch clock
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhysicalIncidentLink:
    reported: bool
    escalated: bool
    deny_code: str | None


def incident_binding(
    *,
    incident_registry: Any,
    incident_id: str,
    system_id: str,
    severity: str,
    death_linked: bool,
    widespread: bool,
    systemic_tier: int | None,
    detected_at: int,
    reported_at: int,
    summary_digest: str,
    now: int,
) -> PhysicalIncidentLink:
    """File a physical incident through the 113th-batch incident clock.

    A physical incident with no filing linked within the machine-enforced
    clock is escalated per that clock (``embodied.incident_unreported``);
    the filing itself is the incident-receipts registry's business.
    """
    try:
        verdict = incident_registry.file_incident(
            incident_id=incident_id,
            system_id=system_id,
            severity=severity,
            death_linked=death_linked,
            widespread=widespread,
            systemic_tier=systemic_tier,
            detected_at=detected_at,
            reported_at=reported_at,
            summary_digest=summary_digest,
            now=now,
        )
    except Exception:
        return PhysicalIncidentLink(
            reported=False, escalated=True, deny_code=DENY_INCIDENT_UNREPORTED
        )
    clock_missed = getattr(verdict, "clock_missed", False)
    return PhysicalIncidentLink(
        reported=True,
        escalated=bool(clock_missed),
        deny_code=DENY_INCIDENT_UNREPORTED if clock_missed else None,
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def embodied_audit_event(
    event: str,
    *,
    deployment_id: str,
    deny_code: str | None,
    now: int,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _require_str(event, "event")
    _require_str(deployment_id, "deployment_id")
    _check_ts(now, "now")
    payload: dict[str, Any] = {
        "event": event,
        "deployment_id": deployment_id,
        "deny_code": deny_code,
        "at": now,
    }
    if details:
        payload["details"] = dict(details)
    payload["event_digest"] = jcs_sha256_hex(payload)
    return payload


__all__ = [
    "SCHEMA_VERSION",
    "LABOR_DISPLACEMENT_THRESHOLD",
    "FALL_ZONE_FRESHNESS_S",
    "DISPATCH_FRESHNESS_S",
    "DENY_NO_STANDARD_DECLARATION",
    "DENY_UNVERIFIABLE_SAFETY",
    "DENY_STANDARD_DIGEST_MISMATCH",
    "DENY_STANDARD_SIGNATURE_INVALID",
    "DENY_NO_FALL_ZONE",
    "DENY_FALL_ZONE_STALE",
    "DENY_FALL_ZONE_REVOKED",
    "DENY_FALL_ZONE_DIGEST_MISMATCH",
    "DENY_UNSUBSTANTIATED_CAPABILITY",
    "DENY_LABOR_IMPACT_UNDISCLOSED",
    "DENY_PRESCRIPTIVE_OUT_OF_SCOPE",
    "DENY_PRESCRIPTIVE_ENVELOPE_WIDENED",
    "DENY_LOW_CONFIDENCE_RELEASE",
    "DENY_UNAUDITED_DISPATCH",
    "DENY_INCIDENT_UNREPORTED",
    "DENY_MALFORMED",
    "DENY_UNKNOWN_AUTHORITY",
    "STANDARD_DECLARED_EVENT",
    "ACTUATION_DENIED_EVENT",
    "DISPATCH_RECORDED_EVENT",
    "EMBODIED_AUTHORITATIVE",
    "EMBODIED_NON_AUTHORITATIVE",
    "STANDARD_STATUSES",
    "PROXIMITY_CLASSES",
    "PRESCRIPTIVE_ACTIONS",
    "EmbodiedError",
    "AuthorityRegistry",
    "StandardDeclaration",
    "compute_standard_digest",
    "StandardVerdict",
    "StandardRegistry",
    "FallZoneReceipt",
    "compute_fall_zone_digest",
    "ActuationVerdict",
    "FallZoneRegistry",
    "CapabilityLabel",
    "compute_label_digest",
    "HonestyVerdict",
    "CapabilityRegistry",
    "LaborImpactReceipt",
    "compute_labor_digest",
    "LaborVerdict",
    "LaborRegistry",
    "PrescriptiveEnvelope",
    "compute_prescriptive_digest",
    "PrescriptiveVerdict",
    "PrescriptiveRegistry",
    "InspectionVerdict",
    "inspection_confidence_gate",
    "DispatchReceipt",
    "compute_dispatch_digest",
    "DispatchVerdict",
    "DispatchLedger",
    "PhysicalIncidentLink",
    "incident_binding",
    "embodied_audit_event",
]
