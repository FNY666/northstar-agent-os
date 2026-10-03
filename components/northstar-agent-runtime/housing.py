"""Fair-housing & coordination isolation (one-hundred-nineteenth batch).

Absorbs the 2026 AI-real-estate research thread (mechanism ideas only,
honestly scoped):

* **Vendor liability is joint.** *Louis v. SafeRent* settled for $2.275M:
  a third-party tenant-score vendor (Registry ScorePLUS, systematically
  lower scores for Black/Latino applicants) and the landlord *shared*
  FHA liability. Here a third-party score vendor cannot enter the
  pipeline without a bias-audit receipt, and the admission binds the
  vendor AND the deploying landlord to the audit digest — liability is
  recorded jointly by construction.
* **Pricing-model coordination is isolated.** RealPage's algorithmic
  rent recommendations drew DOJ antitrust settlements in 2026-06~09:
  competing landlords feeding a common aggregator's live-price data is
  the coordination vector. Here a rent-setting model must bind a
  training-data source-isolation proof: declared data sources, and no
  shared live-price feed from a common aggregator across competing
  landlords. Missing proof denies rent-setting
  (``housing:coordination_risk``).
* **High-stakes decisions are human-final.** Colorado's AI Act
  (2026-06) imposes "reasonable care" against discrimination on
  deployers of high-risk AI; ECOA adverse-action notices that cite
  "model output" as the reason are non-compliant. Here the agent may
  emit ONLY an evidence pack — never an accept/deny verdict — and an
  adverse action must carry specific, human-comprehensible reasons
  bound to a registered human's countersign.
* **Mitigating factors must be presented.** Housing-voucher status,
  co-signers, and other mitigating factors must reach the human
  decision-maker before any adverse decision; suppressed factors deny
  the decision (``housing:mitigating_suppressed``).
* **Steering is probed, not assumed.** Marketing agents are checked
  with synthetic persona pairs differing only in protected
  attributes; inequivalent listings deny and audit
  (``housing:steering_detected``).

Northstar mapping:

* ``FairnessProbeReceipt`` — vendor-signed, hash-chained receipt
  binding ``(probe_id, model_digest, probe_type, demographic_slices,
  probe_digest, measured_at, expires_at)``. ``avm_fairness_receipt()``
  is the fail-closed gate: a valuation/tenant-screening model used in
  a high-stakes housing/credit decision must present a live,
  untampered, vendor-signed probe receipt for the exact model digest.
  No probe means no high-stakes use (``housing:no_fairness_probe``).
* ``EvidencePack`` / ``human_final_gate()`` — the agent's output is an
  evidence pack (factors, metrics, evidence digests) with NO verdict
  field. If the pack contains an accept/deny verdict the gate denies
  (``housing:verdict_emitted_by_agent``). ``countersign_decision()``
  binds a registered human decision-maker's countersign to the exact
  evidence-pack digest.
* ``adverse_action_receipt()`` — binds ``(action_id, subject_id,
  reasons, evidence_pack_digest, human_decision_id)``. Reasons must be
  specific and human-comprehensible; "model output", "algorithmic
  score", or "system decision" as the reason is a hard deny
  (``housing:vague_adverse_action``, the ECOA lesson).
* ``SourceIsolationProof`` / ``coordination_isolation()`` — a
  rent-setting model binds declared training data sources and
  live-price feeds. Any live-price feed whose provider is flagged as
  serving competing landlords (``shared_aggregator=True``) denies
  rent-setting (``housing:coordination_risk``).
* ``steering_probe()`` — deterministic probe: the caller supplies a
  listing function and two synthetic personas differing only in
  protected attributes. Listing sets differing beyond
  ``STEERING_TOLERANCE`` deny and audit
  ``housing:steering_detected``.
* ``VendorAdmission`` / ``vendor_liability_receipt()`` — binds
  ``(vendor_id, landlord_id, audit_digest, auditor_id)``: the vendor
  AND the deploying landlord are both pinned to the bias-audit digest.
  No audit receipt, no pipeline admission.
* ``mitigating_factors()`` — before an adverse decision, the declared
  mitigating factors (voucher status, co-signer, payment history,
  etc.) must all be presented to the human decision-maker. A declared
  factor missing from the presented set denies
  (``housing:mitigating_suppressed``).

Honest boundary: probes are declared evidence — digests recompute,
signatures verify, the audit digest pins. The module cannot certify
statistical fairness (that needs the actual probe methodology and
data, out of scope); it enforces the *structure*: probes before use,
evidence packs before verdicts, humans before adverse actions,
isolation before rent-setting. Vendors self-declare; a lying vendor
fails the audit receipt's auditability requirement, not this gate.

Deterministic: no wall-clock reads (callers inject integer epoch
timestamps), JCS canonical hashing (95th batch), Ed25519 via the
vendored ``ed25519`` module (97th-batch pattern), digest comparisons
via :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

import ed25519
from canonical_json import jcs_canonical_json, jcs_sha256_hex

HOUSING_SCHEMA_VERSION = "northstar.housing.v1"

#: Closed probe-type vocabulary. Only the disparate-impact probe is
#: recognized — a "vibes" probe does not count.
PROBE_TYPES: tuple[str, ...] = (
    "disparate_impact",
)

#: Closed decision-kind vocabulary for the human-final gate.
DECISION_KINDS: tuple[str, ...] = (
    "tenant_screening",
    "adverse_credit_action",
    "rent_setting",
    "marketing",
)

#: Closed mitigating-factor vocabulary. "other" is allowed but must
#: carry a free-text note; the gate checks declared factors were
#: presented, not that the vocabulary was exhaustive.
MITIGATING_FACTORS: tuple[str, ...] = (
    "housing_voucher",
    "co_signer",
    "rental_payment_history",
    "other",
)

#: Reason strings that are never specific enough for an adverse action
#: (the ECOA lesson: "model output" is not a reason).
VAGUE_REASONS: tuple[str, ...] = (
    "model output",
    "algorithmic score",
    "system decision",
    "ai decision",
    "automated decision",
)

#: Synthetic-persona listing sets differing by more than this fraction
#: of listings (symmetric difference / union) is steering.
STEERING_TOLERANCE: float = 0.0

#: Denial reason codes. All start with the ``housing:`` prefix.
DENY_NO_PROBE = "housing:no_fairness_probe"
DENY_PROBE_EXPIRED = "housing:probe_expired"
DENY_PROBE_FUTURE = "housing:probe_from_future"
DENY_PROBE_TAMPERED = "housing:probe_tampered"
DENY_PROBE_DIGEST_MISMATCH = "housing:probe_digest_mismatch"
DENY_PROBE_SLICE_MISMATCH = "housing:probe_slice_mismatch"
DENY_AGENT_VERDICT = "housing:verdict_emitted_by_agent"
DENY_PACK_TAMPERED = "housing:evidence_pack_tampered"
DENY_NO_COUNTERSIGN = "housing:no_human_countersign"
DENY_COUNTERSIGN_TAMPERED = "housing:countersign_tampered"
DENY_COUNTERSIGN_EXPIRED = "housing:countersign_expired"
DENY_COUNTERSIGN_DIGEST_MISMATCH = "housing:countersign_digest_mismatch"
DENY_VAGUE_REASON = "housing:vague_adverse_action"
DENY_ACTION_TAMPERED = "housing:adverse_action_tampered"
DENY_COORDINATION = "housing:coordination_risk"
DENY_ISOLATION_TAMPERED = "housing:isolation_proof_tampered"
DENY_STEERING = "housing:steering_detected"
DENY_VENDOR_NO_AUDIT = "housing:vendor_no_audit"
DENY_VENDOR_TAMPERED = "housing:vendor_admission_tampered"
DENY_VENDOR_EXPIRED = "housing:vendor_admission_expired"
DENY_MITIGATING_SUPPRESSED = "housing:mitigating_suppressed"
DENY_MALFORMED = "housing:malformed"

#: Audit event names (shaped for ``audit_chain.chain_record``).
PROBE_ALLOWED_EVENT = "housing.probe_allowed"
PROBE_DENIED_EVENT = "housing.probe_denied"
PACK_ALLOWED_EVENT = "housing.pack_allowed"
PACK_DENIED_EVENT = "housing.pack_denied"
COUNTERSIGN_EVENT = "housing.decision_countersigned"
ACTION_ALLOWED_EVENT = "housing.action_allowed"
ACTION_DENIED_EVENT = "housing.action_denied"
ISOLATION_ALLOWED_EVENT = "housing.isolation_allowed"
ISOLATION_DENIED_EVENT = "housing.isolation_denied"
STEERING_EVENT = "housing.steering_detected"
VENDOR_ALLOWED_EVENT = "housing.vendor_allowed"
VENDOR_DENIED_EVENT = "housing.vendor_denied"
MITIGATING_EVENT = "housing.mitigating_checked"

_GENESIS = "genesis"
_HEX64_LENGTH = 64
_HEX128_LENGTH = 128


class HousingError(ValueError):
    """Malformed receipt/probe/pack or a programming error.

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
        raise HousingError(f"{field_name} must be 64 lowercase hex chars")
    return value


def _check_hex128(value: Any, field_name: str) -> str:
    if not _is_hex(value, _HEX128_LENGTH):
        raise HousingError(f"{field_name} must be 128 lowercase hex chars")
    return value


def _check_probe_type(value: Any) -> str:
    if value not in PROBE_TYPES:
        raise HousingError(
            f"unknown probe type {value!r}; closed vocabulary {PROBE_TYPES}"
        )
    return value


def _check_decision_kind(value: Any) -> str:
    if value not in DECISION_KINDS:
        raise HousingError(
            f"unknown decision kind {value!r}; closed vocabulary {DECISION_KINDS}"
        )
    return value


def _check_mitigating_factor(value: Any) -> str:
    if value not in MITIGATING_FACTORS:
        raise HousingError(
            f"unknown mitigating factor {value!r}; closed vocabulary {MITIGATING_FACTORS}"
        )
    return value


def _check_ts(value: Any, field_name: str) -> int:
    if not isinstance(value, bool) and isinstance(value, int) and value >= 0:
        return value
    raise HousingError(f"{field_name} must be a non-negative integer epoch")


def _check_secret(value: Any, field_name: str) -> bytes:
    if (
        isinstance(value, (bytes, bytearray))
        and len(bytes(value)) == 32
        and any(b != 0 for b in bytes(value))
    ):
        return bytes(value)
    raise HousingError(f"{field_name} must be a non-degenerate 32-byte secret")


def _check_pubkey_hex(value: Any) -> str:
    if not _is_hex(value, 64):
        raise HousingError("pubkey must be 64 lowercase hex chars (32-byte Ed25519 key)")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HousingError(f"{field_name} must be a non-empty string")
    return value.strip()


def _check_str_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise HousingError(f"{field_name} must be a non-empty list of strings")
    out = tuple(_check_nonempty_str(v, f"{field_name}[]") for v in value)
    return out


# ---------------------------------------------------------------------------
# Fairness probe receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FairnessProbeReceipt:
    """Vendor-signed disparate-impact probe receipt, hash-chained."""

    probe_id: str
    model_digest: str
    probe_type: str
    demographic_slices: tuple[str, ...]
    probe_digest: str
    vendor_id: str
    vendor_pubkey_hex: str
    signature_hex: str
    measured_at: int
    expires_at: int
    prev_digest: str = _GENESIS
    probe_receipt_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _probe_payload(receipt: FairnessProbeReceipt) -> dict[str, Any]:
    return {
        "probe_id": receipt.probe_id,
        "model_digest": receipt.model_digest,
        "probe_type": receipt.probe_type,
        "demographic_slices": list(receipt.demographic_slices),
        "probe_digest": receipt.probe_digest,
        "vendor_id": receipt.vendor_id,
        "vendor_pubkey_hex": receipt.vendor_pubkey_hex,
        "measured_at": receipt.measured_at,
        "expires_at": receipt.expires_at,
        "prev_digest": receipt.prev_digest,
        "schema_version": receipt.schema_version,
    }


def compute_probe_digest(receipt: FairnessProbeReceipt) -> str:
    """Recompute the JCS digest a probe receipt claims."""
    return jcs_sha256_hex(_probe_payload(receipt))


def issue_fairness_probe(
    *,
    probe_id: str,
    model_digest: str,
    probe_type: str,
    demographic_slices: Sequence[str],
    probe_digest: str,
    vendor_id: str,
    vendor_secret: bytes,
    measured_at: int,
    expires_at: int,
    prev_digest: str = _GENESIS,
) -> FairnessProbeReceipt:
    """Issue a vendor-signed fairness-probe receipt and seal it.

    Fail-closed at issuance: unknown probe types raise, empty slice
    lists raise (a probe measured on nobody proves nothing), and
    ``expires_at <= measured_at`` raises. The vendor signature is over
    the canonical payload (signature excluded from the digest input).
    """
    _check_secret(vendor_secret, "vendor_secret")
    probe_id = _check_nonempty_str(probe_id, "probe_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    probe_type = _check_probe_type(probe_type)
    slices = _check_str_list(demographic_slices, "demographic_slices")
    if len(set(slices)) != len(slices):
        raise HousingError("duplicate demographic slice")
    probe_digest = _check_hex64(probe_digest, "probe_digest")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    measured_at = _check_ts(measured_at, "measured_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= measured_at:
        raise HousingError("expires_at must be after measured_at")
    if not isinstance(prev_digest, str) or not prev_digest:
        raise HousingError("prev_digest must be a non-empty string")

    pubkey_hex = ed25519.public_key(vendor_secret).hex()
    bare = FairnessProbeReceipt(
        probe_id=probe_id,
        model_digest=model_digest,
        probe_type=probe_type,
        demographic_slices=tuple(sorted(slices)),
        probe_digest=probe_digest,
        vendor_id=vendor_id,
        vendor_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        measured_at=measured_at,
        expires_at=expires_at,
        prev_digest=prev_digest,
    )
    payload = _probe_payload(bare)
    signature_hex = ed25519.sign(
        vendor_secret, jcs_canonical_json(payload)
    ).hex()
    return FairnessProbeReceipt(
        probe_id=bare.probe_id,
        model_digest=bare.model_digest,
        probe_type=bare.probe_type,
        demographic_slices=bare.demographic_slices,
        probe_digest=bare.probe_digest,
        vendor_id=bare.vendor_id,
        vendor_pubkey_hex=bare.vendor_pubkey_hex,
        signature_hex=signature_hex,
        measured_at=bare.measured_at,
        expires_at=bare.expires_at,
        prev_digest=bare.prev_digest,
        probe_receipt_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


def _verify_probe_integrity(receipt: FairnessProbeReceipt) -> str | None:
    """Return a denial code if the probe receipt is tampered, else None."""
    try:
        if not hmac.compare_digest(
            compute_probe_digest(receipt), receipt.probe_receipt_digest
        ):
            return DENY_PROBE_TAMPERED
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(receipt.vendor_pubkey_hex),
                jcs_canonical_json(_probe_payload(receipt)),
                bytes.fromhex(receipt.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_PROBE_TAMPERED
    except HousingError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class ProbeVerdict:
    allowed: bool
    reason: str
    probe_id: str | None = None


def avm_fairness_receipt(
    probe_receipts: Sequence[FairnessProbeReceipt],
    *,
    model_digest: str,
    decision_kind: str,
    required_slices: Sequence[str],
    check_time: int,
) -> ProbeVerdict:
    """Fail-closed gate: high-stakes use requires a live probe receipt.

    A valuation/tenant-screening model used in a high-stakes
    housing/credit decision must present a vendor-signed probe receipt
    binding the EXACT model digest, covering every required
    demographic slice, live at ``check_time``. Anything else denies.
    """
    model_digest = _check_hex64(model_digest, "model_digest")
    decision_kind = _check_decision_kind(decision_kind)
    slices = _check_str_list(required_slices, "required_slices")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> ProbeVerdict:
        return ProbeVerdict(allowed=False, reason=reason)

    for receipt in probe_receipts:
        if not hmac.compare_digest(receipt.model_digest, model_digest):
            continue
        tamper = _verify_probe_integrity(receipt)
        if tamper is not None:
            return deny(tamper)
        if check_time < receipt.measured_at:
            return deny(DENY_PROBE_FUTURE)
        if check_time >= receipt.expires_at:
            return deny(DENY_PROBE_EXPIRED)
        missing = [s for s in slices if s not in receipt.demographic_slices]
        if missing:
            return deny(DENY_PROBE_SLICE_MISMATCH)
        return ProbeVerdict(allowed=True, reason="ok", probe_id=receipt.probe_id)
    return deny(DENY_NO_PROBE)


def probe_audit_event(verdict: ProbeVerdict, *, action: str) -> dict[str, Any]:
    """Shape a probe verdict as an audit event."""
    return {
        "event": PROBE_ALLOWED_EVENT if verdict.allowed else PROBE_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "probe_id": verdict.probe_id,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Evidence packs + human-final gate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidencePack:
    """Agent-emitted evidence pack. Carries NO verdict — ever."""

    pack_id: str
    subject_id: str
    decision_kind: str
    factors: Mapping[str, str]
    evidence_digests: tuple[str, ...]
    emitted_at: int
    verdict: str | None = None  # must stay None; a set verdict is a gate violation
    pack_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _pack_payload(pack: EvidencePack) -> dict[str, Any]:
    return {
        "pack_id": pack.pack_id,
        "subject_id": pack.subject_id,
        "decision_kind": pack.decision_kind,
        "factors": {k: pack.factors[k] for k in sorted(pack.factors)},
        "evidence_digests": list(pack.evidence_digests),
        "emitted_at": pack.emitted_at,
        "verdict": pack.verdict,
        "schema_version": pack.schema_version,
    }


def compute_pack_digest(pack: EvidencePack) -> str:
    """Recompute the JCS digest an evidence pack claims."""
    return jcs_sha256_hex(_pack_payload(pack))


def build_evidence_pack(
    *,
    pack_id: str,
    subject_id: str,
    decision_kind: str,
    factors: Mapping[str, str],
    evidence_digests: Sequence[str],
    emitted_at: int,
) -> EvidencePack:
    """Build an evidence pack. The builder cannot set a verdict.

    ``factors`` is a mapping of human-readable factor name to
    human-readable value (e.g. ``{"credit_score_band": "620-659"}``).
    """
    pack_id = _check_nonempty_str(pack_id, "pack_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    decision_kind = _check_decision_kind(decision_kind)
    if not isinstance(factors, Mapping) or not factors:
        raise HousingError("factors must be a non-empty mapping")
    clean_factors = {
        _check_nonempty_str(k, "factors key"): _check_nonempty_str(v, "factors value")
        for k, v in factors.items()
    }
    digests = tuple(
        _check_hex64(d, "evidence_digests[]") for d in evidence_digests
    )
    if len(set(digests)) != len(digests):
        raise HousingError("duplicate evidence digest")
    emitted_at = _check_ts(emitted_at, "emitted_at")
    bare = EvidencePack(
        pack_id=pack_id,
        subject_id=subject_id,
        decision_kind=decision_kind,
        factors=clean_factors,
        evidence_digests=tuple(sorted(digests)),
        emitted_at=emitted_at,
    )
    return EvidencePack(
        pack_id=bare.pack_id,
        subject_id=bare.subject_id,
        decision_kind=bare.decision_kind,
        factors=bare.factors,
        evidence_digests=bare.evidence_digests,
        emitted_at=bare.emitted_at,
        verdict=None,
        pack_digest=jcs_sha256_hex(_pack_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class PackVerdict:
    allowed: bool
    reason: str
    pack_id: str | None = None


def human_final_gate(pack: EvidencePack) -> PackVerdict:
    """Fail-closed gate: the agent's output must be evidence only.

    Any verdict present on the pack — even a "recommendation" — denies.
    A tampered pack digest denies. The verdict belongs to a registered
    human (see ``countersign_decision``).
    """
    if pack.verdict is not None:
        return PackVerdict(allowed=False, reason=DENY_AGENT_VERDICT)
    try:
        if not hmac.compare_digest(compute_pack_digest(pack), pack.pack_digest):
            return PackVerdict(allowed=False, reason=DENY_PACK_TAMPERED)
    except HousingError:
        return PackVerdict(allowed=False, reason=DENY_MALFORMED)
    return PackVerdict(allowed=True, reason="ok", pack_id=pack.pack_id)


def pack_audit_event(verdict: PackVerdict, *, action: str) -> dict[str, Any]:
    """Shape a pack verdict as an audit event."""
    return {
        "event": PACK_ALLOWED_EVENT if verdict.allowed else PACK_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "pack_id": verdict.pack_id,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Human countersign + adverse-action receipts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DecisionCountersign:
    """Registered human's countersign bound to an evidence-pack digest."""

    countersign_id: str
    evidence_pack_digest: str
    decision: str  # "approve" | "deny" | "defer" — the human's verdict
    decision_maker_id: str
    decision_maker_pubkey_hex: str
    signature_hex: str
    decided_at: int
    expires_at: int
    countersign_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _countersign_payload(cs: DecisionCountersign) -> dict[str, Any]:
    return {
        "countersign_id": cs.countersign_id,
        "evidence_pack_digest": cs.evidence_pack_digest,
        "decision": cs.decision,
        "decision_maker_id": cs.decision_maker_id,
        "decision_maker_pubkey_hex": cs.decision_maker_pubkey_hex,
        "decided_at": cs.decided_at,
        "expires_at": cs.expires_at,
        "schema_version": cs.schema_version,
    }


def countersign_decision(
    *,
    countersign_id: str,
    pack: EvidencePack,
    decision: str,
    decision_maker_id: str,
    decision_maker_secret: bytes,
    decided_at: int,
    expires_at: int,
) -> DecisionCountersign:
    """A registered human countersigns an evidence pack.

    The countersign binds the EXACT pack digest; a countersign for a
    different pack cannot authorize this decision. ``decision`` is the
    human's verdict (``approve``/``deny``/``defer``) — the only place a
    verdict may exist.
    """
    _check_secret(decision_maker_secret, "decision_maker_secret")
    countersign_id = _check_nonempty_str(countersign_id, "countersign_id")
    pack_digest = _check_hex64(pack.pack_digest, "pack.pack_digest")
    if decision not in ("approve", "deny", "defer"):
        raise HousingError("decision must be approve, deny, or defer")
    decision_maker_id = _check_nonempty_str(decision_maker_id, "decision_maker_id")
    decided_at = _check_ts(decided_at, "decided_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= decided_at:
        raise HousingError("expires_at must be after decided_at")

    pubkey_hex = ed25519.public_key(decision_maker_secret).hex()
    bare = DecisionCountersign(
        countersign_id=countersign_id,
        evidence_pack_digest=pack_digest,
        decision=decision,
        decision_maker_id=decision_maker_id,
        decision_maker_pubkey_hex=pubkey_hex,
        signature_hex="00" * 128,  # placeholder; replaced below
        decided_at=decided_at,
        expires_at=expires_at,
    )
    payload = _countersign_payload(bare)
    signature_hex = ed25519.sign(
        decision_maker_secret, jcs_canonical_json(payload)
    ).hex()
    return DecisionCountersign(
        countersign_id=bare.countersign_id,
        evidence_pack_digest=bare.evidence_pack_digest,
        decision=bare.decision,
        decision_maker_id=bare.decision_maker_id,
        decision_maker_pubkey_hex=bare.decision_maker_pubkey_hex,
        signature_hex=signature_hex,
        decided_at=bare.decided_at,
        expires_at=bare.expires_at,
        countersign_digest=jcs_sha256_hex(payload),
        schema_version=bare.schema_version,
    )


def _verify_countersign(cs: DecisionCountersign, pack: EvidencePack) -> str | None:
    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_countersign_payload(cs)), cs.countersign_digest
        ):
            return DENY_COUNTERSIGN_TAMPERED
        if not hmac.compare_digest(cs.evidence_pack_digest, pack.pack_digest):
            return DENY_COUNTERSIGN_DIGEST_MISMATCH
        try:
            sig_ok = ed25519.verify(
                bytes.fromhex(cs.decision_maker_pubkey_hex),
                jcs_canonical_json(_countersign_payload(cs)),
                bytes.fromhex(cs.signature_hex),
            )
        except Exception:
            sig_ok = False
        if not sig_ok:
            return DENY_COUNTERSIGN_TAMPERED
    except HousingError:
        return DENY_MALFORMED
    return None


@dataclass(frozen=True)
class AdverseAction:
    """Adverse-action receipt with specific, human-comprehensible reasons."""

    action_id: str
    subject_id: str
    reasons: tuple[str, ...]
    evidence_pack_digest: str
    human_decision_id: str
    acted_at: int
    action_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _action_payload(action: AdverseAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "subject_id": action.subject_id,
        "reasons": list(action.reasons),
        "evidence_pack_digest": action.evidence_pack_digest,
        "human_decision_id": action.human_decision_id,
        "acted_at": action.acted_at,
        "schema_version": action.schema_version,
    }


def adverse_action_receipt(
    *,
    action_id: str,
    subject_id: str,
    reasons: Sequence[str],
    pack: EvidencePack,
    countersign: DecisionCountersign,
    acted_at: int,
) -> AdverseAction:
    """Issue an adverse-action receipt.

    Fail-closed at issuance: reasons must be specific and
    human-comprehensible — any reason matching the ``VAGUE_REASONS``
    list raises (the ECOA lesson). The countersign must bind this exact
    pack and the human's decision must be ``deny``.
    """
    action_id = _check_nonempty_str(action_id, "action_id")
    subject_id = _check_nonempty_str(subject_id, "subject_id")
    reason_list = _check_str_list(reasons, "reasons")
    if len(set(reason_list)) != len(reason_list):
        raise HousingError("duplicate reason")
    for reason in reason_list:
        lowered = reason.strip().lower()
        if lowered in VAGUE_REASONS:
            raise HousingError(
                f"reason {reason!r} is not specific enough for an adverse action"
            )
    acted_at = _check_ts(acted_at, "acted_at")
    tamper = _verify_countersign(countersign, pack)
    if tamper is not None:
        raise HousingError(f"countersign invalid: {tamper}")
    if countersign.decision != "deny":
        raise HousingError("adverse action requires a human deny countersign")
    if not hmac.compare_digest(pack.subject_id, subject_id):
        raise HousingError("pack subject does not match action subject")
    bare = AdverseAction(
        action_id=action_id,
        subject_id=subject_id,
        reasons=tuple(reason_list),
        evidence_pack_digest=pack.pack_digest,
        human_decision_id=countersign.countersign_id,
        acted_at=acted_at,
    )
    return AdverseAction(
        action_id=bare.action_id,
        subject_id=bare.subject_id,
        reasons=bare.reasons,
        evidence_pack_digest=bare.evidence_pack_digest,
        human_decision_id=bare.human_decision_id,
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
    action: AdverseAction,
    pack: EvidencePack,
    countersign: DecisionCountersign,
    *,
    check_time: int,
) -> ActionVerdict:
    """Fail-closed check of an adverse-action receipt at use time."""
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> ActionVerdict:
        return ActionVerdict(allowed=False, reason=reason)

    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_action_payload(action)), action.action_digest
        ):
            return deny(DENY_ACTION_TAMPERED)
    except HousingError:
        return deny(DENY_MALFORMED)
    tamper = _verify_countersign(countersign, pack)
    if tamper is not None:
        return deny(tamper)
    if check_time >= countersign.expires_at:
        return deny(DENY_COUNTERSIGN_EXPIRED)
    if not hmac.compare_digest(action.human_decision_id, countersign.countersign_id):
        return deny(DENY_NO_COUNTERSIGN)
    if not hmac.compare_digest(action.evidence_pack_digest, pack.pack_digest):
        return deny(DENY_ACTION_TAMPERED)
    if not hmac.compare_digest(pack.subject_id, action.subject_id):
        return deny(DENY_ACTION_TAMPERED)
    return ActionVerdict(allowed=True, reason="ok", action_id=action.action_id)


def action_audit_event(verdict: ActionVerdict, *, action: str) -> dict[str, Any]:
    """Shape an adverse-action verdict as an audit event."""
    return {
        "event": ACTION_ALLOWED_EVENT if verdict.allowed else ACTION_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "action_id": verdict.action_id,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Source-isolation proofs (coordination isolation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LivePriceFeed:
    """One live-price feed used by a pricing model."""

    feed_id: str
    provider_id: str
    shared_aggregator: bool  # True if the provider also serves competing landlords


@dataclass(frozen=True)
class SourceIsolationProof:
    """Declared training-data source isolation for a rent-setting model."""

    proof_id: str
    model_digest: str
    data_sources: tuple[str, ...]
    live_price_feeds: tuple[LivePriceFeed, ...]
    declared_by: str
    declared_at: int
    proof_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _isolation_payload(proof: SourceIsolationProof) -> dict[str, Any]:
    return {
        "proof_id": proof.proof_id,
        "model_digest": proof.model_digest,
        "data_sources": list(proof.data_sources),
        "live_price_feeds": [
            {
                "feed_id": f.feed_id,
                "provider_id": f.provider_id,
                "shared_aggregator": f.shared_aggregator,
            }
            for f in proof.live_price_feeds
        ],
        "declared_by": proof.declared_by,
        "declared_at": proof.declared_at,
        "schema_version": proof.schema_version,
    }


def declare_source_isolation(
    *,
    proof_id: str,
    model_digest: str,
    data_sources: Sequence[str],
    live_price_feeds: Sequence[Mapping[str, Any]],
    declared_by: str,
    declared_at: int,
) -> SourceIsolationProof:
    """Declare the training-data sources of a rent-setting model.

    Each live-price feed declares whether its provider serves competing
    landlords (``shared_aggregator``). The declaration is sealed with a
    JCS digest; a feed cannot be quietly added later without breaking
    the digest.
    """
    proof_id = _check_nonempty_str(proof_id, "proof_id")
    model_digest = _check_hex64(model_digest, "model_digest")
    sources = _check_str_list(data_sources, "data_sources")
    if len(set(sources)) != len(sources):
        raise HousingError("duplicate data source")
    feeds: list[LivePriceFeed] = []
    for raw in live_price_feeds:
        if not isinstance(raw, Mapping):
            raise HousingError("live_price_feeds entries must be mappings")
        feed_id = _check_nonempty_str(raw.get("feed_id"), "feed_id")
        provider_id = _check_nonempty_str(raw.get("provider_id"), "provider_id")
        shared = raw.get("shared_aggregator")
        if not isinstance(shared, bool):
            raise HousingError("shared_aggregator must be a bool")
        feeds.append(
            LivePriceFeed(
                feed_id=feed_id, provider_id=provider_id, shared_aggregator=shared
            )
        )
    if len({f.feed_id for f in feeds}) != len(feeds):
        raise HousingError("duplicate live-price feed id")
    declared_by = _check_nonempty_str(declared_by, "declared_by")
    declared_at = _check_ts(declared_at, "declared_at")
    bare = SourceIsolationProof(
        proof_id=proof_id,
        model_digest=model_digest,
        data_sources=tuple(sorted(sources)),
        live_price_feeds=tuple(sorted(feeds, key=lambda f: f.feed_id)),
        declared_by=declared_by,
        declared_at=declared_at,
    )
    return SourceIsolationProof(
        proof_id=bare.proof_id,
        model_digest=bare.model_digest,
        data_sources=bare.data_sources,
        live_price_feeds=bare.live_price_feeds,
        declared_by=bare.declared_by,
        declared_at=bare.declared_at,
        proof_digest=jcs_sha256_hex(_isolation_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class IsolationVerdict:
    allowed: bool
    reason: str
    proof_id: str | None = None


def coordination_isolation(
    proof: SourceIsolationProof, *, model_digest: str
) -> IsolationVerdict:
    """Fail-closed coordination gate for rent-setting models.

    Any live-price feed from a provider flagged as serving competing
    landlords denies rent-setting (``housing:coordination_risk``) —
    the RealPage vector, made structural. A tampered proof denies.
    """
    model_digest = _check_hex64(model_digest, "model_digest")

    def deny(reason: str) -> IsolationVerdict:
        return IsolationVerdict(allowed=False, reason=reason)

    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_isolation_payload(proof)), proof.proof_digest
        ):
            return deny(DENY_ISOLATION_TAMPERED)
    except HousingError:
        return deny(DENY_MALFORMED)
    if not hmac.compare_digest(proof.model_digest, model_digest):
        return deny(DENY_ISOLATION_TAMPERED)
    for feed in proof.live_price_feeds:
        if feed.shared_aggregator:
            return deny(DENY_COORDINATION)
    return IsolationVerdict(allowed=True, reason="ok", proof_id=proof.proof_id)


def isolation_audit_event(verdict: IsolationVerdict, *, action: str) -> dict[str, Any]:
    """Shape an isolation verdict as an audit event."""
    return {
        "event": ISOLATION_ALLOWED_EVENT if verdict.allowed else ISOLATION_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "proof_id": verdict.proof_id,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Steering probe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SteeringVerdict:
    allowed: bool
    reason: str
    overlap: float | None = None


def steering_probe(
    list_listings: Callable[[Mapping[str, str]], Sequence[str]],
    persona_a: Mapping[str, str],
    persona_b: Mapping[str, str],
) -> SteeringVerdict:
    """Deterministic steering probe over synthetic persona pairs.

    ``list_listings`` is the marketing agent's listing function;
    ``persona_a``/``persona_b`` must differ ONLY in protected-attribute
    fields (the caller declares which fields are protected via the
    ``protected:`` prefix on the key). If the two listing sets differ
    beyond ``STEERING_TOLERANCE``, the agent is steering and the
    verdict denies (audit ``housing:steering_detected``).
    """
    if not isinstance(persona_a, Mapping) or not isinstance(persona_b, Mapping):
        raise HousingError("personas must be mappings")
    keys_a, keys_b = set(persona_a), set(persona_b)
    if keys_a != keys_b:
        raise HousingError("personas must have identical fields")
    protected = {k for k in keys_a if k.startswith("protected:")}
    if not protected:
        raise HousingError("personas must declare at least one protected: field")
    for k in keys_a - protected:
        if persona_a[k] != persona_b[k]:
            raise HousingError(
                f"personas differ in non-protected field {k!r}; "
                "only protected attributes may differ"
            )
    if all(persona_a[k] == persona_b[k] for k in protected):
        raise HousingError("personas must differ in at least one protected attribute")

    set_a = set(list_listings(dict(persona_a)))
    set_b = set(list_listings(dict(persona_b)))
    union = set_a | set_b
    if not union:
        return SteeringVerdict(allowed=True, reason="ok", overlap=1.0)
    overlap = len(set_a & set_b) / len(union)
    if (1.0 - overlap) > STEERING_TOLERANCE:
        return SteeringVerdict(allowed=False, reason=DENY_STEERING, overlap=overlap)
    return SteeringVerdict(allowed=True, reason="ok", overlap=overlap)


def steering_audit_event(verdict: SteeringVerdict, *, action: str) -> dict[str, Any]:
    """Shape a steering verdict as an audit event."""
    return {
        "event": STEERING_EVENT,
        "action": action,
        "reason": verdict.reason,
        "overlap": verdict.overlap,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Vendor admission (joint liability)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VendorAdmission:
    """Joint-liability admission binding vendor AND landlord to an audit."""

    admission_id: str
    vendor_id: str
    landlord_id: str
    audit_digest: str
    auditor_id: str
    admitted_at: int
    expires_at: int
    admission_digest: str = ""
    schema_version: str = HOUSING_SCHEMA_VERSION


def _vendor_payload(admission: VendorAdmission) -> dict[str, Any]:
    return {
        "admission_id": admission.admission_id,
        "vendor_id": admission.vendor_id,
        "landlord_id": admission.landlord_id,
        "audit_digest": admission.audit_digest,
        "auditor_id": admission.auditor_id,
        "admitted_at": admission.admitted_at,
        "expires_at": admission.expires_at,
        "schema_version": admission.schema_version,
    }


def vendor_liability_receipt(
    *,
    admission_id: str,
    vendor_id: str,
    landlord_id: str,
    audit_digest: str,
    auditor_id: str,
    admitted_at: int,
    expires_at: int,
) -> VendorAdmission:
    """Admit a third-party score vendor to the pipeline.

    The admission pins the vendor AND the deploying landlord to the
    bias-audit digest — liability is joint by construction (the SafeRent
    lesson). An empty/missing audit digest raises: no audit, no
    admission. There is no "vendor certified itself" path — the auditor
    must differ from the vendor.
    """
    admission_id = _check_nonempty_str(admission_id, "admission_id")
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    landlord_id = _check_nonempty_str(landlord_id, "landlord_id")
    audit_digest = _check_hex64(audit_digest, "audit_digest")
    auditor_id = _check_nonempty_str(auditor_id, "auditor_id")
    if hmac.compare_digest(auditor_id.lower(), vendor_id.lower()):
        raise HousingError("auditor must differ from the vendor (no self-certification)")
    admitted_at = _check_ts(admitted_at, "admitted_at")
    expires_at = _check_ts(expires_at, "expires_at")
    if expires_at <= admitted_at:
        raise HousingError("expires_at must be after admitted_at")
    bare = VendorAdmission(
        admission_id=admission_id,
        vendor_id=vendor_id,
        landlord_id=landlord_id,
        audit_digest=audit_digest,
        auditor_id=auditor_id,
        admitted_at=admitted_at,
        expires_at=expires_at,
    )
    return VendorAdmission(
        admission_id=bare.admission_id,
        vendor_id=bare.vendor_id,
        landlord_id=bare.landlord_id,
        audit_digest=bare.audit_digest,
        auditor_id=bare.auditor_id,
        admitted_at=bare.admitted_at,
        expires_at=bare.expires_at,
        admission_digest=jcs_sha256_hex(_vendor_payload(bare)),
        schema_version=bare.schema_version,
    )


@dataclass(frozen=True)
class VendorVerdict:
    allowed: bool
    reason: str
    admission_id: str | None = None


def check_vendor_admission(
    admission: VendorAdmission | None,
    *,
    vendor_id: str,
    check_time: int,
) -> VendorVerdict:
    """Fail-closed vendor-admission check at use time."""
    vendor_id = _check_nonempty_str(vendor_id, "vendor_id")
    check_time = _check_ts(check_time, "check_time")

    def deny(reason: str) -> VendorVerdict:
        return VendorVerdict(allowed=False, reason=reason)

    if admission is None:
        return deny(DENY_VENDOR_NO_AUDIT)
    if not hmac.compare_digest(admission.vendor_id, vendor_id):
        return deny(DENY_VENDOR_NO_AUDIT)
    try:
        if not hmac.compare_digest(
            jcs_sha256_hex(_vendor_payload(admission)), admission.admission_digest
        ):
            return deny(DENY_VENDOR_TAMPERED)
    except HousingError:
        return deny(DENY_MALFORMED)
    if check_time < admission.admitted_at:
        return deny(DENY_VENDOR_TAMPERED)
    if check_time >= admission.expires_at:
        return deny(DENY_VENDOR_EXPIRED)
    return VendorVerdict(allowed=True, reason="ok", admission_id=admission.admission_id)


def vendor_audit_event(verdict: VendorVerdict, *, action: str) -> dict[str, Any]:
    """Shape a vendor verdict as an audit event."""
    return {
        "event": VENDOR_ALLOWED_EVENT if verdict.allowed else VENDOR_DENIED_EVENT,
        "action": action,
        "reason": verdict.reason,
        "admission_id": verdict.admission_id,
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


# ---------------------------------------------------------------------------
# Mitigating factors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MitigatingVerdict:
    allowed: bool
    reason: str
    suppressed: tuple[str, ...] = ()


def mitigating_factors(
    declared_factors: Mapping[str, str],
    presented_factors: Mapping[str, str],
) -> MitigatingVerdict:
    """Fail-closed mitigating-factor presentation check.

    Every declared mitigating factor (housing voucher, co-signer,
    rental-payment history, ...) must be present in the factors
    presented to the human decision-maker before an adverse decision.
    A declared factor missing from the presented set denies
    (``housing:mitigating_suppressed``). Empty declarations are fine —
    there is nothing to suppress.
    """
    if not isinstance(declared_factors, Mapping):
        raise HousingError("declared_factors must be a mapping")
    if not isinstance(presented_factors, Mapping):
        raise HousingError("presented_factors must be a mapping")
    declared = {
        _check_mitigating_factor(k): _check_nonempty_str(v, "declared factor value")
        for k, v in declared_factors.items()
    }
    presented: dict[str, str] = {}
    for k, v in presented_factors.items():
        presented[_check_mitigating_factor(k)] = _check_nonempty_str(
            v, "presented factor value"
        )
    suppressed = tuple(sorted(k for k in declared if k not in presented))
    if suppressed:
        return MitigatingVerdict(
            allowed=False, reason=DENY_MITIGATING_SUPPRESSED, suppressed=suppressed
        )
    return MitigatingVerdict(allowed=True, reason="ok")


def mitigating_audit_event(
    verdict: MitigatingVerdict, *, action: str
) -> dict[str, Any]:
    """Shape a mitigating-factor verdict as an audit event."""
    return {
        "event": MITIGATING_EVENT,
        "action": action,
        "reason": verdict.reason,
        "suppressed": list(verdict.suppressed),
        "schema_version": HOUSING_SCHEMA_VERSION,
    }


__all__ = [
    "HOUSING_SCHEMA_VERSION",
    "PROBE_TYPES",
    "DECISION_KINDS",
    "MITIGATING_FACTORS",
    "VAGUE_REASONS",
    "STEERING_TOLERANCE",
    "HousingError",
    "FairnessProbeReceipt",
    "issue_fairness_probe",
    "compute_probe_digest",
    "ProbeVerdict",
    "avm_fairness_receipt",
    "probe_audit_event",
    "EvidencePack",
    "build_evidence_pack",
    "compute_pack_digest",
    "PackVerdict",
    "human_final_gate",
    "pack_audit_event",
    "DecisionCountersign",
    "countersign_decision",
    "AdverseAction",
    "adverse_action_receipt",
    "ActionVerdict",
    "check_adverse_action",
    "action_audit_event",
    "LivePriceFeed",
    "SourceIsolationProof",
    "declare_source_isolation",
    "IsolationVerdict",
    "coordination_isolation",
    "isolation_audit_event",
    "SteeringVerdict",
    "steering_probe",
    "steering_audit_event",
    "VendorAdmission",
    "vendor_liability_receipt",
    "VendorVerdict",
    "check_vendor_admission",
    "vendor_audit_event",
    "MitigatingVerdict",
    "mitigating_factors",
    "mitigating_audit_event",
    "DENY_NO_PROBE",
    "DENY_PROBE_EXPIRED",
    "DENY_PROBE_FUTURE",
    "DENY_PROBE_TAMPERED",
    "DENY_PROBE_DIGEST_MISMATCH",
    "DENY_PROBE_SLICE_MISMATCH",
    "DENY_AGENT_VERDICT",
    "DENY_PACK_TAMPERED",
    "DENY_NO_COUNTERSIGN",
    "DENY_COUNTERSIGN_TAMPERED",
    "DENY_COUNTERSIGN_EXPIRED",
    "DENY_COUNTERSIGN_DIGEST_MISMATCH",
    "DENY_VAGUE_REASON",
    "DENY_ACTION_TAMPERED",
    "DENY_COORDINATION",
    "DENY_ISOLATION_TAMPERED",
    "DENY_STEERING",
    "DENY_VENDOR_NO_AUDIT",
    "DENY_VENDOR_TAMPERED",
    "DENY_VENDOR_EXPIRED",
    "DENY_MITIGATING_SUPPRESSED",
    "DENY_MALFORMED",
]
