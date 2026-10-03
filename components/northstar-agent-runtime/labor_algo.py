"""Algorithmic-management guards (one-hundred-twenty-seventh batch).

Absorbs the 2026 AI-logistics research thread:

* **Amazon ADAPT+TOT systems** — second-level monitoring, 300-400
  items/hour quotas, a single Baltimore warehouse firing 900+ workers
  automatically, 10%+ annual firing rates, 6.8 injuries per 100
  workers. **California AB 701** bans secret quotas. Governance
  takeaway: productivity quotas are not valid for enforcement unless
  they are *disclosed* in a worker-signed receipt binding (quota
  value, measurement window, appeal path) — a secret quota is
  ``labor:hidden_quota``.
* **Automated firings** — algorithmic termination without a human
  in the loop is the Baltimore lesson. Governance takeaway: an
  algorithmic firing requires a human final adjudicator's countersign
  bound to the exact evidence pack; anything else is
  ``labor:algorithmic_firing``.
* **China platform-algorithm governance (2026-01 negative list)** —
  Meituan cancelled timeout penalties and imposed a 12-hour forced
  offline; riders get 4 unconditional order rejections per day; Didi
  10h service / 6h forced offline; commission 29% -> 27%. Governance
  takeaway: fatigue circuit breakers are *authority-pinned*, not
  platform-tunable (``labor:fatigue_circuit_break``), and lawful
  rejections may never be penalized
  (``labor:rejection_penalty``).
* **DSP driver AI cameras** — biometric surveillance of drivers.
  **GPAI report** — "no upper valve" on monitoring intensity.
  Governance takeaway: worker surveillance requires a proportionality
  receipt binding (declared purpose, scope, retention, biometric
  flag); purpose/scope overreach is
  ``labor:disproportionate_surveillance``.
* **EU AI Act Annex III** — worker-management AI is high-risk.
  Governance takeaway: the module is the enforcement half of that
  classification — the gates below are the mechanism.
* **Autonomous trucks (700K km pilot, JD's 3M-robot procurement)** —
  KBA-style licensing: operation on public roads requires a
  safety-case receipt; without it the deployment registry must refuse
  registration (``labor:no_safety_case``).
* **Amazon 600K-jobs lesson** — large-scale automation displacing
  workers must bind a labor-impact disclosure to the 110th-batch
  deployment registry (``labor:labor_impact_undisclosed``), enforced
  even when the deployment is otherwise compliant.

Northstar mapping:

* ``quota_receipt()`` — quota enforcement is allowed only when a
  registered, authority-signed quota receipt exists whose digest
  matches the declared terms *and* the worker has acknowledged it.
  Missing receipt -> ``labor:hidden_quota``; missing worker ack ->
  ``labor:quota_ack_missing``; terms changed under the worker ->
  ``labor:quota_digest_mismatch``.
* ``algorithmic_termination_gate()`` — a termination is valid only
  with a human adjudicator's countersign bound to the exact evidence
  pack digest, not predating the pack. No countersign ->
  ``labor:algorithmic_firing``.
* ``fatigue_circuit_breaker()`` — an authority-pinned maximum
  continuous-hours policy; shifts at/over the limit must be forced
  offline (``labor:fatigue_circuit_break``). Operating with no pinned
  policy at all is ``labor:no_fatigue_policy`` — the platform cannot
  simply choose not to have a breaker.
* ``surveillance_proportionality_gate()`` — surveillance is allowed
  only under a matching proportionality receipt (purpose, scope,
  retention, biometric flag). Purpose reuse (e.g. safety cameras for
  productivity scoring) -> ``labor:surveillance_purpose_mismatch``;
  scope overreach -> ``labor:disproportionate_surveillance``;
  undeclared biometrics -> ``labor:biometric_surveillance_undeclared``;
  expired retention -> ``labor:surveillance_retention_exceeded``.
* ``dispatch_fairness_probe()`` — an authority-pinned dispatch
  policy grants workers a daily rejection allowance; penalizing a
  lawful rejection -> ``labor:rejection_penalty``.
* ``av_safety_case_receipt()`` — autonomous trucks/warehouse robots
  on public roads require a fresh, unrevoked safety-case receipt
  (``labor:no_safety_case``), binding into the deployment registry.
* ``labor_impact_binding()`` — displacement at/above the threshold
  requires a disclosed labor-impact receipt, bound to the deployment
  (``labor:labor_impact_undisclosed``).

Honest scoping: this module enforces *declared-labor discipline* —
the software cannot authorize what is not declared, pinned, and
fresh. It does not replace labor-law enforcement, real workplace
safety, or the judgment of the human adjudicator (the countersign
binds the *structure* of human review, not its wisdom). Everything is
offline and deterministic; the only clock is the ``now`` the caller
injects (integer epoch seconds). All digest comparisons use
:func:`hmac.compare_digest`.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
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
SCHEMA_VERSION = "northstar.labor_algo.v1"

#: Workers-displaced threshold at or above which a labor-impact
#: disclosure becomes mandatory (bench parameter, not a legal
#: threshold — verify against labor law before legal use).
IMPACT_DISCLOSURE_THRESHOLD = 10

#: Denial reason codes. All start with ``labor:`` for audit filtering.
DENY_HIDDEN_QUOTA = "labor:hidden_quota"
DENY_QUOTA_ACK_MISSING = "labor:quota_ack_missing"
DENY_QUOTA_DIGEST_MISMATCH = "labor:quota_digest_mismatch"
DENY_QUOTA_SIGNATURE_INVALID = "labor:quota_signature_invalid"
DENY_ALGORITHMIC_FIRING = "labor:algorithmic_firing"
DENY_EVIDENCE_PACK_UNKNOWN = "labor:evidence_pack_unknown"
DENY_COUNTERSIGN_PREDATES_PACK = "labor:countersign_predates_pack"
DENY_COUNTERSIGN_SIGNATURE_INVALID = "labor:countersign_signature_invalid"
DENY_NO_FATIGUE_POLICY = "labor:no_fatigue_policy"
DENY_FATIGUE_CIRCUIT_BREAK = "labor:fatigue_circuit_break"
DENY_NO_SURVEILLANCE_RECEIPT = "labor:no_surveillance_receipt"
DENY_SURVEILLANCE_PURPOSE_MISMATCH = "labor:surveillance_purpose_mismatch"
DENY_DISPROPORTIONATE_SURVEILLANCE = "labor:disproportionate_surveillance"
DENY_BIOMETRIC_SURVEILLANCE_UNDECLARED = "labor:biometric_surveillance_undeclared"
DENY_SURVEILLANCE_RETENTION_EXCEEDED = "labor:surveillance_retention_exceeded"
DENY_REJECTION_PENALTY = "labor:rejection_penalty"
DENY_NO_SAFETY_CASE = "labor:no_safety_case"
DENY_AV_SAFETY_CASE_REVOKED = "labor:av_safety_case_revoked"
DENY_AV_SAFETY_CASE_EXPIRED = "labor:av_safety_case_expired"
DENY_LABOR_IMPACT_UNDISCLOSED = "labor:labor_impact_undisclosed"
DENY_MALFORMED = "labor:malformed"
DENY_UNKNOWN_AUTHORITY = "labor:unknown_authority"

#: Audit events.
QUOTA_DISCLOSED_EVENT = "labor.quota_disclosed"
TERMINATION_ADJUDICATED_EVENT = "labor.termination_adjudicated"
TERMINATION_DENIED_EVENT = "labor.termination_denied"
FATIGUE_BREAK_TRIGGERED_EVENT = "labor.fatigue_break_triggered"
SURVEILLANCE_DENIED_EVENT = "labor.surveillance_denied"
DISPATCH_PENALTY_DENIED_EVENT = "labor.dispatch_penalty_denied"
AV_OPERATION_DENIED_EVENT = "labor.av_operation_denied"
IMPACT_DISCLOSURE_RECORDED_EVENT = "labor.impact_disclosure_recorded"

#: Classification tiers.
LABOR_AUTHORITATIVE = "labor-authoritative"
LABOR_NON_AUTHORITATIVE = "labor-non-authoritative"

_GENESIS = "genesis"


class LaborAlgoError(ValueError):
    """Malformed algorithmic-management input. Fail loud, never guess."""


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise LaborAlgoError(f"{name} must be a non-empty string")
    return value


def _require_int(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LaborAlgoError(f"{name} must be an integer")
    return value


def _check_ts(value: Any, name: str) -> int:
    v = _require_int(value, name)
    if v < 0:
        raise LaborAlgoError(f"{name} must be a non-negative epoch")
    return v


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value)
    )


def _check_hex64(value: Any, name: str) -> str:
    if not _is_hex(value, 64):
        raise LaborAlgoError(f"{name} must be 64 lowercase hex chars")
    return value


def _check_sig(value: Any, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise LaborAlgoError(f"{name} must be 64 bytes")
    return value


class AuthorityRegistry:
    """Registered human authorities (authority_id -> Ed25519 public key).

    The platform is never in this registry: there is no code path that
    adds a platform id, and every gate refuses signatures from
    unregistered keys. Registration itself is a host-side operation
    outside this module — the module only reads the table.
    """

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def register(self, authority_id: str, public_key: bytes) -> None:
        _require_str(authority_id, "authority_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise LaborAlgoError("public_key must be 32 bytes")
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


@dataclass(frozen=True)
class LaborAlgoVerdict:
    """Outcome of one algorithmic-management check."""

    allowed: bool
    deny_code: str | None
    classification: str
    receipt_digest: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-algo-verdict",
            "allowed": self.allowed,
            "deny_code": self.deny_code,
            "classification": self.classification,
            "receipt_digest": self.receipt_digest,
            "schema_version": SCHEMA_VERSION,
        }


def _allow(receipt_digest: str = "") -> LaborAlgoVerdict:
    return LaborAlgoVerdict(
        allowed=True,
        deny_code=None,
        classification=LABOR_AUTHORITATIVE,
        receipt_digest=receipt_digest,
    )


def _deny(deny_code: str) -> LaborAlgoVerdict:
    return LaborAlgoVerdict(
        allowed=False,
        deny_code=deny_code,
        classification=LABOR_NON_AUTHORITATIVE,
    )


# ---------------------------------------------------------------------------
# Quota receipts: no secret quotas (AB 701 lesson)
# ---------------------------------------------------------------------------

QUOTA_SCHEMA = "northstar.labor_algo.quota.v1"


def compute_quota_digest(
    *,
    quota_id: str,
    quota_value: int,
    measurement_window_s: int,
    appeal_path: str,
) -> str:
    """JCS digest binding the exact disclosed quota terms."""
    _require_str(quota_id, "quota_id")
    _require_int(quota_value, "quota_value")
    if quota_value <= 0:
        raise LaborAlgoError("quota_value must be positive")
    _require_int(measurement_window_s, "measurement_window_s")
    if measurement_window_s <= 0:
        raise LaborAlgoError("measurement_window_s must be positive")
    _require_str(appeal_path, "appeal_path")
    return jcs_sha256_hex(
        {
            "schema": QUOTA_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "quota_id": quota_id,
            "quota_value": quota_value,
            "measurement_window_s": measurement_window_s,
            "appeal_path": appeal_path,
        }
    )


@dataclass(frozen=True)
class QuotaReceipt:
    """An authority-signed, worker-acknowledged quota disclosure."""

    quota_id: str
    quota_value: int
    measurement_window_s: int
    appeal_path: str
    issued_by: str
    issued_at: int
    quota_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-quota-receipt",
            "quota_id": self.quota_id,
            "quota_value": self.quota_value,
            "measurement_window_s": self.measurement_window_s,
            "appeal_path": self.appeal_path,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at,
            "quota_digest": self.quota_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class QuotaRegistry:
    """Disclosed quotas: authority-signed, worker-acknowledged."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, QuotaReceipt] = {}
        self._acks: dict[str, set[str]] = {}
        self._worker_keys: dict[str, bytes] = {}

    def register_worker(self, worker_id: str, public_key: bytes) -> None:
        _require_str(worker_id, "worker_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise LaborAlgoError("public_key must be 32 bytes")
        self._worker_keys[worker_id] = public_key

    def issue_quota_receipt(
        self,
        *,
        quota_id: str,
        quota_value: int,
        measurement_window_s: int,
        appeal_path: str,
        issued_by: str,
        issued_at: int,
        signature: bytes,
    ) -> QuotaReceipt:
        """Issue an authority-signed quota disclosure.

        The authority signature binds the exact terms; changing the
        quota value, window, or appeal path after issuance breaks the
        digest and the receipt stops being enforceable.
        """
        _require_str(quota_id, "quota_id")
        _require_str(issued_by, "issued_by")
        _check_ts(issued_at, "issued_at")
        _check_sig(signature, "signature")
        digest = compute_quota_digest(
            quota_id=quota_id,
            quota_value=quota_value,
            measurement_window_s=measurement_window_s,
            appeal_path=appeal_path,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=issued_by,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_QUOTA_SIGNATURE_INVALID,
        )
        if code is not None:
            raise LaborAlgoError(f"quota receipt signature invalid: {code}")
        receipt = QuotaReceipt(
            quota_id=quota_id,
            quota_value=quota_value,
            measurement_window_s=measurement_window_s,
            appeal_path=appeal_path,
            issued_by=issued_by,
            issued_at=issued_at,
            quota_digest=digest,
            signature=signature,
        )
        self._receipts[quota_id] = receipt
        return receipt

    def acknowledge_quota(
        self, *, worker_id: str, quota_id: str, worker_signature: bytes
    ) -> None:
        """Record a worker's signed acknowledgment of the quota terms.

        The worker signs the receipt digest — proving the terms were
        disclosed *to them* — not the authority's signature.
        """
        _require_str(worker_id, "worker_id")
        _require_str(quota_id, "quota_id")
        _check_sig(worker_signature, "worker_signature")
        receipt = self._receipts.get(quota_id)
        if receipt is None:
            raise LaborAlgoError(f"unknown quota_id {quota_id!r}")
        pub = self._worker_keys.get(worker_id)
        if pub is None:
            raise LaborAlgoError(f"unknown worker_id {worker_id!r}")
        try:
            ok = _ed25519_verify(
                pub, receipt.quota_digest.encode("utf-8"), worker_signature
            )
        except Exception:
            ok = False
        if not ok:
            raise LaborAlgoError("worker acknowledgment signature invalid")
        self._acks.setdefault(quota_id, set()).add(worker_id)

    def quota_receipt(
        self,
        *,
        quota_id: str,
        declared_value: int,
        declared_window_s: int,
        worker_id: str,
        now: int,
    ) -> LaborAlgoVerdict:
        """Enforce a quota only when it is disclosed and acknowledged.

        Secret quotas — no receipt at all — are ``labor:hidden_quota``.
        A worker facing changed terms without a re-disclosure is
        ``labor:quota_digest_mismatch``. Enforcement against a worker
        who never acknowledged the terms is
        ``labor:quota_ack_missing``.
        """
        _require_str(quota_id, "quota_id")
        _require_int(declared_value, "declared_value")
        _require_int(declared_window_s, "declared_window_s")
        _require_str(worker_id, "worker_id")
        _check_ts(now, "now")
        receipt = self._receipts.get(quota_id)
        if receipt is None:
            return _deny(DENY_HIDDEN_QUOTA)
        declared_digest = compute_quota_digest(
            quota_id=quota_id,
            quota_value=declared_value,
            measurement_window_s=declared_window_s,
            appeal_path=receipt.appeal_path,
        )
        if not hmac.compare_digest(declared_digest, receipt.quota_digest):
            return _deny(DENY_QUOTA_DIGEST_MISMATCH)
        if receipt.issued_at > now:
            return _deny(DENY_MALFORMED)
        if worker_id not in self._acks.get(quota_id, set()):
            return _deny(DENY_QUOTA_ACK_MISSING)
        return _allow(receipt.quota_digest)


# ---------------------------------------------------------------------------
# Termination gate: human final adjudication for algorithmic firings
# ---------------------------------------------------------------------------

PACK_SCHEMA = "northstar.labor_algo.evidence-pack.v1"
TERMINATION_SCHEMA = "northstar.labor_algo.termination.v1"


def compute_pack_digest(
    *,
    pack_id: str,
    worker_id: str,
    evidence_digests: tuple[str, ...] | list[str],
    recorded_at: int,
) -> str:
    """JCS digest binding an evidence pack for a termination."""
    _require_str(pack_id, "pack_id")
    _require_str(worker_id, "worker_id")
    _check_ts(recorded_at, "recorded_at")
    digests = list(evidence_digests)
    if not digests:
        raise LaborAlgoError("evidence_digests must be non-empty")
    for d in digests:
        _check_hex64(d, "evidence_digest")
    return jcs_sha256_hex(
        {
            "schema": PACK_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "pack_id": pack_id,
            "worker_id": worker_id,
            "evidence_digests": sorted(digests),
            "recorded_at": recorded_at,
        }
    )


def compute_termination_digest(
    *,
    termination_id: str,
    pack_digest: str,
    adjudicator_id: str,
    adjudicated_at: int,
) -> str:
    """JCS digest binding a human adjudicator to an exact evidence pack."""
    _require_str(termination_id, "termination_id")
    _check_hex64(pack_digest, "pack_digest")
    _require_str(adjudicator_id, "adjudicator_id")
    _check_ts(adjudicated_at, "adjudicated_at")
    return jcs_sha256_hex(
        {
            "schema": TERMINATION_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "termination_id": termination_id,
            "pack_digest": pack_digest,
            "adjudicator_id": adjudicator_id,
            "adjudicated_at": adjudicated_at,
        }
    )


@dataclass(frozen=True)
class EvidencePack:
    pack_id: str
    worker_id: str
    evidence_digests: tuple[str, ...]
    recorded_at: int
    pack_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-evidence-pack",
            "pack_id": self.pack_id,
            "worker_id": self.worker_id,
            "evidence_digests": list(self.evidence_digests),
            "recorded_at": self.recorded_at,
            "pack_digest": self.pack_digest,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True)
class TerminationCountersign:
    termination_id: str
    pack_id: str
    adjudicator_id: str
    adjudicated_at: int
    termination_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-termination-countersign",
            "termination_id": self.termination_id,
            "pack_id": self.pack_id,
            "adjudicator_id": self.adjudicator_id,
            "adjudicated_at": self.adjudicated_at,
            "termination_digest": self.termination_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class TerminationRegistry:
    """Algorithmic firings: human countersign bound to the evidence pack."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._packs: dict[str, EvidencePack] = {}
        self._countersigns: dict[str, TerminationCountersign] = {}

    def register_evidence_pack(
        self,
        *,
        pack_id: str,
        worker_id: str,
        evidence_digests: tuple[str, ...] | list[str],
        recorded_at: int,
    ) -> EvidencePack:
        _require_str(pack_id, "pack_id")
        digest = compute_pack_digest(
            pack_id=pack_id,
            worker_id=worker_id,
            evidence_digests=evidence_digests,
            recorded_at=recorded_at,
        )
        pack = EvidencePack(
            pack_id=pack_id,
            worker_id=worker_id,
            evidence_digests=tuple(sorted(evidence_digests)),
            recorded_at=recorded_at,
            pack_digest=digest,
        )
        self._packs[pack_id] = pack
        return pack

    def countersign_termination(
        self,
        *,
        termination_id: str,
        pack_id: str,
        adjudicator_id: str,
        adjudicated_at: int,
        signature: bytes,
    ) -> TerminationCountersign:
        """A registered human adjudicator signs off on the exact pack.

        The countersign cannot predate the evidence pack: review happens
        *after* the evidence exists, never before.
        """
        _require_str(termination_id, "termination_id")
        _require_str(pack_id, "pack_id")
        _require_str(adjudicator_id, "adjudicator_id")
        _check_sig(signature, "signature")
        pack = self._packs.get(pack_id)
        if pack is None:
            raise LaborAlgoError(f"unknown pack_id {pack_id!r}")
        if adjudicated_at < pack.recorded_at:
            raise LaborAlgoError(
                "adjudicated_at cannot predate the evidence pack"
            )
        digest = compute_termination_digest(
            termination_id=termination_id,
            pack_digest=pack.pack_digest,
            adjudicator_id=adjudicator_id,
            adjudicated_at=adjudicated_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=adjudicator_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_COUNTERSIGN_SIGNATURE_INVALID,
        )
        if code is not None:
            raise LaborAlgoError(f"countersign signature invalid: {code}")
        countersign = TerminationCountersign(
            termination_id=termination_id,
            pack_id=pack_id,
            adjudicator_id=adjudicator_id,
            adjudicated_at=adjudicated_at,
            termination_digest=digest,
            signature=signature,
        )
        self._countersigns[termination_id] = countersign
        return countersign

    def algorithmic_termination_gate(
        self, *, termination_id: str, pack_id: str, now: int
    ) -> LaborAlgoVerdict:
        """A firing executes only with a valid human countersign.

        No countersign, unknown evidence pack, or a countersign that
        predates the pack -> ``labor:algorithmic_firing`` — the
        Baltimore lesson as a mechanism.
        """
        _require_str(termination_id, "termination_id")
        _require_str(pack_id, "pack_id")
        _check_ts(now, "now")
        pack = self._packs.get(pack_id)
        if pack is None:
            return _deny(DENY_EVIDENCE_PACK_UNKNOWN)
        countersign = self._countersigns.get(termination_id)
        if countersign is None:
            return _deny(DENY_ALGORITHMIC_FIRING)
        if countersign.pack_id != pack_id:
            return _deny(DENY_ALGORITHMIC_FIRING)
        expected = compute_termination_digest(
            termination_id=termination_id,
            pack_digest=pack.pack_digest,
            adjudicator_id=countersign.adjudicator_id,
            adjudicated_at=countersign.adjudicated_at,
        )
        if not hmac.compare_digest(expected, countersign.termination_digest):
            return _deny(DENY_COUNTERSIGN_SIGNATURE_INVALID)
        if countersign.adjudicated_at < pack.recorded_at:
            return _deny(DENY_COUNTERSIGN_PREDATES_PACK)
        code = _verify_signature(
            self._authorities,
            authority_id=countersign.adjudicator_id,
            digest_hex=countersign.termination_digest,
            signature=countersign.signature,
            deny_code=DENY_COUNTERSIGN_SIGNATURE_INVALID,
        )
        if code is not None:
            return _deny(code)
        if countersign.adjudicated_at > now:
            return _deny(DENY_MALFORMED)
        return _allow(countersign.termination_digest)


# ---------------------------------------------------------------------------
# Fatigue circuit breaker: authority-pinned, never platform-tunable
# ---------------------------------------------------------------------------

FATIGUE_SCHEMA = "northstar.labor_algo.fatigue-policy.v1"


def compute_fatigue_policy_digest(
    *, policy_id: str, max_continuous_hours: int, authority_id: str, pinned_at: int
) -> str:
    _require_str(policy_id, "policy_id")
    _require_int(max_continuous_hours, "max_continuous_hours")
    if max_continuous_hours <= 0:
        raise LaborAlgoError("max_continuous_hours must be positive")
    _require_str(authority_id, "authority_id")
    _check_ts(pinned_at, "pinned_at")
    return jcs_sha256_hex(
        {
            "schema": FATIGUE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "policy_id": policy_id,
            "max_continuous_hours": max_continuous_hours,
            "authority_id": authority_id,
            "pinned_at": pinned_at,
        }
    )


@dataclass(frozen=True)
class FatiguePolicy:
    policy_id: str
    max_continuous_hours: int
    authority_id: str
    pinned_at: int
    policy_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-fatigue-policy",
            "policy_id": self.policy_id,
            "max_continuous_hours": self.max_continuous_hours,
            "authority_id": self.authority_id,
            "pinned_at": self.pinned_at,
            "policy_digest": self.policy_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class FatigueBreaker:
    """Forced offline after N continuous hours — pinned by authority.

    The platform cannot tune, suspend, or quietly drop the breaker:
    the only valid policy is the one carrying an authority signature.
    Operating with no pinned policy at all is
    ``labor:no_fatigue_policy`` — fail-closed, the platform cannot
    choose to have no breaker.
    """

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._policies: dict[str, FatiguePolicy] = {}

    def pin_policy(
        self,
        *,
        policy_id: str,
        max_continuous_hours: int,
        authority_id: str,
        pinned_at: int,
        signature: bytes,
    ) -> FatiguePolicy:
        _require_str(policy_id, "policy_id")
        _check_sig(signature, "signature")
        digest = compute_fatigue_policy_digest(
            policy_id=policy_id,
            max_continuous_hours=max_continuous_hours,
            authority_id=authority_id,
            pinned_at=pinned_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_MALFORMED,
        )
        if code is not None:
            raise LaborAlgoError(f"fatigue policy signature invalid: {code}")
        policy = FatiguePolicy(
            policy_id=policy_id,
            max_continuous_hours=max_continuous_hours,
            authority_id=authority_id,
            pinned_at=pinned_at,
            policy_digest=digest,
            signature=signature,
        )
        self._policies[policy_id] = policy
        return policy

    def fatigue_circuit_breaker(
        self, *, policy_id: str, worker_id: str, continuous_hours: int, now: int
    ) -> LaborAlgoVerdict:
        """At/over the pinned limit the worker must be forced offline.

        Below the limit -> allowed (the shift may continue). At or over
        -> ``labor:fatigue_circuit_break`` — the Meituan 12h / Didi 10h
        lesson as a mechanism.
        """
        _require_str(policy_id, "policy_id")
        _require_str(worker_id, "worker_id")
        _require_int(continuous_hours, "continuous_hours")
        if continuous_hours < 0:
            raise LaborAlgoError("continuous_hours must be non-negative")
        _check_ts(now, "now")
        policy = self._policies.get(policy_id)
        if policy is None:
            return _deny(DENY_NO_FATIGUE_POLICY)
        if continuous_hours >= policy.max_continuous_hours:
            return _deny(DENY_FATIGUE_CIRCUIT_BREAK)
        return _allow(policy.policy_digest)


# ---------------------------------------------------------------------------
# Surveillance proportionality gate
# ---------------------------------------------------------------------------

SURVEILLANCE_SCHEMA = "northstar.labor_algo.surveillance.v1"


def compute_surveillance_digest(
    *,
    receipt_id: str,
    purpose: str,
    scope: str,
    retention_days: int,
    biometric: bool,
    authority_id: str,
    issued_at: int,
) -> str:
    _require_str(receipt_id, "receipt_id")
    _require_str(purpose, "purpose")
    _require_str(scope, "scope")
    _require_int(retention_days, "retention_days")
    if retention_days <= 0:
        raise LaborAlgoError("retention_days must be positive")
    if not isinstance(biometric, bool):
        raise LaborAlgoError("biometric must be a bool")
    _require_str(authority_id, "authority_id")
    _check_ts(issued_at, "issued_at")
    return jcs_sha256_hex(
        {
            "schema": SURVEILLANCE_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "purpose": purpose,
            "scope": scope,
            "retention_days": retention_days,
            "biometric": biometric,
            "authority_id": authority_id,
            "issued_at": issued_at,
        }
    )


@dataclass(frozen=True)
class SurveillanceReceipt:
    receipt_id: str
    purpose: str
    scope: str
    retention_days: int
    biometric: bool
    authority_id: str
    issued_at: int
    receipt_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-surveillance-receipt",
            "receipt_id": self.receipt_id,
            "purpose": self.purpose,
            "scope": self.scope,
            "retention_days": self.retention_days,
            "biometric": self.biometric,
            "authority_id": self.authority_id,
            "issued_at": self.issued_at,
            "receipt_digest": self.receipt_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class SurveillanceRegistry:
    """Worker surveillance: declared purpose, scope, retention — or deny."""

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, SurveillanceReceipt] = {}

    def issue_surveillance_receipt(
        self,
        *,
        receipt_id: str,
        purpose: str,
        scope: str,
        retention_days: int,
        biometric: bool,
        authority_id: str,
        issued_at: int,
        signature: bytes,
    ) -> SurveillanceReceipt:
        _require_str(receipt_id, "receipt_id")
        _check_sig(signature, "signature")
        digest = compute_surveillance_digest(
            receipt_id=receipt_id,
            purpose=purpose,
            scope=scope,
            retention_days=retention_days,
            biometric=biometric,
            authority_id=authority_id,
            issued_at=issued_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_MALFORMED,
        )
        if code is not None:
            raise LaborAlgoError(f"surveillance receipt signature invalid: {code}")
        receipt = SurveillanceReceipt(
            receipt_id=receipt_id,
            purpose=purpose,
            scope=scope,
            retention_days=retention_days,
            biometric=biometric,
            authority_id=authority_id,
            issued_at=issued_at,
            receipt_digest=digest,
            signature=signature,
        )
        self._receipts[receipt_id] = receipt
        return receipt

    def surveillance_proportionality_gate(
        self,
        *,
        receipt_id: str,
        declared_purpose: str,
        declared_scope: str,
        declared_biometric: bool,
        now: int,
    ) -> LaborAlgoVerdict:
        """Surveillance is allowed only under a matching receipt.

        Reusing safety cameras for productivity scoring is
        ``labor:surveillance_purpose_mismatch``; widening the monitored
        population beyond the declared scope is
        ``labor:disproportionate_surveillance``; biometric capture the
        receipt never declared is
        ``labor:biometric_surveillance_undeclared``; data held past its
        retention is ``labor:surveillance_retention_exceeded``.
        """
        _require_str(receipt_id, "receipt_id")
        _require_str(declared_purpose, "declared_purpose")
        _require_str(declared_scope, "declared_scope")
        if not isinstance(declared_biometric, bool):
            raise LaborAlgoError("declared_biometric must be a bool")
        _check_ts(now, "now")
        receipt = self._receipts.get(receipt_id)
        if receipt is None:
            return _deny(DENY_NO_SURVEILLANCE_RECEIPT)
        if not hmac.compare_digest(declared_purpose, receipt.purpose):
            return _deny(DENY_SURVEILLANCE_PURPOSE_MISMATCH)
        if not hmac.compare_digest(declared_scope, receipt.scope):
            return _deny(DENY_DISPROPORTIONATE_SURVEILLANCE)
        if declared_biometric and not receipt.biometric:
            return _deny(DENY_BIOMETRIC_SURVEILLANCE_UNDECLARED)
        if now > receipt.issued_at + receipt.retention_days * 86400:
            return _deny(DENY_SURVEILLANCE_RETENTION_EXCEEDED)
        if receipt.issued_at > now:
            return _deny(DENY_MALFORMED)
        return _allow(receipt.receipt_digest)


# ---------------------------------------------------------------------------
# Dispatch fairness probe: lawful rejections are never penalized
# ---------------------------------------------------------------------------

DISPATCH_SCHEMA = "northstar.labor_algo.dispatch-policy.v1"


def compute_dispatch_policy_digest(
    *, policy_id: str, max_rejections_per_day: int, authority_id: str, pinned_at: int
) -> str:
    _require_str(policy_id, "policy_id")
    _require_int(max_rejections_per_day, "max_rejections_per_day")
    if max_rejections_per_day < 0:
        raise LaborAlgoError("max_rejections_per_day must be non-negative")
    _require_str(authority_id, "authority_id")
    _check_ts(pinned_at, "pinned_at")
    return jcs_sha256_hex(
        {
            "schema": DISPATCH_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "policy_id": policy_id,
            "max_rejections_per_day": max_rejections_per_day,
            "authority_id": authority_id,
            "pinned_at": pinned_at,
        }
    )


@dataclass(frozen=True)
class DispatchPolicy:
    policy_id: str
    max_rejections_per_day: int
    authority_id: str
    pinned_at: int
    policy_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-dispatch-policy",
            "policy_id": self.policy_id,
            "max_rejections_per_day": self.max_rejections_per_day,
            "authority_id": self.authority_id,
            "pinned_at": self.pinned_at,
            "policy_digest": self.policy_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class DispatchRegistry:
    """Dispatch fairness: a daily rejection allowance, penalty-free.

    The allowance is authority-pinned (the rider-4-unconditional-
    rejections lesson). Penalizing a rejection inside the allowance is
    ``labor:rejection_penalty`` — the platform may not punish workers
    for exercising a granted right.
    """

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._policies: dict[str, DispatchPolicy] = {}
        self._rejections: dict[tuple[str, int], int] = {}

    def pin_dispatch_policy(
        self,
        *,
        policy_id: str,
        max_rejections_per_day: int,
        authority_id: str,
        pinned_at: int,
        signature: bytes,
    ) -> DispatchPolicy:
        _require_str(policy_id, "policy_id")
        _check_sig(signature, "signature")
        digest = compute_dispatch_policy_digest(
            policy_id=policy_id,
            max_rejections_per_day=max_rejections_per_day,
            authority_id=authority_id,
            pinned_at=pinned_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_MALFORMED,
        )
        if code is not None:
            raise LaborAlgoError(f"dispatch policy signature invalid: {code}")
        policy = DispatchPolicy(
            policy_id=policy_id,
            max_rejections_per_day=max_rejections_per_day,
            authority_id=authority_id,
            pinned_at=pinned_at,
            policy_digest=digest,
            signature=signature,
        )
        self._policies[policy_id] = policy
        return policy

    def record_rejection(self, *, worker_id: str, now: int) -> int:
        """Record one lawful rejection; returns today's count."""
        _require_str(worker_id, "worker_id")
        _check_ts(now, "now")
        key = (worker_id, now // 86400)
        self._rejections[key] = self._rejections.get(key, 0) + 1
        return self._rejections[key]

    def dispatch_fairness_probe(
        self,
        *,
        policy_id: str,
        worker_id: str,
        rejections_today: int,
        penalty_applied: bool,
        now: int,
    ) -> LaborAlgoVerdict:
        """Penalizing a lawful rejection is denied.

        Rejections inside the daily allowance are lawful by
        definition; applying a penalty for one is
        ``labor:rejection_penalty``.
        """
        _require_str(policy_id, "policy_id")
        _require_str(worker_id, "worker_id")
        _require_int(rejections_today, "rejections_today")
        if rejections_today < 0:
            raise LaborAlgoError("rejections_today must be non-negative")
        if not isinstance(penalty_applied, bool):
            raise LaborAlgoError("penalty_applied must be a bool")
        _check_ts(now, "now")
        policy = self._policies.get(policy_id)
        if policy is None:
            return _deny(DENY_MALFORMED)
        if rejections_today <= policy.max_rejections_per_day and penalty_applied:
            return _deny(DENY_REJECTION_PENALTY)
        return _allow(policy.policy_digest)


# ---------------------------------------------------------------------------
# AV safety cases: KBA licensing model for autonomous trucks/robots
# ---------------------------------------------------------------------------

AV_SCHEMA = "northstar.labor_algo.av-safety-case.v1"


def compute_av_digest(
    *,
    case_id: str,
    vehicle_id: str,
    operating_domain_digest: str,
    authority_id: str,
    issued_at: int,
    expires_at: int,
) -> str:
    _require_str(case_id, "case_id")
    _require_str(vehicle_id, "vehicle_id")
    _check_hex64(operating_domain_digest, "operating_domain_digest")
    _require_str(authority_id, "authority_id")
    _check_ts(issued_at, "issued_at")
    _check_ts(expires_at, "expires_at")
    if expires_at <= issued_at:
        raise LaborAlgoError("expires_at must be after issued_at")
    return jcs_sha256_hex(
        {
            "schema": AV_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "vehicle_id": vehicle_id,
            "operating_domain_digest": operating_domain_digest,
            "authority_id": authority_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
    )


@dataclass(frozen=True)
class SafetyCaseReceipt:
    case_id: str
    vehicle_id: str
    operating_domain_digest: str
    authority_id: str
    issued_at: int
    expires_at: int
    case_digest: str
    signature: bytes
    revoked: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-av-safety-case",
            "case_id": self.case_id,
            "vehicle_id": self.vehicle_id,
            "operating_domain_digest": self.operating_domain_digest,
            "authority_id": self.authority_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "case_digest": self.case_digest,
            "signature": self.signature.hex(),
            "revoked": self.revoked,
            "schema_version": SCHEMA_VERSION,
        }


class AVSafetyRegistry:
    """Autonomous trucks/robots on public roads need a safety case.

    Without a fresh, unrevoked safety-case receipt the deployment
    registry must refuse registration (``labor:no_safety_case``) —
    the KBA licensing model as a mechanism.
    """

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._cases: dict[str, SafetyCaseReceipt] = {}

    def issue_safety_case(
        self,
        *,
        case_id: str,
        vehicle_id: str,
        operating_domain_digest: str,
        authority_id: str,
        issued_at: int,
        expires_at: int,
        signature: bytes,
    ) -> SafetyCaseReceipt:
        _require_str(case_id, "case_id")
        _check_sig(signature, "signature")
        digest = compute_av_digest(
            case_id=case_id,
            vehicle_id=vehicle_id,
            operating_domain_digest=operating_domain_digest,
            authority_id=authority_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_MALFORMED,
        )
        if code is not None:
            raise LaborAlgoError(f"safety case signature invalid: {code}")
        case = SafetyCaseReceipt(
            case_id=case_id,
            vehicle_id=vehicle_id,
            operating_domain_digest=operating_domain_digest,
            authority_id=authority_id,
            issued_at=issued_at,
            expires_at=expires_at,
            case_digest=digest,
            signature=signature,
        )
        self._cases[case_id] = case
        return case

    def revoke_safety_case(self, case_id: str) -> None:
        _require_str(case_id, "case_id")
        case = self._cases.get(case_id)
        if case is None:
            raise LaborAlgoError(f"unknown case_id {case_id!r}")
        # Revocation is terminal: no un-revoke path exists.
        self._cases[case_id] = SafetyCaseReceipt(
            **{**case.__dict__, "revoked": True}
        )

    def av_safety_case_receipt(
        self, *, vehicle_id: str, now: int
    ) -> LaborAlgoVerdict:
        """Public-road operation needs a live safety case.

        No case -> ``labor:no_safety_case``; revoked ->
        ``labor:av_safety_case_revoked``; expired ->
        ``labor:av_safety_case_expired``.
        """
        _require_str(vehicle_id, "vehicle_id")
        _check_ts(now, "now")
        for case in self._cases.values():
            if case.vehicle_id != vehicle_id:
                continue
            if case.revoked:
                return _deny(DENY_AV_SAFETY_CASE_REVOKED)
            if now > case.expires_at:
                return _deny(DENY_AV_SAFETY_CASE_EXPIRED)
            if case.issued_at > now:
                return _deny(DENY_MALFORMED)
            return _allow(case.case_digest)
        return _deny(DENY_NO_SAFETY_CASE)


# ---------------------------------------------------------------------------
# Labor-impact binding: displacement binds to the deployment registry
# ---------------------------------------------------------------------------

IMPACT_SCHEMA = "northstar.labor_algo.labor-impact.v1"


def compute_impact_digest(
    *,
    deployment_id: str,
    workers_displaced_estimate: int,
    disclosure_digest: str,
    authority_id: str,
    recorded_at: int,
) -> str:
    _require_str(deployment_id, "deployment_id")
    _require_int(workers_displaced_estimate, "workers_displaced_estimate")
    if workers_displaced_estimate < 0:
        raise LaborAlgoError("workers_displaced_estimate must be non-negative")
    _check_hex64(disclosure_digest, "disclosure_digest")
    _require_str(authority_id, "authority_id")
    _check_ts(recorded_at, "recorded_at")
    return jcs_sha256_hex(
        {
            "schema": IMPACT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "deployment_id": deployment_id,
            "workers_displaced_estimate": workers_displaced_estimate,
            "disclosure_digest": disclosure_digest,
            "authority_id": authority_id,
            "recorded_at": recorded_at,
        }
    )


@dataclass(frozen=True)
class LaborImpactReceipt:
    deployment_id: str
    workers_displaced_estimate: int
    disclosure_digest: str
    authority_id: str
    recorded_at: int
    impact_digest: str
    signature: bytes

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": "labor-impact-receipt",
            "deployment_id": self.deployment_id,
            "workers_displaced_estimate": self.workers_displaced_estimate,
            "disclosure_digest": self.disclosure_digest,
            "authority_id": self.authority_id,
            "recorded_at": self.recorded_at,
            "impact_digest": self.impact_digest,
            "signature": self.signature.hex(),
            "schema_version": SCHEMA_VERSION,
        }


class LaborImpactRegistry:
    """Large-scale automation displacement: disclosed or denied.

    Displacement at/above ``IMPACT_DISCLOSURE_THRESHOLD`` without a
    disclosed, authority-signed receipt is
    ``labor:labor_impact_undisclosed`` — the Amazon 600K-jobs lesson:
    a fully compliant deployment can still automate away a workforce,
    so the disclosure is enforced independently of compliance.
    """

    def __init__(self, authorities: AuthorityRegistry) -> None:
        self._authorities = authorities
        self._receipts: dict[str, LaborImpactReceipt] = {}

    def register_impact_disclosure(
        self,
        *,
        deployment_id: str,
        workers_displaced_estimate: int,
        disclosure_digest: str,
        authority_id: str,
        recorded_at: int,
        signature: bytes,
    ) -> LaborImpactReceipt:
        _require_str(deployment_id, "deployment_id")
        _check_sig(signature, "signature")
        digest = compute_impact_digest(
            deployment_id=deployment_id,
            workers_displaced_estimate=workers_displaced_estimate,
            disclosure_digest=disclosure_digest,
            authority_id=authority_id,
            recorded_at=recorded_at,
        )
        code = _verify_signature(
            self._authorities,
            authority_id=authority_id,
            digest_hex=digest,
            signature=signature,
            deny_code=DENY_MALFORMED,
        )
        if code is not None:
            raise LaborAlgoError(f"impact disclosure signature invalid: {code}")
        receipt = LaborImpactReceipt(
            deployment_id=deployment_id,
            workers_displaced_estimate=workers_displaced_estimate,
            disclosure_digest=disclosure_digest,
            authority_id=authority_id,
            recorded_at=recorded_at,
            impact_digest=digest,
            signature=signature,
        )
        self._receipts[deployment_id] = receipt
        return receipt

    def labor_impact_binding(
        self, *, deployment_id: str, workers_displaced_estimate: int, now: int
    ) -> LaborAlgoVerdict:
        """Displacement at/above the threshold needs a disclosed receipt."""
        _require_str(deployment_id, "deployment_id")
        _require_int(workers_displaced_estimate, "workers_displaced_estimate")
        _check_ts(now, "now")
        if workers_displaced_estimate < IMPACT_DISCLOSURE_THRESHOLD:
            return _allow()
        receipt = self._receipts.get(deployment_id)
        if receipt is None:
            return _deny(DENY_LABOR_IMPACT_UNDISCLOSED)
        if receipt.recorded_at > now:
            return _deny(DENY_MALFORMED)
        return _allow(receipt.impact_digest)


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def labor_audit_event(event: str, **fields: Any) -> dict[str, Any]:
    """Shape an audit event for the labor-algorithmic-management domain."""
    payload: dict[str, Any] = {
        "event": event,
        "domain": "labor",
        "schema_version": SCHEMA_VERSION,
    }
    payload.update(fields)
    return payload
