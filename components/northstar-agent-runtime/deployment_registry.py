"""Deployment registration gate (one-hundred-tenth batch).

Absorbs the 2026 AI-govtech research thread:

* **EU AI Act, Art. 49** — public bodies must REGISTER high-risk AI
  systems in the EU database *before* deployment; Art. 26 requires
  logs kept for at least 6 months; Art. 27 requires a fundamental
  rights impact assessment (FRIA) before deploying a high-risk
  system. (High-risk obligations delayed by the Digital Omnibus, but
  the mechanism is the law's design.)
* **UK DWP** — cut 6 welfare AI prototypes, and *none* of them had
  ever entered the Algorithm Transparency Register: unregistered
  systems operating on citizens.
* **Australia, Medicare agent (June 2026)** — an AI agent accessed a
  benefits portal without authorization: a shadow model doing
  real-world actions with no registration and no accountable owner.

Northstar mapping: deployment itself is the permission gate. A model
or agent with no registration receipt MUST NOT be deployed —
fail-closed, with deliberately NO "deploy now, register later" path.
Registration is a hash-chained, authority-signed receipt binding the
system identity, the exact model digest, the risk class, the FRIA
digest (for high-risk), the Art. 10 training-data record digest, and
the log-retention floor. Runtime invocations that cannot be resolved
to a live registration are shadow deployments: they classify
``unverifiable-process`` (ninety-eighth batch) and audit as
``deployment.shadow_detected``.

Fail-closed rules, in gate order:

1. **Registration required** — ``gate_deployment()`` with no
   registration (``None``) denies. There is no grace period.
2. **Chain integrity** — the receipt's digest recomputes over its
   canonical fields plus ``prev_hash``; the registry log links
   consecutively (``seq`` 0..n-1). Tamper or gap → deny.
3. **Authority signature** — the receipt must be signed by a
   registered authority (Ed25519, vendored ``ed25519`` module);
   unknown signer → deny. Unacceptable risk class is refused at
   registration time, not at gate time.
4. **Risk-class gating** — ``unacceptable`` can never be registered;
   ``high`` requires a FRIA digest and explanation fields; the
   intended use must be within the registered risk class.
5. **Freshness** — expired registration → deny. A superseded
   registration (a newer receipt for the same ``system_id``) is a
   rollback → deny.
6. **Retention floor** — deploying with log retention below the
   registered floor → refused. Retention-floor changes are
   themselves receipted into the chain.
7. **Explanation fields** — high-risk systems must carry
   human-readable explanation fields (decision, grounds, data used,
   appeal path) at registration; ``explain_decision()`` serves them
   to citizens by action-card digest.

Deterministic: no wall-clock reads (callers inject ``now`` as an
integer epoch), canonical JCS hashing (ninety-fifth batch), and all
digest comparisons use :func:`hmac.compare_digest`.

Honest scope:

* This module verifies *registry* integrity — digests recompute,
  signatures verify, links resolve. It cannot force a host to route
  real invocations through ``gate_deployment`` / ``detect_shadow``;
  a host that bypasses the gate bypasses the governance.
* It verifies the *claimed* model digest matches the registry; it
  cannot prove the bits actually running are those bits (that needs
  hardware attestation, ninety-second batch).
* FRIA and training-data records are digests of documents produced
  elsewhere; the module pins them, it does not assess their quality.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Mapping

import ed25519

try:  # ninety-fifth batch: the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


DEPLOYMENT_REGISTRY_SCHEMA_VERSION = "northstar.deployment-registry.v1"

#: Closed risk-class vocabulary (EU AI Act Annex III tiers). There is
#: no fifth value; an unknown class is malformed, not a default.
RISK_CLASSES: tuple[str, ...] = (
    "minimal",
    "limited",
    "high",
    "unacceptable",
)

#: Risk classes that may run a given intended use. ``unacceptable``
#: never appears — it cannot be registered at all.
_RISK_ALLOWS = {
    "minimal": frozenset({"minimal"}),
    "limited": frozenset({"minimal", "limited"}),
    "high": frozenset({"minimal", "limited", "high"}),
}

#: Classification tiers (binary, like the 87th batch's evidence tiers).
REGISTERED_DEPLOYMENT = "registered-deployment"
UNVERIFIABLE_DEPLOYMENT = "unverifiable-deployment"

#: Audit event names.
DEPLOYMENT_DENIED_EVENT = "deployment.unregistered_denied"
DEPLOYMENT_ALLOWED_EVENT = "deployment.registered_allowed"
SHADOW_DETECTED_EVENT = "deployment.shadow_detected"
RETENTION_CHANGE_EVENT = "deployment.retention_floor_changed"

_GENESIS = "genesis"


class DeploymentRegistryError(ValueError):
    """Malformed registration input (construction-time boundary)."""


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------


def _digest_fields(payload: Mapping[str, Any]) -> str:
    return jcs_sha256_hex(dict(payload))


@dataclass(frozen=True)
class RegistrationReceipt:
    """One registered AI system deployment.

    Binds ``(system_id | model_digest | risk_class | fria_digest |
    data_record_digest | retention_floor_days | registered_by |
    expires_at)`` into a hash chain. Construction is the validation
    boundary: malformed input raises :class:`DeploymentRegistryError`.
    """

    system_id: str
    model_digest: str
    risk_class: str
    fria_digest: str | None
    data_record_digest: str
    retention_floor_days: int
    registered_by: str  # authority pubkey hex
    authority_sig_hex: str
    expires_at: int
    explanation_fields: Mapping[str, str] = field(default_factory=dict)
    prev_hash: str = _GENESIS
    seq: int = 0

    def __post_init__(self) -> None:
        if not self.system_id or len(self.system_id) > 128:
            raise DeploymentRegistryError("system_id must be 1..128 chars")
        if not _is_hex64(self.model_digest):
            raise DeploymentRegistryError("model_digest must be sha256 hex")
        if self.risk_class not in RISK_CLASSES:
            raise DeploymentRegistryError(f"unknown risk_class: {self.risk_class!r}")
        if self.risk_class == "unacceptable":
            raise DeploymentRegistryError(
                "unacceptable risk class cannot be registered")
        if self.risk_class == "high" and not self.fria_digest:
            raise DeploymentRegistryError("high-risk registration needs fria_digest")
        if self.fria_digest and not _is_hex64(self.fria_digest):
            raise DeploymentRegistryError("fria_digest must be sha256 hex")
        if not _is_hex64(self.data_record_digest):
            raise DeploymentRegistryError("data_record_digest must be sha256 hex")
        if not isinstance(self.retention_floor_days, int) or self.retention_floor_days < 0:
            raise DeploymentRegistryError("retention_floor_days must be a non-negative int")
        if not _is_hex64(self.registered_by):
            raise DeploymentRegistryError("registered_by must be ed25519 pubkey hex")
        if not _is_hex(self.authority_sig_hex, 128):
            raise DeploymentRegistryError("authority_sig_hex must be 128 hex chars")
        if not isinstance(self.expires_at, int) or self.expires_at <= 0:
            raise DeploymentRegistryError("expires_at must be a positive epoch")
        if self.risk_class == "high":
            missing = [k for k in ("decision", "grounds", "data_used", "appeal_path")
                       if not self.explanation_fields.get(k)]
            if missing:
                raise DeploymentRegistryError(
                    f"high-risk registration missing explanation fields: {missing}")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": DEPLOYMENT_REGISTRY_SCHEMA_VERSION,
            "system_id": self.system_id,
            "model_digest": self.model_digest,
            "risk_class": self.risk_class,
            "fria_digest": self.fria_digest,
            "data_record_digest": self.data_record_digest,
            "retention_floor_days": self.retention_floor_days,
            "registered_by": self.registered_by,
            "expires_at": self.expires_at,
            "explanation_fields": dict(self.explanation_fields),
            "prev_hash": self.prev_hash,
            "seq": self.seq,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest_fields(self.payload())


@dataclass(frozen=True)
class RetentionChangeReceipt:
    """A receipted change to a system's log-retention floor."""

    system_id: str
    old_floor_days: int
    new_floor_days: int
    changed_by: str  # authority pubkey hex
    authority_sig_hex: str
    changed_at: int
    prev_hash: str = _GENESIS
    seq: int = 0

    def __post_init__(self) -> None:
        if not self.system_id or len(self.system_id) > 128:
            raise DeploymentRegistryError("system_id must be 1..128 chars")
        for name in ("old_floor_days", "new_floor_days"):
            v = getattr(self, name)
            if not isinstance(v, int) or v < 0:
                raise DeploymentRegistryError(f"{name} must be a non-negative int")
        if not _is_hex64(self.changed_by):
            raise DeploymentRegistryError("changed_by must be ed25519 pubkey hex")
        if not _is_hex(self.authority_sig_hex, 128):
            raise DeploymentRegistryError("authority_sig_hex must be 128 hex chars")
        if not isinstance(self.changed_at, int) or self.changed_at <= 0:
            raise DeploymentRegistryError("changed_at must be a positive epoch")

    def payload(self) -> dict[str, Any]:
        return {
            "schema": DEPLOYMENT_REGISTRY_SCHEMA_VERSION,
            "kind": "retention-change",
            "system_id": self.system_id,
            "old_floor_days": self.old_floor_days,
            "new_floor_days": self.new_floor_days,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at,
            "prev_hash": self.prev_hash,
            "seq": self.seq,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest_fields(self.payload())


def _is_hex(value: Any, length: int) -> bool:
    return (isinstance(value, str) and len(value) == length
            and all(c in "0123456789abcdefABCDEF" for c in value))


def _is_hex64(value: Any) -> bool:
    return _is_hex(value, 64)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class DeploymentRegistry:
    """Append-only registry of deployment registrations.

    The registry is curated out-of-band (authority keys are provisioned
    by the host); this class verifies chain consistency and signatures,
    it does not decide who the authorities are.
    """

    def __init__(self, authority_pubkeys: Mapping[str, str] | None = None) -> None:
        # authority_id -> pubkey hex
        self._authorities: dict[str, str] = dict(authority_pubkeys or {})
        self._log: list[RegistrationReceipt | RetentionChangeReceipt] = []
        self._latest_by_system: dict[str, RegistrationReceipt] = {}
        self._floor_by_system: dict[str, int] = {}

    # -- authorities ----------------------------------------------------

    def authority_id(self, pubkey_hex: str) -> str | None:
        for aid, pk in self._authorities.items():
            if hmac.compare_digest(pk.lower(), pubkey_hex.lower()):
                return aid
        return None

    # -- registration ---------------------------------------------------

    def register_system(
        self,
        *,
        authority_secret: bytes,
        authority_id: str,
        system_id: str,
        model_digest: str,
        risk_class: str,
        fria_digest: str | None,
        data_record_digest: str,
        retention_floor_days: int,
        expires_at: int,
        explanation_fields: Mapping[str, str] | None = None,
    ) -> RegistrationReceipt:
        """Register a system. ``unacceptable`` risk is refused outright."""
        if risk_class == "unacceptable":
            raise DeploymentRegistryError(
                "unacceptable risk class cannot be registered")
        pubkey_hex = ed25519.public_key(authority_secret).hex()
        if self.authority_id(pubkey_hex) != authority_id:
            raise DeploymentRegistryError("unknown or mismatched authority")
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        seq = len(self._log)
        receipt = RegistrationReceipt(
            system_id=system_id,
            model_digest=model_digest,
            risk_class=risk_class,
            fria_digest=fria_digest,
            data_record_digest=data_record_digest,
            retention_floor_days=retention_floor_days,
            registered_by=pubkey_hex,
            authority_sig_hex=ed25519.sign(
                authority_secret, jcs_canonical_json(_unsigned_payload(
                    system_id, model_digest, risk_class, fria_digest,
                    data_record_digest, retention_floor_days,
                    pubkey_hex, expires_at,
                    dict(explanation_fields or {}), prev, seq))).hex(),
            expires_at=expires_at,
            explanation_fields=dict(explanation_fields or {}),
            prev_hash=prev,
            seq=seq,
        )
        if not self._verify_signature(receipt):
            raise DeploymentRegistryError("registration signature failed to verify")
        self._log.append(receipt)
        self._latest_by_system[system_id] = receipt
        self._floor_by_system[system_id] = retention_floor_days
        return receipt

    def change_retention_floor(
        self,
        *,
        authority_secret: bytes,
        authority_id: str,
        system_id: str,
        new_floor_days: int,
        changed_at: int,
    ) -> RetentionChangeReceipt:
        """Receipt a retention-floor change (the floor is a floor, not a target)."""
        if system_id not in self._latest_by_system:
            raise DeploymentRegistryError("unknown system_id")
        pubkey_hex = ed25519.public_key(authority_secret).hex()
        if self.authority_id(pubkey_hex) != authority_id:
            raise DeploymentRegistryError("unknown or mismatched authority")
        if not isinstance(new_floor_days, int) or new_floor_days < 0:
            raise DeploymentRegistryError("new_floor_days must be a non-negative int")
        old = self._floor_by_system[system_id]
        prev = self._log[-1].receipt_digest if self._log else _GENESIS
        seq = len(self._log)
        payload = {
            "schema": DEPLOYMENT_REGISTRY_SCHEMA_VERSION,
            "kind": "retention-change",
            "system_id": system_id,
            "old_floor_days": old,
            "new_floor_days": new_floor_days,
            "changed_by": pubkey_hex,
            "changed_at": changed_at,
            "prev_hash": prev,
            "seq": seq,
        }
        sig = ed25519.sign(authority_secret, jcs_canonical_json(payload)).hex()
        change = RetentionChangeReceipt(
            system_id=system_id, old_floor_days=old, new_floor_days=new_floor_days,
            changed_by=pubkey_hex, authority_sig_hex=sig, changed_at=changed_at,
            prev_hash=prev, seq=seq,
        )
        if not ed25519.verify(bytes.fromhex(pubkey_hex),
                              jcs_canonical_json(payload),
                              bytes.fromhex(sig)):
            raise DeploymentRegistryError("retention-change signature failed")
        self._log.append(change)
        self._floor_by_system[system_id] = new_floor_days
        return change

    # -- verification ---------------------------------------------------

    def _verify_signature(self, receipt: RegistrationReceipt) -> bool:
        try:
            pub = bytes.fromhex(receipt.registered_by)
            sig = bytes.fromhex(receipt.authority_sig_hex)
            # The signed bytes exclude the signature itself: re-sign over
            # the unsigned canonical payload.
            unsigned = _unsigned_payload(
                receipt.system_id, receipt.model_digest, receipt.risk_class,
                receipt.fria_digest, receipt.data_record_digest,
                receipt.retention_floor_days, receipt.registered_by,
                receipt.expires_at, dict(receipt.explanation_fields),
                receipt.prev_hash, receipt.seq)
            return ed25519.verify(pub, jcs_canonical_json(unsigned), sig)
        except Exception:
            return False

    def verify_registration(self, receipt: RegistrationReceipt, *, now: int) -> tuple[bool, str]:
        """Fail-closed verification of one registration receipt."""
        if not isinstance(receipt, RegistrationReceipt):
            return False, "not a registration receipt"
        if self.authority_id(receipt.registered_by) is None:
            return False, "unknown authority"
        if not self._verify_signature(receipt):
            return False, "authority signature invalid"
        if receipt.risk_class == "unacceptable":
            return False, "unacceptable risk class"
        if receipt.risk_class == "high" and not receipt.fria_digest:
            return False, "high-risk registration missing FRIA"
        if now >= receipt.expires_at:
            return False, "registration expired"
        latest = self._latest_by_system.get(receipt.system_id)
        if latest is not None and not hmac.compare_digest(
                latest.receipt_digest, receipt.receipt_digest):
            return False, "superseded registration (rollback)"
        return True, "registration valid"

    def verify_chain(self) -> tuple[bool, str]:
        """Replay the whole registry log: consecutive seqs, linked digests."""
        prev = _GENESIS
        for i, entry in enumerate(self._log):
            if entry.seq != i:
                return False, f"log seq gap at index {i}"
            if not hmac.compare_digest(entry.prev_hash, prev):
                return False, f"log link broken at index {i}"
            prev = entry.receipt_digest
        return True, "registry chain intact"

    # -- gates ----------------------------------------------------------

    def gate_deployment(
        self,
        *,
        receipt: RegistrationReceipt | None,
        intended_use: str,
        log_retention_days: int,
        now: int,
    ) -> "DeploymentVerdict":
        """Gate one deployment. ``None`` receipt denies — no grace period."""
        if receipt is None:
            return DeploymentVerdict(False, "no registration receipt",
                                     UNVERIFIABLE_DEPLOYMENT, None)
        ok, reason = self.verify_registration(receipt, now=now)
        if not ok:
            return DeploymentVerdict(False, reason, UNVERIFIABLE_DEPLOYMENT,
                                     receipt.receipt_digest)
        if intended_use not in _RISK_ALLOWS.get(receipt.risk_class, frozenset()):
            return DeploymentVerdict(
                False,
                f"intended use {intended_use!r} exceeds registered risk class "
                f"{receipt.risk_class!r}",
                UNVERIFIABLE_DEPLOYMENT, receipt.receipt_digest)
        floor = self._floor_by_system.get(receipt.system_id,
                                          receipt.retention_floor_days)
        if log_retention_days < floor:
            return DeploymentVerdict(
                False,
                f"log retention {log_retention_days}d below floor {floor}d",
                UNVERIFIABLE_DEPLOYMENT, receipt.receipt_digest)
        return DeploymentVerdict(True, "registered deployment",
                                 REGISTERED_DEPLOYMENT, receipt.receipt_digest)

    def detect_shadow(
        self, *, system_id: str, model_digest: str, now: int,
    ) -> "DeploymentVerdict":
        """Runtime probe: invocation must resolve to a live registration."""
        latest = self._latest_by_system.get(system_id)
        if latest is None:
            return DeploymentVerdict(False, "unknown system_id: shadow deployment",
                                     UNVERIFIABLE_DEPLOYMENT, None)
        if not hmac.compare_digest(latest.model_digest.lower(), model_digest.lower()):
            return DeploymentVerdict(False, "model digest mismatch: shadow deployment",
                                     UNVERIFIABLE_DEPLOYMENT, latest.receipt_digest)
        ok, reason = self.verify_registration(latest, now=now)
        if not ok:
            return DeploymentVerdict(False, f"registration invalid: {reason}",
                                     UNVERIFIABLE_DEPLOYMENT, latest.receipt_digest)
        return DeploymentVerdict(True, "invocation matches live registration",
                                 REGISTERED_DEPLOYMENT, latest.receipt_digest)

    def explain_decision(self, *, system_id: str) -> dict[str, Any] | None:
        """Citizen explanation API: human-readable grounds for a system.

        Returns the registered explanation fields (decision, grounds,
        data_used, appeal_path) for high-risk systems, else ``None``.
        """
        latest = self._latest_by_system.get(system_id)
        if latest is None or latest.risk_class != "high":
            return None
        return {
            "system_id": latest.system_id,
            "risk_class": latest.risk_class,
            "receipt_digest": latest.receipt_digest,
            **dict(latest.explanation_fields),
        }


def _unsigned_payload(system_id: str, model_digest: str, risk_class: str,
                      fria_digest: str | None, data_record_digest: str,
                      retention_floor_days: int, registered_by: str,
                      expires_at: int, explanation_fields: dict[str, str],
                      prev_hash: str, seq: int) -> dict[str, Any]:
    """The exact bytes the authority signs (signature excluded)."""
    return {
        "schema": DEPLOYMENT_REGISTRY_SCHEMA_VERSION,
        "system_id": system_id,
        "model_digest": model_digest,
        "risk_class": risk_class,
        "fria_digest": fria_digest,
        "data_record_digest": data_record_digest,
        "retention_floor_days": retention_floor_days,
        "registered_by": registered_by,
        "expires_at": expires_at,
        "explanation_fields": explanation_fields,
        "prev_hash": prev_hash,
        "seq": seq,
    }


@dataclass(frozen=True)
class DeploymentVerdict:
    allowed: bool
    reason: str
    classification: str
    receipt_digest: str | None


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def deployment_audit_event(verdict: DeploymentVerdict, *, action: str) -> dict[str, Any]:
    """Shape a deployment verdict as an audit-chain event dict."""
    return {
        "event": DEPLOYMENT_ALLOWED_EVENT if verdict.allowed else DEPLOYMENT_DENIED_EVENT,
        "action": action,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
    }


def shadow_audit_event(verdict: DeploymentVerdict, *, system_id: str) -> dict[str, Any]:
    """Shape a shadow-detection verdict as an audit-chain event dict."""
    return {
        "event": SHADOW_DETECTED_EVENT,
        "system_id": system_id,
        "allowed": verdict.allowed,
        "reason": verdict.reason,
        "classification": verdict.classification,
        "receipt_digest": verdict.receipt_digest,
    }
