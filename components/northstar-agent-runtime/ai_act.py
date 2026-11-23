"""EU AI Act: risk-classification decision ledger, Simulated.

Research note: Regulation (EU) 2024/1689 (the EU AI Act) frames AI
governance around a small set of enforceable *decisions*. Article 5 bans
prohibited (unacceptable-risk) practices outright; Chapter III pins
high-risk obligations (Articles 8-49) including a conformity assessment
(Article 43) before placing on the market; Article 50 pins transparency
obligations for limited-risk systems; general-purpose AI models carry
their own documentation and evaluation duties (Articles 51-56); serious
incidents must be reported to market-surveillance authorities
(Article 73). What matters for this module is the *decision ledger*:
which AI systems were declared under which risk class, what the booked
conformity-assessment outcome was, and which notifications were
declared - defensible bookkeeping, not proof of compliance.

This module is the *AI Act governance decision* layer, deliberately
distinct from its siblings:

- ``synthetic_media.py`` - the Art. 50 synthetic-content disclosure
  ledger (media lifecycle, not system classification).
- ``compliance.py`` - generic framework -> control-check -> attestation
  governance (an AI Act framework could be registered there, but the
  risk-class / conformity / serious-incident vocabulary belongs here).
- ``grc.py`` - multi-framework governance workflow ledger.
- ``audit_management.py`` - audit-engagement lifecycle.

This module owns the classify -> conform -> notify lifecycle:

* **classify()** - declare one AI system under a pinned risk-class
  vocabulary (``prohibited`` / ``high-risk`` / ``limited-risk`` /
  ``minimal-risk`` / ``gpaI-model`` / ``gpaI-model-systemic``); system
  details travel as ``sha256:`` digest pins only.
* **conform()** - book one declared conformity-assessment decision
  (minted ``cnf-N`` ids) over a pinned outcome vocabulary; outcomes are
  data, never proof of conformity.
* **notify()** - book one declared notification decision (minted
  ``ntf-N`` ids) over pinned channels/reasons; books the routing
  decision, never proof a authority was actually notified.
* **posture()** - pure read: per-system posture as data,
  digest-pinned.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``ai-act.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module performs no risk assessment, conducts no
conformity assessment, notifies no authority, and computes no legal
deadlines. A booked ``high-risk`` means "the ledger says the host
declared the system high-risk", never "the system is high-risk".
A booked ``conform`` means "the host declared a conform outcome",
never "the system conforms". Booked ``notified`` means "the ledger says
a notification decision was declared", never "an authority received it".
GIGO throughout.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
AI_ACT_VERSION = "ai-act.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ai-act.v1"

#: Pinned risk-class vocabulary (AI Act risk tiers + GPAI model tiers).
RISK_CLASSES = (
    "prohibited",
    "high-risk",
    "limited-risk",
    "minimal-risk",
    "gpaI-model",
    "gpaI-model-systemic",
)

#: Pinned conformity-assessment outcome vocabulary.
CONFORMITY_OUTCOMES = (
    "conform",
    "non-conform",
    "conditional",
    "not-applicable",
)

#: Pinned notification channel vocabulary.
NOTIFY_CHANNELS = (
    "eu-database",
    "market-surveillance",
    "notified-body",
    "deployers",
    "internal",
)

#: Pinned notification reason vocabulary (why the notification was declared).
NOTIFY_REASONS = (
    "serious-incident",
    "market-entry",
    "fundamental-rights-impact",
    "withdrawal",
    "manual",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "classified",
    "assessed",
    "notified",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "system",
        "system_name",
        "system_description",
        "description",
        "name",
        "deployer",
        "deployers",
        "vendor",
        "provider",
        "model",
        "model_name",
        "payload",
        "raw",
        "data",
        "text",
        "content",
        "note",
        "notes",
        "secret",
        "key",
        "incident",
        "incident_detail",
        "evidence",
    }
)

_ZERO_PIN = "sha256:" + "00" * 32


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AIActError(Exception):
    """Base error for AI Act ledger misuse."""


class BadSystemError(AIActError):
    """Malformed AI system id."""


class DuplicateSystemError(AIActError):
    """System id already classified."""


class UnknownSystemError(AIActError):
    """System id not classified."""


class BadRiskClassError(AIActError):
    """Unknown risk class."""


class BadOutcomeError(AIActError):
    """Unknown conformity-assessment outcome."""


class BadChannelError(AIActError):
    """Unknown notification channel."""


class BadReasonError(AIActError):
    """Unknown notification reason."""


class UnknownConformityError(AIActError):
    """Conformity id not booked."""


class UnknownNotificationError(AIActError):
    """Notification id not booked."""


class BadDigestError(AIActError):
    """Malformed sha256: digest pin."""


class SeqOrderError(AIActError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(AIActError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadSystemError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClassificationRecord:
    system_id: str
    risk_class: str
    system_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "risk_class": self.risk_class,
            "system_digest": self.system_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "risk_class": self.risk_class,
                "system_digest": self.system_digest,
            }
        )


@dataclass(frozen=True)
class ConformityRecord:
    conformity_id: str
    system_id: str
    outcome: str
    evidence_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "conformity_id": self.conformity_id,
            "system_id": self.system_id,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "conformity_id": self.conformity_id,
                "system_id": self.system_id,
                "outcome": self.outcome,
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    system_id: str
    channel: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "notification_id": self.notification_id,
            "system_id": self.system_id,
            "channel": self.channel,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "notification_id": self.notification_id,
                "system_id": self.system_id,
                "channel": self.channel,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class SystemPosture:
    system_id: str
    risk_class: str
    n_conformities: int
    latest_outcome: str
    n_notifications: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "risk_class": self.risk_class,
            "n_conformities": self.n_conformities,
            "latest_outcome": self.latest_outcome,
            "n_notifications": self.n_notifications,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "risk_class": self.risk_class,
                "n_conformities": self.n_conformities,
                "latest_outcome": self.latest_outcome,
                "n_notifications": self.n_notifications,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ai_act_audit_event(audit_kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the AI Act ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AIAct:
    """EU AI Act (risk-classification) governance decision ledger, Simulated.

    ``classify()`` / ``conform()`` / ``notify()`` mutate the ledger and
    consume caller seqs; ``posture()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, ClassificationRecord] = {}
        self._conformities: Dict[str, ConformityRecord] = {}
        self._conformities_for: Dict[str, List[str]] = {}
        self._notifications: Dict[str, NotificationRecord] = {}
        self._notifications_for: Dict[str, List[str]] = {}
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0
        self._n_cnf = 0
        self._n_ntf = 0

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = ai_act_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ai_act_audit_event(audit_kind, seq, **details))

    # -- classify --------------------------------------------------------------

    def classify(
        self,
        system_id: str,
        risk_class: str,
        seq: int,
        system_digest: str = "",
    ) -> ClassificationRecord:
        """Declare one AI system under a pinned risk-class vocabulary.

        System details and deployer identity travel as ``sha256:``
        digest pins only - raw descriptions never enter records.
        """
        with self._lock:
            try:
                self._claim(seq)
            except AIActError:
                raise
            try:
                _require_id(system_id, "system_id")
                if risk_class not in RISK_CLASSES:
                    raise BadRiskClassError(
                        f"risk_class must be one of {RISK_CLASSES}")
                if system_digest:
                    _require_digest(system_digest, "system_digest")
                else:
                    system_digest = _ZERO_PIN
                if system_id in self._systems:
                    raise DuplicateSystemError(
                        f"system already classified: {system_id!r}")
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "risk_class": risk_class,
                        "system_digest": system_digest,
                    }
                )
                record = ClassificationRecord(
                    system_id=system_id,
                    risk_class=risk_class,
                    system_digest=system_digest,
                    digest=digest,
                )
                self._systems[system_id] = record
                self._conformities_for[system_id] = []
                self._notifications_for[system_id] = []
                self._emit(
                    "classified",
                    seq,
                    system_id=system_id,
                    risk_class=risk_class,
                )
                return record
            except AIActError:
                self._burn(seq, "classify")
                raise

    # -- conform -----------------------------------------------------------------

    def conform(
        self,
        system_id: str,
        seq: int,
        outcome: str = "conform",
        evidence_digest: str = "",
    ) -> ConformityRecord:
        """Book one declared conformity-assessment decision (minted ``cnf-N``).

        The outcome is host-declared data - never proof of conformity.
        """
        with self._lock:
            try:
                self._claim(seq)
            except AIActError:
                raise
            try:
                _require_id(system_id, "system_id")
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if outcome not in CONFORMITY_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {CONFORMITY_OUTCOMES}")
                if evidence_digest:
                    _require_digest(evidence_digest, "evidence_digest")
                else:
                    evidence_digest = _ZERO_PIN
                self._n_cnf += 1
                conformity_id = f"cnf-{self._n_cnf}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "conformity_id": conformity_id,
                        "system_id": system_id,
                        "outcome": outcome,
                        "evidence_digest": evidence_digest,
                    }
                )
                record = ConformityRecord(
                    conformity_id=conformity_id,
                    system_id=system_id,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    digest=digest,
                )
                self._conformities[conformity_id] = record
                self._conformities_for[system_id].append(conformity_id)
                self._emit(
                    "assessed",
                    seq,
                    conformity_id=conformity_id,
                    system_id=system_id,
                    outcome=outcome,
                )
                return record
            except AIActError:
                self._burn(seq, "conform")
                raise

    # -- notify ------------------------------------------------------------------

    def notify(
        self,
        system_id: str,
        seq: int,
        channel: str = "eu-database",
        reason: str = "manual",
    ) -> NotificationRecord:
        """Book one declared notification decision (minted ``ntf-N``).

        Books the routing decision - never proof a notification was sent
        or received.
        """
        with self._lock:
            try:
                self._claim(seq)
            except AIActError:
                raise
            try:
                _require_id(system_id, "system_id")
                if system_id not in self._systems:
                    raise UnknownSystemError(
                        f"unknown system: {system_id!r}")
                if channel not in NOTIFY_CHANNELS:
                    raise BadChannelError(
                        f"channel must be one of {NOTIFY_CHANNELS}")
                if reason not in NOTIFY_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {NOTIFY_REASONS}")
                self._n_ntf += 1
                notification_id = f"ntf-{self._n_ntf}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "notification_id": notification_id,
                        "system_id": system_id,
                        "channel": channel,
                        "reason": reason,
                    }
                )
                record = NotificationRecord(
                    notification_id=notification_id,
                    system_id=system_id,
                    channel=channel,
                    reason=reason,
                    digest=digest,
                )
                self._notifications[notification_id] = record
                self._notifications_for[system_id].append(notification_id)
                self._emit(
                    "notified",
                    seq,
                    notification_id=notification_id,
                    system_id=system_id,
                    channel=channel,
                    reason=reason,
                )
                return record
            except AIActError:
                self._burn(seq, "notify")
                raise

    # -- posture (pure read) -----------------------------------------------------

    def posture(self, system_id: str, seq: int) -> SystemPosture:
        """Pure read: per-system posture as data, digest-pinned."""
        with self._lock:
            self._view_seq_ok(seq)
            record = self._systems.get(system_id)
            if record is None:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            cnf_ids = self._conformities_for.get(system_id, [])
            ntf_ids = self._notifications_for.get(system_id, [])
            integrity_ok = record.verify()
            latest_outcome = "not-assessed"
            for cnf_id in cnf_ids:
                cnf = self._conformities[cnf_id]
                if not cnf.verify():
                    integrity_ok = False
                latest_outcome = cnf.outcome
            for ntf_id in ntf_ids:
                if not self._notifications[ntf_id].verify():
                    integrity_ok = False
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "risk_class": record.risk_class,
                    "n_conformities": len(cnf_ids),
                    "latest_outcome": latest_outcome,
                    "n_notifications": len(ntf_ids),
                    "integrity_ok": integrity_ok,
                }
            )
            return SystemPosture(
                system_id=system_id,
                risk_class=record.risk_class,
                n_conformities=len(cnf_ids),
                latest_outcome=latest_outcome,
                n_notifications=len(ntf_ids),
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def classification_record(self, system_id: str, seq: int) -> ClassificationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._systems.get(system_id)
            if record is None:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return record

    def conformity_record(self, conformity_id: str, seq: int) -> ConformityRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._conformities.get(conformity_id)
            if record is None:
                raise UnknownConformityError(
                    f"unknown conformity: {conformity_id!r}")
            return record

    def notification_record(self, notification_id: str, seq: int) -> NotificationRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._notifications.get(notification_id)
            if record is None:
                raise UnknownNotificationError(
                    f"unknown notification: {notification_id!r}")
            return record

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._systems))

    def conformity_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._conformities))

    def conformities_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return tuple(self._conformities_for.get(system_id, []))

    def notifications_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            if system_id not in self._systems:
                raise UnknownSystemError(
                    f"unknown system: {system_id!r}")
            return tuple(self._notifications_for.get(system_id, []))

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "systems": len(self._systems),
                "conformities": len(self._conformities),
                "notifications": len(self._notifications),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    a = AIAct()
    rec = a.classify("sys-1", "high-risk", 1)
    assert rec.verify()
    cnf = a.conform("sys-1", 2, outcome="conform")
    assert cnf.verify()
    ntf = a.notify("sys-1", 3, channel="eu-database", reason="market-entry")
    assert ntf.verify()
    st = a.posture("sys-1", 0)
    assert st.verify()
    assert st.n_conformities == 1 and st.latest_outcome == "conform"
    assert st.n_notifications == 1 and st.integrity_ok
    print("ai-act OK: classify, conform, notify, posture, pins")


if __name__ == "__main__":
    main()
