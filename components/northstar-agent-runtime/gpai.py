"""GPAI: general-purpose AI model governance decision ledger, Simulated.

Research note: Title VIIIa / Chapter V of the EU AI Act (Regulation
(EU) 2024/1689) places specific obligations on providers of
general-purpose AI models: technical documentation, information for
downstream system providers, a copyright/opt-out policy, and a
summary of training content (Annex XI/XII). Models posing *systemic
risk* - those whose capabilities meet the Article 51 threshold (e.g.
high-impact capabilities with benchmarks comparable to the FLOPs
criterion) - carry additional duties: adversarial testing,
systemic-risk assessment and mitigation, incident tracking and
reporting, and cybersecurity assurance. What matters here is the
*decision ledger*: which models were classified into which GPAI bucket,
which evaluations were declared and with what outcomes, and which
notifications to the AI Office were booked - defensible bookkeeping,
never proof of regulatory compliance.

This module owns the classify -> evaluate -> notify lifecycle:

* **classify()** - book one declared GPAI classification for a model
  (pinned category vocabulary ``gpai`` / ``gpai-systemic-risk`` /
  ``not-gpai``); raw weights, architecture details, and training data
  never enter records - digest pins only.
* **evaluate()** - book one declared evaluation outcome (minted
  ``eval-N`` ids; pinned evaluation-kind and outcome vocabularies)
  against a classified model.
* **notify()** - book one declared notification to the AI Office (minted
  ``ntf-N`` ids; pinned notification vocabulary); books the
  *declaration*, never proof the filing was sent or received.
* **retire()** - terminal retirement of a model id; ids are never
  recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``gpai.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins, and ``audit.ndjson/1`` events.

Honest scope: this module contacts no regulator, runs no benchmark,
inspects no weights, and proves nothing about systemic risk. A booked
``gpai-systemic-risk`` classification means "the host declared it",
never "the model poses systemic risk". Model weights, training data,
capabilities descriptions, and evaluation scores never enter records
or cross the audit boundary - digest pins only.
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
GPAI_VERSION = "gpai.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.gpai.v1"

#: Pinned GPAI classification vocabulary (EU AI Act Article 51-shaped).
CATEGORIES = (
    "not-gpai",
    "gpai",
    "gpai-systemic-risk",
)

#: Pinned evaluation-kind vocabulary.
EVAL_KINDS = (
    "capability",
    "adversarial-robustness",
    "red-team",
    "systemic-risk",
    "benchmark",
)

#: Pinned evaluation-outcome vocabulary.
EVAL_OUTCOMES = (
    "pass",
    "fail",
    "inconclusive",
)

#: Pinned notification vocabulary (AI Office-facing declarations).
NOTIFICATIONS = (
    "ai-office-filing",
    "downstream-info",
    "incident-report",
    "serious-incident",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "classified",
    "evaluated",
    "notified",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "model",
        "training_data",
        "training",
        "dataset",
        "capabilities",
        "capability",
        "architecture",
        "score",
        "scores",
        "result",
        "results",
        "report",
        "filing",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "payload",
        "raw",
        "secret",
        "key",
        "prompt",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GPAIError(Exception):
    """Base error for GPAI ledger misuse."""


class BadIdError(GPAIError):
    """Malformed model, evaluation, or notification id."""


class DuplicateModelError(GPAIError):
    """Model already classified."""


class UnknownModelError(GPAIError):
    """Model not classified."""


class RetiredModelError(GPAIError):
    """Model id already retired; never recycled."""


class BadCategoryError(GPAIError):
    """Unknown GPAI classification category."""


class BadDigestError(GPAIError):
    """Malformed sha256: digest pin."""


class BadKindError(GPAIError):
    """Unknown evaluation kind."""


class BadOutcomeError(GPAIError):
    """Unknown evaluation outcome."""


class UnknownEvaluationError(GPAIError):
    """Evaluation id not booked."""


class BadNotificationError(GPAIError):
    """Unknown notification type."""


class UnknownNotificationError(GPAIError):
    """Notification id not booked."""


class BadReasonError(GPAIError):
    """Unknown retirement reason."""


class SeqOrderError(GPAIError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(GPAIError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
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
    model_id: str
    category: str
    model_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "category": self.category,
            "model_digest": self.model_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "category": self.category,
                "model_digest": self.model_digest,
            }
        )


@dataclass(frozen=True)
class EvaluationRecord:
    eval_id: str
    model_id: str
    eval_kind: str
    outcome: str
    report_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "eval_id": self.eval_id,
            "model_id": self.model_id,
            "eval_kind": self.eval_kind,
            "outcome": self.outcome,
            "report_digest": self.report_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "eval_id": self.eval_id,
                "model_id": self.model_id,
                "eval_kind": self.eval_kind,
                "outcome": self.outcome,
                "report_digest": self.report_digest,
            }
        )


@dataclass(frozen=True)
class NotificationRecord:
    notification_id: str
    model_id: str
    notification: str
    reference_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "notification_id": self.notification_id,
            "model_id": self.model_id,
            "notification": self.notification,
            "reference_digest": self.reference_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "notification_id": self.notification_id,
                "model_id": self.model_id,
                "notification": self.notification,
                "reference_digest": self.reference_digest,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    model_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "model_id": self.model_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "model_id": self.model_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class StatusReport:
    n_models: int
    n_evaluations: int
    n_notifications: int
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_models": self.n_models,
            "n_evaluations": self.n_evaluations,
            "n_notifications": self.n_notifications,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_models": self.n_models,
                "n_evaluations": self.n_evaluations,
                "n_notifications": self.n_notifications,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def gpai_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the GPAI ledger."""
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


class GPAI:
    """GPAI governance decision ledger, Simulated.

    ``classify()`` / ``evaluate()`` / ``notify()`` / ``retire()``
    mutate the ledger and consume caller seqs; views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._classifications: Dict[str, ClassificationRecord] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._evaluations_by_model: Dict[str, List[str]] = {}
        self._notifications: Dict[str, NotificationRecord] = {}
        self._notifications_by_model: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._eval_counter = 0
        self._ntf_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: GPAIError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            gpai_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model already retired: {model_id!r}")

    # -- mutations --------------------------------------------------------

    def classify(
        self,
        model_id: Any,
        seq: Any,
        category: Any = "not-gpai",
        model_digest: Any = "",
    ) -> ClassificationRecord:
        """Book one declared GPAI classification for a model."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(
                        f"model id never recycled: {mid!r}"
                    )
                if mid in self._classifications:
                    raise DuplicateModelError(
                        f"model already classified: {mid!r}"
                    )
                if not isinstance(category, str) or category not in CATEGORIES:
                    raise BadCategoryError(
                        f"category must be one of {sorted(CATEGORIES)}"
                    )
                pin = _require_digest(model_digest, "model_digest")
                rec = ClassificationRecord(
                    model_id=mid,
                    category=category,
                    model_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "model_id": mid,
                            "category": category,
                            "model_digest": pin,
                        }
                    ),
                )
                self._classifications[mid] = rec
                self._audit.append(
                    gpai_audit_event(
                        "classified",
                        seq_v,
                        model_id=mid,
                        category=category,
                    )
                )
                return rec
            except GPAIError as exc:
                self._burn(seq_v, "classify", exc)
                raise

    def evaluate(
        self,
        model_id: Any,
        seq: Any,
        eval_kind: Any = "capability",
        outcome: Any = "pass",
        report_digest: Any = "",
    ) -> EvaluationRecord:
        """Book one declared evaluation outcome (minted ``eval-N``)."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {mid!r}"
                    )
                if mid not in self._classifications:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                if not isinstance(eval_kind, str) or eval_kind not in EVAL_KINDS:
                    raise BadKindError(
                        f"eval_kind must be one of {sorted(EVAL_KINDS)}"
                    )
                if not isinstance(outcome, str) or outcome not in EVAL_OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {sorted(EVAL_OUTCOMES)}"
                    )
                pin = _require_digest(report_digest, "report_digest")
                self._eval_counter += 1
                eid = f"eval-{self._eval_counter}"
                rec = EvaluationRecord(
                    eval_id=eid,
                    model_id=mid,
                    eval_kind=eval_kind,
                    outcome=outcome,
                    report_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "eval_id": eid,
                            "model_id": mid,
                            "eval_kind": eval_kind,
                            "outcome": outcome,
                            "report_digest": pin,
                        }
                    ),
                )
                self._evaluations[eid] = rec
                self._evaluations_by_model.setdefault(mid, []).append(eid)
                self._audit.append(
                    gpai_audit_event(
                        "evaluated",
                        seq_v,
                        eval_id=eid,
                        model_id=mid,
                        eval_kind=eval_kind,
                        outcome=outcome,
                    )
                )
                return rec
            except GPAIError as exc:
                self._burn(seq_v, "evaluate", exc)
                raise

    def notify(
        self,
        model_id: Any,
        seq: Any,
        notification: Any = "ai-office-filing",
        reference_digest: Any = "",
    ) -> NotificationRecord:
        """Book one declared AI Office notification (minted ``ntf-N``)."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {mid!r}"
                    )
                if mid not in self._classifications:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                if (
                    not isinstance(notification, str)
                    or notification not in NOTIFICATIONS
                ):
                    raise BadNotificationError(
                        f"notification must be one of {sorted(NOTIFICATIONS)}"
                    )
                pin = _require_digest(reference_digest, "reference_digest")
                self._ntf_counter += 1
                nid = f"ntf-{self._ntf_counter}"
                rec = NotificationRecord(
                    notification_id=nid,
                    model_id=mid,
                    notification=notification,
                    reference_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "notification_id": nid,
                            "model_id": mid,
                            "notification": notification,
                            "reference_digest": pin,
                        }
                    ),
                )
                self._notifications[nid] = rec
                self._notifications_by_model.setdefault(mid, []).append(nid)
                self._audit.append(
                    gpai_audit_event(
                        "notified",
                        seq_v,
                        notification_id=nid,
                        model_id=mid,
                        notification=notification,
                    )
                )
                return rec
            except GPAIError as exc:
                self._burn(seq_v, "notify", exc)
                raise

    def retire(
        self,
        model_id: Any,
        seq: Any,
        reason: Any = "manual",
    ) -> RetireRecord:
        """Terminally retire a model id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                mid = _require_id(model_id, "model_id")
                if mid in self._retired:
                    raise RetiredModelError(
                        f"model already retired: {mid!r}"
                    )
                if mid not in self._classifications:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(
                        f"reason must be one of {sorted(RETIRE_REASONS)}"
                    )
                rec = RetireRecord(
                    model_id=mid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "model_id": mid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[mid] = rec
                self._audit.append(
                    gpai_audit_event(
                        "retired",
                        seq_v,
                        model_id=mid,
                        reason=reason,
                    )
                )
                return rec
            except GPAIError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def classification_record(self, model_id: Any, seq: Any) -> ClassificationRecord:
        """Return one classification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._classifications:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return self._classifications[mid]

    def model_ids(self, seq: Any) -> Tuple[str, ...]:
        """All classified model ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._classifications.keys())

    def evaluation_record(self, eval_id: Any, seq: Any) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            eid = _require_id(eval_id, "eval_id")
            if eid not in self._evaluations:
                raise UnknownEvaluationError(f"unknown evaluation: {eid!r}")
            return self._evaluations[eid]

    def evaluations_for(self, model_id: Any, seq: Any) -> Tuple[str, ...]:
        """Evaluation ids booked against one model (mint order)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._classifications:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return tuple(self._evaluations_by_model.get(mid, ()))

    def notification_record(
        self, notification_id: Any, seq: Any
    ) -> NotificationRecord:
        """Return one notification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            nid = _require_id(notification_id, "notification_id")
            if nid not in self._notifications:
                raise UnknownNotificationError(
                    f"unknown notification: {nid!r}"
                )
            return self._notifications[nid]

    def notifications_for(self, model_id: Any, seq: Any) -> Tuple[str, ...]:
        """Notification ids booked against one model (mint order)."""
        with self._lock:
            self._check_seq(seq)
            mid = _require_id(model_id, "model_id")
            if mid not in self._classifications:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return tuple(self._notifications_by_model.get(mid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired model ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def status(self, seq: Any) -> StatusReport:
        """Aggregate ledger counts with digest-pinned integrity (pure read)."""
        with self._lock:
            self._check_seq(seq)
            integrity_ok = all(
                rec.verify()
                for rec in (
                    *self._classifications.values(),
                    *self._evaluations.values(),
                    *self._notifications.values(),
                    *self._retired.values(),
                )
            )
            report = StatusReport(
                n_models=len(self._classifications),
                n_evaluations=len(self._evaluations),
                n_notifications=len(self._notifications),
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "n_models": len(self._classifications),
                        "n_evaluations": len(self._evaluations),
                        "n_notifications": len(self._notifications),
                        "integrity_ok": integrity_ok,
                    }
                ),
            )
            return report

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "models": len(self._classifications),
                "evaluations": len(self._evaluations),
                "notifications": len(self._notifications),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    g = GPAI()
    pin = "sha256:" + "ab" * 32
    g.classify("model-1", 1, category="gpai-systemic-risk", model_digest=pin)
    ev = g.evaluate(
        "model-1", 2, eval_kind="systemic-risk", outcome="pass", report_digest=pin
    )
    assert ev.eval_id == "eval-1"
    nt = g.notify(
        "model-1", 3, notification="ai-office-filing", reference_digest=pin
    )
    assert nt.notification_id == "ntf-1"
    g.retire("model-1", 4, reason="decommissioned")
    st = g.status(5)
    assert st.verify()
    assert st.integrity_ok is True
    assert g.stats(6) == {
        "models": 1,
        "evaluations": 1,
        "notifications": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("gpai OK: classify, evaluate, notify, retire, pins, audit")


if __name__ == "__main__":
    main()
