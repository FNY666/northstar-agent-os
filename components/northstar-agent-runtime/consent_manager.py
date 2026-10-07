"""GDPR consent manager (twenty-eighth batch).

Operational consent interface over the consent-records line:

* **GDPR Art. 7(1)** (demonstrability): the controller must be able to
  demonstrate that the data subject has consented. Every
  :meth:`ConsentManager.grant` therefore *requires* non-empty
  ``evidence`` (how/when consent was collected, e.g. ``"ui:checkbox#v3"``)
  — a grant without evidence is refused, fail-closed.
* **GDPR Art. 7(3)** (withdrawal): withdrawing must be as easy as
  giving, and withdrawal is effective immediately. :meth:`withdraw`
  never fails when an active grant exists; a withdrawal is a new
  record, never an edit — there is no "un-withdraw" (a fresh grant is
  a new :meth:`grant`).
* **GDPR Art. 5(1)(b)** (purpose limitation): consent is bound to an
  exact ``(purpose, scope)`` pair. :meth:`consented` matches exactly —
  no wildcards, no subsumption. A grant for ``"analytics"`` does not
  cover ``"marketing"``; a grant for ``"personal"`` does not cover
  ``"special_category"`` (Art. 9).
* **Art. 6(1)(a)**: this manager records *consent*-basis processing
  only. A grant offered under any other lawful basis
  (``contract``, ``legitimate_interests``, ...) is refused — consent
  records must not launder non-consent processing.

Record shape is informed by ISO/IEC 27560:2023 (consent record
information structure) and the EDPB Guidelines 05/2020 on consent;
the consent semantics (use-time check, revocation immediacy) are
consistent with :mod:`consent_receipts`, which is the cryptographic
layer — this module is the operational interface (subjects, purposes,
state machine, audit summaries).

House rules: no wall-clock (callers inject integer seq/epoch values),
frozen dataclasses, fail-closed checks (unknown subject / expired /
withdrawn / tampered record all read as *not consented*), stdlib-only,
records sealed with a sha256 ``record_digest`` over the canonical
payload and chained per ``(subject, purpose, scope)`` via
``prev_digest``. State transitions emit ``audit.ndjson/1`` events.

Honest boundary: this module records *claimed* consent consistently
(digests recompute, the chain is per-key append-only, withdrawal is
immediate and visible). It cannot prove the human understood the
notice, was not coerced, or was the key/click holder. Consent UX and
identity binding are outside this module's scope.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from typing import Any, Mapping


#: Version pin for this module's record shape.
CONSENT_MANAGER_VERSION = "consent-manager.v1"

#: Schema pin carried by records and audit events.
CONSENT_MANAGER_SCHEMA = "northstar.consent-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Record statuses.
GRANTED = "granted"
WITHDRAWN = "withdrawn"
_STATUSES = (GRANTED, WITHDRAWN)

#: GDPR Art. 6(1) lawful bases. This manager records consent only.
LAWFUL_BASIS_CONSENT = "consent"
LAWFUL_BASES = (
    "consent",
    "contract",
    "legal_obligation",
    "vital_interests",
    "public_task",
    "legitimate_interests",
)

#: Data-category vocabulary for consent scope.
SCOPE_PERSONAL = "personal"                # Art. 6 personal data
SCOPE_SPECIAL_CATEGORY = "special_category"  # Art. 9 special categories
SCOPE_CRIMINAL_OFFENCE = "criminal_offence"  # Art. 10
SCOPE_CHILD = "child"                        # Art. 8 (information society services)
SCOPES = (
    SCOPE_PERSONAL,
    SCOPE_SPECIAL_CATEGORY,
    SCOPE_CRIMINAL_OFFENCE,
    SCOPE_CHILD,
)

#: Audit event kinds.
KIND_GRANTED = "consent.granted"
KIND_WITHDRAWN = "consent.withdrawn"
KIND_AUDIT = "consent.audit"
_KINDS = (KIND_GRANTED, KIND_WITHDRAWN, KIND_AUDIT)

_GENESIS = "genesis"


class ConsentError(ValueError):
    """A malformed request or a refused state transition.

    Raised for structural problems (empty subject, unknown scope,
    non-consent lawful basis, bad seq) and for transitions the log
    cannot take (grant over an active grant, withdraw with no active
    grant). *Checks* (:meth:`ConsentManager.consented`) never raise:
    they return ``False`` — a failed consent check is a verdict, a
    malformed request is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConsentError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConsentError(f"{field_name} must be a non-empty string")
    return value


def _check_scope(value: Any) -> str:
    if value not in SCOPES:
        raise ConsentError(f"scope must be one of {SCOPES}, saw {value!r}")
    return value


# ---------------------------------------------------------------------------
# Consent records — one append-only, hash-chained history per key
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConsentRecord:
    """One state of a consent grant for ``(subject_id, purpose, scope)``.

    Each transition (grant, withdrawal, fresh grant) appends a new
    record; records are never edited. ``seq`` is the caller-injected
    sequence/epoch at which this record was created; ``granted_seq``
    is the seq of the grant this record belongs to. ``expires_at`` of
    ``None`` means no expiry. The record is sealed with
    ``record_digest`` and chained to the previous record for the same
    key via ``prev_digest`` (``"genesis"`` for the first).
    """

    subject_id: str
    purpose: str
    scope: str
    status: str
    lawful_basis: str
    granted_seq: int
    seq: int
    expires_at: int | None
    evidence: str
    prev_digest: str = _GENESIS
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.subject_id, "subject_id")
        _check_nonempty_str(self.purpose, "purpose")
        _check_scope(self.scope)
        if self.status not in _STATUSES:
            raise ConsentError(f"status must be one of {_STATUSES}, saw {self.status!r}")
        if self.lawful_basis != LAWFUL_BASIS_CONSENT:
            raise ConsentError(
                "consent records are Art. 6(1)(a) only; "
                f"saw lawful_basis {self.lawful_basis!r}"
            )
        _check_seq(self.granted_seq, "granted_seq")
        _check_seq(self.seq, "seq")
        if self.seq < self.granted_seq:
            raise ConsentError("seq must not predate granted_seq")
        if self.expires_at is not None:
            _check_seq(self.expires_at, "expires_at")
            if self.expires_at <= self.granted_seq:
                raise ConsentError("expires_at must be after granted_seq")
        _check_nonempty_str(self.evidence, "evidence")
        if self.prev_digest != _GENESIS:
            if not isinstance(self.prev_digest, str) or len(self.prev_digest) != 64:
                raise ConsentError("prev_digest must be 'genesis' or a 64-char hex digest")
        if self.record_digest != "" and (
            not isinstance(self.record_digest, str) or len(self.record_digest) != 64
        ):
            raise ConsentError("record_digest must be '' or a 64-char hex digest")


def _record_payload(record: ConsentRecord) -> dict[str, Any]:
    return {
        "schema": CONSENT_MANAGER_SCHEMA,
        "kind": "consent-record",
        "subject_id": record.subject_id,
        "purpose": record.purpose,
        "scope": record.scope,
        "status": record.status,
        "lawful_basis": record.lawful_basis,
        "granted_seq": record.granted_seq,
        "seq": record.seq,
        "expires_at": record.expires_at,
        "evidence": record.evidence,
        "prev_digest": record.prev_digest,
    }


def _canonical(obj: Any) -> bytes:
    # All payload values are str/int/None — no floats, so no >2^53
    # precision hazard; ints serialize exactly.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def compute_record_digest(record: ConsentRecord) -> str:
    """Recompute a record's seal over all fields except itself."""
    return hashlib.sha256(_canonical(_record_payload(record))).hexdigest()


def _seal(record: ConsentRecord) -> ConsentRecord:
    return replace(record, record_digest=compute_record_digest(record))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def consent_manager_audit_event(kind: str, seq: int, **detail: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the consent manager."""
    if kind not in _KINDS:
        raise ConsentError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "consent_manager",
        "module_version": CONSENT_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# ConsentManager
# ---------------------------------------------------------------------------


class ConsentManager:
    """GDPR consent state machine with an append-only per-key history.

    Keyed by exact ``(subject_id, purpose, scope)``. Grants require
    evidence (Art. 7(1)); withdrawal is immediate (Art. 7(3)); checks
    are fail-closed. No wall-clock: every timestamp is a caller-
    injected non-negative int ``seq``.
    """

    def __init__(self) -> None:
        self._history: dict[tuple[str, str, str], list[ConsentRecord]] = {}
        self._events: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    @staticmethod
    def _key(subject_id: str, purpose: str, scope: str) -> tuple[str, str, str]:
        return (subject_id, purpose, scope)

    def _latest(self, key: tuple[str, str, str]) -> ConsentRecord | None:
        hist = self._history.get(key)
        return hist[-1] if hist else None

    # -- grant / withdraw ----------------------------------------------

    def grant(
        self,
        *,
        subject_id: str,
        purpose: str,
        scope: str,
        seq: int,
        expires_at: int | None = None,
        evidence: str,
        lawful_basis: str = LAWFUL_BASIS_CONSENT,
    ) -> ConsentRecord:
        """Record a fresh consent grant. Fail-closed on any bad input.

        Refuses: empty subject/purpose/evidence, unknown scope, a
        lawful basis other than ``"consent"`` (Art. 6(1)(a) only),
        ``expires_at`` not after the grant seq, and a grant over an
        already-active grant for the same key (withdraw first, then
        re-grant — there is no silent refresh).
        """
        subject_id = _check_nonempty_str(subject_id, "subject_id")
        purpose = _check_nonempty_str(purpose, "purpose")
        scope = _check_scope(scope)
        seq = _check_seq(seq, "seq")
        if lawful_basis != LAWFUL_BASIS_CONSENT:
            raise ConsentError(
                "this manager records Art. 6(1)(a) consent only; "
                f"refusing grant under lawful basis {lawful_basis!r}"
            )
        if expires_at is not None:
            expires_at = _check_seq(expires_at, "expires_at")
            if expires_at <= seq:
                raise ConsentError("expires_at must be after the grant seq")
        evidence = _check_nonempty_str(evidence, "evidence")
        key = self._key(subject_id, purpose, scope)
        latest = self._latest(key)
        if latest is not None and latest.status == GRANTED:
            raise ConsentError(
                "duplicate active grant: withdraw the active grant "
                "before recording a fresh one"
            )
        if latest is not None and seq < latest.seq:
            raise ConsentError("seq must not move backwards for a key")
        prev = latest.record_digest if latest is not None else _GENESIS
        record = _seal(ConsentRecord(
            subject_id=subject_id,
            purpose=purpose,
            scope=scope,
            status=GRANTED,
            lawful_basis=LAWFUL_BASIS_CONSENT,
            granted_seq=seq,
            seq=seq,
            expires_at=expires_at,
            evidence=evidence,
            prev_digest=prev,
        ))
        self._history.setdefault(key, []).append(record)
        self._events.append(consent_manager_audit_event(
            KIND_GRANTED, seq,
            subject_id=subject_id, purpose=purpose, scope=scope,
            record_digest=record.record_digest,
        ))
        return record

    def withdraw(self, *, subject_id: str, purpose: str, scope: str, seq: int) -> ConsentRecord:
        """Withdraw an active grant. Effective immediately, irreversible.

        Appends a ``withdrawn`` record chained to the grant — the
        grant itself is never edited or deleted. Raises
        :class:`ConsentError` when there is no active grant for the
        key (fail-closed: refuses to invent a withdrawal), or when
        ``seq`` predates the grant.
        """
        subject_id = _check_nonempty_str(subject_id, "subject_id")
        purpose = _check_nonempty_str(purpose, "purpose")
        scope = _check_scope(scope)
        seq = _check_seq(seq, "seq")
        key = self._key(subject_id, purpose, scope)
        latest = self._latest(key)
        if latest is None or latest.status != GRANTED:
            raise ConsentError("no active grant to withdraw for this key")
        if seq < latest.seq:
            raise ConsentError("withdraw seq must not move backwards for a key")
        if seq < latest.granted_seq:
            raise ConsentError("withdraw seq predates the grant seq")
        record = _seal(ConsentRecord(
            subject_id=subject_id,
            purpose=purpose,
            scope=scope,
            status=WITHDRAWN,
            lawful_basis=latest.lawful_basis,
            granted_seq=latest.granted_seq,
            seq=seq,
            expires_at=latest.expires_at,
            evidence=latest.evidence,
            prev_digest=latest.record_digest,
        ))
        self._history[key].append(record)
        self._events.append(consent_manager_audit_event(
            KIND_WITHDRAWN, seq,
            subject_id=subject_id, purpose=purpose, scope=scope,
            record_digest=record.record_digest,
        ))
        return record

    # -- checks and views -----------------------------------------------

    def consented(self, *, subject_id: str, purpose: str, scope: str, at_seq: int) -> bool:
        """Fail-closed consent check at ``at_seq``.

        Answers "was processing at ``at_seq`` covered by consent?"
        against the key's full history: the record active at ``at_seq``
        (the latest record with ``seq <= at_seq``) must be a sealed
        ``granted`` record with ``at_seq`` inside
        ``[granted_seq, expires_at]``. A grant revoked *after*
        ``at_seq`` therefore still covers ``at_seq`` (withdrawal is
        prospective); a withdrawal *at or before* ``at_seq`` denies.
        Anything else — unknown subject, purpose/scope mismatch,
        withdrawn at ``at_seq``, expired, not-yet-granted, tampered —
        reads as *not consented*.
        """
        try:
            subject_id = _check_nonempty_str(subject_id, "subject_id")
            purpose = _check_nonempty_str(purpose, "purpose")
            scope = _check_scope(scope)
            at_seq = _check_seq(at_seq, "at_seq")
        except ConsentError:
            return False
        # Walk the per-key history (append-only, seq-non-decreasing) to
        # the record that was active at at_seq.
        active: ConsentRecord | None = None
        for record in self._history.get(self._key(subject_id, purpose, scope), []):
            if record.seq > at_seq:
                break
            active = record
        if active is None or active.status != GRANTED:
            return False
        if not hmac.compare_digest(compute_record_digest(active), active.record_digest):
            return False  # tampered record: deny
        if at_seq < active.granted_seq:
            return False
        if active.expires_at is not None and at_seq > active.expires_at:
            return False
        return True

    def records(
        self,
        *,
        subject_id: str | None = None,
        purpose: str | None = None,
        scope: str | None = None,
    ) -> tuple[ConsentRecord, ...]:
        """Latest record per key, optionally filtered."""
        out = []
        for record in (h[-1] for h in self._history.values() if h):
            if subject_id is not None and record.subject_id != subject_id:
                continue
            if purpose is not None and record.purpose != purpose:
                continue
            if scope is not None and record.scope != scope:
                continue
            out.append(record)
        return tuple(out)

    def audit(
        self,
        seq: int,
        *,
        subject_id: str | None = None,
        purpose: str | None = None,
        scope: str | None = None,
    ) -> Mapping[str, Any]:
        """Shape current consent state as an ``audit.ndjson/1`` event.

        Carries a ``state_digest`` pinning the filtered record set, so
        an auditor can detect drift between two audit events.
        """
        seq = _check_seq(seq, "seq")
        filtered = self.records(subject_id=subject_id, purpose=purpose, scope=scope)
        active = [r for r in filtered if r.status == GRANTED]
        state_digest = hashlib.sha256(_canonical(
            sorted(r.record_digest for r in filtered)
        )).hexdigest()
        return consent_manager_audit_event(
            KIND_AUDIT, seq,
            subjects=sorted({r.subject_id for r in filtered}),
            records=len(filtered),
            active_grants=len(active),
            withdrawn=len(filtered) - len(active),
            state_digest=state_digest,
        )

    def audit_trail(self) -> tuple[Mapping[str, Any], ...]:
        """Grant/withdraw events emitted so far, in order."""
        return tuple(self._events)


def main() -> None:
    mgr = ConsentManager()
    grant = mgr.grant(
        subject_id="sub-1", purpose="analytics", scope="personal",
        seq=10, expires_at=100, evidence="ui:checkbox#v3",
    )
    assert mgr.consented(subject_id="sub-1", purpose="analytics",
                         scope="personal", at_seq=50)
    withdrawn = mgr.withdraw(
        subject_id="sub-1", purpose="analytics", scope="personal", seq=60
    )
    assert withdrawn.status == WITHDRAWN
    assert not mgr.consented(subject_id="sub-1", purpose="analytics",
                             scope="personal", at_seq=70)
    fresh = mgr.grant(
        subject_id="sub-1", purpose="analytics", scope="personal",
        seq=80, evidence="ui:checkbox#v4",
    )
    assert fresh.prev_digest == withdrawn.record_digest  # chain continues
    assert mgr.consented(subject_id="sub-1", purpose="analytics",
                         scope="personal", at_seq=90)
    event = mgr.audit(seq=91)
    assert event["schema"] == AUDIT_SCHEMA and event["detail"]["active_grants"] == 1
    print("consent-manager OK: grant, check, withdraw, re-grant, audit")


if __name__ == "__main__":
    main()


__all__ = [
    "AUDIT_SCHEMA",
    "CONSENT_MANAGER_SCHEMA",
    "CONSENT_MANAGER_VERSION",
    "GRANTED",
    "KIND_AUDIT",
    "KIND_GRANTED",
    "KIND_WITHDRAWN",
    "LAWFUL_BASES",
    "LAWFUL_BASIS_CONSENT",
    "SCOPES",
    "SCOPE_CHILD",
    "SCOPE_CRIMINAL_OFFENCE",
    "SCOPE_PERSONAL",
    "SCOPE_SPECIAL_CATEGORY",
    "WITHDRAWN",
    "ConsentError",
    "ConsentManager",
    "ConsentRecord",
    "compute_record_digest",
    "consent_manager_audit_event",
    "main",
]
