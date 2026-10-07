"""Identity verification badges (twenty-ninth batch).

Operational interface for issuing, checking, and revoking *verification
badges* — claimed identity-assurance levels for subjects, in the shape of
platform verification marks (email/phone/KYC/business verification).
The design vocabulary is informed by eIDAS assurance levels
(low/substantial/high) and NIST SP 800-63A identity proofing: each
badge type pins a *claimed* assurance level; the record books the
evidence *reference* (how the check was performed), never the evidence
itself.

Record semantics:

* :meth:`VerificationBadges.issue` mints a new badge (``badge-N`` id)
  for ``(subject_id, badge_type)``. Badges are **append-only**: issuing
  never edits an existing badge.
* :meth:`VerificationBadges.revoke` terminally revokes one badge id.
  A revoked badge can never become active again (fail-closed); a fresh
  issuance is a new badge id.
* :meth:`VerificationBadges.check` is a **pure verdict, never a raise**:
  ``True`` iff the subject holds at least one badge of the given type
  that is active, digest-valid, and unexpired at ``at_seq``. Unknown
  subject/type, revoked, expired, or tampered badges all read as
  ``False``.

House rules: no wall-clock (callers inject non-negative int ``seq`` /
``at_seq``), frozen dataclasses, fail-closed checks, stdlib-only,
records sealed with a sha256 ``record_digest`` over the canonical
payload. State transitions emit ``audit.ndjson/1`` events; the audit
boundary carries ids and digests only — evidence references and
subject identifiers' raw PII never cross it.

Honest boundary: this module records *claimed* verification events
consistently (digests recompute, revocation is terminal and visible).
It cannot prove the human behind the subject, that the evidence was
real, or that the check was performed correctly. Identity proofing UX,
KYC providers, and evidence storage are outside this module's scope.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping


#: Version pin for this module's record shape.
VERIFICATION_BADGES_VERSION = "verification-badges.v1"

#: Schema pin carried by records and audit events.
VERIFICATION_BADGES_SCHEMA = "northstar.verification-badges.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Badge statuses.
ACTIVE = "active"
REVOKED = "revoked"
_STATUSES = (ACTIVE, REVOKED)

#: Pinned badge-type vocabulary: badge -> claimed assurance level.
BADGE_EMAIL = "email"            # address ownership (low)
BADGE_PHONE = "phone"            # number ownership (low)
BADGE_IDENTITY = "identity"      # government ID proofing (substantial)
BADGE_BUSINESS = "business"      # legal-entity verification (substantial)
BADGE_TRUSTED = "trusted"        # manual/organizational vetting (high)
BADGE_TYPES = {
    BADGE_EMAIL: "low",
    BADGE_PHONE: "low",
    BADGE_IDENTITY: "substantial",
    BADGE_BUSINESS: "substantial",
    BADGE_TRUSTED: "high",
}

#: Audit event kinds.
KIND_ISSUED = "badge.issued"
KIND_REVOKED = "badge.revoked"
KIND_AUDIT = "badge.audit"
_KINDS = (KIND_ISSUED, KIND_REVOKED, KIND_AUDIT)

_GENESIS = "genesis"


class VerificationBadgesError(ValueError):
    """A malformed request or a refused state transition.

    Raised for structural problems (empty subject, unknown badge type,
    empty evidence, bad seq) and for transitions the ledger cannot take
    (revoke an unknown or already-revoked badge). *Checks*
    (:meth:`VerificationBadges.check`) never raise: they return
    ``False`` — a failed verification check is a verdict, a malformed
    request is a bug.
    """


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerificationBadgesError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise VerificationBadgesError(f"{field_name} must be a non-empty string")
    return value


def _check_badge_type(value: Any) -> str:
    if value not in BADGE_TYPES:
        raise VerificationBadgesError(
            f"badge_type must be one of {sorted(BADGE_TYPES)}, saw {value!r}"
        )
    return value


# ---------------------------------------------------------------------------
# Badge records — append-only ledger, revocation is terminal per badge id
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BadgeRecord:
    """One issued verification badge.

    ``issued_seq`` is the caller-injected sequence at issuance;
    ``seq`` is the sequence of the record's latest state (issuance or
    revocation). ``expires_at`` of ``None`` means no expiry. The record
    is sealed with ``record_digest``; ``prev_digest`` chains it to the
    previous record for the same ``(subject_id, badge_type)`` key
    (``"genesis"`` for the first).
    """

    badge_id: str
    subject_id: str
    badge_type: str
    status: str
    assurance: str
    evidence: str
    issued_seq: int
    seq: int
    expires_at: int | None
    prev_digest: str = _GENESIS
    record_digest: str = ""

    def __post_init__(self) -> None:
        _check_nonempty_str(self.badge_id, "badge_id")
        _check_nonempty_str(self.subject_id, "subject_id")
        _check_badge_type(self.badge_type)
        if self.status not in _STATUSES:
            raise VerificationBadgesError(
                f"status must be one of {_STATUSES}, saw {self.status!r}"
            )
        if self.assurance != BADGE_TYPES[self.badge_type]:
            raise VerificationBadgesError(
                f"assurance {self.assurance!r} does not match badge_type "
                f"{self.badge_type!r} (expected {BADGE_TYPES[self.badge_type]!r})"
            )
        _check_nonempty_str(self.evidence, "evidence")
        _check_seq(self.issued_seq, "issued_seq")
        _check_seq(self.seq, "seq")
        if self.seq < self.issued_seq:
            raise VerificationBadgesError("seq must not predate issued_seq")
        if self.expires_at is not None:
            _check_seq(self.expires_at, "expires_at")
            if self.expires_at <= self.issued_seq:
                raise VerificationBadgesError("expires_at must be after issued_seq")
        if self.prev_digest != _GENESIS:
            if (
                not isinstance(self.prev_digest, str)
                or len(self.prev_digest) != 64
            ):
                raise VerificationBadgesError(
                    "prev_digest must be 'genesis' or a 64-char hex digest"
                )
        if self.record_digest != "" and (
            not isinstance(self.record_digest, str)
            or len(self.record_digest) != 64
        ):
            raise VerificationBadgesError(
                "record_digest must be '' or a 64-char hex digest"
            )


def _record_payload(record: BadgeRecord) -> dict[str, Any]:
    return {
        "schema": VERIFICATION_BADGES_SCHEMA,
        "kind": "badge-record",
        "badge_id": record.badge_id,
        "subject_id": record.subject_id,
        "badge_type": record.badge_type,
        "status": record.status,
        "assurance": record.assurance,
        "evidence": record.evidence,
        "issued_seq": record.issued_seq,
        "seq": record.seq,
        "expires_at": record.expires_at,
        "prev_digest": record.prev_digest,
    }


def _canonical(obj: Any) -> bytes:
    # All payload values are str/int/None — no floats, so no >2^53
    # precision hazard; ints serialize exactly.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def compute_record_digest(record: BadgeRecord) -> str:
    """Recompute a badge record's seal over all fields except itself."""
    return hashlib.sha256(_canonical(_record_payload(record))).hexdigest()


def _seal(record: BadgeRecord) -> BadgeRecord:
    return replace(record, record_digest=compute_record_digest(record))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def verification_badges_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the badge manager."""
    if kind not in _KINDS:
        raise VerificationBadgesError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "verification_badges",
        "module_version": VERIFICATION_BADGES_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# VerificationBadges
# ---------------------------------------------------------------------------


class VerificationBadges:
    """Verification-badge ledger: issue, check, revoke.

    Append-only per ``(subject_id, badge_type)`` chain; revocation is
    terminal per badge id. Mutation seqs must be strictly increasing
    (fail-closed ledger position: failed mutations consume their seq).
    Thread-safe via an RLock. No wall-clock anywhere.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._last_seq = -1
        self._counter = 0
        self._badges: dict[str, BadgeRecord] = {}
        self._by_key: dict[tuple[str, str], list[str]] = {}
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise VerificationBadgesError(
                f"seq must be strictly increasing (last={self._last_seq}, saw={seq})"
            )
        self._last_seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            verification_badges_audit_event(kind, seq, **detail)
        )

    # -- mutations -----------------------------------------------------

    def issue(
        self,
        subject_id: str,
        badge_type: str,
        seq: int,
        evidence: str,
        expires_at: int | None = None,
    ) -> BadgeRecord:
        """Issue a new badge for ``(subject_id, badge_type)``.

        Requires non-empty evidence describing the check performed
        (e.g. ``"otp:email-link"``). Duplicate *active* badges for the
        same key are refused fail-closed — revoke the old one first.
        """
        with self._lock:
            seq = self._next_seq(seq)  # consumes seq even on refusal
            subject_id = _check_nonempty_str(subject_id, "subject_id")
            badge_type = _check_badge_type(badge_type)
            evidence = _check_nonempty_str(evidence, "evidence")
            if expires_at is not None:
                _check_seq(expires_at, "expires_at")
                if expires_at <= seq:
                    raise VerificationBadgesError(
                        "expires_at must be after seq"
                    )
            key = (subject_id, badge_type)
            for badge_id in self._by_key.get(key, ()):
                if self._badges[badge_id].status == ACTIVE:
                    raise VerificationBadgesError(
                        f"active {badge_type!r} badge already exists for "
                        f"{subject_id!r}; revoke it before re-issuing"
                    )
            self._counter += 1
            badge_id = f"badge-{self._counter}"
            prev = self._by_key.get(key, [])
            prev_digest = (
                self._badges[prev[-1]].record_digest if prev else _GENESIS
            )
            record = _seal(
                BadgeRecord(
                    badge_id=badge_id,
                    subject_id=subject_id,
                    badge_type=badge_type,
                    status=ACTIVE,
                    assurance=BADGE_TYPES[badge_type],
                    evidence=evidence,
                    issued_seq=seq,
                    seq=seq,
                    expires_at=expires_at,
                    prev_digest=prev_digest,
                )
            )
            self._badges[badge_id] = record
            self._by_key.setdefault(key, []).append(badge_id)
            self._audit(
                KIND_ISSUED, seq, badge_id=badge_id,
                subject_id=subject_id, badge_type=badge_type,
            )
            return record

    def revoke(self, badge_id: str, seq: int, reason: str) -> BadgeRecord:
        """Terminally revoke a badge.

        Refuses unknown badge ids and already-revoked badges
        fail-closed. ``reason`` is recorded on the audit event only.
        """
        with self._lock:
            seq = self._next_seq(seq)  # consumes seq even on refusal
            badge_id = _check_nonempty_str(badge_id, "badge_id")
            reason = _check_nonempty_str(reason, "reason")
            record = self._badges.get(badge_id)
            if record is None:
                raise VerificationBadgesError(
                    f"unknown badge_id: {badge_id!r}"
                )
            if record.status == REVOKED:
                raise VerificationBadgesError(
                    f"badge {badge_id!r} is already revoked (terminal)"
                )
            revoked = _seal(replace(record, status=REVOKED, seq=seq))
            self._badges[badge_id] = revoked
            self._audit(
                KIND_REVOKED, seq, badge_id=badge_id,
                subject_id=revoked.subject_id,
                badge_type=revoked.badge_type, reason=reason,
            )
            return revoked

    # -- reads (never raise on verdicts; malformed inputs raise) -------

    def check(self, subject_id: str, badge_type: str, at_seq: int) -> bool:
        """``True`` iff the subject holds a live badge of this type at ``at_seq``.

        Live means: issued, active (not revoked), digest-verified,
        and unexpired at ``at_seq``. Anything else — unknown subject,
        unknown badge type, no badges, all revoked/expired/tampered —
        reads as ``False``. A malformed ``at_seq`` still raises.
        """
        _check_seq(at_seq, "at_seq")
        with self._lock:
            try:
                _check_nonempty_str(subject_id, "subject_id")
            except VerificationBadgesError:
                return False
            if badge_type not in BADGE_TYPES:
                return False
            for badge_id in self._by_key.get((subject_id, badge_type), ()):
                record = self._badges[badge_id]
                if record.status != ACTIVE:
                    continue
                if compute_record_digest(record) != record.record_digest:
                    continue
                if record.expires_at is not None and at_seq >= record.expires_at:
                    continue
                if at_seq < record.issued_seq:
                    continue
                return True
            return False

    def badge(self, badge_id: str) -> BadgeRecord:
        """Return one badge record by id (raises on unknown id)."""
        with self._lock:
            record = self._badges.get(badge_id)
            if record is None:
                raise VerificationBadgesError(f"unknown badge_id: {badge_id!r}")
            return record

    def badge_ids(self, subject_id: str, badge_type: str) -> list[str]:
        """Badge ids ever issued for ``(subject_id, badge_type)``."""
        _check_nonempty_str(subject_id, "subject_id")
        _check_badge_type(badge_type)
        with self._lock:
            return list(self._by_key.get((subject_id, badge_type), ()))

    def audit(self, seq: int) -> Mapping[str, Any]:
        """Emit an aggregate audit summary event."""
        with self._lock:
            seq = self._next_seq(seq)
            counts = {"active": 0, "revoked": 0}
            for record in self._badges.values():
                counts[record.status] += 1
            event = verification_badges_audit_event(
                KIND_AUDIT, seq,
                badges=len(self._badges),
                active=counts["active"], revoked=counts["revoked"],
            )
            self._audit_log.append(event)
            return event

    def audit_log(self) -> list[Mapping[str, Any]]:
        """Append-only audit trail (ids and digests only)."""
        with self._lock:
            return list(self._audit_log)


def main() -> None:
    """Self-check: issue, check, revoke, audit."""
    mgr = VerificationBadges()
    rec = mgr.issue(
        subject_id="sub-1", badge_type="identity", seq=1,
        evidence="kyc:document-v2", expires_at=100,
    )
    assert rec.badge_id == "badge-1"
    assert rec.assurance == "substantial"
    assert mgr.check("sub-1", "identity", at_seq=50) is True
    assert mgr.check("sub-1", "identity", at_seq=100) is False  # expired
    assert mgr.check("sub-1", "email", at_seq=50) is False
    mgr.revoke("badge-1", seq=2, reason="fraud-signal")
    assert mgr.check("sub-1", "identity", at_seq=50) is False
    mgr.audit(seq=3)
    print("verification-badges OK: issue, check, revoke, audit")


if __name__ == "__main__":
    main()
