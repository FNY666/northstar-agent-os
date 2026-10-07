"""CCPA: California Consumer Privacy Act consumer-rights decision ledger.

Research note: the California Consumer Privacy Act (CCPA, as amended by
CPRA) grants California consumers rights over their personal information:
the right to know (what was collected), the right to access / data
portability, the right to delete, the right to opt out of sale or sharing,
and the right to correct inaccurate data. Businesses must verify the
request, respond within statutory timelines, and keep records of how each
request was handled. What matters here is the *decision ledger*: which
requests were declared, how the host assessed them, what response was
booked, and which deletions were declared executed - defensible
bookkeeping, not proof of compliance or proof that any data moved.

This module is the *CCPA request-lifecycle* layer, deliberately distinct
from its siblings:

- ``legal_hold.py`` - eDiscovery preservation directives (freezes
  destruction); this module is consumer-initiated data-rights requests.
- ``compliance.py`` - framework control-check governance; this module
  owns individual consumer request lifecycles, not framework controls.
- ``differential_privacy.py`` - privacy-budget/noise bookkeeping; this
  module books request decisions, no mechanism math.
- ``private_inference.py`` - private-ML query-policy ledger; this module
  is statutory rights bookkeeping.

This module owns the assess -> respond -> delete lifecycle:

* **assess()** - declare one assessment of a consumer rights request
  (pinned request-kind vocabulary ``know`` / ``access`` / ``delete`` /
  ``opt-out`` / ``correct``; pinned verdict vocabulary ``valid`` /
  ``invalid`` / ``needs-verification`` / ``exempt``, booked as data).
  Consumer identity travels as a ``sha256:`` digest pin only - raw names,
  emails, addresses, and personal information never enter records.
* **respond()** - book one declared response (pinned outcome vocabulary
  ``fulfilled`` / ``denied`` / ``partial`` / ``extended``); one response
  per request; outcome must be consistent with the booked verdict
  (``fulfilled`` requires a ``valid`` verdict), fail-closed.
* **delete()** - terminal: book the declared deletion execution for a
  ``delete``-kind request with a ``valid`` verdict and a ``fulfilled``
  response; the id is retired forever, never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``ccpa.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: this module deletes no data, enforces no policy, and
contacts no consumer. A booked ``deleted`` means "the ledger says the
host declared deletion", never "personal information was actually
erased". A booked ``fulfilled`` is ledger truth, never proof of a timely
statutory response. Consumer PII never crosses the module boundary -
digest pins only.
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
CCPA_VERSION = "ccpa.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.ccpa.v1"

#: Pinned request-kind vocabulary (statutory consumer rights).
REQUEST_KINDS = (
    "know",
    "access",
    "delete",
    "opt-out",
    "correct",
)

#: Pinned assessment-verdict vocabulary (host-declared, booked as data).
VERDICTS = (
    "valid",
    "invalid",
    "needs-verification",
    "exempt",
)

#: Pinned response-outcome vocabulary (host-declared, booked as data).
OUTCOMES = (
    "fulfilled",
    "denied",
    "partial",
    "extended",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "responded",
    "deleted",
    "rejected",
)

#: Keys that may never appear raw in an audit row (consumer PII / payload).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "consumer",
        "consumer_id",
        "consumer_name",
        "name",
        "email",
        "email_address",
        "address",
        "phone",
        "phone_number",
        "ssn",
        "social_security",
        "driver_license",
        "personal_info",
        "personal_information",
        "pii",
        "data",
        "subject",
        "note",
        "notes",
        "text",
        "content",
        "payload",
        "raw",
        "document",
        "secret",
        "private_key",
        "key",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CCPAError(Exception):
    """Base error for CCPA ledger misuse."""


class BadRequestError(CCPAError):
    """Malformed request id."""


class DuplicateRequestError(CCPAError):
    """Request id already assessed."""


class RetiredRequestError(CCPAError):
    """Request id retired after deletion; never recycled."""


class UnknownRequestError(CCPAError):
    """Request id not assessed."""


class BadKindError(CCPAError):
    """Unknown request kind."""


class BadVerdictError(CCPAError):
    """Unknown assessment verdict."""


class BadOutcomeError(CCPAError):
    """Unknown response outcome."""


class BadDigestError(CCPAError):
    """Malformed sha256: digest pin."""


class VerdictConflictError(CCPAError):
    """Response outcome conflicts with the booked verdict."""


class AlreadyRespondedError(CCPAError):
    """A response is already booked for this request."""


class DeletionStateError(CCPAError):
    """Deletion preconditions not met (kind/verdict/response)."""


class SeqOrderError(CCPAError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(CCPAError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadRequestError(f"{field_name} must be a non-empty str <= 128 chars")
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
class AssessmentRecord:
    request_id: str
    request_kind: str
    verdict: str
    consumer_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "request_id": self.request_id,
            "request_kind": self.request_kind,
            "verdict": self.verdict,
            "consumer_digest": self.consumer_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "request_id": self.request_id,
                "request_kind": self.request_kind,
                "verdict": self.verdict,
                "consumer_digest": self.consumer_digest,
            }
        )


@dataclass(frozen=True)
class ResponseRecord:
    request_id: str
    outcome: str
    detail_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "request_id": self.request_id,
            "outcome": self.outcome,
            "detail_digest": self.detail_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "request_id": self.request_id,
                "outcome": self.outcome,
                "detail_digest": self.detail_digest,
            }
        )


@dataclass(frozen=True)
class DeletionRecord:
    request_id: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "request_id": self.request_id,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"schema": SCHEMA_PIN, "request_id": self.request_id}
        )


@dataclass(frozen=True)
class AuditReport:
    n_requests: int
    n_responded: int
    n_deleted: int
    kind_tallies: Tuple[Tuple[str, int], ...]
    outcome_tallies: Tuple[Tuple[str, int], ...]
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "n_requests": self.n_requests,
            "n_responded": self.n_responded,
            "n_deleted": self.n_deleted,
            "kind_tallies": [
                {"request_kind": k, "count": c} for k, c in self.kind_tallies
            ],
            "outcome_tallies": [
                {"outcome": o, "count": c} for o, c in self.outcome_tallies
            ],
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "n_requests": self.n_requests,
                "n_responded": self.n_responded,
                "n_deleted": self.n_deleted,
                "kind_tallies": [
                    {"request_kind": k, "count": c}
                    for k, c in self.kind_tallies
                ],
                "outcome_tallies": [
                    {"outcome": o, "count": c}
                    for o, c in self.outcome_tallies
                ],
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def ccpa_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the CCPA ledger."""
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


class CCPA:
    """CCPA consumer-rights decision ledger, Simulated.

    ``assess()`` / ``respond()`` / ``delete()`` mutate the ledger and
    consume caller seqs; ``audit()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._responses: Dict[str, ResponseRecord] = {}
        self._deletions: Dict[str, DeletionRecord] = {}
        self._retired: set = set()
        self._audit: List[Dict[str, Any]] = []
        self._seq = 0

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
            row = ccpa_audit_event("rejected", seq,
                                   rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(ccpa_audit_event(audit_kind, seq, **details))

    def _live_request(self, request_id: str) -> AssessmentRecord:
        """Fail-closed: request must be assessed and not retired."""
        if request_id in self._retired:
            raise RetiredRequestError(
                f"request id retired after deletion, never recycled: {request_id!r}")
        record = self._assessments.get(request_id)
        if record is None:
            raise UnknownRequestError(f"unknown request: {request_id!r}")
        return record

    # -- assess ------------------------------------------------------------

    def assess(
        self,
        request_id: str,
        request_kind: str,
        seq: int,
        verdict: str = "valid",
        consumer_digest: str = "",
    ) -> AssessmentRecord:
        """Declare one assessment of a consumer rights request.

        The consumer's identity travels as a ``sha256:`` digest pin only -
        raw names, emails, addresses, and personal information never enter
        records. The verdict is host-declared bookkeeping, booked as data,
        never proof of statutory validity.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CCPAError:
                raise
            try:
                _require_id(request_id, "request_id")
                if request_kind not in REQUEST_KINDS:
                    raise BadKindError(
                        f"request_kind must be one of {REQUEST_KINDS}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {VERDICTS}")
                if consumer_digest:
                    _require_digest(consumer_digest, "consumer_digest")
                else:
                    consumer_digest = "sha256:" + "00" * 32
                if request_id in self._retired:
                    raise RetiredRequestError(
                        f"request id retired, never recycled: {request_id!r}")
                if request_id in self._assessments:
                    raise DuplicateRequestError(
                        f"request already assessed: {request_id!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "request_id": request_id,
                     "request_kind": request_kind, "verdict": verdict,
                     "consumer_digest": consumer_digest}
                )
                record = AssessmentRecord(
                    request_id=request_id, request_kind=request_kind,
                    verdict=verdict, consumer_digest=consumer_digest,
                    digest=digest,
                )
                self._assessments[request_id] = record
                self._emit(
                    "assessed", seq, request_id=request_id,
                    request_kind=request_kind, verdict=verdict,
                )
                return record
            except CCPAError:
                self._burn(seq, "assess")
                raise

    # -- respond -------------------------------------------------------------

    def respond(
        self,
        request_id: str,
        seq: int,
        outcome: str = "fulfilled",
        detail_digest: str = "",
    ) -> ResponseRecord:
        """Book one declared response for an assessed request.

        One response per request (fail-closed). The outcome must be
        consistent with the booked verdict: ``fulfilled``/``partial``
        require ``valid``; ``denied`` requires ``invalid`` or ``exempt``;
        ``extended`` requires ``valid`` or ``needs-verification``.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CCPAError:
                raise
            try:
                assessment = self._live_request(request_id)
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(
                        f"outcome must be one of {OUTCOMES}")
                if detail_digest:
                    _require_digest(detail_digest, "detail_digest")
                else:
                    detail_digest = "sha256:" + "00" * 32
                if request_id in self._responses:
                    raise AlreadyRespondedError(
                        f"response already booked for request: {request_id!r}")
                verdict = assessment.verdict
                allowed = {
                    "fulfilled": ("valid",),
                    "partial": ("valid",),
                    "denied": ("invalid", "exempt"),
                    "extended": ("valid", "needs-verification"),
                }
                if verdict not in allowed[outcome]:
                    raise VerdictConflictError(
                        f"outcome {outcome!r} conflicts with verdict "
                        f"{verdict!r}")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "request_id": request_id,
                     "outcome": outcome, "detail_digest": detail_digest}
                )
                record = ResponseRecord(
                    request_id=request_id, outcome=outcome,
                    detail_digest=detail_digest, digest=digest,
                )
                self._responses[request_id] = record
                self._emit(
                    "responded", seq, request_id=request_id,
                    outcome=outcome,
                )
                return record
            except CCPAError:
                self._burn(seq, "respond")
                raise

    # -- delete --------------------------------------------------------------

    def delete(self, request_id: str, seq: int) -> DeletionRecord:
        """Terminal: book the declared deletion execution.

        Requires a ``delete``-kind request with a ``valid`` verdict and a
        booked ``fulfilled`` response. The request id is retired forever;
        ids are never recycled.
        """
        with self._lock:
            try:
                self._claim(seq)
            except CCPAError:
                raise
            try:
                assessment = self._live_request(request_id)
                if assessment.request_kind != "delete":
                    raise DeletionStateError(
                        "delete() requires a 'delete'-kind request")
                if assessment.verdict != "valid":
                    raise DeletionStateError(
                        "delete() requires a 'valid' verdict")
                response = self._responses.get(request_id)
                if response is None or response.outcome != "fulfilled":
                    raise DeletionStateError(
                        "delete() requires a booked 'fulfilled' response")
                digest = _digest_pin(
                    {"schema": SCHEMA_PIN, "request_id": request_id}
                )
                record = DeletionRecord(request_id=request_id, digest=digest)
                self._deletions[request_id] = record
                self._retired.add(request_id)
                self._emit("deleted", seq, request_id=request_id)
                return record
            except CCPAError:
                self._burn(seq, "delete")
                raise

    # -- audit (pure read) -----------------------------------------------------

    def audit(self, seq: int, request_id: str = "") -> AuditReport:
        """Pure read: request tallies as data, digest-pinned.

        With ``request_id`` set, the report scopes to that one request
        (unknown ids report zero counts as data, never raised); without
        it, the report covers the whole ledger.
        """
        with self._lock:
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SeqOrderError("audit seq must be a non-negative int")
            if request_id:
                ids: List[str] = (
                    [request_id] if request_id in self._assessments else []
                )
            else:
                ids = sorted(self._assessments)
            integrity_ok = True
            kind_counts: Dict[str, int] = {}
            outcome_counts: Dict[str, int] = {}
            n_responded = 0
            for rid in ids:
                assessment = self._assessments[rid]
                if not assessment.verify():
                    integrity_ok = False
                kind_counts[assessment.request_kind] = (
                    kind_counts.get(assessment.request_kind, 0) + 1
                )
                response = self._responses.get(rid)
                if response is not None:
                    n_responded += 1
                    if not response.verify():
                        integrity_ok = False
                    outcome_counts[response.outcome] = (
                        outcome_counts.get(response.outcome, 0) + 1
                    )
                deletion = self._deletions.get(rid)
                if deletion is not None and not deletion.verify():
                    integrity_ok = False
            kind_tallies = tuple(sorted(kind_counts.items()))
            outcome_tallies = tuple(sorted(outcome_counts.items()))
            n_deleted = sum(1 for rid in ids if rid in self._deletions)
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "n_requests": len(ids),
                    "n_responded": n_responded,
                    "n_deleted": n_deleted,
                    "kind_tallies": [
                        {"request_kind": k, "count": c}
                        for k, c in kind_tallies
                    ],
                    "outcome_tallies": [
                        {"outcome": o, "count": c}
                        for o, c in outcome_tallies
                    ],
                    "integrity_ok": integrity_ok,
                }
            )
            return AuditReport(
                n_requests=len(ids),
                n_responded=n_responded,
                n_deleted=n_deleted,
                kind_tallies=kind_tallies,
                outcome_tallies=outcome_tallies,
                integrity_ok=integrity_ok,
                digest=digest,
            )

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def assessment_record(self, request_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._assessments.get(request_id)
            if record is None:
                raise UnknownRequestError(f"unknown request: {request_id!r}")
            return record

    def response_record(self, request_id: str, seq: int) -> ResponseRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._responses.get(request_id)
            if record is None:
                raise UnknownRequestError(
                    f"no response booked for request: {request_id!r}")
            return record

    def deletion_record(self, request_id: str, seq: int) -> DeletionRecord:
        with self._lock:
            self._view_seq_ok(seq)
            record = self._deletions.get(request_id)
            if record is None:
                raise UnknownRequestError(
                    f"no deletion booked for request: {request_id!r}")
            return record

    def request_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._assessments))

    def deleted_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._deletions))

    def is_deleted(self, request_id: str, seq: int) -> bool:
        with self._lock:
            self._view_seq_ok(seq)
            return request_id in self._deletions

    def stats(self, seq: int) -> Dict[str, int]:
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "requests": len(self._assessments),
                "responded": len(self._responses),
                "deleted": len(self._deletions),
                "retired": len(self._retired),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)


def main() -> None:
    c = CCPA()
    rec = c.assess("req-1", "delete", 1, verdict="valid")
    assert rec.verify()
    assert rec.request_kind == "delete" and rec.verdict == "valid"
    rsp = c.respond("req-1", 2, outcome="fulfilled")
    assert rsp.verify()
    deletion = c.delete("req-1", 3)
    assert deletion.verify()
    assert c.is_deleted("req-1", 0)
    report = c.audit(0)
    assert report.verify()
    assert report.n_requests == 1 and report.n_deleted == 1
    assert report.kind_tallies == (("delete", 1),)
    assert report.outcome_tallies == (("fulfilled", 1),)
    print("ccpa OK: assess, respond, delete, pins, audit")


if __name__ == "__main__":
    main()
