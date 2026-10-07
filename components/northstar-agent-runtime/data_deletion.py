"""GDPR right to erasure: request/verify/execute deletion ledger (simulated).

Research note: GDPR Article 17 ("right to erasure") and its analogues
(CCPA/CPRA deletion right, China's PIPL Art. 47, Brazil's LGPD Art. 18)
all converge on one load-bearing shape: the data subject *requests*
erasure, the controller *verifies the requester's identity*, then
*executes* erasure unless an exception applies. The expensive failure
modes are the same everywhere:

1. **No unverified deletion.** Executing erasure on an unauthenticated
   claim lets an attacker delete someone else's data — a destructive
   variant of the classic confused-deputy problem. Here ``execute()``
   refuses any request that is not in the ``VERIFIED`` state, and
   ``verify()`` is the only path to ``VERIFIED``.
2. **No partial amnesia.** Erasure must cover *every* registered copy
   in the categories the request names. The receipt's proof digest is
   computed over the digests of exactly the records that were
   destroyed, so a missing category is detectable by recomputation.
3. **Exceptions are explicit and fail-closed.** GDPR Art. 17(3) allows
   refusal (legal claims, legal obligations, freedom of
   expression/information, public interest, etc.). A simulated record
   flagged ``legal_hold=True`` refuses execution: the request moves to
   ``REFUSED`` with the reason recorded, and the held data is never
   touched. Held data is reported, never destroyed.
4. **Requests are single-shot.** A request cannot be executed twice
   and a subject cannot keep a second pending request open while the
   first is in flight — replaying an old verification code against a
   fresh request denies.
5. **Verification is time-boxed.** An identity check that happened
   years ago must not authorize today's destruction. ``verify()``
   compares a caller-supplied epoch against ``requested_at``; past the
   TTL the request moves to ``EXPIRED`` and must be re-requested.

This module is the *claims ledger* for that shape, against a
simulated record store. :meth:`DataDeletion.register_records` seeds
per-subject, per-category records; :meth:`request` opens a deletion
request and issues a deterministic verification code to the caller
(who forwards it to the subject out of band); :meth:`verify`
authenticates the code; :meth:`execute` destroys the in-scope records
and returns a frozen :class:`ErasureReceipt` whose ``proof_digest``
pins exactly what was destroyed.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (no wall-clock — callers inject integer epoch timestamps; no
RNG — verification codes are derived deterministically from the
request digest), RLock-guarded, fail-closed (bad categories, unknown
requests, duplicate pending requests, bad/expired verification,
wrong-state transitions, non-increasing seqs all raise a subclass of
:class:`DataDeletionError`), stdlib-only, type-tagged canonical digest
encoding (bool != int; floats and |n| >= 2**53 refused),
``sha256:`` digest pins, audit events shaped for ``audit.ndjson/1``,
``main()`` self-check.

Honest scope: this is a *simulated* store and a *simulated*
out-of-band verification channel. The verification code is a
deterministic function of the request digest — it demonstrates the
state machine, not a real identity proof. It cannot prove the human
who presented the code is the data subject, cannot reach data held by
other controllers or processors, and cannot erase backups the host
does not register. Real erasure also requires downstream propagation
and backup-rotation discipline, which are outside this module.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

VERSION = "data-deletion.v1"
SCHEMA = "northstar.data-deletion.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "DATA_CATEGORIES",
    "REQUESTED",
    "VERIFIED",
    "EXECUTED",
    "REFUSED",
    "EXPIRED",
    "VERIFICATION_TTL_S",
    "DataDeletionError",
    "BadCategoryError",
    "UnknownRequestError",
    "DuplicateRequestError",
    "BadRequestError",
    "BadVerificationError",
    "StateTransitionError",
    "LegalHoldError",
    "DataRecord",
    "DeletionRequest",
    "ErasureReceipt",
    "DataDeletion",
    "data_deletion_audit_event",
]

#: Closed vocabulary of data categories an erasure request may name.
#: Categories are matched exactly — ``profile`` does not cover
#: ``messages``.
DATA_CATEGORIES: Tuple[str, ...] = (
    "profile",
    "activity",
    "messages",
    "media",
    "location",
)

#: Request lifecycle states.
REQUESTED = "requested"
VERIFIED = "verified"
EXECUTED = "executed"
REFUSED = "refused"
EXPIRED = "expired"

_STATES = (REQUESTED, VERIFIED, EXECUTED, REFUSED, EXPIRED)

#: How long (seconds) a verification window stays open after
#: ``requested_at``. Past this, ``verify()`` moves the request to
#: ``EXPIRED`` instead of verifying.
VERIFICATION_TTL_S = 86_400

#: Length (hex chars) of the simulated verification code issued at
#: request time.
_VERIFICATION_CODE_HEX_LEN = 16

_INT_LIMIT = 2**53
_GENESIS = "genesis"

REQUESTED_EVENT = "data-deletion.requested"
VERIFIED_EVENT = "data-deletion.verified"
VERIFICATION_FAILED_EVENT = "data-deletion.verification_failed"
EXECUTED_EVENT = "data-deletion.executed"
REFUSED_EVENT = "data-deletion.refused"
EXPIRED_EVENT = "data-deletion.expired"


class DataDeletionError(Exception):
    """Base for all data-deletion errors (fail-closed taxonomy)."""


class BadCategoryError(DataDeletionError):
    """A requested category is not in DATA_CATEGORIES, or the
    category list is empty/duplicated."""


class UnknownRequestError(DataDeletionError):
    """The request id is not known to this ledger."""


class DuplicateRequestError(DataDeletionError):
    """The subject already has a pending (REQUESTED or VERIFIED)
    request — one erasure request per subject at a time."""


class BadRequestError(DataDeletionError):
    """Structural problem: bad subject id, bad epoch, malformed id."""


class BadVerificationError(DataDeletionError):
    """The presented verification code did not match (fail-closed:
    the request stays REQUESTED; the failure audits)."""


class StateTransitionError(DataDeletionError):
    """The requested transition is illegal in the current state —
    e.g. execute before verify, execute twice, verify after execute."""


class LegalHoldError(DataDeletionError):
    """Erasure refused: one or more in-scope records carry a legal
    hold (GDPR Art. 17(3) style exception). The request moves to
    REFUSED; the held data is never touched."""


# ---------------------------------------------------------------------------
# Canonical digest encoding (type-tagged; bool != int; floats refused)
# ---------------------------------------------------------------------------


def _canon(obj: Any) -> bytes:
    """Type-tagged canonical encoding for digest computation.

    Raises DataDeletionError on floats and on |int| >= 2**53, so digest
    pins can never silently collide across types or lose precision.
    """
    if obj is None:
        return b"n"
    if isinstance(obj, bool):
        return b"b" + (b"1" if obj else b"0")
    if isinstance(obj, int):
        if abs(obj) >= _INT_LIMIT:
            raise DataDeletionError(f"|int| >= 2**53 refused: {obj}")
        return b"i" + str(obj).encode("ascii")
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return b"s" + str(len(raw)).encode("ascii") + b":" + raw
    if isinstance(obj, (list, tuple)):
        parts = b"".join(_canon(x) for x in obj)
        return b"l" + str(len(obj)).encode("ascii") + b":" + parts
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: _canon_key(kv[0]))
        parts = b"".join(_canon(k) + _canon(v) for k, v in items)
        return b"d" + str(len(items)).encode("ascii") + b":" + parts
    raise DataDeletionError(f"unencodable type: {type(obj).__name__}")


def _canon_key(key: Any) -> bytes:
    return _canon(key)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest_pin(obj: Any) -> str:
    return "sha256:" + _sha256_hex(_canon(obj))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def data_deletion_audit_event(seq: int, event: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped event record."""
    return {
        "schema": "audit.ndjson/1",
        "seq": seq,
        "module": SCHEMA,
        "event": event,
        "payload": dict(payload),
    }


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataRecord:
    """One simulated stored record belonging to a subject.

    ``legal_hold`` simulates a GDPR Art. 17(3) exception: held records
    refuse erasure and are reported, never destroyed.
    """

    record_id: str
    category: str
    content_digest: str
    legal_hold: bool = False


@dataclass(frozen=True)
class DeletionRequest:
    """A frozen view of a deletion request.

    ``verification_code`` is returned to the *caller* of ``request()``
    only (the caller forwards it to the subject out of band); it is
    never stored and never appears in later views.
    """

    request_id: str
    subject_id: str
    categories: Tuple[str, ...]
    requested_at: int
    state: str
    digest: str
    verification_code: Optional[str] = None


@dataclass(frozen=True)
class ErasureReceipt:
    """Proof that erasure executed.

    ``proof_digest`` recomputes over ``(request_digest, per-category
    sorted record-digests of destroyed records)`` — a missing category
    is detectable by recomputation. ``held`` lists record ids that
    carried a legal hold and were therefore NOT destroyed (empty in
    the normal case).
    """

    request_id: str
    subject_id: str
    deleted_categories: Tuple[str, ...]
    destroyed_record_digests: Tuple[str, ...]
    proof_digest: str
    executed_seq: int
    held: Tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


_ID_RE = "del-"


class DataDeletion:
    """Simulated GDPR-style right-to-erasure ledger.

    Thread-safe (RLock), caller-driven seqs: every mutation takes a
    caller-supplied strictly-increasing int ``seq``. Failed mutations
    consume their seq (fail-closed ledger position). ``now`` epoch
    parameters are caller-supplied — this module never reads the
    wall clock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._counter = 0
        # request_id -> mutable record
        self._requests: Dict[str, Dict[str, Any]] = {}
        # subject_id -> list of pending (non-terminal) request ids
        self._pending: Dict[str, List[str]] = {}
        # subject_id -> {category: [DataRecord]}
        self._store: Dict[str, Dict[str, List[DataRecord]]] = {}

    # -- internals ----------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise BadRequestError("seq must be an int")
        if seq <= self._last_seq:
            raise BadRequestError(
                f"seq must be strictly increasing (last={self._last_seq})"
            )
        # Consume immediately: failed mutations burn their seq too.
        self._last_seq = seq
        return seq

    def _check_subject(self, subject_id: Any) -> str:
        if not isinstance(subject_id, str) or not subject_id.strip():
            raise BadRequestError("subject_id must be a non-empty string")
        if len(subject_id) > 256:
            raise BadRequestError("subject_id too long")
        return subject_id

    def _check_categories(self, categories: Any) -> Tuple[str, ...]:
        if not isinstance(categories, (list, tuple)) or not categories:
            raise BadCategoryError("categories must be a non-empty list/tuple")
        cats: List[str] = []
        for c in categories:
            if not isinstance(c, str) or c not in DATA_CATEGORIES:
                raise BadCategoryError(f"unknown data category: {c!r}")
            if c in cats:
                raise BadCategoryError(f"duplicate category: {c!r}")
            cats.append(c)
        return tuple(cats)

    def _check_epoch(self, value: Any, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BadRequestError(f"{name} must be a non-negative int epoch")
        if value >= _INT_LIMIT:
            raise BadRequestError(f"{name} >= 2**53 refused")
        return value

    def _lookup(self, request_id: Any) -> Dict[str, Any]:
        if not isinstance(request_id, str) or not request_id:
            raise BadRequestError("request_id must be a non-empty string")
        try:
            return self._requests[request_id]
        except KeyError:
            raise UnknownRequestError(f"unknown request: {request_id!r}")

    def _derive_code(self, request_digest: str) -> str:
        code_hex = _sha256_hex(
            ("code|" + request_digest[len("sha256:"):]).encode("ascii")
        )
        return code_hex[:_VERIFICATION_CODE_HEX_LEN]

    def _view(self, rec: Dict[str, Any], include_code: bool = False) -> DeletionRequest:
        return DeletionRequest(
            request_id=rec["request_id"],
            subject_id=rec["subject_id"],
            categories=rec["categories"],
            requested_at=rec["requested_at"],
            state=rec["state"],
            digest=rec["digest"],
            verification_code=rec.get("issued_code") if include_code else None,
        )

    # -- simulated store ----------------------------------------------

    def register_records(
        self,
        subject_id: str,
        category: str,
        records: List[Mapping[str, Any]],
        seq: int,
    ) -> List[DataRecord]:
        """Seed the simulated store (test/host fixture only)."""
        with self._lock:
            self._claim_seq(seq)
            subject_id = self._check_subject(subject_id)
            (category,) = self._check_categories([category])
            if not isinstance(records, (list, tuple)) or not records:
                raise BadRequestError("records must be a non-empty list")
            out: List[DataRecord] = []
            for r in records:
                if not isinstance(r, Mapping):
                    raise BadRequestError("each record must be a mapping")
                rec = DataRecord(
                    record_id=str(r.get("record_id", "")),
                    category=category,
                    content_digest=_digest_pin(r.get("content")),
                    legal_hold=bool(r.get("legal_hold", False)),
                )
                if not rec.record_id:
                    raise BadRequestError("record_id must be non-empty")
                out.append(rec)
            bucket = self._store.setdefault(subject_id, {})
            bucket.setdefault(category, []).extend(out)
            return out

    def stored_records(self, subject_id: str) -> Dict[str, List[DataRecord]]:
        """Snapshot of what the simulated store holds for a subject."""
        with self._lock:
            subject_id = self._check_subject(subject_id)
            return {
                cat: list(recs)
                for cat, recs in self._store.get(subject_id, {}).items()
            }

    # -- request --------------------------------------------------------

    def request(
        self,
        subject_id: str,
        categories: List[str],
        seq: int,
        requested_at: int,
    ) -> DeletionRequest:
        """Open a deletion request; returns the view WITH the one-time
        verification code. The caller forwards the code to the subject
        out of band."""
        with self._lock:
            self._claim_seq(seq)
            subject_id = self._check_subject(subject_id)
            cats = self._check_categories(categories)
            requested_at = self._check_epoch(requested_at, "requested_at")
            pending = self._pending.get(subject_id, [])
            if any(self._requests[r]["state"] in (REQUESTED, VERIFIED) for r in pending):
                raise DuplicateRequestError(
                    f"subject {subject_id!r} already has a pending request"
                )
            self._counter += 1
            request_id = f"{_ID_RE}{self._counter}"
            digest = _digest_pin(
                {"request_id": request_id, "subject_id": subject_id,
                 "categories": list(cats), "requested_at": requested_at,
                 "genesis": _GENESIS}
            )
            code = self._derive_code(digest)
            code_digest = _digest_pin({"request_id": request_id, "code": code})
            rec = {
                "request_id": request_id,
                "subject_id": subject_id,
                "categories": cats,
                "requested_at": requested_at,
                "state": REQUESTED,
                "digest": digest,
                "code_digest": code_digest,
                "issued_code": code,
                "events": [
                    data_deletion_audit_event(
                        seq, REQUESTED_EVENT,
                        {"request_id": request_id, "subject_id": subject_id,
                         "categories": list(cats), "digest": digest},
                    )
                ],
            }
            self._requests[request_id] = rec
            self._pending.setdefault(subject_id, []).append(request_id)
            return self._view(rec, include_code=True)

    def get_request(self, request_id: str) -> DeletionRequest:
        """Frozen view of a request (never carries the code)."""
        with self._lock:
            return self._view(self._lookup(request_id))

    # -- verify ----------------------------------------------------------

    def verify(self, request_id: str, code: Any, seq: int, now: int) -> DeletionRequest:
        """Authenticate the subject's verification code.

        Moves REQUESTED -> VERIFIED on a match. On a wrong code the
        request stays REQUESTED (failure audits). Past the TTL the
        request moves to EXPIRED instead of verifying.
        """
        with self._lock:
            self._claim_seq(seq)
            now = self._check_epoch(now, "now")
            rec = self._lookup(request_id)
            state = rec["state"]
            if state != REQUESTED:
                raise StateTransitionError(
                    f"verify() requires state {REQUESTED!r}, got {state!r}"
                )
            if now < rec["requested_at"]:
                raise BadRequestError("now precedes requested_at")
            if now - rec["requested_at"] > VERIFICATION_TTL_S:
                rec["state"] = EXPIRED
                rec["events"].append(
                    data_deletion_audit_event(
                        seq, EXPIRED_EVENT, {"request_id": request_id}
                    )
                )
                return self._view(rec)
            presented = _digest_pin({"request_id": request_id, "code": code}) \
                if isinstance(code, str) and code else None
            if presented is None or not hmac.compare_digest(
                presented, rec["code_digest"]
            ):
                rec["events"].append(
                    data_deletion_audit_event(
                        seq, VERIFICATION_FAILED_EVENT,
                        {"request_id": request_id},
                    )
                )
                raise BadVerificationError("verification code did not match")
            rec["state"] = VERIFIED
            rec["events"].append(
                data_deletion_audit_event(
                    seq, VERIFIED_EVENT, {"request_id": request_id}
                )
            )
            return self._view(rec)

    # -- execute ----------------------------------------------------------

    def execute(self, request_id: str, seq: int, now: int) -> ErasureReceipt:
        """Destroy the in-scope records and return a proof receipt.

        Requires VERIFIED. Any in-scope record with a legal hold
        refuses the whole request: state -> REFUSED, nothing destroyed,
        :class:`LegalHoldError` raised.
        """
        with self._lock:
            self._claim_seq(seq)
            self._check_epoch(now, "now")
            rec = self._lookup(request_id)
            state = rec["state"]
            if state != VERIFIED:
                raise StateTransitionError(
                    f"execute() requires state {VERIFIED!r}, got {state!r}"
                )
            subject_id = rec["subject_id"]
            cats = rec["categories"]
            bucket = self._store.get(subject_id, {})
            held = [
                r.record_id
                for c in cats
                for r in bucket.get(c, [])
                if r.legal_hold
            ]
            if held:
                rec["state"] = REFUSED
                rec["events"].append(
                    data_deletion_audit_event(
                        seq, REFUSED_EVENT,
                        {"request_id": request_id, "reason": "legal_hold",
                         "held": sorted(held)},
                    )
                )
                raise LegalHoldError(
                    f"erasure refused: {len(held)} record(s) under legal hold"
                )
            destroyed: List[str] = []
            for c in cats:
                for r in bucket.get(c, []):
                    destroyed.append(r.content_digest)
                bucket[c] = []
            destroyed_sorted = tuple(sorted(destroyed))
            proof = _digest_pin(
                {"request_digest": rec["digest"],
                 "destroyed": list(destroyed_sorted),
                 "genesis": _GENESIS}
            )
            rec["state"] = EXECUTED
            rec["events"].append(
                data_deletion_audit_event(
                    seq, EXECUTED_EVENT,
                    {"request_id": request_id, "categories": list(cats),
                     "destroyed_count": len(destroyed_sorted),
                     "proof_digest": proof},
                )
            )
            return ErasureReceipt(
                request_id=request_id,
                subject_id=subject_id,
                deleted_categories=cats,
                destroyed_record_digests=destroyed_sorted,
                proof_digest=proof,
                executed_seq=seq,
            )

    # -- audit -------------------------------------------------------------

    def audit_log(self, request_id: str) -> Tuple[Dict[str, Any], ...]:
        """Audit events for one request, in seq order."""
        with self._lock:
            rec = self._lookup(request_id)
            return tuple(rec["events"])


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> int:
    dd = DataDeletion()
    dd.register_records("alice", "profile",
                        [{"record_id": "p1", "content": "name=alice"}], 0)
    req = dd.request("alice", ["profile"], 1, 1_000)
    assert req.state == REQUESTED and req.verification_code
    dd.verify(req.request_id, req.verification_code, 2, 1_000 + 60)
    rcpt = dd.execute(req.request_id, 3, 1_000 + 61)
    assert rcpt.proof_digest.startswith("sha256:")
    assert dd.stored_records("alice")["profile"] == []
    print(f"data_deletion self-check ok: {VERSION} receipt={rcpt.proof_digest[:20]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
