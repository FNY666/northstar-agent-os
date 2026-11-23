"""MPC: multi-party computation session-orchestration ledger (simulated).

Research motivation: secure multi-party computation (Yao 1982; Goldreich,
Micali, Wigderson 1987) lets ``n`` parties compute a joint function over
private inputs without revealing them. Beneath every MPC protocol sit two
different halves:

* the *algebra*: secret sharing, share arithmetic, degree reduction
  (Shamir 1979; BGW 1988);
* the *ceremony*: who is in the session, who committed an input, which
  circuit ran, and who received the output -- the multi-round orchestration
  that turns primitives into an auditable computation.

This module is the ceremony layer, deliberately distinct from the sibling
layers:

* ``mpc_interface.py`` - Shamir share / reconstruct / add_shares *algebra*
  over a prime field (shares integers, BGW local addition);
* ``secret_sharing.py`` - byte-oriented key *backup* (split / recover of
  key bytes for offline recovery);
* ``mpc.py`` - THIS module: the *session orchestration* ledger --
  ``share`` (input commitment), ``compute`` (declared joint computation),
  ``reconstruct`` (output delivery). It pins digests only and never sees a
  share value, a raw input, or a circuit body.

API:

* **session()** opens an MPC session: ``n`` named parties, threshold
  ``t`` (``2 <= t <= n``). State machine:
  ``open`` -> ``ready`` -> ``committed`` -> ``computed`` -> ``closed``.
* **register_party()** seats one party in an ``open`` session; when the
  party count reaches ``n_parties`` the session becomes ``ready``.
* **share()** books one party's *input commitment*: the party's private
  input pinned by a ``sha256:`` digest only -- raw input text/bytes never
  enter a record. Each party commits exactly once; when all ``n`` have
  committed the session becomes ``committed``.
* **compute()** books the declared joint computation over the committed
  inputs: the circuit pinned by digest, the number of committed inputs
  booked as data. Requires ``committed``; moves the session to ``computed``.
* **reconstruct()** books output delivery: the host-declared output digest
  (GIGO -- the module inspects no values and proves no function was
  evaluated). Terminal: the session id is retired forever and later
  mutations are refused fail-closed.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book a ``rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module books *declared* session events. It cannot run a
real MPC protocol, cannot verify that committed inputs match any real
secret shares, cannot check that the booked circuit was actually evaluated,
and cannot prove the booked output digest corresponds to the declared
computation. A ``reconstructed`` record means "the host declared the output
digest", never "the parties jointly computed this". Do not use it as a
security boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
MPC_VERSION = "mpc.v1"

#: Schema pin carried by records and audit events.
MPC_SCHEMA = "northstar.mpc.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Session lifecycle states (booked in order, never backwards).
STATES = ("open", "ready", "committed", "computed", "closed")

#: Audit kinds for this module (append-only vocabulary).
KIND_SESSION_OPENED = "mpc-session-opened"
KIND_PARTY_REGISTERED = "mpc-party-registered"
KIND_INPUT_SHARED = "mpc-input-shared"
KIND_COMPUTED = "mpc-computed"
KIND_RECONSTRUCTED = "mpc-reconstructed"
KIND_REJECTED = "mpc.rejected"
_KINDS = (
    KIND_SESSION_OPENED,
    KIND_PARTY_REGISTERED,
    KIND_INPUT_SHARED,
    KIND_COMPUTED,
    KIND_RECONSTRUCTED,
    KIND_REJECTED,
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class MPCError(Exception):
    """Base class for all MPC session-orchestration failures."""


class BadSessionError(MPCError):
    """Malformed session id."""


class DuplicateSessionError(MPCError):
    """A session with this id is already open."""


class RetiredSessionError(MPCError):
    """The session id was retired (closed) and may never be reused."""


class UnknownSessionError(MPCError):
    """No session with this id is known."""


class BadPartyError(MPCError):
    """Malformed party id."""


class DuplicatePartyError(MPCError):
    """This party id is already registered in the session."""


class UnknownPartyError(MPCError):
    """No party with this id is registered in the session."""


class TooManyPartiesError(MPCError):
    """Registration would exceed the session's declared n_parties."""


class BadThresholdError(MPCError):
    """Threshold is not an int with 2 <= t <= n_parties."""


class BadPartiesError(MPCError):
    """n_parties is not a positive int >= 2."""


class BadDigestError(MPCError):
    """A digest pin is not a ``sha256:<64hex>`` pin (or is empty)."""


class DuplicateShareError(MPCError):
    """This party already committed an input to this session."""


class SessionStateError(MPCError):
    """The session is not in the phase this call requires."""


class SeqOrderError(MPCError):
    """Seq is not a strictly increasing int."""


class AuditKindError(MPCError):
    """Unknown audit kind, or banned raw-text key in audit detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str, error_cls: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise error_cls(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise error_cls(f"{name} must not contain whitespace")
    return value


def _check_session_id(value: Any) -> str:
    return _check_id(value, "session_id", BadSessionError)


def _check_party_id(value: Any) -> str:
    return _check_id(value, "party_id", BadPartyError)


def _check_digest(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        raise BadDigestError(f"{name} must be 'sha256:' + 64 hex chars")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"{name} hex part is not hex") from None
    return value


def _check_n_parties(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadPartiesError(f"n_parties must be int, got {type(value).__name__}")
    if value < 2:
        raise BadPartiesError(f"n_parties must be >= 2, got {value}")
    return value


def _check_threshold(value: Any, n_parties: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadThresholdError(f"threshold must be int, got {type(value).__name__}")
    if not (2 <= value <= n_parties):
        raise BadThresholdError(
            f"threshold must satisfy 2 <= t <= n_parties ({n_parties}), "
            f"got {value}"
        )
    return value


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(obj).encode("utf-8")
    import json

    def _norm(value: Any) -> Any:
        if isinstance(value, bool):
            return {"__bool__": value}
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueError("non-finite float not canonicalizable")
            return {"__float__": repr(value)}
        if isinstance(value, int):
            return {"__int__": str(value)}
        if isinstance(value, (list, tuple)):
            return [_norm(v) for v in value]
        if isinstance(value, dict):
            return {str(k): _norm(value[k]) for k in sorted(value)}
        if value is None:
            return None
        return str(value)

    return json.dumps(_norm(obj), separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.mpc:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SessionRecord:
    """One opened MPC session (state at booking is always ``open``)."""

    session_id: str
    n_parties: int
    threshold: int
    digest: str
    schema: str = MPC_SCHEMA
    version: str = MPC_VERSION

    def verify(self) -> bool:
        """Recompute the digest pin; False means the record was tampered with."""
        return self.digest == _digest_pin(
            (self.session_id, self.n_parties, self.threshold),
            "session",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "session_id": self.session_id,
            "n_parties": self.n_parties,
            "threshold": self.threshold,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class PartyRecord:
    """One party seated in a session."""

    session_id: str
    party_id: str
    digest: str
    schema: str = MPC_SCHEMA
    version: str = MPC_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.session_id, self.party_id),
            "party",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "session_id": self.session_id,
            "party_id": self.party_id,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ShareCommitment:
    """One party's committed input (digest pin only; raw input never recorded)."""

    session_id: str
    party_id: str
    input_digest: str
    digest: str
    schema: str = MPC_SCHEMA
    version: str = MPC_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.session_id, self.party_id, self.input_digest),
            "share",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "session_id": self.session_id,
            "party_id": self.party_id,
            "input_digest": self.input_digest,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ComputeRecord:
    """One declared joint computation over the committed inputs."""

    session_id: str
    circuit_digest: str
    n_inputs: int
    digest: str
    schema: str = MPC_SCHEMA
    version: str = MPC_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.session_id, self.circuit_digest, self.n_inputs),
            "compute",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "session_id": self.session_id,
            "circuit_digest": self.circuit_digest,
            "n_inputs": self.n_inputs,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ReconstructRecord:
    """Terminal output-delivery booking for one session."""

    session_id: str
    output_digest: str
    digest: str
    schema: str = MPC_SCHEMA
    version: str = MPC_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.session_id, self.output_digest),
            "reconstruct",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "session_id": self.session_id,
            "output_digest": self.output_digest,
            "digest": self.digest,
        }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def mpc_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw inputs never cross this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "input",
        "inputs",
        "secret",
        "secrets",
        "share",
        "shares",
        "value",
        "values",
        "text",
        "raw",
        "payload",
        "output",
        "circuit",
        "data",
        "message",
        "reason",
        "note",
        "notes",
        "comment",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "mpc",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# MPC session-orchestration ledger
# ---------------------------------------------------------------------------


class MPC:
    """MPC session orchestration: open, seat parties, commit inputs,
    declare the joint computation, and deliver the output -- booked as a
    deterministic, digest-pinned ledger.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # session_id -> SessionRecord (insertion order)
        self._sessions: Dict[str, SessionRecord] = {}
        # session_id -> lifecycle state
        self._states: Dict[str, str] = {}
        # session_id -> n_parties (declared at open)
        self._n_parties: Dict[str, int] = {}
        # session_id -> PartyRecord list (booking order)
        self._parties: Dict[str, List[PartyRecord]] = {}
        # (session_id, party_id) -> ShareCommitment
        self._shares: Dict[Tuple[str, str], ShareCommitment] = {}
        # session_id -> ComputeRecord
        self._computes: Dict[str, ComputeRecord] = {}
        # session_id -> ReconstructRecord
        self._reconstructs: Dict[str, ReconstructRecord] = {}
        # retired session ids (closed; never recycled)
        self._retired = set()  # type: ignore[var-annotated]
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(mpc_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: MPCError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _live_session(self, session_id: str, seq: int) -> str:
        """Return the current state, or raise fail-closed for unknown/retired."""
        record = self._sessions.get(session_id)
        if record is None:
            if session_id in self._retired:
                raise RetiredSessionError(f"session {session_id!r} is retired")
            raise UnknownSessionError(f"unknown session {session_id!r}")
        return self._states[session_id]

    # -- mutations ----------------------------------------------------------

    def session(
        self, session_id: str, n_parties: int, threshold: int, seq: int
    ) -> SessionRecord:
        """Open one MPC session with n declared parties and threshold t."""
        with self._lock:
            seq = self._claim(seq)
            try:
                session_id = _check_session_id(session_id)
                if session_id in self._retired:
                    raise RetiredSessionError(
                        f"session id {session_id!r} is retired and never recycled"
                    )
                if session_id in self._sessions:
                    raise DuplicateSessionError(
                        f"session {session_id!r} is already open"
                    )
                n_parties = _check_n_parties(n_parties)
                threshold = _check_threshold(threshold, n_parties)
            except MPCError as exc:
                self._fail(seq, exc, session_id=str(session_id))
            record = SessionRecord(
                session_id=session_id,
                n_parties=n_parties,
                threshold=threshold,
                digest=_digest_pin((session_id, n_parties, threshold), "session"),
            )
            self._sessions[session_id] = record
            self._states[session_id] = "open"
            self._n_parties[session_id] = n_parties
            self._parties[session_id] = []
            self._emit(
                KIND_SESSION_OPENED,
                seq,
                session_id=session_id,
                n_parties=n_parties,
                threshold=threshold,
            )
            return record

    def register_party(
        self, session_id: str, party_id: str, seq: int
    ) -> PartyRecord:
        """Seat one party in an ``open`` session."""
        with self._lock:
            seq = self._claim(seq)
            try:
                session_id = _check_session_id(session_id)
                party_id = _check_party_id(party_id)
                state = self._live_session(session_id, seq)
                if state != "open":
                    raise SessionStateError(
                        f"session {session_id!r} is {state!r}; "
                        "parties may only register while open"
                    )
                booked = self._parties[session_id]
                if any(p.party_id == party_id for p in booked):
                    raise DuplicatePartyError(
                        f"party {party_id!r} already registered in {session_id!r}"
                    )
                if len(booked) >= self._n_parties[session_id]:
                    raise TooManyPartiesError(
                        f"session {session_id!r} already has "
                        f"{self._n_parties[session_id]} parties"
                    )
            except MPCError as exc:
                self._fail(seq, exc, session_id=str(session_id))
            record = PartyRecord(
                session_id=session_id,
                party_id=party_id,
                digest=_digest_pin((session_id, party_id), "party"),
            )
            self._parties[session_id].append(record)
            if len(self._parties[session_id]) == self._n_parties[session_id]:
                self._states[session_id] = "ready"
            self._emit(
                KIND_PARTY_REGISTERED,
                seq,
                session_id=session_id,
                party_id=party_id,
            )
            return record

    def share(
        self, session_id: str, party_id: str, input_digest: str, seq: int
    ) -> ShareCommitment:
        """Book one party's input commitment (digest pin only)."""
        with self._lock:
            seq = self._claim(seq)
            try:
                session_id = _check_session_id(session_id)
                party_id = _check_party_id(party_id)
                input_digest = _check_digest(input_digest, "input_digest")
                state = self._live_session(session_id, seq)
                if state != "ready":
                    raise SessionStateError(
                        f"session {session_id!r} is {state!r}; "
                        "inputs may only be shared while ready"
                    )
                if not any(p.party_id == party_id for p in self._parties[session_id]):
                    raise UnknownPartyError(
                        f"party {party_id!r} is not registered in {session_id!r}"
                    )
                key = (session_id, party_id)
                if key in self._shares:
                    raise DuplicateShareError(
                        f"party {party_id!r} already shared in {session_id!r}"
                    )
            except MPCError as exc:
                self._fail(seq, exc, session_id=str(session_id))
            record = ShareCommitment(
                session_id=session_id,
                party_id=party_id,
                input_digest=input_digest,
                digest=_digest_pin((session_id, party_id, input_digest), "share"),
            )
            self._shares[(session_id, party_id)] = record
            if len([k for k in self._shares if k[0] == session_id]) == self._n_parties[
                session_id
            ]:
                self._states[session_id] = "committed"
            self._emit(
                KIND_INPUT_SHARED,
                seq,
                session_id=session_id,
                party_id=party_id,
                input_digest=input_digest,
            )
            return record

    def compute(self, session_id: str, circuit_digest: str, seq: int) -> ComputeRecord:
        """Book the declared joint computation over the committed inputs."""
        with self._lock:
            seq = self._claim(seq)
            try:
                session_id = _check_session_id(session_id)
                circuit_digest = _check_digest(circuit_digest, "circuit_digest")
                state = self._live_session(session_id, seq)
                if state != "committed":
                    raise SessionStateError(
                        f"session {session_id!r} is {state!r}; "
                        "compute requires all inputs committed"
                    )
            except MPCError as exc:
                self._fail(seq, exc, session_id=str(session_id))
            n_inputs = len([k for k in self._shares if k[0] == session_id])
            record = ComputeRecord(
                session_id=session_id,
                circuit_digest=circuit_digest,
                n_inputs=n_inputs,
                digest=_digest_pin((session_id, circuit_digest, n_inputs), "compute"),
            )
            self._computes[session_id] = record
            self._states[session_id] = "computed"
            self._emit(
                KIND_COMPUTED,
                seq,
                session_id=session_id,
                circuit_digest=circuit_digest,
                n_inputs=n_inputs,
            )
            return record

    def reconstruct(
        self, session_id: str, output_digest: str, seq: int
    ) -> ReconstructRecord:
        """Book output delivery. Terminal: the session id is retired."""
        with self._lock:
            seq = self._claim(seq)
            try:
                session_id = _check_session_id(session_id)
                output_digest = _check_digest(output_digest, "output_digest")
                state = self._live_session(session_id, seq)
                if state != "computed":
                    raise SessionStateError(
                        f"session {session_id!r} is {state!r}; "
                        "reconstruct requires a computed session"
                    )
            except MPCError as exc:
                self._fail(seq, exc, session_id=str(session_id))
            record = ReconstructRecord(
                session_id=session_id,
                output_digest=output_digest,
                digest=_digest_pin((session_id, output_digest), "reconstruct"),
            )
            self._reconstructs[session_id] = record
            self._states[session_id] = "closed"
            del self._sessions[session_id]
            self._retired.add(session_id)
            self._emit(
                KIND_RECONSTRUCTED,
                seq,
                session_id=session_id,
                output_digest=output_digest,
            )
            return record

    # -- pure reads ----------------------------------------------------------

    def session_state(self, session_id: str, seq: int) -> str:
        """Pure-read current lifecycle state of one session."""
        with self._lock:
            _check_seq(seq)
            session_id = _check_session_id(session_id)
            if session_id in self._retired:
                return "closed"
            state = self._states.get(session_id)
            if state is None:
                raise UnknownSessionError(f"unknown session {session_id!r}")
            return state

    def session_record(self, session_id: str, seq: int) -> SessionRecord:
        """Pure-read lookup of one session record."""
        with self._lock:
            _check_seq(seq)
            session_id = _check_session_id(session_id)
            record = self._sessions.get(session_id)
            if record is None:
                raise UnknownSessionError(f"unknown session {session_id!r}")
            return record

    def commitment(self, session_id: str, party_id: str, seq: int) -> ShareCommitment:
        """Pure-read lookup of one booked input commitment."""
        with self._lock:
            _check_seq(seq)
            session_id = _check_session_id(session_id)
            party_id = _check_party_id(party_id)
            record = self._shares.get((session_id, party_id))
            if record is None:
                raise UnknownPartyError(
                    f"no commitment for party {party_id!r} in {session_id!r}"
                )
            return record

    def session_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._sessions)

    def party_ids(self, session_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            session_id = _check_session_id(session_id)
            booked = self._parties.get(session_id)
            if booked is None:
                raise UnknownSessionError(f"unknown session {session_id!r}")
            return tuple(p.party_id for p in booked)

    def commitments_for(self, session_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            session_id = _check_session_id(session_id)
            if session_id not in self._sessions and session_id not in self._retired:
                raise UnknownSessionError(f"unknown session {session_id!r}")
            return tuple(
                party_id for (sid, party_id) in self._shares if sid == session_id
            )

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure-read ledger statistics."""
        with self._lock:
            _check_seq(seq)
            return {
                "sessions": len(self._sessions) + len(self._retired),
                "open_sessions": len(self._sessions),
                "closed_sessions": len(self._retired),
                "parties": sum(len(p) for p in self._parties.values()),
                "commitments": len(self._shares),
                "computations": len(self._computes),
                "reconstructions": len(self._reconstructs),
                "audit_rows": len(self._audit_events),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_events)


def main() -> None:
    """Self-check entry point."""
    mpc = MPC()
    digest = "sha256:" + "ab" * 32
    rec = mpc.session("sess-1", 2, 2, 1)
    assert rec.verify()
    mpc.register_party("sess-1", "alice", 2)
    mpc.register_party("sess-1", "bob", 3)
    assert mpc.session_state("sess-1", 3) == "ready"
    s1 = mpc.share("sess-1", "alice", digest, 4)
    assert s1.verify()
    s2 = mpc.share("sess-1", "bob", digest, 5)
    assert s2.verify()
    assert mpc.session_state("sess-1", 5) == "committed"
    c = mpc.compute("sess-1", digest, 6)
    assert c.verify()
    r = mpc.reconstruct("sess-1", digest, 7)
    assert r.verify()
    assert mpc.session_state("sess-1", 7) == "closed"
    print("mpc OK: session, register, share, compute, reconstruct, pins, audit")


if __name__ == "__main__":
    main()
