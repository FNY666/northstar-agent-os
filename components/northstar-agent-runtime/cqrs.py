"""Command Query Responsibility Segregation (CQRS) ledger.

Research note: CQRS (Meyer's command-query separation, popularized by Greg
Young) splits the write path (commands) from the read path (queries). This
module is the *ledger* layer of that split, distinct from
``cqrs_pattern.py`` (dispatch-point handler segregation):

* ``command()`` books an intent-to-mutate on the write-side command log.
  Commands return nothing but a booking record -- the write path never
  returns domain data.
* ``project()`` advances a named projector's read model by folding the
  command log's digest pins into a deterministic state digest. The module
  does not interpret command semantics; it books *that* the projection
  advanced and *which* commands were folded.
* ``query()`` books a read against a projector's read model and returns the
  projector's state digest. Staleness (projector cursor behind the write
  head) is reported as data, never refused.

House style: frozen dataclasses, no wall-clock (all seqs are caller-supplied
strictly increasing ints), RLock-guarded, fail-closed (duplicate ids,
unknown projectors, bad digests all refuse loudly; failed mutations consume
their seq and book a ``cqrs.rejected`` audit row), stdlib-only, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin + schema pin,
``main()`` self-check.

Honest scope: this books *declared* commands, projections, and queries. It
cannot prove a command was ever executed by the host, cannot verify a
projection reflects real state, and cannot observe the wire. A booked query
means "the read model was consulted at this cursor", never "the data is
fresh" -- staleness is ledger truth about positions, not a freshness proof.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover
    _cj = None  # type: ignore

#: Module version pin.
CQRS_VERSION = "cqrs.v1"

#: Schema pin carried by records and audit events.
CQRS_SCHEMA = "northstar.cqrs.v1"

#: Audit schema marker.
AUDIT_SCHEMA = "audit.ndjson/1"


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class CQRSError(Exception):
    """Root error for the cqrs module."""


class BadCommandError(CQRSError):
    """A command id/type failed validation."""


class DuplicateCommandError(CQRSError):
    """A command id is already booked (ids are never recycled)."""


class BadQueryError(CQRSError):
    """A query id/type failed validation."""


class DuplicateQueryError(CQRSError):
    """A query id is already booked (ids are never recycled)."""


class BadProjectorError(CQRSError):
    """A projector id failed validation."""


class DuplicateProjectorError(CQRSError):
    """A projector id is already registered."""


class UnknownProjectorError(CQRSError):
    """Referenced projector is not registered."""


class BadDigestError(CQRSError):
    """A value is not a well-formed ``sha256:`` + 64-hex digest pin."""


class BadUpToError(CQRSError):
    """The projection bound is not a valid position."""


class SeqOrderError(CQRSError):
    """The supplied seq does not strictly increase."""


class AuditKindError(CQRSError):
    """Unknown audit kind requested."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, name: str, exc: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value \
            or len(value) > 256:
        raise exc(f"{name} must be a non-empty str (<=256 chars)")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SeqOrderError("seq must be a positive int")
    return value


def _check_digest(value: Any, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{name} must be a sha256: digest pin")
    if not value.startswith("sha256:"):
        raise BadDigestError(f"{name} must start with 'sha256:'")
    hexpart = value[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{name} must be 'sha256:' + 64 lowercase hex")
    return value


def _digest(*parts: str) -> str:
    body = "\x00".join(parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    """Deterministic string form of a JSON-safe value (digest inputs)."""
    if _cj is not None:
        try:
            raw = _cj.encode(value)  # type: ignore[attr-defined]
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        except Exception:
            pass
    import json as _json

    return _json.dumps(value, sort_keys=True, separators=(",", ":"))


#: Domain-separated genesis state digest for every projector.
GENESIS_STATE_DIGEST = _digest("northstar.cqrs.state.v1", "genesis")


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CommandRecord:
    """A booked write intent. Payload is digest-pinned only."""

    command_id: str
    command_type: str
    payload_digest: str
    seq: int
    log_position: int  # 1-based position in the write-side command log
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            "northstar.cqrs.command.v1",
            self.command_id,
            self.command_type,
            self.payload_digest,
            str(self.seq),
            str(self.log_position),
        )


@dataclass(frozen=True)
class ProjectorRecord:
    """A registered read-model projector with its projection cursor."""

    projector_id: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            "northstar.cqrs.projector.v1", self.projector_id, str(self.seq)
        )


@dataclass(frozen=True)
class ProjectionRecord:
    """One projection step: commands folded into a projector's read model."""

    projector_id: str
    applied_command_ids: Tuple[str, ...]  # in log order
    from_cursor: int
    to_cursor: int
    state_digest: str  # deterministic fold of the applied command pins
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            "northstar.cqrs.projection.v1",
            self.projector_id,
            _canonical(list(self.applied_command_ids)),
            str(self.from_cursor),
            str(self.to_cursor),
            self.state_digest,
            str(self.seq),
        )


@dataclass(frozen=True)
class QueryRecord:
    """A booked read against a projector's read model."""

    query_id: str
    query_type: str
    projector_id: str
    state_digest: str  # the projector's read-model digest at query time
    stale: bool  # True when the projector cursor lagged the write head
    projector_cursor: int
    write_head: int
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest(
            "northstar.cqrs.query.v1",
            self.query_id,
            self.query_type,
            self.projector_id,
            self.state_digest,
            "stale" if self.stale else "fresh",
            str(self.projector_cursor),
            str(self.write_head),
            str(self.seq),
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_COMMAND_BOOKED = "cqrs.command-booked"
KIND_PROJECTOR_REGISTERED = "cqrs.projector-registered"
KIND_PROJECTED = "cqrs.projected"
KIND_QUERY_BOOKED = "cqrs.query-booked"
KIND_REJECTED = "cqrs.rejected"
_KINDS = frozenset(
    {
        KIND_COMMAND_BOOKED,
        KIND_PROJECTOR_REGISTERED,
        KIND_PROJECTED,
        KIND_QUERY_BOOKED,
        KIND_REJECTED,
    }
)


def cqrs_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for cqrs."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    # Digest pins only; raw payloads must never cross the audit boundary.
    banned = {"payload", "value", "data", "message", "raw", "body"}
    if any(k in detail for k in banned):
        raise CQRSError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "cqrs",
        "module_version": CQRS_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class CQRS:
    """Deterministic CQRS ledger: command log, projections, read queries.

    The write path (``command``) and the read path (``query``) never meet
    directly: reads are always served from a projector's read model, and a
    projection is an explicit ``project`` step that folds command digest
    pins into a deterministic state digest.

    Simulated: there is no handler execution, no storage, no network -- the
    host declares everything through these calls. All mutations take a
    caller-supplied strictly increasing ``seq`` (monotonic logical time);
    no wall-clock is read anywhere. Failed mutations consume their seq
    (fail-closed ledger position). Read views validate the seq shape but do
    not consume it and write no audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # command_id -> CommandRecord; order list for log positions
        self._commands: Dict[str, CommandRecord] = {}
        self._log: List[str] = []  # command_ids in booking order
        # Max command seq booked (the write head); projection cursors and
        # staleness are measured against this, not the ledger seq.
        self._write_head = 0
        # projector_id -> {"record": ProjectorRecord, "cursor": int,
        #                  "state_digest": str, "projections": [...]}
        self._projectors: Dict[str, Dict[str, Any]] = {}
        self._queries: Dict[str, QueryRecord] = {}
        self._audit: List[Mapping[str, Any]] = []

    # -- internals ----------------------------------------------------------

    def _claim(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._seq}, got={seq})"
            )
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(cqrs_audit_event(kind, seq, **detail))

    def _fail(self, seq: int, exc: CQRSError, **detail: Any) -> None:
        """Book a rejection row, consume the seq, then raise."""
        self._seq = seq
        self._emit(KIND_REJECTED, seq, reason=str(exc), **detail)
        raise exc

    def _get_projector(self, projector_id: str) -> Dict[str, Any]:
        try:
            return self._projectors[projector_id]
        except KeyError:
            raise UnknownProjectorError(
                f"unknown projector: {projector_id!r}"
            )

    @staticmethod
    def _fold_state(prev_digest: str, command_pins: Sequence[str]) -> str:
        """Deterministic read-model fold over command digest pins."""
        return _digest(
            "northstar.cqrs.state.v1",
            prev_digest,
            _canonical(list(command_pins)),
        )

    # -- mutations -----------------------------------------------------------

    def register_projector(
        self, projector_id: str, seq: int
    ) -> ProjectorRecord:
        """Register a read-model projector; cursor starts at 0."""
        with self._lock:
            seq = self._claim(seq)
            try:
                pid = _check_id(projector_id, "projector_id",
                                BadProjectorError)
                if pid in self._projectors:
                    raise DuplicateProjectorError(
                        f"projector already registered: {pid!r}")
            except CQRSError as exc:
                self._fail(seq, exc, projector_id=str(projector_id))
            record = ProjectorRecord(
                projector_id=pid,
                seq=seq,
                digest=_digest(
                    "northstar.cqrs.projector.v1", pid, str(seq)),
            )
            self._projectors[pid] = {
                "record": record,
                "cursor": 0,
                "state_digest": GENESIS_STATE_DIGEST,
                "projections": [],
            }
            self._seq = seq
            self._emit(KIND_PROJECTOR_REGISTERED, seq, projector_id=pid)
            return record

    def command(
        self, command_id: str, command_type: str, payload_digest: str,
        seq: int,
    ) -> CommandRecord:
        """Book a write intent on the command log.

        The payload travels by digest pin only -- raw payloads never enter
        a record. Returns the booking record, never domain data.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                cid = _check_id(command_id, "command_id", BadCommandError)
                ctype = _check_id(
                    command_type, "command_type", BadCommandError)
                pin = _check_digest(payload_digest, "payload_digest")
                if cid in self._commands:
                    raise DuplicateCommandError(
                        f"command already booked: {cid!r}")
            except CQRSError as exc:
                self._fail(seq, exc, command_id=str(command_id))
            position = len(self._log) + 1
            digest = _digest(
                "northstar.cqrs.command.v1", cid, ctype, pin,
                str(seq), str(position),
            )
            record = CommandRecord(
                command_id=cid,
                command_type=ctype,
                payload_digest=pin,
                seq=seq,
                log_position=position,
                digest=digest,
            )
            self._commands[cid] = record
            self._log.append(cid)
            self._seq = seq
            self._write_head = seq
            self._emit(
                KIND_COMMAND_BOOKED, seq,
                command_id=cid, command_type=ctype,
                payload_digest=pin, log_position=position,
            )
            return record

    def project(
        self, projector_id: str, seq: int, upto_seq: Optional[int] = None
    ) -> ProjectionRecord:
        """Advance a projector's read model over the command log.

        Applies every command booked at a ledger ``seq`` in
        ``(cursor, upto]`` (``upto_seq=None`` means the current write
        head). An empty application is a valid no-op -- the projector is
        already caught up.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                pid = _check_id(projector_id, "projector_id",
                                BadProjectorError)
                proj = self._get_projector(pid)
                if upto_seq is None:
                    upto = self._write_head
                else:
                    if isinstance(upto_seq, bool) \
                            or not isinstance(upto_seq, int) \
                            or upto_seq < 0:
                        raise BadUpToError(
                            "upto_seq must be a non-negative int or None")
                    upto = upto_seq
            except CQRSError as exc:
                self._fail(seq, exc, projector_id=str(projector_id))
            cursor = proj["cursor"]
            applied: List[str] = []
            pins: List[str] = []
            for cid in self._log:
                rec = self._commands[cid]
                if cursor < rec.seq <= upto:
                    applied.append(cid)
                    pins.append(rec.payload_digest)
            new_state = self._fold_state(proj["state_digest"], pins)
            record = ProjectionRecord(
                projector_id=pid,
                applied_command_ids=tuple(applied),
                from_cursor=cursor,
                to_cursor=upto if applied else cursor,
                state_digest=new_state,
                seq=seq,
                digest=_digest(
                    "northstar.cqrs.projection.v1",
                    pid,
                    _canonical(applied),
                    str(cursor),
                    str(upto if applied else cursor),
                    new_state,
                    str(seq),
                ),
            )
            if applied:
                proj["cursor"] = upto
                proj["state_digest"] = new_state
            proj["projections"].append(record)
            self._seq = seq
            self._emit(
                KIND_PROJECTED, seq,
                projector_id=pid,
                applied_count=len(applied),
                from_cursor=cursor,
                to_cursor=record.to_cursor,
                state_digest=new_state,
            )
            return record

    def query(
        self, query_id: str, query_type: str, projector_id: str, seq: int
    ) -> QueryRecord:
        """Book a read against a projector's read model.

        Returns the projector's state digest as data. ``stale`` is data
        too: True when the projector cursor lagged the write head -- the
        query is still booked, never refused, so staleness is observable
        rather than hidden.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                qid = _check_id(query_id, "query_id", BadQueryError)
                qtype = _check_id(query_type, "query_type", BadQueryError)
                pid = _check_id(projector_id, "projector_id",
                                BadProjectorError)
                if qid in self._queries:
                    raise DuplicateQueryError(
                        f"query already booked: {qid!r}")
                proj = self._get_projector(pid)
            except CQRSError as exc:
                self._fail(seq, exc, query_id=str(query_id))
            cursor = proj["cursor"]
            head = self._write_head
            stale = cursor < head
            state_digest = proj["state_digest"]
            digest = _digest(
                "northstar.cqrs.query.v1",
                qid, qtype, pid, state_digest,
                "stale" if stale else "fresh",
                str(cursor), str(head), str(seq),
            )
            record = QueryRecord(
                query_id=qid,
                query_type=qtype,
                projector_id=pid,
                state_digest=state_digest,
                stale=stale,
                projector_cursor=cursor,
                write_head=head,
                seq=seq,
                digest=digest,
            )
            self._queries[qid] = record
            self._seq = seq
            self._emit(
                KIND_QUERY_BOOKED, seq,
                query_id=qid, query_type=qtype,
                projector_id=pid, stale=stale,
                state_digest=state_digest,
            )
            return record

    # -- read views (pure: validate seq shape, never consume) -----------------

    def _peek(self, seq: int) -> None:
        _check_seq(seq)

    def command_record(self, command_id: str, seq: int) -> CommandRecord:
        """Return a booked command record (pure read)."""
        self._peek(seq)
        try:
            return self._commands[command_id]
        except KeyError:
            raise UnknownCommandError(
                f"unknown command: {command_id!r}") from None

    def command_ids(self, seq: int) -> Tuple[str, ...]:
        """Command ids in booking order (pure read)."""
        self._peek(seq)
        return tuple(self._log)

    def projector(self, projector_id: str, seq: int) -> ProjectorRecord:
        """Return a projector's registration record (pure read)."""
        self._peek(seq)
        return self._get_projector(projector_id)["record"]

    def projector_ids(self, seq: int) -> Tuple[str, ...]:
        """Registered projector ids, sorted (pure read)."""
        self._peek(seq)
        return tuple(sorted(self._projectors))

    def projection_cursor(self, projector_id: str, seq: int) -> int:
        """A projector's current cursor (pure read)."""
        self._peek(seq)
        return self._get_projector(projector_id)["cursor"]

    def projector_state(self, projector_id: str, seq: int) -> str:
        """A projector's current read-model state digest (pure read)."""
        self._peek(seq)
        return self._get_projector(projector_id)["state_digest"]

    def write_head(self, seq: int) -> int:
        """The latest booked command seq (pure read)."""
        self._peek(seq)
        return self._write_head

    def stats(self, seq: int) -> Mapping[str, Any]:
        """Ledger counters (pure read)."""
        self._peek(seq)
        return {
            "schema": CQRS_SCHEMA,
            "commands": len(self._commands),
            "projectors": len(self._projectors),
            "queries": len(self._queries),
            "write_head": self._write_head,
        }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """The audit trail (pure read)."""
        return tuple(self._audit)


class UnknownCommandError(CQRSError):
    """Referenced command id is not booked."""


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    ledger = CQRS()
    ledger.register_projector("orders-read", 1)
    ledger.command("cmd-1", "PlaceOrder", _digest("order", "1"), 2)
    ledger.command("cmd-2", "CancelOrder", _digest("order", "2"), 3)
    proj = ledger.project("orders-read", 4)
    assert proj.applied_command_ids == ("cmd-1", "cmd-2")
    assert proj.from_cursor == 0 and proj.to_cursor == 3
    assert ledger.projection_cursor("orders-read", 5) == 3
    q = ledger.query("q-1", "OrderStatus", "orders-read", 6)
    assert q.stale is False
    ledger.command("cmd-3", "ShipOrder", _digest("order", "3"), 7)
    q2 = ledger.query("q-2", "OrderStatus", "orders-read", 8)
    assert q2.stale is True
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert KIND_COMMAND_BOOKED in kinds and KIND_QUERY_BOOKED in kinds
    print("cqrs OK: command, project, query, stale, pins, audit")


if __name__ == "__main__":
    main()
