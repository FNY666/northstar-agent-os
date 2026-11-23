"""Command Query Responsibility Segregation (CQRS) dispatch point.

Research note: CQRS (Meyer's command-query separation, popularized by Greg
Young) splits the write path (commands) from the read path (queries). In an
agent runtime this is a *safety* primitive, not just an architecture nicety:

* a query handler that mutates state is an unlogged side effect — reads must
  never write;
* a command handler that returns domain data smuggles reads through the
  write path, bypassing read-side admission, budgets, and audit.

This module pins the segregation at the dispatch point, with two separate
handler registries:

* ``Command`` records carry intent-to-mutate. ``dispatch_command`` routes to
  a registered command handler and returns only an acknowledgment — a handler
  that returns anything other than ``None`` is rejected fail-closed
  (``HandlerViolation``), so the write path can never leak data.
* ``Query`` records carry read intent. ``dispatch_query`` routes to a
  registered query handler and returns the data. Queries are never routed to
  command handlers and vice versa (cross-type dispatch raises ``TypeError``).

House style: frozen dataclasses, no wall-clock (all seqs are caller-supplied
ints), fail-closed (unknown types, duplicate registrations, cross-type
dispatch, and data-leaking handlers all raise loudly), stdlib-only,
deterministic, version pin + schema pin, ``main()`` self-check.

Honest scope: this is *dispatch-time* segregation — the bus guarantees that
commands and queries reach *separate handler registries*. It cannot prove a
query handler didn't mutate (the handler runs in the host's process; only the
host's audit trail can corroborate that). A clean dispatch means "routed to
the right side", never "no side effect happened". Digest pins cover the
dispatch envelope (ids, type, seq, outcome), not the payload.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping

#: Module version.
CQRS_PATTERN_VERSION = "cqrs-pattern.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cqrs-pattern.v1"


class UnknownCommandType(Exception):
    """Raised when a command has no registered handler."""

    def __init__(self, command_type: str):
        self.command_type = command_type
        super().__init__(f"no command handler registered for {command_type!r}")


class UnknownQueryType(Exception):
    """Raised when a query has no registered handler."""

    def __init__(self, query_type: str):
        self.query_type = query_type
        super().__init__(f"no query handler registered for {query_type!r}")


class HandlerViolation(Exception):
    """Raised when a command handler breaks the segregation contract.

    A command handler must return ``None``. Anything else means the write
    path is leaking data — fail closed.
    """

    def __init__(self, command_type: str, returned: Any):
        self.command_type = command_type
        self.returned = returned
        super().__init__(
            f"command handler for {command_type!r} returned {type(returned).__name__}; "
            "command handlers must return None"
        )


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


def _check_type(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str")
    return value


def _check_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("seq must be a non-negative int")
    return value


def _check_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a mapping")
    return value


def _digest(*parts: str) -> str:
    body = "\x00".join(parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Command:
    """Intent to mutate. Routed to command handlers only; never returns data."""

    command_id: str
    command_type: str
    payload: Mapping[str, Any]
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.command_id, "command_id")
        _check_type(self.command_type, "command_type")
        _check_mapping(self.payload, "payload")
        _check_seq(self.seq)

    def digest(self) -> str:
        """Pin the dispatch envelope (ids, type, seq) for audit."""
        return _digest(SCHEMA_PIN, "command", self.command_id, self.command_type, str(self.seq))


@dataclass(frozen=True)
class Query:
    """Intent to read. Routed to query handlers only; must not mutate."""

    query_id: str
    query_type: str
    criteria: Mapping[str, Any]
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.query_id, "query_id")
        _check_type(self.query_type, "query_type")
        _check_mapping(self.criteria, "criteria")
        _check_seq(self.seq)

    def digest(self) -> str:
        """Pin the dispatch envelope (ids, type, seq) for audit."""
        return _digest(SCHEMA_PIN, "query", self.query_id, self.query_type, str(self.seq))


@dataclass(frozen=True)
class CommandResult:
    """Acknowledgment of a dispatched command. Carries no domain data."""

    command_id: str
    command_type: str
    accepted: bool
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.command_id, "command_id")
        _check_type(self.command_type, "command_type")
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be a bool")
        _check_seq(self.seq)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": CQRS_PATTERN_VERSION,
            "kind": "command-result",
            "command_id": self.command_id,
            "command_type": self.command_type,
            "accepted": self.accepted,
            "seq": self.seq,
            "digest": _digest(
                SCHEMA_PIN, "command-result", self.command_id, self.command_type,
                "accepted" if self.accepted else "refused", str(self.seq),
            ),
        }


@dataclass(frozen=True)
class QueryResult:
    """Answer to a dispatched query. Data only — no mutation happened here."""

    query_id: str
    query_type: str
    data: Any
    seq: int

    def __post_init__(self) -> None:
        _check_id(self.query_id, "query_id")
        _check_type(self.query_type, "query_type")
        _check_seq(self.seq)

    def as_dict(self) -> Dict[str, Any]:
        try:
            data_repr = json.dumps(self.data, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            data_repr = repr(self.data)
        return {
            "schema": SCHEMA_PIN,
            "version": CQRS_PATTERN_VERSION,
            "kind": "query-result",
            "query_id": self.query_id,
            "query_type": self.query_type,
            "data": data_repr,
            "seq": self.seq,
            "digest": _digest(
                SCHEMA_PIN, "query-result", self.query_id, self.query_type, str(self.seq)
            ),
        }


class CQRSBus:
    """Separate registries for commands and queries; cross-type dispatch refused."""

    def __init__(self) -> None:
        self._command_handlers: Dict[str, Callable[[Command], None]] = {}
        self._query_handlers: Dict[str, Callable[[Query], Any]] = {}

    def register_command_handler(
        self, command_type: str, handler: Callable[[Command], None]
    ) -> None:
        """Register the handler for one command type. Re-registering refuses."""
        _check_type(command_type, "command_type")
        if not callable(handler):
            raise TypeError("command handler must be callable")
        if command_type in self._command_handlers:
            raise ValueError(f"command handler already registered for {command_type!r}")
        self._command_handlers[command_type] = handler

    def register_query_handler(
        self, query_type: str, handler: Callable[[Query], Any]
    ) -> None:
        """Register the handler for one query type. Re-registering refuses."""
        _check_type(query_type, "query_type")
        if not callable(handler):
            raise TypeError("query handler must be callable")
        if query_type in self._query_handlers:
            raise ValueError(f"query handler already registered for {query_type!r}")
        self._query_handlers[query_type] = handler

    def command_types(self) -> tuple:
        """Registered command types, sorted."""
        return tuple(sorted(self._command_handlers))

    def query_types(self) -> tuple:
        """Registered query types, sorted."""
        return tuple(sorted(self._query_handlers))

    def dispatch_command(self, command: Command) -> CommandResult:
        """Route a command to its handler. Returns an acknowledgment only."""
        if not isinstance(command, Command):
            raise TypeError(
                f"dispatch_command requires a Command, got {type(command).__name__}"
            )
        handler = self._command_handlers.get(command.command_type)
        if handler is None:
            raise UnknownCommandType(command.command_type)
        returned = handler(command)
        if returned is not None:
            # Write path leaked data: fail closed.
            raise HandlerViolation(command.command_type, returned)
        return CommandResult(
            command_id=command.command_id,
            command_type=command.command_type,
            accepted=True,
            seq=command.seq,
        )

    def dispatch_query(self, query: Query) -> QueryResult:
        """Route a query to its handler. Returns the data; never mutates."""
        if not isinstance(query, Query):
            raise TypeError(
                f"dispatch_query requires a Query, got {type(query).__name__}"
            )
        handler = self._query_handlers.get(query.query_type)
        if handler is None:
            raise UnknownQueryType(query.query_type)
        data = handler(query)
        return QueryResult(
            query_id=query.query_id,
            query_type=query.query_type,
            data=data,
            seq=query.seq,
        )


def cqrs_audit_event(record: Any, seq: int) -> Dict[str, Any]:
    """Shape a CommandResult/QueryResult into an audit.ndjson/1-style record."""
    _check_seq(seq)
    if not isinstance(record, (CommandResult, QueryResult)):
        raise TypeError("record must be a CommandResult or QueryResult")
    event = record.as_dict()
    event["audit_seq"] = seq
    return event


def main() -> None:
    store: Dict[str, Any] = {}

    def set_handler(cmd: Command) -> None:
        store[cmd.payload["key"]] = cmd.payload["value"]

    def get_handler(q: Query) -> Any:
        return store.get(q.criteria["key"])

    bus = CQRSBus()
    bus.register_command_handler("set", set_handler)
    bus.register_query_handler("get", get_handler)

    cmd = Command(command_id="c-1", command_type="set",
                  payload={"key": "k", "value": "v"}, seq=0)
    ack = bus.dispatch_command(cmd)
    assert ack.accepted and ack.command_id == "c-1"

    q = Query(query_id="q-1", query_type="get", criteria={"key": "k"}, seq=1)
    res = bus.dispatch_query(q)
    assert res.data == "v"

    # Cross-type dispatch refuses.
    try:
        bus.dispatch_command(q)  # type: ignore[arg-type]
        raise AssertionError("cross-type dispatch should refuse")
    except TypeError:
        pass

    # A leaking command handler is rejected fail-closed.
    bus.register_command_handler("leak", lambda c: "data")  # noqa: ARG005
    try:
        bus.dispatch_command(Command(command_id="c-2", command_type="leak",
                                     payload={}, seq=2))
        raise AssertionError("leaking handler should raise")
    except HandlerViolation:
        pass

    print("cqrs-pattern OK: segregated dispatch, ack-only writes, fail-closed")


if __name__ == "__main__":
    main()
