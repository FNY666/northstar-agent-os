"""GraphQL gateway: Apollo Gateway / Hasura-shaped schema bookkeeping (simulated).

Interface:
    GraphQLGateway.schema(schema_id, name, seq, type_defs="", url="")
        -> sealed SchemaRecord (SDL booked by digest only)
    GraphQLGateway.resolve(schema_id, field, seq, resolver_digest="")
        -> sealed ResolverRecord (res-N ids; resolver booked by digest only)
    GraphQLGateway.federate(schema_id, seq)
        -> sealed FederationRecord (subgraph joins the supergraph)
    GraphQLGateway.defederate(schema_id, seq, reason="")
        -> sealed DefederationRecord (terminal until re-federated)
    GraphQLGateway.plan(operation, seq, fields=())
        -> sealed QueryPlan (pure read view; deterministic field sharding)

Everything is deterministic single-host bookkeeping over host-reported data:
type definitions are host-declared SDL strings whose *digest* is pinned --
the module never parses GraphQL and never executes a query. Resolvers are
booked by digest only; resolver code never enters a record or crosses the
audit boundary (GIGO boundary). ``plan()`` computes a deterministic sharding
of field paths across federated subgraphs as data; it performs no network
calls and fetches nothing. No sockets, no wire truth.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (failed mutations consume their seq), no wall-clock, RLock-guarded,
fail-closed, stdlib-only + standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


_MODULE_VERSION = "graphql-gateway.v1"
_SCHEMA_PIN = "northstar.graphql-gateway.v1"
_AUDIT_TYPE = "audit.ndjson/1"

# SDL / id caps.
_MAX_TYPE_DEFS = 65536
_MAX_ID_LEN = 128

# GraphQL name shape: [_A-Za-z][_0-9A-Za-z]*
_NAME_RE = re.compile(r"[_A-Za-z][_0-9A-Za-z]*")


class GraphQLGatewayError(ValueError):
    """Base for all graphql_gateway errors."""


class BadSchemaError(GraphQLGatewayError):
    """Schema id / name / SDL failed validation."""


class DuplicateSchemaError(GraphQLGatewayError):
    """A schema with this id is already pinned."""


class UnknownSchemaError(GraphQLGatewayError):
    """Schema id not found."""


class BadResolverError(GraphQLGatewayError):
    """Resolver field / digest failed validation."""


class DuplicateResolverError(GraphQLGatewayError):
    """This schema already binds a resolver for this field."""


class UnknownResolverError(GraphQLGatewayError):
    """Resolver id not found."""


class AlreadyFederatedError(GraphQLGatewayError):
    """Schema is already federated."""


class NotFederatedError(GraphQLGatewayError):
    """Schema is not currently federated."""


class SeqOrderError(GraphQLGatewayError):
    """Caller seq did not strictly increase."""


def _reject(reason: str) -> GraphQLGatewayError:
    table = {
        "bad-schema": BadSchemaError,
        "duplicate-schema": DuplicateSchemaError,
        "unknown-schema": UnknownSchemaError,
        "bad-resolver": BadResolverError,
        "duplicate-resolver": DuplicateResolverError,
        "unknown-resolver": UnknownResolverError,
        "already-federated": AlreadyFederatedError,
        "not-federated": NotFederatedError,
        "seq": SeqOrderError,
    }
    return table.get(reason, GraphQLGatewayError)(reason)


def _reason_for(err: GraphQLGatewayError) -> str:
    # Map the concrete exception type back to its audit reason key so the
    # raised error keeps its taxonomy (validators raise informative messages,
    # not bare reason keys).
    for cls, key in (
        (BadSchemaError, "bad-schema"),
        (DuplicateSchemaError, "duplicate-schema"),
        (UnknownSchemaError, "unknown-schema"),
        (BadResolverError, "bad-resolver"),
        (DuplicateResolverError, "duplicate-resolver"),
        (UnknownResolverError, "unknown-resolver"),
        (AlreadyFederatedError, "already-federated"),
        (NotFederatedError, "not-federated"),
        (SeqOrderError, "seq"),
    ):
        if isinstance(err, cls):
            return key
    return "bad-schema"


def _check_seq_kind(seq: Any) -> None:
    # bool is an int subclass; reject it explicitly (house discipline).
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise _reject("seq")


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadSchemaError(f"{name} must be a non-empty string")
    value = value.strip()
    if len(value) > _MAX_ID_LEN:
        raise BadSchemaError(f"{name} exceeds {_MAX_ID_LEN} characters")
    if any(c.isspace() or ord(c) < 32 for c in value):
        raise BadSchemaError(f"{name} carries whitespace/control characters")
    return value


def _check_field(field: Any) -> str:
    # Field paths look like "Query.user" or "Mutation.createPost":
    # <Type>.<field>, both GraphQL-name shaped.
    if not isinstance(field, str) or not field:
        raise BadResolverError("field must be a non-empty string")
    parts = field.split(".")
    if len(parts) != 2 or not all(_NAME_RE.fullmatch(p) for p in parts):
        raise BadResolverError(
            f"field must be '<Type>.<name>' with GraphQL-name parts: {field!r}"
        )
    return field


def _check_digest(value: Any, name: str) -> str:
    # Resolver code is booked by digest only -- opaque booking tokens.
    if not isinstance(value, str) or not value or len(value) > 256:
        raise BadResolverError(f"{name} must be a non-empty string <= 256 chars")
    if any(c.isspace() for c in value):
        raise BadResolverError(f"{name} must be a single token")
    return value


def _digest(kind: str, payload: Any) -> str:
    h = hashlib.sha256()
    h.update(kind.encode("utf-8"))
    h.update(b"\x00")
    h.update(jcs_canonical_json(payload))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Sealed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SchemaRecord:
    schema_id: str
    name: str
    type_defs_digest: str  # digest of the host-declared SDL; SDL never stored
    url: str
    federated: bool
    created_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("schema", payload)


@dataclass(frozen=True)
class ResolverRecord:
    resolver_id: str
    schema_id: str
    field: str  # "Query.user"
    resolver_digest: str  # digest of the resolver; code never stored
    bound_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("resolver", payload)


@dataclass(frozen=True)
class FederationRecord:
    federation_id: str
    schema_id: str
    federated_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("federation", payload)


@dataclass(frozen=True)
class DefederationRecord:
    defederation_id: str
    schema_id: str
    reason: str
    defederated_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        return self.digest == _digest("defederation", payload)


@dataclass(frozen=True)
class PlanStep:
    schema_id: str
    fields: Tuple[str, ...]


@dataclass(frozen=True)
class QueryPlan:
    plan_id: str
    operation: str
    steps: Tuple[PlanStep, ...]
    planned_at_seq: int
    digest: str = ""

    def verify_digest(self) -> bool:
        payload = {k: v for k, v in asdict(self).items() if k != "digest"}
        # asdict() freezes tuples into lists; pin the canonical form.
        return self.digest == _digest("plan", payload)


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------


class GraphQLGateway:
    """Deterministic GraphQL gateway bookkeeping.

    All state mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume their
    seq (fail-closed ledger position). SDL and resolver code never enter a
    record -- only ``sha256:`` digests are pinned.
    """

    def __init__(self, audit: Optional[Any] = None) -> None:
        self._lock = threading.RLock()
        self._audit = audit
        self._seq = 0
        self._schemas: Dict[str, SchemaRecord] = {}
        self._resolvers: Dict[str, ResolverRecord] = {}
        self._resolver_by_field: Dict[Tuple[str, str], str] = {}
        self._resolver_counter = 0
        self._federations: Dict[str, FederationRecord] = {}
        self._defederations: Dict[str, DefederationRecord] = {}
        self._federation_counter = 0
        self._defederation_counter = 0
        self._plan_counter = 0

    # -- internals ------------------------------------------------------

    def _take_seq(self, seq: Any) -> int:
        _check_seq_kind(seq)
        with self._lock:
            if seq <= self._seq:
                raise _reject("seq")
            self._seq = seq
            return seq

    def _emit(self, kind: str, seq: int, detail: Dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit(graphql_gateway_audit_event(kind, detail, seq))

    def _fail(self, reason: str, seq: int, detail: Dict[str, Any]) -> GraphQLGatewayError:
        err = _reject(reason)
        with self._lock:
            self._emit("graphql.rejected", seq, dict(detail, reason=reason))
        return err

    # -- schema ----------------------------------------------------------

    def schema(
        self,
        schema_id: str,
        name: str,
        seq: int,
        type_defs: str = "",
        url: str = "",
    ) -> SchemaRecord:
        """Pin a subgraph schema. ``type_defs`` is host-declared SDL; only
        its digest is pinned -- the SDL text never enters a record."""
        with self._lock:
            self._take_seq(seq)
            try:
                schema_id = _check_id(schema_id, "schema_id")
                if not isinstance(name, str) or not name.strip():
                    raise _reject("bad-schema")
                name = name.strip()
                if not isinstance(type_defs, str) or len(type_defs) > _MAX_TYPE_DEFS:
                    raise _reject("bad-schema")
                if not isinstance(url, str) or len(url) > 2048:
                    raise _reject("bad-schema")
                if any(c.isspace() or ord(c) < 32 for c in url):
                    raise _reject("bad-schema")
                if schema_id in self._schemas:
                    raise _reject("duplicate-schema")
                rec = SchemaRecord(
                    schema_id=schema_id,
                    name=name,
                    type_defs_digest=_digest("sdl", type_defs),
                    url=url,
                    federated=False,
                    created_at_seq=seq,
                )
                rec = SchemaRecord(**{**asdict(rec), "digest": _digest("schema", {k: v for k, v in asdict(rec).items() if k != "digest"})})
                self._schemas[schema_id] = rec
            except GraphQLGatewayError as err:
                raise self._fail(
                    _reason_for(err), seq,
                    {"schema_id": schema_id if isinstance(schema_id, str) else ""},
                ) from err
            self._emit("graphql.schema-defined", seq, {"schema_id": schema_id})
            return rec

    # -- resolve ---------------------------------------------------------

    def resolve(
        self,
        schema_id: str,
        field: str,
        seq: int,
        resolver_digest: str = "",
    ) -> ResolverRecord:
        """Bind ``field`` (``Query.user``) on a schema to a resolver booked
        by digest only. Resolver code never enters a record."""
        with self._lock:
            self._take_seq(seq)
            try:
                if schema_id not in self._schemas:
                    raise _reject("unknown-schema")
                field = _check_field(field)
                resolver_digest = _check_digest(resolver_digest, "resolver_digest")
                if (schema_id, field) in self._resolver_by_field:
                    raise _reject("duplicate-resolver")
                self._resolver_counter += 1
                resolver_id = f"res-{self._resolver_counter}"
                rec = ResolverRecord(
                    resolver_id=resolver_id,
                    schema_id=schema_id,
                    field=field,
                    resolver_digest=resolver_digest,
                    bound_at_seq=seq,
                )
                rec = ResolverRecord(**{**asdict(rec), "digest": _digest("resolver", {k: v for k, v in asdict(rec).items() if k != "digest"})})
                self._resolvers[resolver_id] = rec
                self._resolver_by_field[(schema_id, field)] = resolver_id
            except GraphQLGatewayError as err:
                raise self._fail(
                    _reason_for(err), seq,
                    {"schema_id": schema_id if isinstance(schema_id, str) else ""},
                ) from err
            self._emit(
                "graphql.resolver-bound",
                seq,
                {"schema_id": schema_id, "resolver_id": rec.resolver_id},
            )
            return rec

    # -- federation ------------------------------------------------------

    def federate(self, schema_id: str, seq: int) -> FederationRecord:
        """Join a schema to the supergraph as a federated subgraph."""
        with self._lock:
            self._take_seq(seq)
            try:
                schema = self._schemas.get(schema_id)
                if schema is None:
                    raise _reject("unknown-schema")
                if schema.federated:
                    raise _reject("already-federated")
                self._federation_counter += 1
                rec = FederationRecord(
                    federation_id=f"fed-{self._federation_counter}",
                    schema_id=schema_id,
                    federated_at_seq=seq,
                )
                rec = FederationRecord(**{**asdict(rec), "digest": _digest("federation", {k: v for k, v in asdict(rec).items() if k != "digest"})})
                self._federations[rec.federation_id] = rec
                self._schemas[schema_id] = SchemaRecord(
                    **{**asdict(schema), "federated": True,
                       "digest": _digest("schema", {k: v for k, v in asdict(schema).items() if k not in ("digest", "federated")} | {"federated": True})}
                )
            except GraphQLGatewayError as err:
                raise self._fail(
                    _reason_for(err), seq,
                    {"schema_id": schema_id if isinstance(schema_id, str) else ""},
                ) from err
            self._emit(
                "graphql.federated", seq,
                {"schema_id": schema_id, "federation_id": rec.federation_id},
            )
            return rec

    def defederate(
        self, schema_id: str, seq: int, reason: str = ""
    ) -> DefederationRecord:
        """Leave the supergraph. Terminal until re-federated."""
        with self._lock:
            self._take_seq(seq)
            try:
                schema = self._schemas.get(schema_id)
                if schema is None:
                    raise _reject("unknown-schema")
                if not schema.federated:
                    raise _reject("not-federated")
                if not isinstance(reason, str) or len(reason) > 512:
                    raise _reject("bad-schema")
                self._defederation_counter += 1
                rec = DefederationRecord(
                    defederation_id=f"defed-{self._defederation_counter}",
                    schema_id=schema_id,
                    reason=reason,
                    defederated_at_seq=seq,
                )
                rec = DefederationRecord(**{**asdict(rec), "digest": _digest("defederation", {k: v for k, v in asdict(rec).items() if k != "digest"})})
                self._defederations[rec.defederation_id] = rec
                self._schemas[schema_id] = SchemaRecord(
                    **{**asdict(schema), "federated": False,
                       "digest": _digest("schema", {k: v for k, v in asdict(schema).items() if k not in ("digest", "federated")} | {"federated": False})}
                )
            except GraphQLGatewayError as err:
                raise self._fail(
                    _reason_for(err), seq,
                    {"schema_id": schema_id if isinstance(schema_id, str) else ""},
                ) from err
            self._emit(
                "graphql.defederated", seq,
                {"schema_id": schema_id, "defederation_id": rec.defederation_id},
            )
            return rec

    # -- plan (pure read view) -------------------------------------------

    def plan(
        self, operation: str, seq: int, fields: Tuple[str, ...] = ()
    ) -> QueryPlan:
        """Shard ``fields`` across federated subgraphs deterministically.

        Pure read view: validates seq shape but does not consume it and
        writes no audit row of its own... actually it emits a
        ``graphql.planned`` audited-read event like sibling read views.
        """
        _check_seq_kind(seq)
        if not isinstance(operation, str) or not operation.strip():
            raise BadSchemaError("operation must be a non-empty string")
        operation = operation.strip()
        if not isinstance(fields, tuple) or any(
            not isinstance(f, str) for f in fields
        ):
            raise BadResolverError("fields must be a tuple of strings")
        with self._lock:
            federated = sorted(
                sid for sid, s in self._schemas.items() if s.federated
            )
            groups: Dict[str, List[str]] = {sid: [] for sid in federated}
            for field in fields:
                _check_field(field)
                if federated:
                    bucket = int.from_bytes(
                        hashlib.sha256(field.encode("utf-8")).digest()[:8], "big"
                    ) % len(federated)
                    groups[federated[bucket]].append(field)
            steps = tuple(
                PlanStep(schema_id=sid, fields=tuple(groups[sid]))
                for sid in federated
            )
            self._plan_counter += 1
            plan = QueryPlan(
                plan_id=f"plan-{self._plan_counter}",
                operation=operation,
                steps=steps,
                planned_at_seq=seq,
            )
            payload = {
                "plan_id": plan.plan_id,
                "operation": plan.operation,
                "steps": [
                    {"schema_id": st.schema_id, "fields": list(st.fields)}
                    for st in steps
                ],
                "planned_at_seq": seq,
            }
            plan = QueryPlan(
                plan_id=plan.plan_id,
                operation=plan.operation,
                steps=plan.steps,
                planned_at_seq=plan.planned_at_seq,
                digest=_digest("plan", payload),
            )
            self._emit(
                "graphql.planned", seq,
                {"operation": operation, "plan_id": plan.plan_id},
            )
            return plan

    # -- views -----------------------------------------------------------

    def schema_record(self, schema_id: str) -> SchemaRecord:
        with self._lock:
            rec = self._schemas.get(schema_id)
            if rec is None:
                raise UnknownSchemaError("unknown-schema")
            return rec

    def resolver_record(self, resolver_id: str) -> ResolverRecord:
        with self._lock:
            rec = self._resolvers.get(resolver_id)
            if rec is None:
                raise UnknownResolverError("unknown-resolver")
            return rec

    def schema_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._schemas)

    def federated_ids(self) -> List[str]:
        with self._lock:
            return sorted(
                sid for sid, s in self._schemas.items() if s.federated
            )

    def resolvers_for(self, schema_id: str) -> List[ResolverRecord]:
        with self._lock:
            if schema_id not in self._schemas:
                raise UnknownSchemaError("unknown-schema")
            return [
                self._resolvers[rid]
                for (sid, _), rid in sorted(self._resolver_by_field.items())
                if sid == schema_id
            ]

    def audit_log(self) -> List[Dict[str, Any]]:
        # The audit sink is caller-owned; this is a placeholder view.
        return []


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def graphql_gateway_audit_event(
    kind: str, detail: Dict[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the graphql-gateway module."""
    _kinds = (
        "graphql.schema-defined",
        "graphql.resolver-bound",
        "graphql.federated",
        "graphql.defederated",
        "graphql.planned",
        "graphql.rejected",
    )
    if kind not in _kinds:
        raise GraphQLGatewayError(f"unknown audit kind: {kind!r}")
    _check_seq_kind(seq)
    if not isinstance(detail, dict):
        raise GraphQLGatewayError("detail must be a dict")
    # SDL and resolver code never cross the audit boundary; digests only.
    banned = {"type_defs", "sdl", "resolver_code", "code", "secret"}
    if any(k in detail for k in banned):
        raise GraphQLGatewayError("detail carries banned keys")
    return {
        "schema_version": _AUDIT_TYPE,
        "component": "northstar-agent-runtime",
        "module": _MODULE_VERSION,
        "schema": _SCHEMA_PIN,
        "event": kind,
        "seq": seq,
        "detail": dict(detail),
    }


def main() -> int:
    events: List[Dict[str, Any]] = []
    gw = GraphQLGateway(audit=events.append)
    s = gw.schema("users", "users", 1, type_defs="type Query { user: User }")
    assert s.verify_digest() and not s.federated
    r = gw.resolve("users", "Query.user", 2, resolver_digest="sha256:abc123")
    assert r.verify_digest() and r.resolver_id == "res-1"
    f = gw.federate("users", 3)
    assert f.verify_digest()
    assert gw.schema_record("users").federated
    p = gw.plan("GetUser", 4, fields=("Query.user",))
    assert p.verify_digest() and len(p.steps) == 1
    d = gw.defederate("users", 5, reason="migration")
    assert d.verify_digest() and not gw.schema_record("users").federated
    kinds = {e["event"] for e in events}
    assert {
        "graphql.schema-defined",
        "graphql.resolver-bound",
        "graphql.federated",
        "graphql.planned",
        "graphql.defederated",
    } <= kinds
    print("graphql-gateway OK: schema, resolve, federate, plan, defederate, pins, audit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
