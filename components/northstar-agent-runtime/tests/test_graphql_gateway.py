"""Tests for graphql_gateway: Apollo/Hasura-shaped schema bookkeeping."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from graphql_gateway import (
    GraphQLGateway,
    GraphQLGatewayError,
    BadSchemaError,
    DuplicateSchemaError,
    UnknownSchemaError,
    BadResolverError,
    DuplicateResolverError,
    UnknownResolverError,
    AlreadyFederatedError,
    NotFederatedError,
    SeqOrderError,
    SchemaRecord,
    ResolverRecord,
    FederationRecord,
    DefederationRecord,
    QueryPlan,
    graphql_gateway_audit_event,
    main,
    _MODULE_VERSION,
    _SCHEMA_PIN,
)

MOD = Path(__file__).resolve().parent.parent / "graphql_gateway.py"


def new_gw():
    events = []
    return GraphQLGateway(audit=events.append), events


def test_version_pins():
    assert _MODULE_VERSION == "graphql-gateway.v1"
    assert _SCHEMA_PIN == "northstar.graphql-gateway.v1"


def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    stdlib = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "canonical_json", "json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in stdlib, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in stdlib, node.module


def test_schema_roundtrip_and_digest():
    gw, events = new_gw()
    s = gw.schema("users", "users-svc", 1, type_defs="type Query { user: User }")
    assert isinstance(s, SchemaRecord)
    assert s.verify_digest()
    assert s.type_defs_digest.startswith("sha256:")
    assert not s.federated
    assert gw.schema_record("users") == s
    assert gw.schema_ids() == ["users"]
    assert events[-1]["event"] == "graphql.schema-defined"


def test_schema_duplicate_refused():
    gw, _ = new_gw()
    gw.schema("users", "users", 1)
    with pytest.raises(DuplicateSchemaError):
        gw.schema("users", "users", 2)


def test_schema_bad_inputs():
    gw, _ = new_gw()
    with pytest.raises(BadSchemaError):
        gw.schema("", "n", 1)
    with pytest.raises(BadSchemaError):
        gw.schema("s", "", 2)
    with pytest.raises(BadSchemaError):
        gw.schema("s", "n", 3, type_defs="x" * 70000)
    with pytest.raises(BadSchemaError):
        gw.schema("s", "n", 4, url="has space")


def test_resolve_roundtrip_and_digest():
    gw, events = new_gw()
    gw.schema("users", "users", 1)
    r = gw.resolve("users", "Query.user", 2, resolver_digest="sha256:abc")
    assert isinstance(r, ResolverRecord)
    assert r.verify_digest()
    assert r.resolver_id == "res-1"
    assert gw.resolver_record("res-1") == r
    assert [x.field for x in gw.resolvers_for("users")] == ["Query.user"]
    assert events[-1]["event"] == "graphql.resolver-bound"


def test_resolve_unknown_schema_and_bad_field():
    gw, _ = new_gw()
    with pytest.raises(UnknownSchemaError):
        gw.resolve("nope", "Query.user", 1, resolver_digest="sha256:x")
    gw.schema("users", "users", 2)
    with pytest.raises(BadResolverError):
        gw.resolve("users", "not-a-field", 3, resolver_digest="sha256:x")
    with pytest.raises(BadResolverError):
        gw.resolve("users", "Query.user", 4, resolver_digest="")


def test_resolve_duplicate_field_refused():
    gw, _ = new_gw()
    gw.schema("users", "users", 1)
    gw.resolve("users", "Query.user", 2, resolver_digest="sha256:a")
    with pytest.raises(DuplicateResolverError):
        gw.resolve("users", "Query.user", 3, resolver_digest="sha256:b")


def test_federate_defederate_lifecycle():
    gw, events = new_gw()
    gw.schema("users", "users", 1)
    f = gw.federate("users", 2)
    assert isinstance(f, FederationRecord) and f.verify_digest()
    assert gw.schema_record("users").federated
    assert gw.federated_ids() == ["users"]
    with pytest.raises(AlreadyFederatedError):
        gw.federate("users", 3)
    d = gw.defederate("users", 4, reason="migration")
    assert isinstance(d, DefederationRecord) and d.verify_digest()
    assert not gw.schema_record("users").federated
    with pytest.raises(NotFederatedError):
        gw.defederate("users", 5)
    # re-federate works after defederation
    gw.federate("users", 6)
    assert gw.federated_ids() == ["users"]
    kinds = {e["event"] for e in events}
    assert {"graphql.federated", "graphql.defederated"} <= kinds


def test_federate_unknown_schema():
    gw, _ = new_gw()
    with pytest.raises(UnknownSchemaError):
        gw.federate("nope", 1)


def test_plan_deterministic_sharding():
    gw, _ = new_gw()
    gw.schema("a", "a", 1)
    gw.schema("b", "b", 2)
    gw.federate("a", 3)
    gw.federate("b", 4)
    p1 = gw.plan("Op", 5, fields=("Query.x", "Query.y", "Mutation.z"))
    p2 = gw.plan("Op", 6, fields=("Query.x", "Query.y", "Mutation.z"))
    assert isinstance(p1, QueryPlan) and p1.verify_digest()
    assert [s.schema_id for s in p1.steps] == ["a", "b"]
    assigned = [f for s in p1.steps for f in s.fields]
    assert sorted(assigned) == ["Mutation.z", "Query.x", "Query.y"]
    # deterministic across calls
    assert [(s.schema_id, s.fields) for s in p1.steps] == [
        (s.schema_id, s.fields) for s in p2.steps
    ]
    # empty federation -> no steps, still valid data
    gw2, _ = new_gw()
    gw2.schema("solo", "solo", 1)
    p3 = gw2.plan("Op", 2, fields=("Query.x",))
    assert p3.steps == ()


def test_seq_ordering_and_failed_mutation_consumes_seq():
    gw, _ = new_gw()
    with pytest.raises(SeqOrderError):
        gw.schema("a", "a", 0)
    with pytest.raises(SeqOrderError):
        gw.schema("a", "a", True)
    gw.schema("a", "a", 1)
    with pytest.raises(SeqOrderError):
        gw.schema("b", "b", 1)  # rewind
    # failed mutation consumed seq 2; next valid seq is 3
    with pytest.raises(DuplicateSchemaError):
        gw.schema("a", "a", 2)
    with pytest.raises(SeqOrderError):
        gw.schema("b", "b", 2)
    gw.schema("b", "b", 3)
    assert gw.schema_ids() == ["a", "b"]


def test_audit_shapes_and_banned_keys():
    ev = graphql_gateway_audit_event(
        "graphql.schema-defined", {"schema_id": "users"}, 1
    )
    assert ev["schema_version"] == "audit.ndjson/1"
    assert ev["module"] == "graphql-gateway.v1"
    assert ev["event"] == "graphql.schema-defined"
    with pytest.raises(GraphQLGatewayError):
        graphql_gateway_audit_event("bogus.kind", {}, 1)
    with pytest.raises(GraphQLGatewayError):
        graphql_gateway_audit_event(
            "graphql.schema-defined", {"type_defs": "type Q { x: Int }"}, 1
        )
    with pytest.raises(GraphQLGatewayError):
        graphql_gateway_audit_event(
            "graphql.resolver-bound", {"resolver_code": "fn(){}"}, 1
        )
    # rejected events are booked on failure
    gw, events = new_gw()
    with pytest.raises(DuplicateSchemaError):
        gw.schema("a", "a", 1)
        gw.schema("a", "a", 2)
    assert events[-1]["event"] == "graphql.rejected"


def test_unknown_lookups():
    gw, _ = new_gw()
    with pytest.raises(UnknownSchemaError):
        gw.schema_record("nope")
    with pytest.raises(UnknownResolverError):
        gw.resolver_record("res-99")


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(MOD.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "graphql-gateway OK" in proc.stdout
    assert main() == 0
