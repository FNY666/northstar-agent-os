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


# ---------------------------------------------------------------------------
# The digest-pin defects (B173 slice, measured 2026-11-25)
#
# `graphql_gateway.py` carried the same four defects of the family that
# `graph_database.py`, `status_page.py`, `zero_knowledge.py`,
# `ai_constitution.py`, `ai_interpretability.py` and `ai_perturbation.py`
# carried before their slices.
#
# NOTE the per-module shape: this module has NO `_pin`; its digest
# helper is `_digest(kind, payload)`, and the fallback was a bare
# `json.dumps` shim with no surrogate check.  `plan()` is a **pure read
# view**: it consumes no seq and books no row of its own, so "no
# rejected row" is the CORRECT shape there, not a defect.  What fails
# open in `plan()` is the seq: `planned_at_seq` rides in the plan
# payload, and above the safe range the digest stops pinning it.


SURROGATE = "\ud800"


def test_a_refusal_raises_the_modules_own_error_type():
    """The module's own taxonomy, not the sibling helper's.

    `JcsError` is a `ValueError`, so a caller guarding on
    `except ValueError` would treat a refused mutation as a parse
    error.  The module's error must be what escapes.
    """
    gw, _ = new_gw()
    with pytest.raises(GraphQLGatewayError):
        gw.plan(SURROGATE, 1)


def test_the_shipped_path_and_the_fallback_agree_about_legality():
    """Both configurations must refuse a lone surrogate.

    They need not agree about the resulting digest bytes -- the
    fallback's tagged form is deliberately its own string -- but a
    value one refuses must be refused by both.  RFC 8785 §3.2.2.3
    requires a compliant implementation to terminate with an error.
    """
    import graphql_gateway as gqm
    saved = gqm._cj
    try:
        assert gqm._cj is not None, "the shipped path is not installed"

        gqm._cj = saved
        with pytest.raises(GraphQLGatewayError):
            gqm._canonical([SURROGATE])

        gqm._cj = None
        with pytest.raises(GraphQLGatewayError):
            gqm._canonical([SURROGATE])
    finally:
        gqm._cj = saved


def test_both_configurations_accept_a_value_both_can_canonicalize():
    """The control: the fallback must not refuse everything.

    Without this, a fallback that refused every input would satisfy
    the test above vacuously.
    """
    import graphql_gateway as gqm
    saved = gqm._cj
    try:
        for cfg in (saved, None):
            gqm._cj = cfg
            assert gqm._canonical(["ordinary", 7, ["a"]])
    finally:
        gqm._cj = saved


def test_a_seq_above_the_safe_range_is_refused():
    """A seq that cannot be pinned must not be accepted.

    Without this bound, 2**53 and 2**53+1 canonicalize to the same
    bytes, so the digest stops pinning the seq.
    """
    gw, _ = new_gw()
    with pytest.raises(GraphQLGatewayError):
        gw.plan("op", 2 ** 53)


def test_an_oversized_seq_is_refused_as_a_malformed_seq():
    """The refusal's SHAPE, not just its type.

    A malformed SEQ consumes nothing and books nothing -- the call
    never reached the ledger.  `plan()` is a pure read view, so it
    books no row for ANY refusal; the seq is what must not be
    consumed.
    """
    gw, events = new_gw()
    with pytest.raises(GraphQLGatewayError):
        gw.plan("op", 2 ** 53)
    # nothing booked
    assert [e for e in events if e["event"] == "graphql.planned"] == []
    # a later, valid seq still works: the oversized one was not consumed
    gw.schema("s1", "n", 1)
    assert gw.schema_record("s1").schema_id == "s1"


def test_a_tampered_seq_above_the_safe_range_cannot_verify():
    """The control: the digest must pin the seq.

    This is the property the bound protects.  The seq rides in the
    record payload, so a record whose seq was bumped must not still
    verify -- and the digest cannot even be MINTED over an
    out-of-range seq.
    """
    import graphql_gateway as gqm
    from dataclasses import asdict
    rec = gqm.SchemaRecord(
        schema_id="s1", name="n", type_defs_digest="d", url="u",
        federated=False, created_at_seq=2 ** 53 - 1,
    )
    payload = {k: v for k, v in asdict(rec).items() if k != "digest"}
    digest = gqm._digest("schema", payload)
    tampered = gqm.SchemaRecord(
        schema_id="s1", name="n", type_defs_digest="d", url="u",
        federated=False, created_at_seq=2 ** 53 + 1, digest=digest,
    )
    assert tampered.verify_digest() is False
    # and the digest cannot be minted over an out-of-range seq at all
    with pytest.raises(GraphQLGatewayError):
        gqm._digest("schema", {
            "schema_id": "s1", "name": "n", "type_defs_digest": "d",
            "url": "u", "federated": False, "created_at_seq": 2 ** 53,
        })


def test_the_safe_range_boundary_is_accepted():
    """The control: the bound must not over-refuse.

    2**53 - 1 is the last integer JCS pins exactly.
    """
    gw, _ = new_gw()
    gw.schema("s1", "n", 2 ** 53 - 1)
    assert gw.schema_record("s1").created_at_seq == 2 ** 53 - 1


def test_a_pin_refuses_an_integer_outside_the_safe_range():
    """A payload integer that cannot be pinned must be refused.

    The shipped path loses the distinction between 2**53 and
    2**53+1, so a pin over such a payload stops pinning it.
    """
    import graphql_gateway as gqm
    with pytest.raises(GraphQLGatewayError):
        gqm._canonical([2 ** 53])
    with pytest.raises(GraphQLGatewayError):
        gqm._canonical([2 ** 53 + 1])


def test_a_pin_still_accepts_the_last_safe_integer():
    """The control: the pin refusal must not over-reach."""
    import graphql_gateway as gqm
    assert gqm._canonical([2 ** 53 - 1])


def test_verify_answers_false_for_a_record_it_cannot_canonicalize():
    """`verify_digest()` answers a question; a question is not an
    exception.

    The record's digest cannot be recomputed over a lone surrogate, so
    the answer is "not intact" -- `False`.  It must not raise.
    """
    import graphql_gateway as gqm
    rec = gqm.SchemaRecord(
        schema_id=SURROGATE, name="n", type_defs_digest="d", url="u",
        federated=False, created_at_seq=1, digest="sha256:" + "0" * 64,
    )
    assert rec.verify_digest() is False


def test_an_oversized_seq_is_refused_before_the_digest_would():
    """The refusal's SHAPE distinguishes the layers.

    A malformed SEQ consumes nothing and books nothing -- the call never
    reached the ledger.  A failed DIGEST at a valid seq consumes the seq
    and books a `rejected` row.  Both raise `GraphQLGatewayError`, so
    "the call raised" cannot tell them apart; only the shape can.

    Without this test, removing the seq bound is invisible: the digest's
    own integer refusal raises the same error type, so every test that
    only asserted "it raised" still passed.
    """
    gw, events = new_gw()
    with pytest.raises(GraphQLGatewayError):
        gw.schema("s1", "n", 2 ** 53)
    # a malformed SEQ books NO rejected row
    assert [e for e in events if e["event"] == "graphql.rejected"] == []
    # and consumes NO seq: seq 1 is still claimable
    gw.schema("s2", "n", 1)
    assert gw.schema_record("s2").created_at_seq == 1
