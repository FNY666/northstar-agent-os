"""Tests for materialized_view: refresh-on-demand view maintenance."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from materialized_view import (
    AUDIT_SCHEMA,
    MATERIALIZED_VIEW_VERSION,
    SCHEMA_PIN,
    QUERY_KINDS,
    AuditKindError,
    BadKeyError,
    BadQueryError,
    BadValueError,
    BadViewError,
    MaterializedView,
    MaterializedViewError,
    SeqOrderError,
    UnknownKeyError,
    materialized_view_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "materialized_view.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "json",
    "canonical_json",
}


def test_version_pins():
    assert MATERIALIZED_VIEW_VERSION == "materialized-view.v1"
    assert SCHEMA_PIN == "northstar.materialized-view.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(QUERY_KINDS) == {"select", "count", "sum", "avg"}


def test_stdlib_only_ast():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW


def test_constructor_bad_inputs():
    for bad in ("", 123, None, True, "x" * 300):
        try:
            MaterializedView(bad, "select")
        except BadViewError:
            pass
        else:
            raise AssertionError(f"expected BadViewError for {bad!r}")
    for bad_kind in ("join", "", None, 42, True):
        try:
            MaterializedView("v", bad_kind)
        except BadQueryError:
            pass
        else:
            raise AssertionError(f"expected BadQueryError for {bad_kind!r}")


def test_select_roundtrip_and_digest_pins():
    v = MaterializedView("v1", "select")
    rec = v.base_upsert("k", "val", seq=1)
    assert rec.verify()
    assert rec.key_digest.startswith("sha256:")
    assert rec.value_digest.startswith("sha256:")
    assert rec.present is True
    assert v.is_stale()
    ref = v.refresh(seq=2)
    assert ref.verify() and ref.refresh_no == 1
    assert ref.changed is True and ref.rows == 1
    assert ref.deltas_applied == 1
    assert not v.is_stale()
    q = v.query(seq=3, key="k")
    assert q.found and q.value == "val" and q.fresh
    assert q.result_digest.startswith("sha256:")


def test_stale_is_data_not_error():
    v = MaterializedView("v1", "count")
    v.refresh(seq=1)  # empty base -> fresh, count 0
    assert v.query(seq=2).value == 0
    v.base_upsert("a", "x", seq=3)
    assert v.is_stale()
    q = v.query(seq=4)  # staleness reported as data, not raised
    assert q.fresh is False and q.found is True
    stats = v.stats()
    assert stats.stale and stats.pending_deltas == 1


def test_refresh_changed_flag_and_delta_clearing():
    v = MaterializedView("v1", "sum")
    v.base_upsert("a", 5, seq=1)
    first = v.refresh(seq=2)
    assert first.changed is True and first.deltas_applied == 1
    second = v.refresh(seq=3)
    assert second.changed is False and second.deltas_applied == 0
    assert second.result_digest == first.result_digest
    v.base_upsert("a", 5, seq=4)  # same value, still a delta
    third = v.refresh(seq=5)
    assert third.changed is False and third.deltas_applied == 1


def test_base_delete_lifecycle():
    v = MaterializedView("v1", "select")
    v.base_upsert("k", "v", seq=1)
    v.refresh(seq=2)
    rec = v.base_delete("k", seq=3)
    assert rec.present is False and rec.value_digest is None
    assert v.refresh(seq=4).rows == 0
    miss = v.query(seq=5, key="k")
    assert not miss.found and miss.value is None
    # Unknown key delete refused fail-closed.
    try:
        v.base_delete("ghost", seq=6)
    except UnknownKeyError:
        pass
    else:
        raise AssertionError("expected UnknownKeyError")
    # Failed mutation consumed its seq: seq 6 cannot be reused.
    try:
        v.base_upsert("z", "w", seq=6)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("expected SeqOrderError after burn")


def test_invalidate_forces_staleness():
    v = MaterializedView("v1", "count")
    v.base_upsert("a", "x", seq=1)
    v.refresh(seq=2)
    assert v.query(seq=3).fresh
    inv = v.invalidate(seq=4, reason="base-migrated")
    assert inv.reason == "base-migrated"
    assert v.is_stale()
    assert not v.query(seq=5).fresh
    assert v.stats().invalidations == 1
    assert v.refresh(seq=6).rows == 1  # recompute restores freshness


def test_count_aggregate():
    v = MaterializedView("v1", "count")
    for i, s in enumerate((1, 2, 3), start=1):
        v.base_upsert(f"k{i}", f"v{i}", seq=s)
    v.refresh(seq=4)
    q = v.query(seq=5)
    assert q.found and q.value == 3 and q.fresh
    v.base_delete("k2", seq=6)
    v.refresh(seq=7)
    assert v.query(seq=8).value == 2


def test_sum_aggregate_and_int_discipline():
    v = MaterializedView("v1", "sum")
    v.base_upsert("a", 10, seq=1)
    v.base_upsert("b", -4, seq=2)
    v.refresh(seq=3)
    assert v.query(seq=4).value == 6
    # bool values refused for sum/avg at upsert time (fail-closed).
    for bad in (True, False):
        try:
            v.base_upsert("c", bad, seq=5)
        except BadValueError:
            pass
        else:
            raise AssertionError("expected BadValueError for bool")
    try:
        v.base_upsert("c", 2.5, seq=5)
    except BadValueError:
        pass
    else:
        raise AssertionError("expected BadValueError for float")


def test_avg_is_exact_text_no_floats():
    v = MaterializedView("v1", "avg")
    v.base_upsert("x", 3, seq=1)
    v.base_upsert("y", 5, seq=2)
    v.refresh(seq=3)
    q = v.query(seq=4)
    assert q.value == "8/2" and isinstance(q.value, str)
    e = MaterializedView("v2", "avg")
    e.refresh(seq=1)
    assert e.query(seq=2).value == "0/0"


def test_value_validation_table():
    v = MaterializedView("v1", "select")
    s = 0
    for bad_value in (None, 2**53, -(2**53), float("nan"), float("inf"), ["x"]):
        s += 1
        try:
            v.base_upsert("k", bad_value, seq=s)
        except BadValueError:
            pass
        else:
            raise AssertionError(f"expected BadValueError for {bad_value!r}")
    for bad_key in ("", None, 7, True, "k" * 5000):
        s += 1
        try:
            v.base_upsert(bad_key, "v", seq=s)
        except BadKeyError:
            pass
        else:
            raise AssertionError(f"expected BadKeyError for {bad_key!r}")


def test_seq_ordering_and_burn():
    v = MaterializedView("v1", "select")
    v.base_upsert("a", "x", seq=1)
    for bad in (1, 0, -1, True, 1.5, "2"):
        try:
            v.base_upsert("b", "y", seq=bad)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"expected SeqOrderError for {bad!r}")
    # Pure reads validate seq shape but never consume: same seq twice is fine.
    v.refresh(seq=2)
    q1 = v.query(seq=3, key="a")
    q2 = v.query(seq=3, key="a")
    assert q1.value == q2.value == "x"
    # Reads do not advance the claim: a later mutation with seq=3 works.
    v.base_upsert("b", "y", seq=3)
    # Refresh-on-demand: the base row is not visible until refresh.
    assert not v.query(seq=3, key="b").found
    v.refresh(seq=4)
    assert v.query(seq=4, key="b").value == "y"


def test_audit_shapes_and_value_leak_ban():
    v = MaterializedView("v1", "select")
    v.base_upsert("k", "secret", seq=1)
    v.base_delete("k", seq=2)
    v.refresh(seq=3)
    v.invalidate(seq=4)
    kinds = [row["kind"] for row in v.audit_log()]
    assert kinds == [
        "materialized-view.base-upserted",
        "materialized-view.base-deleted",
        "materialized-view.refreshed",
        "materialized-view.invalidated",
    ], kinds
    for row in v.audit_log():
        assert row["schema"] == AUDIT_SCHEMA
        assert "secret" not in str(row)
    # Banned keys rejected by the audit builder.
    for banned in ("value", "payload", "row", "rows_data"):
        try:
            materialized_view_audit_event("refreshed", 9, **{banned: "x"})
        except AuditKindError:
            pass
        else:
            raise AssertionError(f"expected AuditKindError for {banned}")
    try:
        materialized_view_audit_event("nope", 9)
    except AuditKindError:
        pass
    else:
        raise AssertionError("expected AuditKindError for bad kind")
    ev = materialized_view_audit_event("refreshed", 9, rows=3)
    assert ev["module"] == MATERIALIZED_VIEW_VERSION and ev["seq"] == 9


def test_main_self_check():
    out = subprocess.run(
        [sys.executable, MODULE_PATH],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "materialized-view OK" in out.stdout
