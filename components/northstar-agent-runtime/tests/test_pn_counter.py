"""Tests for pn_counter: deterministic PN-counter ledger."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from pn_counter import (
    AUDIT_SCHEMA,
    KIND_CREATED,
    KIND_DECREMENTED,
    KIND_INCREMENTED,
    KIND_MERGED,
    PN_COUNTER_SCHEMA,
    PN_COUNTER_VERSION,
    AuditKindError,
    BadCounterError,
    BadDeltaError,
    BadMergeError,
    BadReplicaError,
    DuplicateCounterError,
    PNCounter,
    PNCounterError,
    SeqOrderError,
    UnknownCounterError,
    pn_counter_audit_event,
)

MOD = Path(__file__).resolve().parent.parent / "pn_counter.py"


def fresh(seq_start: int = 1):
    pn = PNCounter()
    pn.create("c", seq=seq_start)
    return pn, seq_start + 1


def test_version_pins():
    assert PN_COUNTER_VERSION == "pn-counter.v1"
    assert PN_COUNTER_SCHEMA == "northstar.pn-counter.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, r.stderr
    assert "pn-counter OK" in r.stdout


def test_create_roundtrip():
    pn = PNCounter()
    rec = pn.create("hits", seq=1)
    assert rec.counter_id == "hits"
    assert rec.verify()
    assert pn.counter_ids() == ("hits",)


def test_create_bad_inputs():
    pn = PNCounter()
    for bad in ("", "   ", 123, None, True, "x" * 257):
        with pytest.raises((BadCounterError, PNCounterError)):
            pn.create(bad, seq=pn._seq + 1)


def test_create_duplicate_refused():
    pn = PNCounter()
    pn.create("c", seq=1)
    with pytest.raises(DuplicateCounterError):
        pn.create("c", seq=2)


def test_inc_roundtrip_and_totals():
    pn, s = fresh()
    rec = pn.inc("c", "a", 5, seq=s)
    assert rec.new_total == 5 and rec.verify()
    rec2 = pn.inc("c", "a", 3, seq=s + 1)
    assert rec2.new_total == 8
    assert pn.value("c", seq=0).value == 8


def test_dec_roundtrip_and_net_value():
    pn, s = fresh()
    pn.inc("c", "a", 10, seq=s)
    pn.dec("c", "a", 4, seq=s + 1)
    rep = pn.value("c", seq=0)
    assert rep.inc_total == 10 and rep.dec_total == 4 and rep.value == 6
    assert rep.verify()


def test_multi_replica_value():
    pn, s = fresh()
    pn.inc("c", "a", 10, seq=s)
    pn.inc("c", "b", 7, seq=s + 1)
    pn.dec("c", "b", 2, seq=s + 2)
    rep = pn.value("c", seq=0)
    assert rep.value == 15 and rep.replica_count == 2


def test_bad_deltas():
    pn, s = fresh()
    for bad in (0, -1, True, 1.5, "3", None):
        with pytest.raises((BadDeltaError, PNCounterError)):
            pn.inc("c", "a", bad, seq=pn._seq + 1)


def test_bad_replica_ids():
    pn, s = fresh()
    for bad in ("", "  ", 7, None, True):
        with pytest.raises((BadReplicaError, PNCounterError)):
            pn.inc("c", bad, 1, seq=pn._seq + 1)


def test_unknown_counter():
    pn = PNCounter()
    with pytest.raises(UnknownCounterError):
        pn.inc("nope", "a", 1, seq=1)
    with pytest.raises(UnknownCounterError):
        pn.value("nope", seq=0)


def test_merge_converges_both_orders():
    left, s1 = fresh()
    right = PNCounter()
    right.create("c", seq=1)
    left.inc("c", "a", 10, seq=s1)
    left.dec("c", "a", 4, seq=s1 + 1)
    right.inc("c", "b", 7, seq=2)
    right.dec("c", "b", 2, seq=3)
    li, ld = left.contributions("c", seq=0)
    ri, rd = right.contributions("c", seq=0)
    m1 = left.merge("c", dict(ri), dict(rd), seq=s1 + 2)
    m2 = right.merge("c", dict(li), dict(ld), seq=4)
    assert m1.value == m2.value == 11
    assert m1.verify() and m2.verify()


def test_merge_idempotent():
    pn, s = fresh()
    pn.inc("c", "a", 5, seq=s)
    inc_map, dec_map = pn.contributions("c", seq=0)
    before = pn.value("c", seq=0).value
    pn.merge("c", dict(inc_map), dict(dec_map), seq=s + 1)
    assert pn.value("c", seq=0).value == before


def test_merge_bad_snapshots():
    pn, s = fresh()
    with pytest.raises(BadMergeError):
        pn.merge("c", "not-a-map", {}, seq=s)
    with pytest.raises(BadMergeError):
        pn.merge("c", {"a": -1}, {}, seq=pn._seq + 1)
    with pytest.raises(BadMergeError):
        pn.merge("c", {"a": True}, {}, seq=pn._seq + 1)
    with pytest.raises((BadReplicaError, BadMergeError)):
        pn.merge("c", {"": 3}, {}, seq=pn._seq + 1)


def test_merge_keeps_max():
    pn, s = fresh()
    pn.inc("c", "a", 10, seq=s)
    # Stale remote snapshot (lower) must not drag the total down.
    pn.merge("c", {"a": 4}, {}, seq=s + 1)
    assert pn.value("c", seq=0).inc_total == 10
    # Fresh remote snapshot advances it.
    pn.merge("c", {"a": 15}, {}, seq=s + 2)
    assert pn.value("c", seq=0).inc_total == 15


def test_value_is_pure_read():
    pn, s = fresh()
    pn.inc("c", "a", 3, seq=s)
    before = pn._seq
    pn.value("c", seq=0)
    pn.value("c", seq=5)
    assert pn._seq == before  # views consume no seq


def test_seq_rewind_refused():
    pn, s = fresh()
    pn.inc("c", "a", 1, seq=s)
    with pytest.raises(SeqOrderError):
        pn.inc("c", "a", 1, seq=s)  # rewind refused, ledger unchanged
    assert pn._seq == s
    pn.inc("c", "a", 1, seq=s + 1)  # next valid seq works
    assert pn.value("c", seq=0).value == 2


def test_failed_mutation_consumes_seq():
    pn, s = fresh()
    with pytest.raises(BadDeltaError):
        pn.inc("c", "a", -5, seq=s)  # burns s
    with pytest.raises(SeqOrderError):
        pn.inc("c", "a", 1, seq=s)
    rejected = [e for e in pn.audit_log() if e["kind"] == "pn-counter.rejected"]
    assert rejected


def test_audit_shapes_and_banned_keys():
    pn, s = fresh()
    pn.inc("c", "a", 2, seq=s)
    kinds = [e["kind"] for e in pn.audit_log()]
    assert KIND_CREATED in kinds and KIND_INCREMENTED in kinds
    for e in pn.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        for banned in ("inc_map", "dec_map", "remote_inc", "remote_dec", "contributions"):
            assert banned not in e["detail"]
    with pytest.raises(AuditKindError):
        pn_counter_audit_event("bogus", seq=1)
    with pytest.raises(AuditKindError):
        pn_counter_audit_event(KIND_MERGED, seq=1, inc_map={"a": 1})


def test_contributions_roundtrip_into_merge():
    pn, s = fresh()
    pn.inc("c", "a", 6, seq=s)
    pn.dec("c", "a", 1, seq=s + 1)
    inc_items, dec_items = pn.contributions("c", seq=0)
    other = PNCounter()
    other.create("c", seq=1)
    m = other.merge("c", dict(inc_items), dict(dec_items), seq=2)
    assert m.value == 5


def test_as_dict_snapshot():
    pn, s = fresh()
    pn.inc("c", "a", 4, seq=s)
    snap = pn.as_dict()
    assert snap["module_version"] == PN_COUNTER_VERSION
    assert snap["counters"]["c"]["value"] == 4
