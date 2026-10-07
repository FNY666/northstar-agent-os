"""Tests for twopset.py (Two-Phase Set)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import twopset
from twopset import (
    TWOPSET_SCHEMA,
    TWOPSET_VERSION,
    TwoPSet,
    TwoPSetError,
    BadElementError,
    BadMergeError,
    SeqOrderError,
    twopset_audit_event,
)


MODULE_PATH = Path(twopset.__file__)
STDLIB_ALLOW = {
    "hashlib", "hmac", "threading", "dataclasses", "typing",
    "json", "canonical_json", "_cj", "__future__",
}


def test_version_and_schema_pins():
    assert TWOPSET_VERSION == "twopset.v1"
    assert TWOPSET_SCHEMA == "northstar.twopset.v1"
    assert twopset.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, f"non-stdlib imports: {imports - STDLIB_ALLOW}"


def test_add_roundtrip():
    s = TwoPSet()
    rec = s.add("alpha", 1)
    assert s.contains("alpha", 1)
    assert s.members(1) == ("alpha",)
    assert rec.verify()
    assert rec.schema == TWOPSET_SCHEMA
    assert rec.redundant is False
    assert rec.element_digest.startswith("sha256:")


def test_add_bad_inputs():
    s = TwoPSet()
    for bad in (True, False, None, 1.5, float("nan"), ["x"], {"x": 1}, "", 2**60):
        with pytest.raises(BadElementError):
            s.add(bad, 1)
        s = TwoPSet()  # fresh: failed add must not corrupt, but burns seq below


def test_add_int_and_str_distinct():
    s = TwoPSet()
    s.add(1, 1)
    s.add("1", 2)
    assert s.contains(1, 2)
    assert s.contains("1", 2)
    assert len(s.members(2)) == 2


def test_duplicate_add_is_redundant_not_error():
    s = TwoPSet()
    s.add("x", 1)
    rec = s.add("x", 2)
    assert rec.redundant is True
    assert s.members(2) == ("x",)
    stats = s.stats(2)
    assert stats.members == 1 and stats.added == 1 and stats.add_records == 2


def test_remove_roundtrip():
    s = TwoPSet()
    s.add("gone", 1)
    rec = s.remove("gone", 2)
    assert rec.verify()
    assert rec.was_member is True
    assert not s.contains("gone", 2)
    assert s.members(2) == ()


def test_remove_never_added_is_tombstone():
    s = TwoPSet()
    rec = s.remove("phantom", 1)
    assert rec.was_member is False
    t = TwoPSet()
    t.add("phantom", 1)
    t.merge(s, 2)
    # Convergent tombstone: the phantom never becomes a member after merge.
    assert not t.contains("phantom", 2)


def test_two_phase_remove_then_add_never_resurrects():
    s = TwoPSet()
    s.add("dead", 1)
    s.remove("dead", 2)
    s.add("dead", 3)
    assert not s.contains("dead", 3)
    assert s.members(3) == ()


def test_remove_bad_inputs():
    s = TwoPSet()
    for bad in (True, None, 2.5, b"bytes", ()):
        with pytest.raises(BadElementError):
            s.remove(bad, 1)
        s = TwoPSet()


def test_seq_ordering():
    s = TwoPSet()
    s.add("a", 1)
    for bad_seq in (1, 0, -3, True, 1.0, "2", None):
        with pytest.raises((SeqOrderError, TwoPSetError)):
            s.add("b", bad_seq)


def test_failed_mutation_consumes_seq():
    s = TwoPSet()
    s.add("ok", 1)
    with pytest.raises(BadElementError):
        s.add(None, 2)
    with pytest.raises(SeqOrderError):
        s.add("late", 2)  # seq 2 was burned by the failed add
    s.add("late", 3)
    assert s.contains("late", 3)


def test_merge_union():
    a = TwoPSet(set_id="a")
    b = TwoPSet(set_id="b")
    a.add("one", 1)
    a.add("two", 2)
    a.remove("two", 3)
    b.add("three", 1)
    b.add("four", 2)
    b.remove("four", 3)
    rec = a.merge(b, 4)
    assert rec.verify()
    # "four" is the only tombstone new to a ("two" was already tombstoned).
    assert rec.added_imported == 2 and rec.removed_imported == 1
    assert set(a.members(4)) == {"one", "three"}
    # Merge record pins totals.
    assert rec.added_total == 4 and rec.removed_total == 2


def test_merge_converges_regardless_of_order():
    def pair():
        x, y = TwoPSet(set_id="x"), TwoPSet(set_id="y")
        x.add("p", 1); x.remove("q", 2)
        y.add("q", 1); y.remove("p", 2); y.add("r", 3)
        return x, y
    x1, y1 = pair()
    x1.merge(y1, 10)
    x2, y2 = pair()
    y2.merge(x2, 10)
    assert set(x1.members(10)) == set(y2.members(10)) == {"r"}


def test_merge_idempotent_and_self_merge():
    a = TwoPSet(set_id="a")
    b = TwoPSet(set_id="b")
    a.add("k", 1)
    b.add("j", 1)
    a.merge(b, 2)
    before = set(a.members(2))
    a.merge(b, 3)
    assert set(a.members(3)) == before
    a.merge(a, 4)  # self-merge is a trivially convergent no-op
    assert set(a.members(4)) == before


def test_merge_bad_source():
    s = TwoPSet()
    for bad in ("nope", 42, None, ["x"], {"_added": {}}):
        with pytest.raises(BadMergeError):
            s.merge(bad, 1)
        s = TwoPSet()
    # Rejection was audited.
    t = TwoPSet()
    with pytest.raises(BadMergeError):
        t.merge(object(), 7)
    rows = t.audit_log()
    assert rows[-1]["kind"] == "twopset.rejected"


def test_audit_shapes_and_element_leak_ban():
    s = TwoPSet()
    s.add("secret-value", 1)
    s.remove("secret-value", 2)
    s.merge(TwoPSet(set_id="peer"), 3)
    rows = s.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds == [
        "twopset.element-added",
        "twopset.element-removed",
        "twopset.merged",
    ]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "twopset"
        text = repr(row)
        assert "secret-value" not in text
        assert "element_digest" in row["detail"] or "other_set_id" in row["detail"]
    with pytest.raises(TwoPSetError):
        twopset_audit_event("twopset.element-added", 9, element="raw")
    with pytest.raises(TwoPSetError):
        twopset_audit_event("twopset.bogus-kind", 9)


def test_records_verify_and_tamper():
    s = TwoPSet(seed="pepper")
    arec = s.add("e", 1)
    rrec = s.remove("f", 2)
    assert arec.verify("pepper") and rrec.verify("pepper")
    assert not arec.verify("wrong-seed")
    assert not rrec.verify("wrong-seed")


def test_stats_and_read_does_not_consume_seq():
    s = TwoPSet(set_id="stats")
    s.add("m", 1)
    st = s.stats(99)
    assert st.set_id == "stats" and st.members == 1 and st.audit_rows == 1
    # Reads validate seq shape, consume nothing, write no audit rows.
    s.members(5)
    s.contains("m", 5)
    assert len(s.audit_log()) == 1
    with pytest.raises(SeqOrderError):
        s.members(-1)
    with pytest.raises(BadElementError):
        s.contains(None, 5)


def test_thread_concurrency_smoke():
    s = TwoPSet()
    errors = []

    def worker(n):
        try:
            base = n * 1000
            for i in range(25):
                s.add(f"w{n}-{i}", base + i + 1)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    st = s.stats(10**6)
    assert st.members == 8 * 25


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "twopset OK: add, remove, merge, pins, audit" in proc.stdout
