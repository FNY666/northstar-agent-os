"""Tests for write_through_cache (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from write_through_cache import (
    SCHEMA_PIN,
    WRITE_THROUGH_CACHE_VERSION,
    ReadOutcome,
    StoreError,
    SyncRecord,
    SeqOrderError,
    WriteRecord,
    WriteThroughCache,
    WriteThroughCacheError,
    _digest_key,
    write_through_cache_audit_event,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "write_through_cache.py"


def test_version_and_schema_pins():
    assert WRITE_THROUGH_CACHE_VERSION == "write-through-cache.v1"
    assert SCHEMA_PIN == "northstar.write-through-cache.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {"hashlib", "dataclasses", "typing", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_write_then_read_hit():
    c = WriteThroughCache("wt", capacity=4)
    rec = c.write("a", 1, seq=1)
    assert isinstance(rec, WriteRecord)
    assert not rec.overwritten
    out = c.read("a", seq=2)
    assert isinstance(out, ReadOutcome)
    assert out.hit and not out.from_store and out.value == 1
    assert c.stats().hits == 1


def test_write_overwrite_flag():
    c = WriteThroughCache("wt", capacity=4)
    c.write("a", 1, seq=1)
    rec = c.write("a", 2, seq=2)
    assert rec.overwritten
    assert c.read("a", seq=3).value == 2


def test_read_miss_is_data_not_raised():
    c = WriteThroughCache("wt", capacity=4)
    out = c.read("ghost", seq=1)
    assert not out.hit and not out.from_store and out.value is None
    assert c.stats().misses == 1


def test_read_through_populates_cache():
    backing = {}

    def sw(k, v):
        backing[k] = v

    def sr(k):
        return (k in backing, backing.get(k))

    writer = WriteThroughCache("writer", capacity=2, store_write=sw, store_read=sr)
    reader = WriteThroughCache("reader", capacity=2, store_write=sw, store_read=sr)
    writer.write("x", "vx", seq=1)
    out = reader.read("x", seq=1)
    assert out.hit and out.from_store and out.value == "vx"
    assert reader.stats().read_throughs == 1
    # Second read is a cache hit now.
    out2 = reader.read("x", seq=2)
    assert out2.hit and not out2.from_store


def test_lru_eviction_on_write():
    c = WriteThroughCache("wt", capacity=2)
    c.write("a", 1, seq=1)
    c.write("b", 2, seq=2)
    c.read("a", seq=3)  # a is now most-recently-used
    c.write("c", 3, seq=4)  # evicts b from the cache
    # Write-through keeps b in the store, so the read is a read-through.
    out = c.read("b", seq=5)
    assert out.hit and out.from_store and out.value == 2
    assert c.read("c", seq=6).value == 3
    # One eviction for the write of c, one for the read-through of b.
    assert c.stats().evictions == 2
    assert c.stats().read_throughs == 1


def test_store_failure_leaves_cache_untouched():
    def boom_write(k, v):
        raise RuntimeError("store down")

    c = WriteThroughCache(
        "flaky", capacity=2, store_write=boom_write, store_read=lambda k: (False, None)
    )
    with pytest.raises(StoreError):
        c.write("z", 9, seq=1)
    assert c.stats().store_failures == 1
    # Cache must not hold a store-less value (all-or-nothing write-through).
    assert not c.read("z", seq=2).hit
    assert c.stats().writes == 0


def test_store_read_failure_raises():
    def boom_read(k):
        raise RuntimeError("store down")

    c = WriteThroughCache(
        "flaky", capacity=2, store_write=lambda k, v: None, store_read=boom_read
    )
    with pytest.raises(StoreError):
        c.read("anything", seq=1)


def test_bad_inputs_fail_closed():
    c = WriteThroughCache("wt", capacity=2)
    with pytest.raises(WriteThroughCacheError):
        c.write("", 1, seq=1)
    with pytest.raises(WriteThroughCacheError):
        c.write(True, 1, seq=2)
    with pytest.raises(WriteThroughCacheError):
        c.write("k", None, seq=3)
    with pytest.raises(WriteThroughCacheError):
        WriteThroughCache("wt", capacity=0)
    with pytest.raises(WriteThroughCacheError):
        WriteThroughCache("", capacity=2)


def test_seq_strictly_increases():
    c = WriteThroughCache("wt", capacity=2)
    c.write("a", 1, seq=5)
    with pytest.raises(SeqOrderError):
        c.write("b", 2, seq=5)  # rewind
    with pytest.raises(SeqOrderError):
        c.read("a", seq=True)  # bool seq
    with pytest.raises(SeqOrderError):
        c.sync(seq=-1)  # negative seq


def test_sync_coherent_then_divergent():
    backing = {}

    def sw(k, v):
        backing[k] = v

    def sr(k):
        return (k in backing, backing.get(k))

    c = WriteThroughCache("wt", capacity=4, store_write=sw, store_read=sr)
    c.write("a", 1, seq=1)
    c.write("b", 2, seq=2)
    synced = c.sync(seq=3)
    assert isinstance(synced, SyncRecord)
    assert synced.coherent and synced.checked == 2
    backing["a"] = "tampered"  # host mutates the store behind the cache
    synced = c.sync(seq=4)
    assert not synced.coherent
    assert synced.divergent_key_digests == (_digest_key("a"),)
    assert synced.state_digest.startswith("sha256:")


def test_audit_shapes_and_value_leak_ban():
    c = WriteThroughCache("wt", capacity=2)
    c.write("a", 1, seq=1)
    kinds = [e["kind"] for e in c.audit_log()]
    assert "write-through-cache.write" in kinds
    for event in c.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert "value" not in event and "values" not in event
    good = write_through_cache_audit_event("write", 1, key_digest=_digest_key("a"))
    assert good["kind"] == "write-through-cache.write"
    with pytest.raises(WriteThroughCacheError):
        write_through_cache_audit_event("nope", 1)
    with pytest.raises(WriteThroughCacheError):
        write_through_cache_audit_event("write", 1, value="raw")


def test_as_dict_records():
    c = WriteThroughCache("wt", capacity=2)
    rec = c.write("a", 1, seq=1)
    d = rec.as_dict()
    assert d["schema"] == SCHEMA_PIN and d["key_digest"] == _digest_key("a")
    out = c.read("a", seq=2)
    assert out.as_dict()["value"] == 1
    missed = c.read("nope", seq=3)
    assert missed.as_dict()["value"] is None
    synced = c.sync(seq=4)
    assert synced.as_dict()["coherent"] is True


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "write-through-cache OK" in proc.stdout
