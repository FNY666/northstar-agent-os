"""Tests for read_through_cache: load/fill/evict, TTL, loader failure as data."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from read_through_cache import (
    AUDIT_SCHEMA,
    READ_THROUGH_CACHE_VERSION,
    SCHEMA_PIN,
    BadCapacityError,
    BadKeyError,
    BadLoaderError,
    BadTTLError,
    BadValueError,
    ReadThroughCache,
    ReadThroughCacheError,
    SeqOrderError,
    read_through_cache_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "read_through_cache.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "dataclasses",
    "typing",
    "__future__",
}


def loader_factory(store, calls):
    def loader(key):
        calls.append(key)
        if key not in store:
            raise KeyError(key)
        return store[key]

    return loader


def fresh(**kw):
    calls = []
    store = kw.pop("store", {"a": "va", "b": "vb", "c": "vc"})
    c = ReadThroughCache("rt", 4, loader=loader_factory(store, calls), **kw)
    return c, calls


# --- pins ------------------------------------------------------------------


def test_version_pins():
    assert READ_THROUGH_CACHE_VERSION == "read-through-cache.v1"
    assert SCHEMA_PIN == "northstar.read-through-cache.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_record_pins():
    c, _ = fresh()
    rec = c.fill("k", "v", seq=1)
    assert rec.version == READ_THROUGH_CACHE_VERSION
    d = rec.as_dict()
    assert d["schema"] == SCHEMA_PIN
    assert d["key_digest"].startswith("sha256:")
    assert c.stats().as_dict()["schema"] == SCHEMA_PIN


def test_stdlib_only_ast():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW


# --- load: the read path -----------------------------------------------------


def test_load_miss_calls_loader_and_fills():
    c, calls = fresh()
    out = c.load("a", seq=1)
    assert calls == ["a"]
    assert out.hit is False
    assert out.loaded is True
    assert out.source == "loader"
    assert out.value == "va"
    assert out.error is None
    assert c.contains("a")


def test_load_hit_does_not_call_loader():
    c, calls = fresh()
    c.load("a", seq=1)
    out = c.load("a", seq=2)
    assert calls == ["a"], calls  # loader not called again
    assert out.hit is True
    assert out.loaded is False
    assert out.source == "cache"
    assert out.value == "va"
    d = out.as_dict()
    assert d["value"] == "va" and d["error"] is None


def test_load_miss_outcome_carries_no_value():
    c, calls = fresh(store={})
    out = c.load("nope", seq=1)
    assert out.hit is False and out.loaded is False
    assert out.source == "miss"
    assert out.as_dict()["value"] is None
    assert not c.contains("nope")


def test_loader_exception_is_data_never_raised():
    def bad(key):
        raise RuntimeError("store down")

    c = ReadThroughCache("rt", 2, loader=bad)
    out = c.load("x", seq=1)  # must not raise
    assert out.hit is False and out.loaded is False
    assert out.source == "miss"
    assert out.error == "RuntimeError"
    assert not c.contains("x")
    assert c.stats().load_failures == 1
    assert c.stats().misses == 1 and c.stats().loads == 0


def test_loader_returning_none_is_miss():
    c = ReadThroughCache("rt", 2, loader=lambda k: None)
    out = c.load("x", seq=1)
    assert out.loaded is False and out.error == "LoaderReturnedNone"
    assert not c.contains("x")


def test_default_loader_simulates_empty_store():
    c = ReadThroughCache("rt", 2)
    out = c.load("z", seq=1)
    assert out.hit is False and out.loaded is False
    assert out.error == "LoaderMissError"


# --- fill / evict ------------------------------------------------------------


def test_fill_overwrite_and_explicit_evict():
    c, _ = fresh()
    c.fill("k", "v1", seq=1)
    rec = c.fill("k", "v2", seq=2)
    assert rec.evicted_key_digest is None
    assert c.load("k", seq=3).value == "v2"
    assert c.evict("k", seq=4) is True
    assert c.evict("k", seq=5) is False
    assert not c.contains("k")


def test_lru_eviction_is_deterministic():
    c, _ = fresh()
    c._capacity  # 4; use a smaller cache instead
    small = ReadThroughCache("s", 2, loader=loader_factory({}, []))
    small.fill("a", 1, seq=1)
    small.fill("b", 2, seq=2)
    small.load("a", seq=3)  # refresh "a"; "b" is now LRU
    rec = small.fill("c", 3, seq=4)
    assert rec.evicted_key_digest is not None
    assert not small.contains("b")
    assert small.contains("a") and small.contains("c")
    assert small.stats().evictions == 1


def test_ttl_stale_entry_reloads_through_loader():
    c, calls = fresh(ttl_seqs=3)
    c.load("a", seq=10)  # filled_at=10
    assert c.load("a", seq=12).hit is True  # age 2 < 3: fresh
    out = c.load("a", seq=13)  # age 3 >= 3: stale -> reload
    assert out.loaded is True and out.value == "va"
    assert calls == ["a", "a"], calls
    reasons = [r.reason for r in c.eviction_log()]
    assert "expired" in reasons


def test_no_ttl_by_default():
    c, calls = fresh()
    c.load("a", seq=1)
    assert c.load("a", seq=10_000).hit is True
    assert calls == ["a"]


# --- validation (fail-closed) ------------------------------------------------


def test_bad_inputs_fail_closed():
    c, _ = fresh()
    for bad in ("", 123, None, True, b"k", "x" * 4097):
        for op in (c.load, c.evict):
            try:
                op(bad, seq=1)
            except BadKeyError:
                pass
            else:
                raise AssertionError(f"key={bad!r} accepted")
        try:
            c.fill(bad, "v", seq=1)
        except BadKeyError:
            pass
        else:
            raise AssertionError(f"fill key={bad!r} accepted")
    try:
        c.fill("k", None, seq=1)
    except BadValueError:
        pass
    else:
        raise AssertionError("None value accepted")
    for bad_cap in (0, -2, True, "4", 2.5, 1_000_001):
        try:
            ReadThroughCache("rt", bad_cap)
        except BadCapacityError:
            pass
        else:
            raise AssertionError(f"capacity={bad_cap!r} accepted")
    for bad_ttl in (-1, True, "3", 1.5):
        try:
            ReadThroughCache("rt", 2, ttl_seqs=bad_ttl)
        except BadTTLError:
            pass
        else:
            raise AssertionError(f"ttl={bad_ttl!r} accepted")
    try:
        ReadThroughCache("rt", 2, loader="not-callable")
    except BadLoaderError:
        pass
    else:
        raise AssertionError("non-callable loader accepted")
    try:
        ReadThroughCache("", 2)
    except ReadThroughCacheError:
        pass
    else:
        raise AssertionError("empty name accepted")


def test_bad_seq_rejected():
    c, _ = fresh()
    for bad in (-1, True, "1", 1.5, None):
        for op in (lambda s: c.load("a", seq=s),
                   lambda s: c.fill("a", "v", seq=s),
                   lambda s: c.evict("a", seq=s)):
            try:
                op(bad)
            except SeqOrderError:
                pass
            else:
                raise AssertionError(f"seq={bad!r} accepted")
        try:
            read_through_cache_audit_event("hit", bad)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"audit seq={bad!r} accepted")


# --- stats / audit -----------------------------------------------------------


def test_stats_counters_and_hit_rate():
    c, calls = fresh()
    assert c.stats().hit_rate is None  # no lookups yet
    c.load("a", seq=1)  # miss + load
    c.load("a", seq=2)  # hit
    c.load("zz", seq=3)  # miss, loader KeyError -> failure
    s = c.stats()
    assert (s.hits, s.misses) == (1, 2)
    assert (s.loads, s.load_failures) == (1, 1)
    assert s.fills == 1
    assert s.hit_rate == 1 / 3
    assert s.size == 1 and s.capacity == 4


def test_audit_shapes_value_ban_and_bad_kind():
    ev = read_through_cache_audit_event(
        "loaded", 7, key_digest="sha256:abc"
    )
    assert ev["schema"] == AUDIT_SCHEMA
    assert ev["kind"] == "read-through-cache.loaded"
    assert ev["module"] == READ_THROUGH_CACHE_VERSION
    assert ev["seq"] == 7
    try:
        read_through_cache_audit_event("bogus", 1)
    except ReadThroughCacheError:
        pass
    else:
        raise AssertionError("bad audit kind accepted")
    try:
        read_through_cache_audit_event("hit", 1, value="raw-bytes")
    except ReadThroughCacheError:
        pass
    else:
        raise AssertionError("raw value leaked into audit")


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, MODULE_PATH],
        capture_output=True, text=True, timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "read-through-cache OK" in r.stdout
