"""Tests for cache_stampede: 15 cases."""

import ast
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cache_stampede
from cache_stampede import (
    CACHE_STAMPEDE_VERSION,
    CACHE_STAMPEDE_SCHEMA,
    AUDIT_SCHEMA,
    CacheStampede,
    CacheStampedeError,
    BadDigestError,
    BadJitterError,
    BadProtectionError,
    CoalesceDecision,
    DuplicateProtectionError,
    DuplicateRequestError,
    RemovedKeyError,
    SeqOrderError,
    UnknownKeyError,
    UnknownRefreshError,
    WrongLeaderError,
    cache_stampede_audit_event,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def fresh():
    return CacheStampede()


def protected(cs, key_id="k1", ttl_seq=100, seq=1, backend=""):
    return cs.protect(key_id, ttl_seq, seq, backend=backend)


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert CACHE_STAMPEDE_VERSION == "cache-stampede.v1"
    assert CACHE_STAMPEDE_SCHEMA == "northstar.cache-stampede.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    cs = fresh()
    p = protected(cs)
    assert p.verify()
    d = cs.coalesce("k1", "r1", 2)
    assert isinstance(d, CoalesceDecision) and d.verify()
    j = cs.jitter("k1", 3, 10)
    assert j.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "cache_stampede.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_protect_roundtrip_and_bad_inputs():
    cs = fresh()
    p = protected(cs, backend="redis")
    assert p.key_id == "k1" and p.ttl_seq == 100 and p.backend == "redis"
    assert p.entry_seq == 1
    for bad_ttl in (True, 0, -5, "100", 1.5, None):
        cs2 = fresh()
        try:
            cs2.protect("kx", bad_ttl, 1)
        except BadProtectionError:
            pass
        else:
            raise AssertionError(f"ttl {bad_ttl!r} must be refused")
    for bad_key in ("", "   ", None, 123):
        try:
            fresh().protect(bad_key, 10, 1)
        except CacheStampedeError:
            pass
        else:
            raise AssertionError(f"key {bad_key!r} must be refused")


# 4 ---------------------------------------------------------------------


def test_protect_duplicate_refused():
    cs = fresh()
    protected(cs)
    try:
        cs.protect("k1", 50, 2)
    except DuplicateProtectionError:
        pass
    else:
        raise AssertionError("duplicate protection must raise")
    # failed mutation consumed its seq
    try:
        cs.coalesce("k1", "r1", 2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("failed mutation must consume its seq")


# 5 ---------------------------------------------------------------------


def test_coalesce_hit_leader_follower_cycle():
    cs = fresh()
    protected(cs, ttl_seq=100)
    d1 = cs.coalesce("k1", "r1", 2)
    assert d1.role == "hit" and d1.refresh_id == ""
    d2 = cs.coalesce("k1", "r2", 150)     # entry stale -> leader
    assert d2.role == "leader" and d2.refresh_id == "ref-1"
    d3 = cs.coalesce("k1", "r3", 151)     # coalesced follower
    assert d3.role == "follower" and d3.refresh_id == "ref-1"
    assert cs.follower_ids("k1") == ("r3",)
    assert cs.inflight("k1").leader_request_id == "r2"
    done = cs.complete_refresh("k1", "ref-1", GOOD_DIGEST, 152)
    assert done.released_followers == 1 and done.verify()
    assert cs.inflight("k1") is None
    d4 = cs.coalesce("k1", "r4", 153)     # fresh again -> hit
    assert d4.role == "hit"


# 6 ---------------------------------------------------------------------


def test_coalesce_duplicate_request_refused():
    cs = fresh()
    protected(cs)
    cs.coalesce("k1", "r1", 2)
    try:
        cs.coalesce("k1", "r1", 3)
    except DuplicateRequestError:
        pass
    else:
        raise AssertionError("duplicate request id must raise")


# 7 ---------------------------------------------------------------------


def test_coalesce_unknown_key():
    cs = fresh()
    try:
        cs.coalesce("nope", "r1", 1)
    except UnknownKeyError:
        pass
    else:
        raise AssertionError("unknown key must raise")


# 8 ---------------------------------------------------------------------


def test_complete_refresh_bad_digest_and_unknown_refresh():
    cs = fresh()
    protected(cs, ttl_seq=10)
    d = cs.coalesce("k1", "r1", 50)       # stale -> leader
    for bad in ("", "md5:abc", "sha256:" + "zz" * 32, "sha256:abc", None, 42):
        try:
            cs.complete_refresh("k1", d.refresh_id, bad, 51)
        except BadDigestError:
            pass
        else:
            raise AssertionError(f"digest {bad!r} must be refused")
    try:
        cs.complete_refresh("k1", "ref-999", GOOD_DIGEST, 99)
    except UnknownRefreshError:
        pass
    else:
        raise AssertionError("unknown refresh id must raise")
    cs.complete_refresh("k1", d.refresh_id, GOOD_DIGEST, 100)
    try:
        cs.complete_refresh("k1", d.refresh_id, GOOD_DIGEST, 101)
    except UnknownRefreshError:
        pass
    else:
        raise AssertionError("double completion must raise")


# 9 ---------------------------------------------------------------------


def test_jitter_deterministic_and_bounds():
    cs = fresh()
    protected(cs, ttl_seq=100)
    j1 = cs.jitter("k1", 2, 20)
    assert 0 <= j1.stagger <= 20
    # same config on a fresh instance gives the same stagger (deterministic)
    cs2 = fresh()
    protected(cs2)
    j2 = cs2.jitter("k1", 2, 20)
    assert j2.stagger == j1.stagger
    assert cs.jittered_expiry("k1") == 1 + 100 - j1.stagger
    for bad in (True, -1, "20", None):
        try:
            fresh().jitter("k1", 2, bad)
        except (BadJitterError, CacheStampedeError):
            pass
        else:
            raise AssertionError(f"spread {bad!r} must be refused")


# 10 --------------------------------------------------------------------


def test_jitter_spread_too_wide_refused():
    cs = fresh()
    protected(cs, ttl_seq=10)
    try:
        cs.jitter("k1", 2, 10)            # spread must be < ttl
    except BadJitterError:
        pass
    else:
        raise AssertionError("spread >= ttl must raise")
    j = cs.jitter("k1", 3, 9)
    assert j.spread_seq == 9


# 11 --------------------------------------------------------------------


def test_unprotect_terminal_and_id_retirement():
    cs = fresh()
    protected(cs)
    u = cs.unprotect("k1", 2, "hot key retired")
    assert u.verify() and u.reason == "hot key retired"
    try:
        cs.protect("k1", 100, 3)          # id never recycled
    except RemovedKeyError:
        pass
    else:
        raise AssertionError("retired id must never be reused")
    try:
        cs.unprotect("k1", 4)
    except RemovedKeyError:
        pass
    else:
        raise AssertionError("double unprotect must raise")


# 12 --------------------------------------------------------------------


def test_unprotect_with_refresh_in_flight_refused():
    cs = fresh()
    protected(cs, ttl_seq=10)
    cs.coalesce("k1", "r1", 50)           # leader starts refresh
    try:
        cs.unprotect("k1", 51)
    except CacheStampedeError:
        pass
    else:
        raise AssertionError("unprotect during in-flight refresh must raise")


# 13 --------------------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    cs = fresh()
    protected(cs)
    try:
        cs.protect("k2", 10, 1)           # rewind
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind must raise")
    for bad in (True, -1, 1.5, "2", None):
        try:
            fresh().protect("k", 10, bad)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"seq {bad!r} must be refused")


# 14 --------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    cs = fresh()
    protected(cs)
    cs.coalesce("k1", "r1", 2)
    d = cs.coalesce("k1", "r2", 150)
    cs.complete_refresh("k1", d.refresh_id, GOOD_DIGEST, 151)
    cs.jitter("k1", 152, 10)
    kinds = {e["kind"] for e in cs.audit_log()}
    assert "cache-stampede.protected" in kinds
    assert "cache-stampede.refresh-started" in kinds
    assert "cache-stampede.refresh-completed" in kinds
    assert "cache-stampede.jitter-set" in kinds
    for e in cs.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        for banned in ("value", "payload", "body", "value_digest"):
            assert banned not in e["detail"]
    # audit helper: bad kind + banned key refused
    try:
        cache_stampede_audit_event("bogus", {}, 1)
    except CacheStampedeError:
        pass
    else:
        raise AssertionError("bogus audit kind must raise")
    try:
        cache_stampede_audit_event("cache-stampede.protected", {"value": "x"}, 1)
    except CacheStampedeError:
        pass
    else:
        raise AssertionError("banned audit key must raise")


# 15 --------------------------------------------------------------------


def test_views_stats_and_concurrency():
    cs = fresh()
    protected(cs, "k1", ttl_seq=10, seq=1)
    protected(cs, "k2", ttl_seq=50, seq=2)
    assert cs.key_ids() == ("k1", "k2")
    assert cs.stats()["protected"] == 2
    d = cs.coalesce("k1", "r1", 60)       # leader on k1
    assert d.role == "leader"
    assert cs.stats()["in_flight"] == 1
    cs.complete_refresh("k1", d.refresh_id, GOOD_DIGEST, 61)
    assert cs.stats()["in_flight"] == 0
    cs.unprotect("k1", 62)
    assert cs.stats()["protected"] == 1 and cs.stats()["removed"] == 1

    def worker(n):
        try:
            cs.coalesce("k2", f"t{n}", 100 + n)
        except CacheStampedeError:
            pass

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert cs.stats()["protected"] == 1
