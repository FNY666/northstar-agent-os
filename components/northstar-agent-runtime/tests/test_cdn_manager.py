"""Tests for cdn_manager: purge/prefetch bookkeeping. 17 tests."""

import ast
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cdn_manager import (  # noqa: E402
    AlreadyCompletedError,
    AuditKindError,
    BadTargetError,
    BadURLError,
    BadZoneError,
    CDN_MANAGER_SCHEMA,
    CDN_MANAGER_VERSION,
    CDNManager,
    CDNManagerError,
    DuplicateZoneError,
    MaxAttemptsError,
    SeqOrderError,
    UnknownPrefetchError,
    UnknownPurgeError,
    UnknownZoneError,
    cdn_manager_audit_event,
)


@pytest.fixture()
def mgr():
    return CDNManager(seed="t")


@pytest.fixture()
def zoned(mgr):
    mgr.register_zone("z1", 1)
    return mgr


def test_pins():
    assert CDN_MANAGER_VERSION == "cdn-manager.v1"
    assert CDN_MANAGER_SCHEMA == "northstar.cdn-manager.v1"


def test_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "cdn_manager.py")
    tree = ast.parse(open(path).read())
    allowed = {
        "ast", "hashlib", "threading", "dataclasses", "typing",
        "__future__", "json", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_register_roundtrip(mgr):
    z = mgr.register_zone("z1", 1)
    assert z.zone_id == "z1" and z.seq == 1
    assert z.verify()
    assert mgr.zone_ids() == ("z1",)


def test_register_duplicate(mgr):
    mgr.register_zone("z1", 1)
    with pytest.raises(DuplicateZoneError):
        mgr.register_zone("z1", 2)


def test_register_bad_id(mgr):
    for bad in ("", "   ", None, 42, True):
        with pytest.raises((BadZoneError, CDNManagerError)):
            mgr.register_zone(bad, 1 if bad != "" else 2)


def test_purge_happy(zoned):
    p = zoned.purge("z1", "/assets/app.js", 2)
    assert p.status == "completed" and p.attempt == 1
    assert p.purge_id == "pur-1" and p.prev_purge_id == ""
    assert p.verify()
    assert zoned.purge_record("pur-1").verify()


def test_purge_wildcard(zoned):
    p = zoned.purge("z1", "*", 2)
    assert p.status == "completed" and p.verify()


def test_purge_unknown_zone(mgr):
    with pytest.raises(UnknownZoneError):
        mgr.purge("nope", "/x", 1)


def test_purge_bad_targets(zoned):
    for i, bad in enumerate(("no-slash", "", "/has space", "x" * 3000)):
        with pytest.raises(BadTargetError):
            zoned.purge("z1", bad, 2 + i)  # fresh seq: refusals burn theirs


def test_purge_fail_as_data():
    m = CDNManager(seed="t", edge=lambda _z, _t: False)
    m.register_zone("z1", 1)
    p = m.purge("z1", "/x", 2)
    assert p.status == "failed"  # data, not an exception
    assert p.verify()


def test_purge_raising_edge_counts_as_failure():
    def boom(_z, _t):
        raise RuntimeError("edge down")

    m = CDNManager(seed="t", edge=boom)
    m.register_zone("z1", 1)
    assert m.purge("z1", "/x", 2).status == "failed"


def test_retry_chain():
    m = CDNManager(seed="t", edge=lambda _z, _t: False)
    m.register_zone("z1", 1)
    p1 = m.purge("z1", "/x", 2)
    p2 = m.retry_purge(p1.purge_id, 3)
    assert p2.attempt == 2 and p2.prev_purge_id == p1.purge_id
    assert p2.status == "failed" and p2.verify()
    assert m.purges_for("z1") == (p1.purge_id, p2.purge_id)


def test_retry_completed_refused(zoned):
    p = zoned.purge("z1", "/x", 2)
    with pytest.raises(AlreadyCompletedError):
        zoned.retry_purge(p.purge_id, 3)


def test_retry_max_attempts():
    m = CDNManager(seed="t", edge=lambda _z, _t: False)
    m.register_zone("z1", 1)
    p = m.purge("z1", "/x", 2)
    for i in range(4):
        p = m.retry_purge(p.purge_id, 3 + i)
    assert p.attempt == 5
    with pytest.raises(MaxAttemptsError):
        m.retry_purge(p.purge_id, 7)
    with pytest.raises(UnknownPurgeError):
        m.retry_purge("pur-999", 8)


def test_prefetch_happy(zoned):
    b = zoned.prefetch(
        "z1", ["https://cdn.example.com/a.js", "https://cdn.example.com/b.css"], 2
    )
    assert b.prefetch_id == "prf-1"
    assert [i.status for i in b.items] == ["completed", "completed"]
    assert b.verify() and all(i.verify() for i in b.items)
    assert zoned.prefetch_record("prf-1").verify()


def test_prefetch_mixed_outcomes():
    m = CDNManager(seed="t", warmer=lambda _z, u: "ok" in u)
    m.register_zone("z1", 1)
    b = m.prefetch(
        "z1",
        ["https://cdn.example.com/ok.js", "https://cdn.example.com/bad.js"],
        2,
    )
    assert [i.status for i in b.items] == ["completed", "failed"]
    with pytest.raises(UnknownPrefetchError):
        m.prefetch_record("prf-999")


def test_prefetch_bad_urls(zoned):
    for bad in (["http://insecure/x"], ["not-a-url"], [], "https://x/y"):
        with pytest.raises((BadURLError, CDNManagerError)):
            zoned.prefetch("z1", bad, 2 if bad != ["http://insecure/x"] else 3)


def test_seq_ordering(zoned):
    with pytest.raises(SeqOrderError):
        zoned.purge("z1", "/x", 1)  # rewind
    with pytest.raises(CDNManagerError):
        zoned.purge("z1", "/x", True)  # bool seq
    with pytest.raises(CDNManagerError):
        zoned.stats(-1)


def test_failed_mutation_consumes_seq(zoned):
    with pytest.raises(BadTargetError):
        zoned.purge("z1", "bad", 2)
    with pytest.raises(SeqOrderError):
        zoned.purge("z1", "/ok", 2)  # seq 2 was burned by the refusal
    p = zoned.purge("z1", "/ok", 3)
    assert p.verify()


def test_stats(zoned):
    zoned.purge("z1", "/a", 2)
    m = zoned
    b = m.prefetch("z1", ["https://cdn.example.com/a.js"], 3)
    assert b.verify()
    s = m.stats(4)
    assert s.verify()
    assert (s.zones, s.purges_completed, s.purges_failed) == (1, 1, 0)
    assert (s.prefetches, s.urls_prefetched, s.urls_completed) == (1, 1, 1)
    # stats is a read: seq not consumed
    m.purge("z1", "/b", 4)
    assert m.purge_record("pur-2").verify()


def test_audit_shapes_and_leak_ban(zoned):
    zoned.purge("z1", "/secret/path?token=abc", 2)
    zoned.prefetch("z1", ["https://cdn.example.com/s3cr3t.js"], 3)
    kinds = [e["kind"] for e in zoned.audit_log()]
    assert kinds == ["zone-registered", "purged", "prefetched"]
    blob = str(zoned.audit_log())
    assert "/secret/path" not in blob and "s3cr3t" not in blob
    ev = cdn_manager_audit_event("purged", 9, zone_id="z1", purge_id="pur-1")
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "cdn-manager.v1"
    with pytest.raises(AuditKindError):
        cdn_manager_audit_event("bogus", 1)


def test_concurrency():
    m = CDNManager(seed="t")
    m.register_zone("z1", 0)
    lock = threading.Lock()
    seqs = iter(range(1, 41))

    def worker():
        while True:
            with lock:
                try:
                    s = next(seqs)
                except StopIteration:
                    return
            m.purge("z1", f"/f{s}", s)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.stats(41).purges_completed == 40


def test_main():
    import subprocess

    path = os.path.join(os.path.dirname(__file__), "..", "cdn_manager.py")
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert "cdn-manager OK" in out.stdout
