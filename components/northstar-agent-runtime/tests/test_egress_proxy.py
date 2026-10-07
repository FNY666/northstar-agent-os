"""Tests for egress_proxy: 15 cases."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import egress_proxy
from egress_proxy import (
    AUDIT_SCHEMA,
    EGRESS_PROXY_SCHEMA,
    EGRESS_PROXY_VERSION,
    KIND_CIDR,
    KIND_DOMAIN,
    KIND_HOST,
    AllowEntry,
    BadEntryError,
    BadRequestError,
    DuplicateEntryError,
    DuplicateRequestError,
    EgressProxy,
    EgressProxyError,
    FilterDecision,
    SeqOrderError,
    UnknownEntryError,
    egress_proxy_audit_event,
)


def fresh():
    return EgressProxy()


def host_entry(proxy, entry_id="e1", target="example.com", seq=1):
    return proxy.allow(entry_id, target, KIND_HOST, seq)


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert EGRESS_PROXY_VERSION == "egress-proxy.v1"
    assert EGRESS_PROXY_SCHEMA == "northstar.egress-proxy.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    proxy = fresh()
    entry = host_entry(proxy)
    assert entry.verify()
    decision = proxy.filter("r1", "example.com", 2)
    assert decision.verify()
    removal = proxy.remove("e1", 3, "done")
    assert removal.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "egress_proxy.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "ipaddress", "threading", "dataclasses", "typing",
        "json", "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_main_runs():
    import subprocess
    path = os.path.join(os.path.dirname(__file__), "..", "egress_proxy.py")
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, check=True,
    )
    assert "egress-proxy OK" in out.stdout


# 4 ---------------------------------------------------------------------


def test_allow_roundtrip_and_views():
    proxy = fresh()
    entry = host_entry(proxy)
    assert entry.entry_id == "e1"
    assert entry.kind == KIND_HOST
    assert entry.target == "example.com"
    assert entry.seq == 1
    assert not entry.removed
    assert proxy.allow_entry("e1") == entry
    assert proxy.allow_ids() == ("e1",)
    assert proxy.active_ids() == ("e1",)


# 5 ---------------------------------------------------------------------


def test_allow_kinds():
    proxy = fresh()
    proxy.allow("e1", ".internal.example.com", KIND_DOMAIN, 1)
    proxy.allow("e2", "10.0.0.0/8", KIND_CIDR, 2)
    proxy.allow("e3", "api.example.com:8443", KIND_HOST, 3)
    assert proxy.allow_ids() == ("e1", "e2", "e3")
    e3 = proxy.allow_entry("e3")
    assert e3.target == "api.example.com:8443"


# 6 ---------------------------------------------------------------------


def test_allow_bad_inputs():
    proxy = fresh()
    bad = [
        ("", "example.com", KIND_HOST),
        ("e1", "", KIND_HOST),
        ("e1", "example.com", "bogus"),
        ("e1", "not a cidr", KIND_CIDR),
        ("e1", "internal.example.com", KIND_DOMAIN),  # missing leading dot
        ("e1", "example.com:99999", KIND_HOST),  # port out of range
        ("e1", "http://example.com/x", KIND_HOST),  # whitespace-free but ok?
    ]
    for i, (eid, target, kind) in enumerate(bad, start=1):
        try:
            proxy.allow(eid, target, kind, i)
        except EgressProxyError:
            continue
        raise AssertionError(f"bad input accepted: {(eid, target, kind)}")


# 7 ---------------------------------------------------------------------


def test_allow_duplicate_refused():
    proxy = fresh()
    host_entry(proxy)
    try:
        host_entry(proxy, seq=2)
    except DuplicateEntryError:
        pass
    else:
        raise AssertionError("duplicate entry accepted")


# 8 ---------------------------------------------------------------------


def test_remove_lifecycle():
    proxy = fresh()
    host_entry(proxy)
    removal = proxy.remove("e1", 2, "decommissioned")
    assert removal.entry_id == "e1"
    assert removal.reason == "decommissioned"
    entry = proxy.allow_entry("e1")
    assert entry.removed
    assert proxy.active_ids() == ()
    assert proxy.allow_ids() == ("e1",)


# 9 ---------------------------------------------------------------------


def test_remove_unknown_and_double():
    proxy = fresh()
    try:
        proxy.remove("nope", 1, "x")
    except UnknownEntryError:
        pass
    else:
        raise AssertionError("unknown removal accepted")
    host_entry(proxy, seq=2)
    proxy.remove("e1", 3, "x")
    try:
        proxy.remove("e1", 4, "x")
    except EgressProxyError:
        pass
    else:
        raise AssertionError("double removal accepted")


# 10 ---------------------------------------------------------------------


def test_filter_allow_and_deny():
    proxy = fresh()
    host_entry(proxy)
    ok = proxy.filter("r1", "example.com", 2)
    assert ok.verdict == "allow"
    assert ok.matched_entry_id == "e1"
    no = proxy.filter("r2", "evil.example.net", 3)
    assert no.verdict == "deny"
    assert no.matched_entry_id is None


# 11 ---------------------------------------------------------------------


def test_filter_domain_and_cidr_match():
    proxy = fresh()
    proxy.allow("e1", ".internal.example.com", KIND_DOMAIN, 1)
    proxy.allow("e2", "10.0.0.0/8", KIND_CIDR, 2)
    sub = proxy.filter("r1", "db.internal.example.com", 3)
    assert sub.verdict == "allow"
    bare = proxy.filter("r2", "internal.example.com", 4)
    assert bare.verdict == "allow"
    ipr = proxy.filter("r3", "10.1.2.3", 5)
    assert ipr.verdict == "allow"
    outside = proxy.filter("r4", "11.0.0.1", 6)
    assert outside.verdict == "deny"


# 12 ---------------------------------------------------------------------


def test_filter_bad_inputs():
    proxy = fresh()
    host_entry(proxy)
    cases = [
        ("", "example.com", "GET"),
        ("r1", "", "GET"),
        ("r1", "https://example.com/x", "GET"),  # scheme refused
        ("r1", "exa mple.com", "GET"),  # whitespace refused
        ("r1", "example.com", "BREW"),  # bad method
    ]
    for i, (rid, dest, method) in enumerate(cases, start=2):
        try:
            proxy.filter(rid, dest, i, method)
        except (BadRequestError, EgressProxyError):
            continue
        raise AssertionError(f"bad filter accepted: {(rid, dest, method)}")
    # duplicate request id
    proxy.filter("r9", "example.com", 20)
    try:
        proxy.filter("r9", "example.com", 21)
    except DuplicateRequestError:
        pass
    else:
        raise AssertionError("duplicate request accepted")


# 13 ---------------------------------------------------------------------


def test_seq_order_and_failed_consumes_seq():
    proxy = fresh()
    host_entry(proxy)
    try:
        proxy.filter("r1", "example.com", 1)  # rewind
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind accepted")
    try:
        proxy.allow("", "example.com", KIND_HOST, True)  # bool refused
    except SeqOrderError:
        pass
    else:
        raise AssertionError("bool seq accepted")
    # failed mutation consumed its seq: next valid seq must be > 2
    host_entry(proxy, entry_id="e2", seq=3)
    assert proxy.allow_ids() == ("e1", "e2")


# 14 ---------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    proxy = fresh()
    host_entry(proxy)
    proxy.filter("r1", "example.com", 2)
    log = proxy.audit_log()
    kinds = {e["kind"] for e in log}
    assert "egress.allow-added" in kinds
    assert "egress.filtered" in kinds
    for event in log:
        assert event["schema"] == "audit.ndjson/1"
        assert "destination" not in event["detail"]
        assert "target" not in event["detail"]
    ev = egress_proxy_audit_event(
        "egress.filtered", {"request_id": "r1", "verdict": "allow"}, 9,
    )
    assert ev["kind"] == "egress.filtered"
    try:
        egress_proxy_audit_event(
            "egress.filtered", {"destination": "x"}, 10,
        )
    except EgressProxyError:
        pass
    else:
        raise AssertionError("banned audit key accepted")
    try:
        egress_proxy_audit_event("nope", {}, 11)
    except EgressProxyError:
        pass
    else:
        raise AssertionError("bad audit kind accepted")


# 15 ---------------------------------------------------------------------


def test_views_decisions_for_and_stats():
    proxy = fresh()
    host_entry(proxy)
    proxy.filter("r1", "example.com", 2)
    proxy.filter("r2", "evil.example.net", 3)
    proxy.filter("r3", "example.com", 4, method="POST")
    mine = proxy.decisions_for("example.com")
    assert [d.request_id for d in mine] == ["r1", "r3"]
    assert mine[1].method == "POST"
    assert proxy.decision("r2").verdict == "deny"
    stats = proxy.stats()
    assert stats == {
        "entries": 1, "active": 1, "removed": 0,
        "decisions": 3, "allowed": 2, "denied": 1,
    }
