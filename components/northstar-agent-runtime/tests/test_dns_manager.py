"""Tests for dns_manager: simulated authoritative-DNS bookkeeping."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dns_manager import (
    AUDIT_SCHEMA,
    DEFAULT_TTL,
    DNS_MANAGER_SCHEMA,
    DNS_MANAGER_VERSION,
    BadHealthError,
    BadObservationError,
    BadRecordError,
    BadZoneError,
    CnameConflictError,
    DNSManager,
    DNSManagerError,
    DuplicateHealthError,
    DuplicateRecordError,
    DuplicateZoneError,
    KIND_HEALTH_DEFINED,
    KIND_HEALTH_REPORTED,
    KIND_RECORD_CREATED,
    KIND_RECORD_DELETED,
    KIND_REJECTED,
    KIND_ZONE_CREATED,
    RECORD_TYPES,
    RTYPE_A,
    RTYPE_AAAA,
    RTYPE_CNAME,
    RTYPE_MX,
    RTYPE_SRV,
    RTYPE_TXT,
    SeqOrderError,
    UnknownHealthError,
    UnknownRecordError,
    UnknownZoneError,
    dns_manager_audit_event,
)

MODULE_PATH = os.path.join(os.path.dirname(__file__), "..", "dns_manager.py")

_STDLIB_ALLOW = {
    "__future__",
    "canonical_json",
    "dataclasses",
    "hashlib",
    "hmac",
    "ipaddress",
    "json",
    "re",
    "threading",
    "typing",
}


def fresh(seed="t"):
    return DNSManager(seed=seed)


def make_zone(mgr, seq=0, zone_id="z1", domain="example.com"):
    return mgr.zone(zone_id, domain, seq)


# --- pins / stdlib ------------------------------------------------------------


def test_version_pins():
    assert DNS_MANAGER_VERSION == "dns-manager.v1"
    assert DNS_MANAGER_SCHEMA == "northstar.dns-manager.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(RECORD_TYPES) == {
        "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA"
    }


def test_stdlib_only():
    tree = ast.parse(open(MODULE_PATH, encoding="utf-8").read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= _STDLIB_ALLOW, imports - _STDLIB_ALLOW


# --- zones --------------------------------------------------------------------


def test_zone_roundtrip_and_normalization():
    mgr = fresh()
    z = make_zone(mgr, domain="Example.COM.")
    assert z.zone_id == "z1"
    assert z.domain == "example.com"
    assert z.verify(seed="t")
    assert not z.verify(seed="other")
    assert mgr.zone_ids(1) == ("z1",)
    assert mgr.zone_record("z1", 1) is z


def test_zone_bad_domains_and_duplicates():
    mgr = fresh()
    for bad in ["", "   ", "not a domain", "bad..dots", "-lead.com", "trail-.com",
                "x" * 64 + ".com", "nonascii.\u00e9xample"]:
        try:
            mgr.zone("zb", bad, 10)
        except DNSManagerError:
            pass
        else:
            raise AssertionError(f"accepted bad domain: {bad!r}")
    make_zone(mgr, seq=20)
    for fn, exc in [
        (lambda: mgr.zone("z1", "other.com", 21), DuplicateZoneError),
        (lambda: mgr.zone("z2", "example.com", 22), DuplicateZoneError),
    ]:
        try:
            fn()
        except exc:
            pass
        else:
            raise AssertionError("duplicate not refused")
    try:
        mgr.zone_record("nope", 23)
    except UnknownZoneError:
        pass
    else:
        raise AssertionError("unknown zone lookup not refused")


# --- records ------------------------------------------------------------------


def test_record_a_roundtrip():
    mgr = fresh()
    make_zone(mgr)
    r = mgr.record("r1", "z1", "www", RTYPE_A, ["93.184.216.34"], 1)
    assert r.name == "www"
    assert r.ttl == DEFAULT_TTL
    assert r.values == (("93.184.216.34",),)
    assert r.verify(seed="t")
    assert mgr.record_entry("r1", 2) is r
    assert mgr.records_for("z1", 2) == ("r1",)
    assert mgr.record_ids(2) == ("r1",)


def test_record_types_and_values():
    mgr = fresh()
    make_zone(mgr)
    cases = [
        ("ra", RTYPE_A, ["10.0.0.1"]),
        ("ra6", RTYPE_AAAA, ["2001:db8::1"]),
        ("rmx", RTYPE_MX, [(10, "mail.example.com")]),
        ("rtxt", RTYPE_TXT, ["v=spf1 -all"]),
        ("rsrv", RTYPE_SRV, [(0, 5, 443, "web.example.com")]),
    ]
    for i, (rid, rtype, values) in enumerate(cases):
        r = mgr.record(rid, "z1", f"n{i}", rtype, values, i + 1)
        assert r.verify(seed="t"), rid
    assert mgr.record("apex", "z1", "@", RTYPE_A, ["10.0.0.2"], 10).name == "@"


def test_record_bad_inputs():
    mgr = fresh()
    make_zone(mgr)
    bad_cases = [
        ("b1", "noz", "www", RTYPE_A, ["10.0.0.1"], UnknownZoneError),
        ("b2", "z1", "www", "BOGUS", ["10.0.0.1"], BadRecordError),
        ("b3", "z1", "www", RTYPE_A, ["999.1.1.1"], BadRecordError),
        ("b4", "z1", "www", RTYPE_A, ["10.0.0"], BadRecordError),
        ("b5", "z1", "www", RTYPE_AAAA, ["not-ipv6"], BadRecordError),
        ("b6", "z1", "www", RTYPE_A, [], BadRecordError),
        ("b7", "z1", "www", RTYPE_MX, [("x", "h")], BadRecordError),
        ("b8", "z1", "www", RTYPE_MX, [(70000, "h")], BadRecordError),
        ("b9", "z1", "www", RTYPE_SRV, [(0, 0, 80)], BadRecordError),
        ("b10", "z1", "www", RTYPE_TXT, ["x" * 256], BadRecordError),
        ("b11", "z1", "www", RTYPE_CNAME, ["a.com", "b.com"], BadRecordError),
        ("b12", "z1", "bad name", RTYPE_A, ["10.0.0.1"], BadRecordError),
    ]
    for i, (rid, zid, name, rtype, values, exc) in enumerate(bad_cases):
        try:
            mgr.record(rid, zid, name, rtype, values, 100 + i)
        except exc:
            pass
        else:
            raise AssertionError(f"not refused: {rid}")
    try:
        mgr.record("b13", "z1", "www", RTYPE_A, ["10.0.0.1"], 200, ttl=0)
    except BadRecordError:
        pass
    else:
        raise AssertionError("bad ttl not refused")
    try:
        mgr.record("b14", "z1", "www", RTYPE_A, ["10.0.0.1"], 201, ttl=True)
    except BadRecordError:
        pass
    else:
        raise AssertionError("bool ttl not refused")


def test_cname_exclusivity():
    mgr = fresh()
    make_zone(mgr)
    mgr.record("c1", "z1", "alias", RTYPE_CNAME, ["target.example.com"], 1)
    try:
        mgr.record("c2", "z1", "alias", RTYPE_A, ["10.0.0.1"], 2)
    except CnameConflictError:
        pass
    else:
        raise AssertionError("A-after-CNAME not refused")
    mgr.record("c3", "z1", "plain", RTYPE_A, ["10.0.0.1"], 3)
    try:
        mgr.record("c4", "z1", "plain", RTYPE_CNAME, ["target.example.com"], 4)
    except CnameConflictError:
        pass
    else:
        raise AssertionError("CNAME-after-A not refused")


def test_delete_record_terminal():
    mgr = fresh()
    make_zone(mgr)
    mgr.record("d1", "z1", "www", RTYPE_A, ["10.0.0.1"], 1)
    d = mgr.delete_record("d1", 2)
    assert d.verify(seed="t")
    assert mgr.record_ids(3) == ()
    try:
        mgr.record_entry("d1", 3)
    except UnknownRecordError:
        pass
    else:
        raise AssertionError("deleted record still visible")
    try:
        mgr.delete_record("d1", 4)
    except UnknownRecordError:
        pass
    else:
        raise AssertionError("double delete not refused")
    try:
        mgr.delete_record("ghost", 5)
    except UnknownRecordError:
        pass
    else:
        raise AssertionError("unknown delete not refused")
    # Ids are never recycled.
    try:
        mgr.record("d1", "z1", "www", RTYPE_A, ["10.0.0.1"], 6)
    except DuplicateRecordError:
        pass
    else:
        raise AssertionError("recycled record id accepted")


# --- health -------------------------------------------------------------------


def test_health_define_report_status():
    mgr = fresh()
    h = mgr.health("h1", "93.184.216.34", 0)
    assert h.target == "93.184.216.34" and h.verify(seed="t")
    assert mgr.health_status("h1", 1) == "unknown"
    o1 = mgr.report("h1", True, 2)
    assert o1.verify(seed="t")
    assert mgr.health_status("h1", 3) == "healthy"
    o2 = mgr.report("h1", False, 4)
    assert o2.prev_digest == o1.digest
    assert o2.verify(seed="t")
    assert mgr.health_status("h1", 5) == "unhealthy"


def test_health_bad_inputs():
    mgr = fresh()
    try:
        mgr.health("h1", "not an ip or host!!!", 0)
    except DNSManagerError:
        pass
    else:
        raise AssertionError("bad health target accepted")
    mgr.health("h1", "web.example.com", 1)
    try:
        mgr.health("h1", "other.example.com", 2)
    except DuplicateHealthError:
        pass
    else:
        raise AssertionError("duplicate health id accepted")
    try:
        mgr.report("ghost", True, 3)
    except UnknownHealthError:
        pass
    else:
        raise AssertionError("report to unknown check accepted")
    for i, bad in enumerate(["yes", 1, None]):
        try:
            mgr.report("h1", bad, 4 + i)
        except BadObservationError:
            pass
        else:
            raise AssertionError(f"non-bool observation accepted: {bad!r}")
    try:
        mgr.health_status("ghost", 5)
    except UnknownHealthError:
        pass
    else:
        raise AssertionError("status of unknown check accepted")


# --- seq discipline -------------------------------------------------------------


def test_seq_order_and_failed_mutation_consumes_seq():
    mgr = fresh()
    make_zone(mgr, seq=0)
    try:
        mgr.zone("z2", "other.com", 0)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq rewind not refused")
    for bad_seq in [True, -1, 1.5, "2"]:
        try:
            mgr.zone("z3", "x.com", bad_seq)
        except DNSManagerError:
            pass
        else:
            raise AssertionError(f"bad seq accepted: {bad_seq!r}")
    # Failed mutation consumed seq 1 (duplicate zone): the next call
    # with seq 1 must fail with SeqOrderError even though it is new.
    try:
        mgr.zone("z1", "other.com", 1)
    except DuplicateZoneError:
        pass
    try:
        mgr.zone("z2", "ok.com", 1)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("seq not consumed by failed mutation")
    mgr.zone("z2", "ok.com", 2)  # works after the failed seq 1


# --- audit ----------------------------------------------------------------------


def test_audit_shapes_and_banned_keys():
    mgr = fresh()
    make_zone(mgr)
    mgr.record("r1", "z1", "www", RTYPE_A, ["10.0.0.1"], 1)
    log = mgr.audit_log(2)
    kinds = [e["kind"] for e in log]
    assert KIND_ZONE_CREATED in kinds and KIND_RECORD_CREATED in kinds
    for e in log:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "dns_manager"
        assert "values" not in e["detail"] and "target" not in e["detail"]
    try:
        dns_manager_audit_event("dns.nope", 0)
    except DNSManagerError:
        pass
    else:
        raise AssertionError("bad audit kind accepted")
    try:
        dns_manager_audit_event(KIND_ZONE_CREATED, 0, values=["x"])
    except DNSManagerError:
        pass
    else:
        raise AssertionError("banned audit key accepted")
    # Cross-instance digest determinism.
    a, b = DNSManager(seed="same"), DNSManager(seed="same")
    a.zone("z", "example.com", 0)
    b.zone("z", "example.com", 0)
    assert a.zone_record("z", 1).digest == b.zone_record("z", 1).digest


# --- main -----------------------------------------------------------------------


def test_health_ipv6_target_and_view_edges():
    mgr = fresh()
    h = mgr.health("h6", "2001:db8::1", 0)
    assert h.target == "2001:db8::1"
    assert h.verify(seed="t")
    try:
        mgr.records_for("nozone", 1)
    except UnknownZoneError:
        pass
    else:
        raise AssertionError("records_for unknown zone accepted")
    make_zone(mgr, seq=1)
    assert mgr.records_for("z1", 2) == ()
    try:
        mgr.record_entry("ghost", 2)
    except UnknownRecordError:
        pass
    else:
        raise AssertionError("record_entry unknown accepted")


def test_main_selfcheck():
    import subprocess

    out = subprocess.run(
        [sys.executable, MODULE_PATH], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    assert "dns-manager OK" in out.stdout
