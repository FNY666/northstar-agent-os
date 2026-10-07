"""Tests for synthetic_monitor: simulated uptime-check bookkeeping."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from synthetic_monitor import (
    ASSERT_CERT_VALID,
    ASSERT_KEYWORD_PRESENT,
    ASSERT_LATENCY_LE,
    ASSERT_STATUS_2XX,
    AUDIT_SCHEMA,
    BadAlertError,
    BadCheckError,
    BadObservationError,
    BadSlaError,
    DuplicateAlertError,
    DuplicateCheckError,
    KIND_ALERT_DEFINED,
    KIND_ALERT_EVALUATED,
    KIND_CHECK_DEFINED,
    KIND_CHECKED,
    KIND_REJECTED,
    KIND_SLA_REPORTED,
    SeqOrderError,
    SyntheticMonitor,
    SyntheticMonitorError,
    UnknownAlertError,
    UnknownCheckError,
    synthetic_monitor_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "synthetic_monitor.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "hmac",
    "json",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "canonical_json",  # standard guarded fallback across the batch line
}


def fresh(seed="t"):
    return SyntheticMonitor(seed=seed)


def define_web(mon, seq=0, check_id="web"):
    return mon.define(
        check_id,
        "homepage",
        "http",
        "https://example.com",
        3,
        [(ASSERT_STATUS_2XX, None), (ASSERT_LATENCY_LE, 500)],
        seq,
    )


def check_up(mon, seq, check_id="web", latency_ms=120):
    return mon.check(
        check_id,
        {
            "status": "up",
            "latency_ms": latency_ms,
            "assertions_passed": [ASSERT_STATUS_2XX, ASSERT_LATENCY_LE],
        },
        seq,
    )


# --- pins -----------------------------------------------------------------


def test_version_schema_pins():
    import synthetic_monitor as sm

    assert sm.SYNTHETIC_MONITOR_VERSION == "synthetic-monitor.v1"
    assert sm.SYNTHETIC_MONITOR_SCHEMA == "northstar.synthetic-monitor.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(sm.CHECK_KINDS) == {
        "http",
        "tcp",
        "dns",
        "ssl",
        "icmp",
        "keyword",
    }
    assert set(sm.ALERT_CONDITIONS) == {
        "consecutive-failures",
        "latency-ms-gt",
        "availability-below",
    }
    assert set(sm.SLO_TARGETS) == {99.0, 99.9, 99.95, 99.99}


def test_stdlib_only_ast():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW


# --- define ----------------------------------------------------------------


def test_define_roundtrip():
    mon = fresh()
    d = define_web(mon, 0)
    assert d.check_id == "web" and d.kind == "http" and d.target.endswith("example.com")
    assert d.interval_seq == 3
    assert d.verify(seed="t")
    assert mon.definition("web").check_id == "web"


def test_define_duplicate():
    mon = fresh()
    define_web(mon, 0)
    try:
        define_web(mon, 1)
        assert False, "expected duplicate"
    except DuplicateCheckError:
        pass


def test_define_bad_inputs():
    mon = fresh()
    cases = [
        lambda s: mon.define("a", "n", "telnet", "t", 1, [(ASSERT_STATUS_2XX, None)], s),
        lambda s: mon.define("a", "n", "http", "", 1, [(ASSERT_STATUS_2XX, None)], s),
        lambda s: mon.define("a", "n", "http", "t", 0, [(ASSERT_STATUS_2XX, None)], s),
        lambda s: mon.define("a", "n", "http", "t", 1, [], s),
        lambda s: mon.define(
            "a", "n", "http", "t", 1, [("pwned", None)], s
        ),
        lambda s: mon.define(
            "a", "n", "http", "t", 1, [(ASSERT_STATUS_2XX, None), (ASSERT_STATUS_2XX, None)], s
        ),
        lambda s: mon.define(
            "a", "n", "http", "t", 1, [(ASSERT_LATENCY_LE, -5)], s
        ),
        lambda s: mon.define(
            "a", "n", "http", "t", 1, [(ASSERT_STATUS_2XX, "x")], s
        ),
    ]
    seq = 0
    for fn in cases:
        try:
            fn(seq)
            assert False, "expected BadCheckError"
        except SyntheticMonitorError:
            pass
        seq += 1
    # failed mutations consumed their seqs
    assert mon._last_seq == len(cases) - 1


def test_define_unknown_lookup():
    mon = fresh()
    try:
        mon.definition("nope")
        assert False
    except UnknownCheckError:
        pass


def test_seq_ordering():
    mon = fresh()
    define_web(mon, 0)
    for bad in (-1, True, "x"):
        try:
            define_web(mon, bad, check_id="other")
            assert False, "expected rejection"
        except SyntheticMonitorError:
            pass
    try:
        define_web(mon, 0, check_id="other")
        assert False, "expected rewind"
    except SeqOrderError:
        pass


# --- check -----------------------------------------------------------------


def test_check_up_verdict():
    mon = fresh()
    define_web(mon, 0)
    r = check_up(mon, 1)
    assert r.status == "up"
    assert r.assertions_failed == ()
    assert r.verify(seed="t")
    assert r.prev_digest == "genesis"
    kinds = [e["kind"] for e in mon.audit_log()]
    assert KIND_CHECKED in kinds


def test_check_down_verdict_is_data():
    mon = fresh()
    define_web(mon, 0)
    r = mon.check(
        "web",
        {
            "status": "down",
            "latency_ms": 0,
            "assertions_passed": [],
        },
        1,
    )
    assert r.status == "down"
    assert sorted(r.assertions_failed) == sorted([ASSERT_STATUS_2XX, ASSERT_LATENCY_LE])


def test_check_degraded_verdict():
    mon = fresh()
    define_web(mon, 0)
    r = mon.check(
        "web",
        {
            "status": "up",
            "latency_ms": 200,
            "assertions_passed": [ASSERT_STATUS_2XX],
        },
        1,
    )
    assert r.status == "degraded"
    assert r.assertions_failed == (ASSERT_LATENCY_LE,)


def test_check_bad_observation_branches():
    mon = fresh()
    define_web(mon, 0)
    bads = [
        {"status": "maybe", "latency_ms": 1, "assertions_passed": []},
        {"status": "up", "latency_ms": -1, "assertions_passed": []},
        {"status": "up", "latency_ms": 99999, "assertions_passed": [ASSERT_STATUS_2XX, ASSERT_LATENCY_LE]},
        {"status": "up", "latency_ms": 100, "assertions_passed": ["pwned"]},
        {"status": "up", "latency_ms": 100, "assertions_passed": "up"},
        "not-a-mapping",
    ]
    seq = 1
    for obs in bads:
        try:
            mon.check("web", obs, seq)
            assert False, "expected BadObservationError"
        except BadObservationError:
            pass
        seq += 1
    try:
        mon.check("unknown", {"status": "up", "latency_ms": 1, "assertions_passed": []}, seq)
        assert False
    except UnknownCheckError:
        pass


def test_check_result_chain():
    mon = fresh()
    define_web(mon, 0)
    r1 = check_up(mon, 1)
    r2 = check_up(mon, 2)
    assert r2.prev_digest == r1.digest
    assert mon.result("res-1").result_id == "res-1"
    assert len(mon.results_for("web")) == 2


# --- alerts ----------------------------------------------------------------


def test_alert_define_roundtrip():
    mon = fresh()
    define_web(mon, 0)
    p = mon.alert("fail3", "web", "consecutive-failures", 3, 1)
    assert p.verify(seed="t")
    assert mon.alert_policy("fail3").condition == "consecutive-failures"
    kinds = [e["kind"] for e in mon.audit_log()]
    assert KIND_ALERT_DEFINED in kinds


def test_alert_bad_inputs():
    mon = fresh()
    define_web(mon, 0)
    cases = [
        lambda s: mon.alert("a", "web", "panic", 3, s),
        lambda s: mon.alert("a", "web", "consecutive-failures", 0, s),
        lambda s: mon.alert("a", "web", "consecutive-failures", 2.5, s),
        lambda s: mon.alert("a", "web", "availability-below", 100, s),
        lambda s: mon.alert("a", "web", "latency-ms-gt", -1, s),
        lambda s: mon.alert("a", "web", "latency-ms-gt", float("nan"), s),
        lambda s: mon.alert("a", "unknown", "consecutive-failures", 2, s),
        lambda s: mon.alert("a", "web", "consecutive-failures", 2, s, window=0),
    ]
    seq = 1
    for fn in cases:
        try:
            fn(seq)
            assert False, "expected BadAlertError/UnknownCheckError"
        except (BadAlertError, UnknownCheckError):
            pass
        seq += 1
    mon.alert("a", "web", "consecutive-failures", 2, seq)
    try:
        mon.alert("a", "web", "consecutive-failures", 2, seq + 1)
        assert False
    except DuplicateAlertError:
        pass


def test_evaluate_consecutive_failures_fires():
    mon = fresh()
    define_web(mon, 0)
    for s in range(1, 4):
        mon.check("web", {"status": "down", "latency_ms": 0, "assertions_passed": []}, s)
    mon.alert("fail3", "web", "consecutive-failures", 3, 4)
    ev = mon.evaluate("fail3", 5)
    assert ev.firing is True
    assert ev.verify(seed="t")
    assert mon.evaluate("fail3", 5).firing is True  # pure view: seq not consumed
    kinds = [e["kind"] for e in mon.audit_log()]
    assert KIND_ALERT_EVALUATED in kinds


def test_evaluate_not_firing_after_recovery():
    mon = fresh()
    define_web(mon, 0)
    mon.check("web", {"status": "down", "latency_ms": 0, "assertions_passed": []}, 1)
    mon.check("web", {"status": "down", "latency_ms": 0, "assertions_passed": []}, 2)
    check_up(mon, 3)
    mon.alert("fail3", "web", "consecutive-failures", 3, 4)
    assert mon.evaluate("fail3", 5).firing is False


def test_evaluate_latency_and_availability_conditions():
    mon = fresh()
    mon.define(
        "web",
        "homepage",
        "http",
        "https://example.com",
        3,
        [(ASSERT_STATUS_2XX, None)],
        0,
    )
    mon.check(
        "web",
        {
            "status": "up",
            "latency_ms": 800,
            "assertions_passed": [ASSERT_STATUS_2XX],
        },
        1,
    )
    mon.alert("lat", "web", "latency-ms-gt", 500, 2)
    assert mon.evaluate("lat", 3).firing is True
    mon.check(
        "web",
        {
            "status": "up",
            "latency_ms": 100,
            "assertions_passed": [ASSERT_STATUS_2XX],
        },
        4,
    )
    assert mon.evaluate("lat", 5).firing is False
    mon.alert("avail", "web", "availability-below", 90, 6, window=4)
    mon.check("web", {"status": "down", "latency_ms": 0, "assertions_passed": []}, 7)
    assert mon.evaluate("avail", 8).firing is True  # 2 up of 3 -> 66.67% < 90


def test_evaluate_unknown_alert():
    mon = fresh()
    try:
        mon.evaluate("nope", 0)
        assert False
    except UnknownAlertError:
        pass


# --- sla -------------------------------------------------------------------


def test_sla_report():
    mon = fresh()
    define_web(mon, 0)
    check_up(mon, 1)
    check_up(mon, 2)
    mon.check("web", {"status": "down", "latency_ms": 0, "assertions_passed": []}, 3)
    report = mon.sla("web", 99.9, 4)
    assert report.total == 3 and report.ups == 2 and report.downs == 1
    assert abs(report.availability - 66.666667) < 0.001
    assert report.met is False
    assert report.verify(seed="t")
    assert KIND_SLA_REPORTED in [e["kind"] for e in mon.audit_log()]


def test_sla_perfect_meets_slo():
    mon = fresh()
    define_web(mon, 0)
    check_up(mon, 1)
    report = mon.sla("web", 99.99, 2)
    assert report.met is True and report.availability == 100.0


def test_sla_bad_inputs():
    mon = fresh()
    define_web(mon, 0)
    try:
        mon.sla("web", 98.5, 1)
        assert False
    except BadSlaError:
        pass
    try:
        mon.sla("web", 99.9, 1, window=0)
        assert False
    except BadSlaError:
        pass
    try:
        mon.sla("unknown", 99.9, 1)
        assert False
    except UnknownCheckError:
        pass


# --- due / views ------------------------------------------------------------


def test_due_never_run_and_interval():
    mon = fresh()
    mon.define("a", "A", "tcp", "db:5432", 2, [(ASSERT_STATUS_2XX, None)], 0)
    assert mon.due(1) == ("a",)
    obs = {"status": "up", "latency_ms": 5, "assertions_passed": [ASSERT_STATUS_2XX]}
    mon.check("a", obs, 1)
    assert mon.due(2) == ()  # last run at run#1, interval 2 -> due at run#3
    mon.define("b", "B", "dns", "ns1", 1, [(ASSERT_STATUS_2XX, None)], 2)
    mon.check("a", obs, 3)  # run#2 for a
    assert mon.due(4) == ("b",)  # a last run run#2 -> due run#4; b never ran
    mon.check("b", obs, 4)  # run#3
    assert mon.due(5) == ()  # a: 2+2=4<=3? no. b: 3+1=4<=3? no.
    mon.check("b", obs, 5)  # run#4
    assert mon.due(6) == ("a",)  # a: 2+2=4<=4 yes; b: 4+1=5<=4 no


def test_views_and_stats():
    mon = fresh()
    define_web(mon, 0)
    check_up(mon, 1)
    mon.alert("fail3", "web", "consecutive-failures", 3, 2)
    assert mon.check_ids() == ("web",)
    assert mon.alert_ids() == ("fail3",)
    s = mon.stats()
    assert (s["checks"], s["results"], s["alerts"]) == (1, 1, 1)
    d = mon.as_dict()
    assert d["version"] == "synthetic-monitor.v1" and d["last_seq"] == 2


# --- audit -----------------------------------------------------------------


def test_audit_shapes_and_bad_kind():
    ev = synthetic_monitor_audit_event(KIND_CHECK_DEFINED, 1, check_id="web", digest="sha256:x")
    assert ev["schema"] == AUDIT_SCHEMA and ev["module"] == "synthetic_monitor"
    try:
        synthetic_monitor_audit_event("bogus", 1)
        assert False
    except SyntheticMonitorError:
        pass
    mon = fresh()
    define_web(mon, 0)
    try:
        define_web(mon, 1)
    except DuplicateCheckError:
        pass
    kinds = [e["kind"] for e in mon.audit_log()]
    assert KIND_CHECK_DEFINED in kinds and KIND_REJECTED in kinds


def test_digest_determinism_across_instances():
    a, b = fresh(seed="same"), fresh(seed="same")
    define_web(a, 0)
    define_web(b, 0)
    ra = check_up(a, 1)
    rb = check_up(b, 1)
    assert ra.digest == rb.digest
    assert a.alert("f", "web", "latency-ms-gt", 10, 2).digest == b.alert(
        "f", "web", "latency-ms-gt", 10, 2
    ).digest


def test_main_selfcheck(capsys=None):
    import synthetic_monitor as sm

    sm.main()
