"""Tests for ddos_protection: 22 cases."""

import ast
import math
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ddos_protection
from ddos_protection import (
    DDOS_VERSION,
    DDOS_SCHEMA,
    AUDIT_SCHEMA,
    ATTACK_TYPES,
    METRICS,
    MITIGATION_LEVELS,
    VERDICTS,
    DDoSProtection,
    DDoSProtectionError,
    ActiveMitigationError,
    AllowlistRecord,
    BadAllowlistError,
    BadCountersError,
    BadMitigationError,
    BadProfileError,
    DetectionReport,
    DuplicateAllowlistError,
    DuplicateProfileError,
    MitigationRecord,
    ProfileRecord,
    SeqOrderError,
    StandDownRecord,
    UnknownAllowlistError,
    UnknownDetectionError,
    UnknownMitigationError,
    UnknownProfileError,
    ddos_protection_audit_event,
)

FULL_THRESHOLDS = {
    "requests": (1000, 10000),
    "unique_sources": (500, 5000),
    "syn_ratio": (0.3, 0.7),
    "slow_connections": (100, 1000),
    "amplification_factor": (3.0, 10.0),
    "bandwidth_bytes": (10**9, 10**10),
    "error_rate": (0.1, 0.4),
}

CALM_COUNTERS = {
    "requests": 120,
    "unique_sources": 40,
    "syn_ratio": 0.05,
    "slow_connections": 5,
    "amplification_factor": 1.2,
    "bandwidth_bytes": 10**7,
    "error_rate": 0.01,
}


def fresh():
    return DDoSProtection()


def make_profile(ddos, profile_id="edge", seq=1):
    return ddos.define_profile(
        profile_id, list(ATTACK_TYPES), FULL_THRESHOLDS, seq
    )


def attack_counters():
    return {
        "requests": 50000,
        "unique_sources": 20000,
        "syn_ratio": 0.02,
        "slow_connections": 10,
        "amplification_factor": 1.1,
        "bandwidth_bytes": 5 * 10**10,
        "error_rate": 0.02,
    }


def detect_attack(ddos, source="ip:198.51.100.9", seq=2):
    make_profile(ddos, seq=1)
    return ddos.detect(source, "edge", attack_counters(), seq)


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert DDOS_VERSION == "ddos-protection.v1"
    assert DDOS_SCHEMA == "northstar.ddos-protection.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(VERDICTS) == {"normal", "suspect", "attack"}
    assert set(MITIGATION_LEVELS) == {
        "monitor", "challenge", "throttle", "scrub", "blackhole",
    }
    assert len(METRICS) == 7
    ddos = fresh()
    profile = make_profile(ddos)
    assert profile.verify()
    report = ddos.detect("ip:203.0.113.7", "edge", dict(CALM_COUNTERS), 2)
    assert report.verify()
    # mitigate on a ledger holding the detection:
    d2 = fresh()
    det = detect_attack(d2, seq=2)
    m = d2.mitigate("t1", det.detection_id, "scrub", 3)
    assert m.verify()
    sd = d2.stand_down("t1", 4, "over")
    assert sd.verify()
    entry = d2.allowlist("e1", "ip:203.0.113.7", 5, "ops")
    assert entry.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "ddos_protection.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "ipaddress", "math", "threading", "dataclasses",
        "typing", "json", "canonical_json", "__future__", "ast",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3 ---------------------------------------------------------------------


def test_main_selfcheck():
    ddos_protection.main()


# 4 ---------------------------------------------------------------------


def test_define_profile_roundtrip():
    ddos = fresh()
    profile = make_profile(ddos)
    assert profile.profile_id == "edge"
    assert profile.attack_types == tuple(ATTACK_TYPES)
    assert len(profile.thresholds) == 7
    assert profile.warn_score == 2 and profile.crit_score == 4
    assert profile.verify()
    assert ddos.profile("edge") == profile
    assert ddos.profile_ids() == ("edge",)
    # thresholds sorted by metric name
    names = [t.metric for t in profile.thresholds]
    assert names == sorted(names)


# 5 ---------------------------------------------------------------------


def test_define_profile_bad_inputs():
    ddos = fresh()
    make_profile(ddos, seq=1)
    kinds_before = [e["kind"] for e in ddos.audit_log()]
    # duplicate
    try:
        make_profile(ddos, seq=2)
    except DuplicateProfileError:
        pass
    else:
        raise AssertionError("duplicate profile must raise")
    # unknown attack type
    try:
        ddos.define_profile("p2", ["laser-strike"], FULL_THRESHOLDS, 3)
    except BadProfileError:
        pass
    else:
        raise AssertionError("unknown attack type must raise")
    # duplicate attack type
    try:
        ddos.define_profile(
            "p3", ["syn-flood", "syn-flood"], FULL_THRESHOLDS, 4
        )
    except BadProfileError:
        pass
    else:
        raise AssertionError("duplicate attack type must raise")
    # warn >= crit
    try:
        ddos.define_profile(
            "p4", ["syn-flood"], {"syn_ratio": (0.7, 0.3)}, 5
        )
    except BadProfileError:
        pass
    else:
        raise AssertionError("warn >= crit must raise")
    # unknown metric
    try:
        ddos.define_profile("p5", ["syn-flood"], {"lasers": (1, 2)}, 6)
    except BadProfileError:
        pass
    else:
        raise AssertionError("unknown metric must raise")
    # ratio crit > 1
    try:
        ddos.define_profile(
            "p6", ["syn-flood"], {"syn_ratio": (0.3, 1.5)}, 7
        )
    except BadProfileError:
        pass
    else:
        raise AssertionError("ratio crit > 1 must raise")
    # bad score order
    try:
        ddos.define_profile(
            "p7", ["syn-flood"], {"syn_ratio": (0.3, 0.7)}, 8,
            warn_score=4, crit_score=4,
        )
    except BadProfileError:
        pass
    else:
        raise AssertionError("warn_score >= crit_score must raise")
    # failed mutations consumed their seqs: 7 rejections audited
    kinds = [e["kind"] for e in ddos.audit_log()]
    assert kinds.count("ddos.rejected") == 7, kinds


# 6 ---------------------------------------------------------------------


def test_detect_normal():
    ddos = fresh()
    make_profile(ddos, seq=1)
    report = ddos.detect("ip:203.0.113.7", "edge", dict(CALM_COUNTERS), 2)
    assert report.verdict == "normal"
    assert report.attack_type == "none"
    assert report.score == 0
    assert not report.allowlisted
    assert all(r.level == "ok" for r in report.results)
    assert report.verify()
    assert ddos.detection(report.detection_id) == report


# 7 ---------------------------------------------------------------------


def test_detect_suspect():
    ddos = fresh()
    make_profile(ddos, seq=1)
    counters = dict(CALM_COUNTERS)
    counters["requests"] = 1500  # above warn(1000), below crit(10000)
    counters["unique_sources"] = 600  # above warn(500): 1 + 1 = 2 -> suspect
    report = ddos.detect("ip:203.0.113.7", "edge", counters, 2)
    assert report.verdict == "suspect"
    assert report.attack_type == "none"
    assert report.score == 2
    warn = [r for r in report.results if r.level == "warn"]
    assert len(warn) == 2
    assert {r.metric for r in warn} == {"requests", "unique_sources"}
    assert report.verify()


# 8 ---------------------------------------------------------------------


def test_detect_attack_volumetric():
    ddos = fresh()
    report = detect_attack(ddos, seq=2)
    assert report.verdict == "attack"
    assert report.attack_type == "volumetric-flood"
    assert report.score >= 4
    crit = [r for r in report.results if r.level == "crit"]
    assert {r.metric for r in crit} >= {
        "requests", "unique_sources", "bandwidth_bytes",
    }
    assert report.verify()


# 9 ---------------------------------------------------------------------


def test_detect_attack_syn_flood():
    ddos = fresh()
    make_profile(ddos, seq=1)
    counters = dict(CALM_COUNTERS)
    counters["syn_ratio"] = 0.9       # syn-flood: crit (2 pts)
    counters["requests"] = 1500       # volumetric: warn only (1 pt)
    counters["unique_sources"] = 600  # volumetric: warn only (1 pt)
    report = ddos.detect("ip:198.51.100.9", "edge", counters, 2)
    assert report.verdict == "attack"  # 2 + 1 + 1 = 4 >= crit_score
    assert report.attack_type == "syn-flood"  # only syn-flood at crit
    assert report.verify()


# 10 --------------------------------------------------------------------


def test_detect_mixed():
    ddos = fresh()
    make_profile(ddos, seq=1)
    counters = dict(CALM_COUNTERS)
    counters["syn_ratio"] = 0.9          # syn-flood: crit (2 pts)
    counters["slow_connections"] = 5000  # slowloris: crit (2 pts)
    report = ddos.detect("ip:198.51.100.9", "edge", counters, 2)
    assert report.verdict == "attack"
    assert report.attack_type == "mixed"
    assert report.verify()


# 11 --------------------------------------------------------------------


def test_detect_unknown_shape():
    ddos = fresh()
    make_profile(ddos, seq=1)
    counters = dict(CALM_COUNTERS)
    counters["error_rate"] = 0.9  # type-neutral, crit -> 2 pts
    counters["requests"] = 1500   # warn -> 1 pt
    counters["unique_sources"] = 600  # warn -> 1 pt
    # total 4 -> attack, but only volumetric typed at warn (no crit)
    report = ddos.detect("ip:198.51.100.9", "edge", counters, 2)
    assert report.verdict == "attack"
    # volumetric typed points exist (2 warn pts) -> attributed, not unknown
    assert report.attack_type == "volumetric-flood"
    assert report.verify()
    # pure type-neutral attack -> unknown-shape
    ddos2 = fresh()
    ddos2.define_profile(
        "err", ["volumetric-flood"], {"error_rate": (0.1, 0.4)}, 1,
        warn_score=1, crit_score=2,
    )
    rep2 = ddos2.detect(
        "ip:198.51.100.9", "err", {"error_rate": 0.9}, 2
    )
    assert rep2.verdict == "attack"
    assert rep2.attack_type == "unknown-shape"
    assert rep2.verify()


# 12 --------------------------------------------------------------------


def test_detect_bad_inputs_consume_seq():
    ddos = fresh()
    make_profile(ddos, seq=1)
    # unknown profile
    try:
        ddos.detect("ip:1.1.1.1", "nope", dict(CALM_COUNTERS), 2)
    except UnknownProfileError:
        pass
    else:
        raise AssertionError("unknown profile must raise")
    # NaN value
    bad = dict(CALM_COUNTERS)
    bad["requests"] = math.nan
    try:
        ddos.detect("ip:1.1.1.1", "edge", bad, 3)
    except BadCountersError:
        pass
    else:
        raise AssertionError("NaN must raise")
    # negative value
    bad = dict(CALM_COUNTERS)
    bad["requests"] = -5
    try:
        ddos.detect("ip:1.1.1.1", "edge", bad, 4)
    except BadCountersError:
        pass
    else:
        raise AssertionError("negative must raise")
    # bool value
    bad = dict(CALM_COUNTERS)
    bad["requests"] = True
    try:
        ddos.detect("ip:1.1.1.1", "edge", bad, 5)
    except BadCountersError:
        pass
    else:
        raise AssertionError("bool must raise")
    # unknown metric
    bad = dict(CALM_COUNTERS)
    bad["lasers"] = 10
    try:
        ddos.detect("ip:1.1.1.1", "edge", bad, 6)
    except BadCountersError:
        pass
    else:
        raise AssertionError("unknown metric must raise")
    # non-mapping counters
    try:
        ddos.detect("ip:1.1.1.1", "edge", [1, 2], 7)
    except BadCountersError:
        pass
    else:
        raise AssertionError("non-mapping must raise")
    kinds = [e["kind"] for e in ddos.audit_log()]
    assert kinds.count("ddos.rejected") == 6, kinds


# 13 --------------------------------------------------------------------


def test_seq_order_enforced():
    ddos = fresh()
    make_profile(ddos, seq=1)
    ddos.detect("ip:1.1.1.1", "edge", dict(CALM_COUNTERS), 2)
    for bad_seq in (2, 0, -1, True, "3", 2.5):
        try:
            ddos.detect("ip:1.1.1.1", "edge", dict(CALM_COUNTERS), bad_seq)
        except SeqOrderError:
            pass
        else:
            raise AssertionError(f"seq {bad_seq!r} must raise SeqOrderError")
    # ledger position unchanged: next valid seq still works
    rep = ddos.detect("ip:1.1.1.1", "edge", dict(CALM_COUNTERS), 3)
    assert rep.verify()


# 14 --------------------------------------------------------------------


def test_mitigate_happy_path():
    ddos = fresh()
    det = detect_attack(ddos, seq=2)
    mit = ddos.mitigate("edge-pop-1", det.detection_id, "scrub", 3)
    assert mit.mitigation_id == "mit-1"
    assert mit.target_id == "edge-pop-1"
    assert mit.detection_id == det.detection_id
    assert mit.level == "scrub"
    assert mit.status == "active"
    assert mit.verify()
    assert ddos.active_mitigation("edge-pop-1") == mit
    assert ddos.mitigated_targets() == ("edge-pop-1",)


# 15 --------------------------------------------------------------------


def test_mitigate_refused():
    ddos = fresh()
    make_profile(ddos, seq=1)
    calm = ddos.detect("ip:1.1.1.1", "edge", dict(CALM_COUNTERS), 2)
    susp_counters = dict(CALM_COUNTERS)
    susp_counters["requests"] = 1500
    susp = ddos.detect("ip:1.1.1.2", "edge", susp_counters, 3)
    # normal verdict -> refused
    try:
        ddos.mitigate("t1", calm.detection_id, "scrub", 4)
    except BadMitigationError:
        pass
    else:
        raise AssertionError("normal detection must not justify mitigation")
    # suspect verdict -> refused
    try:
        ddos.mitigate("t1", susp.detection_id, "scrub", 5)
    except BadMitigationError:
        pass
    else:
        raise AssertionError("suspect detection must not justify mitigation")
    # unknown detection
    try:
        ddos.mitigate("t1", "det-999", "scrub", 6)
    except UnknownDetectionError:
        pass
    else:
        raise AssertionError("unknown detection must raise")
    # unknown level
    det = detect_attack(fresh(), seq=2)
    ddos2 = fresh()
    det2 = detect_attack(ddos2, seq=2)
    try:
        ddos2.mitigate("t1", det2.detection_id, "nuke", 3)
    except BadMitigationError:
        pass
    else:
        raise AssertionError("unknown level must raise")
    kinds = [e["kind"] for e in ddos.audit_log()]
    assert kinds.count("ddos.rejected") == 3, kinds


# 16 --------------------------------------------------------------------


def test_mitigate_double_active_then_stand_down():
    ddos = fresh()
    det = detect_attack(ddos, seq=2)
    ddos.mitigate("edge-pop-1", det.detection_id, "throttle", 3)
    try:
        ddos.mitigate("edge-pop-1", det.detection_id, "scrub", 4)
    except ActiveMitigationError:
        pass
    else:
        raise AssertionError("double mitigate must raise")
    sd = ddos.stand_down("edge-pop-1", 5, "traffic normalized")
    assert sd.verify()
    assert ddos.active_mitigation("edge-pop-1") is None
    assert ddos.mitigated_targets() == ()
    # re-mitigate after stand-down works with a fresh id
    det2 = ddos.detect("ip:198.51.100.9", "edge", attack_counters(), 6)
    mit2 = ddos.mitigate("edge-pop-1", det2.detection_id, "scrub", 7)
    assert mit2.mitigation_id == "mit-2"
    assert mit2.verify()


# 17 --------------------------------------------------------------------


def test_stand_down_refusals():
    ddos = fresh()
    try:
        ddos.stand_down("ghost", 1, "nope")
    except UnknownMitigationError:
        pass
    else:
        raise AssertionError("stand-down without mitigation must raise")
    ddos2 = fresh()
    det = detect_attack(ddos2, seq=2)
    ddos2.mitigate("t1", det.detection_id, "monitor", 3)
    ddos2.stand_down("t1", 4, "done")
    try:
        ddos2.stand_down("t1", 5, "again")
    except UnknownMitigationError:
        pass
    else:
        raise AssertionError("double stand-down must raise")


# 18 --------------------------------------------------------------------


def test_allowlist_roundtrip_and_bad_shapes():
    ddos = fresh()
    e1 = ddos.allowlist("ops", "ip:203.0.113.7", 1, "ops host")
    assert e1.verify() and e1.active
    e2 = ddos.allowlist("net", "cidr:198.51.100.0/24", 2, "partner net")
    assert e2.verify()
    e3 = ddos.allowlist("web", "host:example.com", 3, "partner")
    assert e3.verify()
    e4 = ddos.allowlist("ix", "asn:AS64500", 4, "peering")
    assert e4.verify()
    assert ddos.active_allowlist_ids() == ("ix", "net", "ops", "web")
    # duplicate id
    try:
        ddos.allowlist("ops", "ip:203.0.113.8", 5, "dup")
    except DuplicateAllowlistError:
        pass
    else:
        raise AssertionError("duplicate entry id must raise")
    # bad shapes
    bad_shapes = ("203.0.113.7", "ip:999.1.1.1", "cidr:10.0.0.0/99",
                  "host:bad host", "asn:AS", "asn:xyz")
    for i, bad in enumerate(bad_shapes):
        try:
            ddos.allowlist("bad", bad, 6 + i, "bad")
        except (BadAllowlistError, DDoSProtectionError):
            pass
        else:
            raise AssertionError(f"identity {bad!r} must raise")
    assert ddos.allowlist_entry("ops") == e1


# 19 --------------------------------------------------------------------


def test_allowlist_bypass():
    ddos = fresh()
    make_profile(ddos, seq=1)
    ddos.allowlist("ops", "cidr:203.0.113.0/24", 2, "ops netblock")
    ddos.allowlist("partner", "host:example.com", 3, "partner")
    ddos.allowlist("peer", "asn:AS64500", 4, "peering")
    # exact ip covered by cidr bypasses even attack-level counters
    rep = ddos.detect("ip:203.0.113.7", "edge", attack_counters(), 5)
    assert rep.allowlisted and rep.verdict == "normal"
    assert rep.attack_type == "none" and rep.score == 0
    assert rep.results == () and rep.verify()
    # host bypass
    rep2 = ddos.detect("host:example.com", "edge", attack_counters(), 6)
    assert rep2.allowlisted
    # asn bypass (case-insensitive)
    rep3 = ddos.detect("asn:as64500", "edge", attack_counters(), 7)
    assert rep3.allowlisted
    # non-covered source still classified
    rep4 = ddos.detect("ip:198.51.100.9", "edge", attack_counters(), 8)
    assert not rep4.allowlisted and rep4.verdict == "attack"


# 20 --------------------------------------------------------------------


def test_remove_allowlist_terminal():
    ddos = fresh()
    make_profile(ddos, seq=1)
    ddos.allowlist("ops", "cidr:203.0.113.0/24", 2, "ops netblock")
    removed = ddos.remove_allowlist("ops", 3, "offboarding")
    assert removed.verify() and not removed.active
    assert ddos.active_allowlist_ids() == ()
    # detect no longer bypasses
    rep = ddos.detect("ip:203.0.113.7", "edge", attack_counters(), 4)
    assert not rep.allowlisted and rep.verdict == "attack"
    # double remove refused
    try:
        ddos.remove_allowlist("ops", 5, "again")
    except UnknownAllowlistError:
        pass
    else:
        raise AssertionError("double remove must raise")
    # unknown entry
    try:
        ddos.remove_allowlist("ghost", 6, "nope")
    except UnknownAllowlistError:
        pass
    else:
        raise AssertionError("unknown entry must raise")


# 21 --------------------------------------------------------------------


def test_audit_shapes_and_bans():
    ddos = fresh()
    make_profile(ddos, seq=1)
    det = ddos.detect("ip:1.1.1.1", "edge", dict(CALM_COUNTERS), 2)
    kinds = {e["kind"] for e in ddos.audit_log()}
    assert {"ddos.profile-defined", "ddos.detected"} <= kinds
    for event in ddos.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert event["module"] == "ddos-protection.v1"
        assert "counters" not in event["detail"]
        assert "identity" not in event["detail"]
    # helper bans
    try:
        ddos_protection_audit_event(
            "ddos.detected", {"counters": {"a": 1}}, 9
        )
    except DDoSProtectionError:
        pass
    else:
        raise AssertionError("counters must be banned from audit detail")
    try:
        ddos_protection_audit_event(
            "ddos.allowlisted", {"identity": "ip:1.1.1.1"}, 9
        )
    except DDoSProtectionError:
        pass
    else:
        raise AssertionError("identity must be banned from audit detail")
    try:
        ddos_protection_audit_event("ddos.nope", {}, 9)
    except DDoSProtectionError:
        pass
    else:
        raise AssertionError("unknown audit kind must raise")
    assert det.detection_id in [
        e["detail"].get("detection_id") for e in ddos.audit_log()
    ]


# 22 --------------------------------------------------------------------


def test_concurrency_smoke():
    ddos = fresh()
    make_profile(ddos, seq=0)
    errors = []

    def worker(n):
        try:
            for i in range(10):
                seq = 1 + n * 10 + i
                ddos.detect(
                    f"ip:10.0.{n}.{i}", "edge", dict(CALM_COUNTERS), seq
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # seqs collide across threads -> SeqOrderError is acceptable; nothing
    # else may escape the lock.
    assert all(isinstance(e, SeqOrderError) for e in errors), errors
    assert ddos.stats()["detections"] >= 0
