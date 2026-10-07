"""Tests for api_analytics (thirty-fourth batch)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api_analytics import (  # noqa: E402
    APIAnalytics,
    APIAnalyticsError,
    API_ANALYTICS_SCHEMA,
    API_ANALYTICS_VERSION,
    KIND_CALL_TRACKED,
    KIND_COHORT,
    KIND_FUNNEL,
    KIND_REJECTED,
    METHODS,
    SeqOrderError,
    UnknownCallError,
    api_analytics_audit_event,
    compute_call_digest,
    compute_cohort_digest,
    compute_funnel_digest,
)

MODULE = Path(__file__).resolve().parent.parent / "api_analytics.py"


def _tracker_with_calls() -> APIAnalytics:
    aa = APIAnalytics()
    aa.track("u1", "GET", "/signup", 1)
    aa.track("u1", "POST", "/checkout", 2)
    aa.track("u2", "GET", "/signup", 3)
    aa.track("u2", "POST", "/checkout", 4)
    return aa


# -- pins and stdlib discipline ------------------------------------------------


def test_version_pins():
    assert API_ANALYTICS_VERSION == "api-analytics.v1"
    assert API_ANALYTICS_SCHEMA == "northstar.api-analytics.v1"
    assert set(METHODS) == {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {"hashlib", "json", "dataclasses", "threading", "typing", "__future__"}
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.asname or a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module.split(".")[0] if node.module else "")
    assert imports - allowed == set(), imports - allowed


# -- track ---------------------------------------------------------------------


def test_track_roundtrip_and_chain():
    aa = APIAnalytics()
    c1 = aa.track("u1", "GET", "/a", 1, status_code=200, latency_ms=12)
    c2 = aa.track("u1", "POST", "/a", 2, status_code=201, latency_ms=30)
    assert c1.call_id == "call-1"
    assert c2.call_id == "call-2"
    assert c1.prev_digest == "genesis"
    assert c2.prev_digest == c1.record_digest
    assert c1.record_digest.startswith("sha256:")
    assert compute_call_digest(c1) == c1.record_digest
    assert aa.call("call-1") is c1


def test_track_unknown_call():
    aa = APIAnalytics()
    with pytest.raises(UnknownCallError):
        aa.call("call-999")


def test_track_bad_inputs():
    aa = APIAnalytics()
    with pytest.raises(APIAnalyticsError):
        aa.track("", "GET", "/a", 1)                      # empty user
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "BREW", "/a", 2)                    # bad method
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "no-slash", 3)               # no leading slash
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "/a b", 4)                   # whitespace
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "/a", 5, status_code=99)     # bad status
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "/a", 6, latency_ms=-1)      # negative latency
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "/a", 7, latency_ms=True)     # bool latency


def test_seq_ordering_and_failed_mutation_consumes_seq():
    aa = APIAnalytics()
    aa.track("u1", "GET", "/a", 5)
    with pytest.raises(SeqOrderError):
        aa.track("u1", "GET", "/a", 5)     # not strictly increasing
    with pytest.raises(SeqOrderError):
        aa.track("u1", "GET", "/a", 3)     # rewind
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "GET", "/a", True)  # bool seq
    # A failed mutation still advances the ledger position.
    with pytest.raises(APIAnalyticsError):
        aa.track("u1", "BREW", "/a", 6)
    with pytest.raises(SeqOrderError):
        aa.track("u1", "GET", "/a", 6)
    aa.track("u1", "GET", "/a", 7)
    assert aa.call_ids() == ("call-1", "call-2")


# -- funnel --------------------------------------------------------------------


def test_funnel_counts_and_rates():
    aa = _tracker_with_calls()
    report = aa.funnel(
        "onboarding",
        [("GET", "/signup"), ("POST", "/checkout")],
        10,
        conversion_window=10,
    )
    assert report.step_counts == (2, 2)
    assert report.conversion_rates == (1.0, 1.0)
    assert report.analyzed_calls == 4
    assert compute_funnel_digest(report) == report.record_digest


def test_funnel_window_expiry():
    aa = APIAnalytics()
    aa.track("u1", "GET", "/a", 1)
    aa.track("u1", "POST", "/b", 100)  # outside window of 10
    report = aa.funnel("w", [("GET", "/a"), ("POST", "/b")], 101, conversion_window=10)
    assert report.step_counts == (1, 0)
    assert report.conversion_rates == (1.0, 0.0)


def test_funnel_empty_ledger_is_data():
    aa = APIAnalytics()
    report = aa.funnel("w", [("GET", "/a"), ("POST", "/b")], 1, conversion_window=10)
    assert report.step_counts == (0, 0)
    assert report.conversion_rates == (0.0, 0.0)


def test_funnel_bad_inputs():
    aa = APIAnalytics()
    with pytest.raises(APIAnalyticsError):
        aa.funnel("w", [("GET", "/a")], 1, conversion_window=10)  # < 2 steps
    with pytest.raises(APIAnalyticsError):
        aa.funnel("w", [("BREW", "/a"), ("GET", "/b")], 2, conversion_window=10)
    with pytest.raises(APIAnalyticsError):
        aa.funnel("w", [("GET", "/a"), ("GET", "/b")], 3, conversion_window=0)


# -- cohort --------------------------------------------------------------------


def test_cohort_retention():
    aa = APIAnalytics()
    # u1 anchors at seq 1, active in period 0 and 1.
    aa.track("u1", "GET", "/home", 1)
    aa.track("u1", "POST", "/use", 2)
    aa.track("u1", "POST", "/use", 12)
    # u2 anchors at seq 13, never active afterwards.
    aa.track("u2", "GET", "/home", 13)
    report = aa.cohort(
        ("GET", "/home"), ("POST", "/use"),
        20, bucket_size=10, periods=2,
    )
    assert report.buckets[0] == (0, 1, (1, 1))
    assert report.buckets[1] == (1, 1, (0, 0))
    assert compute_cohort_digest(report) == report.record_digest


def test_cohort_bad_inputs():
    aa = APIAnalytics()
    with pytest.raises(APIAnalyticsError):
        aa.cohort(("BREW", "/a"), ("GET", "/b"), 1, bucket_size=10, periods=2)
    with pytest.raises(APIAnalyticsError):
        aa.cohort(("GET", "/a"), ("GET", "/b"), 2, bucket_size=0, periods=2)
    with pytest.raises(APIAnalyticsError):
        aa.cohort(("GET", "/a"), ("GET", "/b"), 3, bucket_size=10, periods=0)


# -- views and audit -----------------------------------------------------------


def test_views_and_stats():
    aa = _tracker_with_calls()
    assert aa.call_ids() == ("call-1", "call-2", "call-3", "call-4")
    assert [c.call_id for c in aa.calls_for("u1")] == ["call-1", "call-2"]
    assert aa.calls_for("nobody") == ()
    assert aa.stats() == {"calls": 4, "users": 2, "last_seq": 4}


def test_audit_boundary_bans_user_id():
    aa = _tracker_with_calls()
    blob = str(aa.audit_log())
    assert "u1" not in blob and "u2" not in blob
    kinds = {e["kind"] for e in aa.audit_log()}
    assert kinds == {KIND_CALL_TRACKED}
    aa.funnel("f", [("GET", "/signup"), ("POST", "/checkout")], 10, conversion_window=10)
    aa.cohort(("GET", "/signup"), ("POST", "/checkout"), 11, bucket_size=10, periods=1)
    kinds = {e["kind"] for e in aa.audit_log()}
    assert KIND_FUNNEL in kinds and KIND_COHORT in kinds
    # Rejected mutations are audited too.
    with pytest.raises(APIAnalyticsError):
        aa.track("u3", "BREW", "/x", 12)
    assert aa.audit_log()[-1]["kind"] == KIND_REJECTED
    assert api_analytics_audit_event(KIND_CALL_TRACKED, 1)["schema"] == "audit.ndjson/1"
    with pytest.raises(APIAnalyticsError):
        api_analytics_audit_event("bogus", 1)


def test_main_self_check():
    out = subprocess.run(
        [sys.executable, str(MODULE)], capture_output=True, text=True, cwd="/tmp"
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "api-analytics OK: track, funnel, cohort, pins, audit"
