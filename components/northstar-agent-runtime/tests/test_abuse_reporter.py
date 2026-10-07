"""Tests for abuse_reporter: 15 cases."""

import ast
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from abuse_reporter import (
    ABUSE_REPORTER_VERSION,
    SCHEMA_PIN,
    ACTIONS,
    CATEGORIES,
    PRIORITIES,
    AbuseReporter,
    AbuseReporterError,
    BadReportError,
    BadResolutionError,
    BadTriageError,
    DuplicateReportError,
    InvalidStateError,
    SeqOrderError,
    TerminalReportError,
    UnknownReportError,
    abuse_reporter_audit_event,
)

ALLOWED_STDLIB = {
    "hashlib", "hmac", "secrets", "threading", "dataclasses",
    "typing", "__future__", "json", "canonical_json",
}


def make_mgr(seed=b"abuse-reporter-test"):
    return AbuseReporter(seed=seed)


def test_version_pins():
    assert ABUSE_REPORTER_VERSION == "abuse-reporter.v1"
    assert SCHEMA_PIN == "northstar.abuse-reporter.v1"
    assert set(CATEGORIES) >= {"spam", "harassment", "fraud", "other"}
    assert set(PRIORITIES) == {"low", "medium", "high", "urgent"}
    assert set(ACTIONS) >= {"no-violation", "content-removed", "account-banned"}


def test_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "abuse_reporter.py")
    tree = ast.parse(open(path).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    assert imported <= ALLOWED_STDLIB, imported - ALLOWED_STDLIB


def test_report_roundtrip_and_verify():
    mgr = make_mgr()
    rep = mgr.report("user-1", "user-9", "spam", "spammy posts", 1,
                     evidence=("https://example/x/1",))
    assert rep.report_id == "abr-1"
    assert rep.state == "open"
    assert rep.category == "spam"
    assert len(rep.evidence) == 1
    assert rep.evidence[0].verify("https://example/x/1")
    assert not rep.evidence[0].verify("https://example/x/2")
    assert rep.verify(mgr)
    assert mgr.get_report("abr-1") == rep


def test_report_bad_inputs():
    mgr = make_mgr()
    bad_calls = [
        lambda s: mgr.report("", "s", "spam", "d", s),
        lambda s: mgr.report("r", "", "spam", "d", s),
        lambda s: mgr.report("r", "s", "nope", "d", s),
        lambda s: mgr.report("r", "s", "spam", "", s),
        lambda s: mgr.report("r", "s", "spam", "x" * 4001, s),
        lambda s: mgr.report("r", "s", "spam", "d", s, evidence=("",)),
        lambda s: mgr.report("r", "s", "spam", "d", s, evidence=("a",) * 33),
    ]
    for i, call in enumerate(bad_calls, start=1):
        try:
            call(i)
        except BadReportError:
            pass
        else:
            raise AssertionError(f"bad call {i} did not raise")
        # seqs strictly increase even across failures
    assert mgr._seq == 7


def test_duplicate_open_report_refused():
    mgr = make_mgr()
    mgr.report("user-1", "user-9", "spam", "first", 1)
    try:
        mgr.report("user-1", "user-9", "spam", "second", 2)
    except DuplicateReportError:
        pass
    else:
        raise AssertionError("duplicate not refused")
    # same subject, different category is fine
    rep = mgr.report("user-1", "user-9", "fraud", "other", 3)
    assert rep.report_id == "abr-2"


def test_triage_happy_path():
    mgr = make_mgr()
    mgr.report("user-1", "user-9", "harassment", "mean msgs", 1)
    tri = mgr.triage("abr-1", "mod-1", 2, "high", "reviewer-2")
    assert tri.triage_id == "trg-1"
    assert tri.priority == "high"
    assert tri.verify(mgr)
    assert mgr.get_report("abr-1").state == "triaged"
    kinds = [e["event"] for e in mgr.audit_log()]
    assert kinds == ["reported", "triaged"]


def test_triage_bad_inputs():
    mgr = make_mgr()
    mgr.report("user-1", "user-9", "spam", "d", 1)
    for seq, kw, exc in [
        (2, dict(report_id="abr-99", triager_id="m",
              priority="high", assignee="r"), UnknownReportError),
        (3, dict(report_id="abr-1", triager_id="m",
              priority="nope", assignee="r"), BadTriageError),
        (4, dict(report_id="abr-1", triager_id="",
              priority="high", assignee="r"), BadReportError),
    ]:
        try:
            mgr.triage(seq=seq, **kw)
        except exc:
            pass
        else:
            raise AssertionError(f"{kw} did not raise {exc}")
    # triage twice -> invalid state
    mgr.triage("abr-1", "mod-1", 5, "low", "r2")
    try:
        mgr.triage("abr-1", "mod-1", 6, "low", "r2")
    except InvalidStateError:
        pass
    else:
        raise AssertionError("double triage not refused")


def test_resolve_happy_path_terminal():
    mgr = make_mgr()
    mgr.report("user-1", "user-9", "fraud", "scam", 1)
    mgr.triage("abr-1", "mod-1", 2, "urgent", "r2")
    res = mgr.resolve("abr-1", "r2", 3, "account-suspended", "confirmed")
    assert res.resolution_id == "res-1"
    assert res.verify(mgr)
    assert mgr.get_report("abr-1").state == "resolved"
    # second resolve is terminal
    try:
        mgr.resolve("abr-1", "r2", 4, "no-violation")
    except TerminalReportError:
        pass
    else:
        raise AssertionError("double resolve not terminal")
    # triage after resolve is terminal too
    try:
        mgr.triage("abr-1", "mod-1", 5, "low", "r2")
    except TerminalReportError:
        pass
    else:
        raise AssertionError("triage after resolve not terminal")


def test_resolve_bad_inputs():
    mgr = make_mgr()
    mgr.report("user-1", "user-9", "spam", "d", 1)
    # resolve before triage
    try:
        mgr.resolve("abr-1", "r", 2, "no-violation")
    except InvalidStateError:
        pass
    else:
        raise AssertionError("resolve-before-triage not refused")
    mgr.triage("abr-1", "m", 3, "low", "r")
    try:
        mgr.resolve("abr-1", "r", 4, "nuke-everything")
    except BadResolutionError:
        pass
    else:
        raise AssertionError("bad action not refused")
    try:
        mgr.resolve("abr-99", "r", 5, "no-violation")
    except UnknownReportError:
        pass
    else:
        raise AssertionError("unknown report not refused")


def test_seq_ordering():
    mgr = make_mgr()
    mgr.report("a", "b", "spam", "d", 1)
    for bad in (1, 0, -5, True, "2", 1.5):
        try:
            mgr.report("a", "b", "spam", "d", bad)
        except (SeqOrderError, DuplicateReportError):
            pass
        else:
            raise AssertionError(f"seq {bad!r} not refused")


def test_failed_mutation_consumes_seq():
    mgr = make_mgr()
    mgr.report("a", "b", "spam", "d", 1)
    try:
        mgr.report("a", "b", "spam", "d", 2)  # duplicate
    except DuplicateReportError:
        pass
    # seq 2 was consumed; next valid mutation needs seq 3
    try:
        mgr.report("a", "b", "fraud", "d", 2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("consumed seq reusable")
    rep = mgr.report("a", "b", "fraud", "d", 3)
    assert rep.report_id == "abr-2"


def test_views():
    mgr = make_mgr()
    mgr.report("u1", "s1", "spam", "d1", 1)
    mgr.report("u2", "s1", "fraud", "d2", 2)
    mgr.report("u3", "s2", "spam", "d3", 3)
    mgr.triage("abr-1", "m", 4, "low", "r")
    assert [r.report_id for r in mgr.open_reports()] == ["abr-2", "abr-3"]
    assert [r.report_id for r in mgr.reports_by_subject("s1")] == ["abr-1", "abr-2"]
    assert mgr.report_ids() == ["abr-1", "abr-2", "abr-3"]
    try:
        mgr.get_report("abr-99")
    except UnknownReportError:
        pass
    else:
        raise AssertionError("unknown get not refused")


def test_audit_shapes_and_evidence_ban():
    mgr = make_mgr()
    secret_evidence = "https://internal/secret-evidence-42"
    mgr.report("u1", "s1", "spam", "d", 1, evidence=(secret_evidence,))
    blob = str(mgr.audit_log())
    assert secret_evidence not in blob
    ev = abuse_reporter_audit_event("reported", {"report_id": "abr-1"})
    assert ev["schema"] == SCHEMA_PIN
    assert ev["module_version"] == ABUSE_REPORTER_VERSION
    assert ev["event"] == "reported"


def test_concurrency():
    mgr = make_mgr()
    errors = []

    def worker(n):
        try:
            for i in range(10):
                with mgr._lock:
                    seq = mgr._seq + 1
                mgr.report(f"u-{n}-{i}", f"s-{n}-{i}", "spam", "d", seq)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(mgr.report_ids()) == 40


def test_main():
    import abuse_reporter
    abuse_reporter.main()


if __name__ == "__main__":
    test_version_pins()
    test_stdlib_only()
    test_report_roundtrip_and_verify()
    test_report_bad_inputs()
    test_duplicate_open_report_refused()
    test_triage_happy_path()
    test_triage_bad_inputs()
    test_resolve_happy_path_terminal()
    test_resolve_bad_inputs()
    test_seq_ordering()
    test_failed_mutation_consumes_seq()
    test_views()
    test_audit_shapes_and_evidence_ban()
    test_concurrency()
    test_main()
    print("all 15 abuse_reporter tests passed")
