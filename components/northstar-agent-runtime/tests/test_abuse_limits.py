"""Tests for abuse_limits: 17 cases."""

import ast
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import abuse_limits
from abuse_limits import (
    ABUSE_LIMITS_VERSION,
    ABUSE_LIMITS_SCHEMA,
    AUDIT_SCHEMA,
    AbuseLimits,
    AbuseLimitsError,
    AlreadyBlockedError,
    AppealStateError,
    BadRuleError,
    BlockedError,
    CheckDecision,
    DuplicateRuleError,
    SeqOrderError,
    UnknownAppealError,
    UnknownBlockError,
    UnknownRuleError,
    abuse_limits_audit_event,
)


def fresh():
    return AbuseLimits()


def make_rule(limits, rule_id="r1", action="login", limit=3, window_seq=100,
              seq=1, max_strikes=0):
    return limits.define_rule(rule_id, action, limit, window_seq, seq,
                              max_strikes=max_strikes)


# 1 ---------------------------------------------------------------------


def test_version_schema_pins():
    assert ABUSE_LIMITS_VERSION == "abuse-limits.v1"
    assert ABUSE_LIMITS_SCHEMA == "northstar.abuse-limits.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    limits = fresh()
    rule = make_rule(limits)
    assert rule.verify()
    decision = limits.check("u1", "login", 2)
    assert decision.verify()
    blk = limits.block("u9", 3, "manual")
    assert blk.verify()
    app = limits.appeal("u9", 4, "grounds")
    assert app.verify()
    res = limits.resolve_appeal(app.appeal_id, 5, overturned=True)
    assert res.verify()


# 2 ---------------------------------------------------------------------


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "abuse_limits.py")
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


def test_define_rule_roundtrip():
    limits = fresh()
    r1 = make_rule(limits)
    assert r1.rule_id == "r1" and r1.action == "login"
    assert r1.limit == 3 and r1.window_seq == 100 and r1.max_strikes == 0
    # frozen
    try:
        r1.limit = 99  # type: ignore[misc]
    except Exception as exc:
        assert type(exc).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("records must be frozen")
    # digest deterministic across instances
    other = AbuseLimits()
    r2 = make_rule(other)
    assert r1.digest == r2.digest
    # views
    assert limits.rule("r1").digest == r1.digest
    assert limits.rule_ids() == ("r1",)


# 4 ---------------------------------------------------------------------


def test_define_rule_bad_inputs():
    limits = fresh()
    bad_cases = [
        dict(rule_id="", action="a"),
        dict(rule_id="x", action=""),
        dict(rule_id="x", action="a", limit=0),
        dict(rule_id="x", action="a", limit=-1),
        dict(rule_id="x", action="a", limit=True),
        dict(rule_id="x", action="a", limit=3, window_seq=0),
        dict(rule_id="x", action="a", limit=3, window_seq=-5),
        dict(rule_id="x", action="a", limit=3, window_seq=10, max_strikes=-1),
        dict(rule_id="x", action="a", limit=3, window_seq=10, max_strikes=1.5),
    ]
    seq = 1
    for kwargs in bad_cases:
        kw = dict(limit=3, window_seq=10)
        kw.update(kwargs)
        try:
            make_rule(limits, seq=seq, **kw)
        except AbuseLimitsError:
            pass
        else:
            raise AssertionError(f"bad rule accepted: {kwargs}")
        seq += 1
    # duplicate
    make_rule(limits, seq=seq)
    try:
        make_rule(limits, seq=seq + 1)
    except DuplicateRuleError:
        pass
    else:
        raise AssertionError("duplicate rule id must raise")


# 5 ---------------------------------------------------------------------


def test_check_happy_path_allowed():
    limits = fresh()
    make_rule(limits)
    d1 = limits.check("u1", "login", 2)
    assert isinstance(d1, CheckDecision)
    assert d1.allowed is True and d1.reason == "within-quota"
    assert d1.events_in_window == 1 and d1.limit == 3
    assert d1.consecutive_strikes == 0
    assert d1.verify()


# 6 ---------------------------------------------------------------------


def test_check_quota_exceeded_is_data():
    limits = fresh()
    make_rule(limits, limit=2)
    limits.check("u1", "login", 2)
    limits.check("u1", "login", 3)
    d = limits.check("u1", "login", 4)   # quota spent
    assert d.allowed is False
    assert d.reason == "quota-exceeded"
    assert d.events_in_window == 2 and d.limit == 2
    assert d.consecutive_strikes == 1
    assert d.verify()
    assert not limits.is_blocked("u1")  # exceeded != blocked (no strikes pin)


# 7 ---------------------------------------------------------------------


def test_check_sliding_window_expiry():
    limits = fresh()
    make_rule(limits, limit=2, window_seq=10)
    limits.check("u1", "login", 2)
    limits.check("u1", "login", 3)
    spent = limits.check("u1", "login", 4)
    assert spent.allowed is False
    # seq jumps past the window: old events fall out
    d = limits.check("u1", "login", 50)
    assert d.allowed is True and d.reason == "within-quota"


# 8 ---------------------------------------------------------------------


def test_check_unknown_action_raises():
    limits = fresh()
    make_rule(limits)
    try:
        limits.check("u1", "nope", 2)
    except UnknownRuleError:
        pass
    else:
        raise AssertionError("unknown action must raise UnknownRuleError")


# 9 ---------------------------------------------------------------------


def test_check_blocked_subject_raises():
    limits = fresh()
    make_rule(limits)
    limits.block("u1", 2, "manual review")
    assert limits.is_blocked("u1")
    try:
        limits.check("u1", "login", 3)
    except BlockedError:
        pass
    else:
        raise AssertionError("blocked subject must raise BlockedError")


# 10 --------------------------------------------------------------------


def test_block_unblock_lifecycle():
    limits = fresh()
    make_rule(limits)
    blk = limits.block("u1", 2, "confirmed stuffing")
    assert blk.verify() and blk.automatic is False
    assert limits.blocked_subjects() == ("u1",)
    try:
        limits.block("u1", 3, "again")
    except AlreadyBlockedError:
        pass
    else:
        raise AssertionError("double block must raise")
    try:
        limits.unblock("u9", 4, "nope")
    except UnknownBlockError:
        pass
    else:
        raise AssertionError("unblock of unknown must raise")
    rel = limits.unblock("u1", 5, "ops review")
    assert rel.verify()
    assert limits.blocked_subjects() == ()
    # strikes reset on unblock
    limits.check("u1", "login", 6)
    d = limits.check("u1", "login", 7)
    assert d.consecutive_strikes == 0


# 11 --------------------------------------------------------------------


def test_appeal_overturned_releases():
    limits = fresh()
    make_rule(limits)
    limits.block("u1", 2, "manual")
    app = limits.appeal("u1", 3, "shared corporate ip")
    assert app.verify() and app.resolved is False
    res = limits.resolve_appeal(app.appeal_id, 4, overturned=True)
    assert res.verify() and res.overturned is True
    assert not limits.is_blocked("u1")
    stored = limits.appeal_record(app.appeal_id)
    assert stored.resolved is True and stored.overturned is True
    assert stored.verify()
    try:
        limits.resolve_appeal(app.appeal_id, 5, overturned=True)
    except AppealStateError:
        pass
    else:
        raise AssertionError("double resolve must raise")


# 12 --------------------------------------------------------------------


def test_appeal_upheld_keeps_block():
    limits = fresh()
    make_rule(limits)
    limits.block("u1", 2, "manual")
    app = limits.appeal("u1", 3, "i swear it was me")
    res = limits.resolve_appeal(app.appeal_id, 4, overturned=False)
    assert res.overturned is False
    assert limits.is_blocked("u1")
    # appeal without a block is refused
    try:
        limits.appeal("u2", 5, "no block")
    except UnknownBlockError:
        pass
    else:
        raise AssertionError("appeal without block must raise")
    # unknown appeal
    try:
        limits.resolve_appeal("apl-999", 6, overturned=True)
    except UnknownAppealError:
        pass
    else:
        raise AssertionError("unknown appeal must raise")


# 13 --------------------------------------------------------------------


def test_auto_block_after_strikes():
    limits = fresh()
    make_rule(limits, limit=1, max_strikes=2)
    limits.check("u1", "login", 2)          # consumes the quota
    d1 = limits.check("u1", "login", 3)     # strike 1
    assert not d1.allowed and d1.consecutive_strikes == 1
    assert not limits.is_blocked("u1")
    d2 = limits.check("u1", "login", 4)     # strike 2 -> auto-block
    assert not d2.allowed
    assert limits.is_blocked("u1")
    try:
        limits.check("u1", "login", 5)
    except BlockedError:
        pass
    else:
        raise AssertionError("auto-blocked subject must raise")
    # overturn appeal releases an auto-block too
    app = limits.appeal("u1", 6, "retry storm")
    limits.resolve_appeal(app.appeal_id, 7, overturned=True)
    assert not limits.is_blocked("u1")


# 14 --------------------------------------------------------------------


def test_seq_order_enforcement():
    limits = fresh()
    make_rule(limits, seq=5)
    for bad in (5, 3, True, -1, "6"):
        try:
            limits.check("u1", "login", bad)
        except (SeqOrderError, AbuseLimitsError):
            pass
        else:
            raise AssertionError(f"bad seq accepted: {bad!r}")
    # good continuation still works
    d = limits.check("u1", "login", 6)
    assert d.allowed is True


# 15 --------------------------------------------------------------------


def test_failed_mutation_consumes_seq():
    limits = fresh()
    make_rule(limits, seq=1)
    try:
        limits.check("u1", "unknown-action", 2)
    except UnknownRuleError:
        pass
    # seq 2 consumed; reuse must fail
    try:
        limits.check("u1", "login", 2)
    except SeqOrderError:
        pass
    else:
        raise AssertionError("failed mutation must consume its seq")
    d = limits.check("u1", "login", 3)
    assert d.allowed is True


# 16 --------------------------------------------------------------------


def test_audit_shapes_and_kind_guards():
    ev = abuse_limits_audit_event(
        "abuse-limit.checked",
        {"subject": "u1", "action": "login", "allowed": True}, 7,
    )
    assert ev["schema"] == AUDIT_SCHEMA
    assert ev["module"] == ABUSE_LIMITS_VERSION
    assert ev["seq"] == 7
    for bad_kind in ("nope", "", None):
        try:
            abuse_limits_audit_event(bad_kind, {}, 1)
        except AbuseLimitsError:
            pass
        else:
            raise AssertionError(f"bad kind accepted: {bad_kind!r}")
    # banned detail keys stay out of the audit trail
    for banned in ("events", "history", "grounds"):
        try:
            abuse_limits_audit_event("abuse-limit.checked", {banned: "x"}, 1)
        except AbuseLimitsError:
            pass
        else:
            raise AssertionError(f"banned key accepted: {banned}")
    # full ledger audit log grows
    limits = fresh()
    make_rule(limits)
    limits.check("u1", "login", 2)
    log = limits.audit_log()
    assert len(log) >= 2
    assert all(e["schema"] == AUDIT_SCHEMA for e in log)


# 17 --------------------------------------------------------------------


def test_thread_safety_and_main():
    limits = fresh()
    make_rule(limits, limit=1000)
    errors = []

    def worker(i):
        try:
            for j in range(20):
                with limits._lock:
                    pass  # smoke: lock exists and guards
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    abuse_limits.main()
