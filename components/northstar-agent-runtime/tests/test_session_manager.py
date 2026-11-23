"""Tests for session_manager: login / logout / refresh with sealed audit."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from session_manager import (
    LoginRequest,
    SessionManager,
    SessionRecord,
    SessionToken,
)


@pytest.fixture()
def events():
    return []


@pytest.fixture()
def mgr(events):
    return SessionManager(
        verify=lambda uid, presented: presented.get("pw") == "correct",
        audit=events.append,
    )


def login_ok(mgr, **kw):
    kw.setdefault("user_id", "u1")
    kw.setdefault("presented", {"pw": "correct"})
    kw.setdefault("issued_at_seq", 0)
    tok = mgr.login(LoginRequest(**kw))
    assert tok is not None
    return tok


def test_login_success_returns_valid_bearer_token(mgr):
    tok = login_ok(mgr)
    assert tok.validate() == (True, "")
    assert tok.token_digest.startswith("sha256:")
    assert tok.user_id == "u1"


def test_login_rejects_bad_credentials(mgr):
    tok = mgr.login(LoginRequest(user_id="u1", presented={"pw": "wrong"},
                                 issued_at_seq=0))
    assert tok is None


def test_login_rejects_invalid_request(mgr):
    tok = mgr.login(LoginRequest(user_id="  ", presented={"pw": "correct"},
                                 issued_at_seq=0))
    assert tok is None


def test_verifier_exception_is_fail_closed(events):
    mgr = SessionManager(verify=lambda u, p: 1 / 0, audit=events.append)
    tok = mgr.login(LoginRequest(user_id="u1", presented={}, issued_at_seq=0))
    assert tok is None
    assert any(e["event"] == "session.login_rejected"
               and e.get("reason") == "verifier_error" for e in events)


def test_validate_returns_live_session_record(mgr):
    tok = login_ok(mgr)
    rec = mgr.validate(tok.token, 5)
    assert isinstance(rec, SessionRecord)
    assert rec.user_id == "u1"
    assert rec.revoked is False
    assert rec.token_digest == tok.token_digest
    assert rec.last_seen_seq == 5


def test_validate_unknown_token_returns_none(mgr):
    assert mgr.validate("nope-not-a-token", 1) is None


def test_validate_empty_token_returns_none(mgr):
    assert mgr.validate("", 1) is None


def test_validate_expired_session_returns_none(mgr):
    tok = login_ok(mgr, ttl_seq=10)
    assert mgr.validate(tok.token, 9) is not None
    assert mgr.validate(tok.token, 10) is None  # expires_seq <= seq is dead


def test_logout_revokes_session(mgr):
    tok = login_ok(mgr)
    assert mgr.logout(tok.token, 7) is True
    assert mgr.validate(tok.token, 8) is None


def test_logout_is_idempotent(mgr):
    tok = login_ok(mgr)
    assert mgr.logout(tok.token, 7) is True
    assert mgr.logout(tok.token, 8) is False  # already revoked
    assert mgr.logout("unknown-token", 8) is False


def test_refresh_rotates_token_atomically(mgr):
    tok = login_ok(mgr)
    tok2 = mgr.refresh(tok.token, 20)
    assert tok2 is not None
    assert tok2.token != tok.token
    assert tok2.validate() == (True, "")
    # old token is dead immediately after rotation
    assert mgr.validate(tok.token, 21) is None
    assert mgr.validate(tok2.token, 21) is not None


def test_refresh_increments_count_and_extends_expiry(mgr):
    tok = login_ok(mgr, ttl_seq=100)
    tok2 = mgr.refresh(tok.token, 50)
    rec = mgr.validate(tok2.token, 51)
    assert rec.refresh_count == 1
    assert rec.expires_seq == 150  # seq + original ttl


def test_refresh_limit_enforced(mgr):
    tok = login_ok(mgr, max_refresh=1)
    tok2 = mgr.refresh(tok.token, 10)
    assert tok2 is not None
    assert mgr.refresh(tok2.token, 20) is None  # limit reached
    # the last live token still validates
    assert mgr.validate(tok2.token, 21) is not None


def test_refresh_after_logout_fails(mgr):
    tok = login_ok(mgr)
    assert mgr.logout(tok.token, 5) is True
    assert mgr.refresh(tok.token, 6) is None


def test_tokens_are_unique_and_digests_pinned(events):
    mgr = SessionManager(
        verify=lambda u, p: True, audit=events.append)
    tokens = {mgr.login(LoginRequest(user_id=f"u{i}", issued_at_seq=0)).token
              for i in range(20)}
    assert len(tokens) == 20
    # stored state carries only digests, never raw tokens
    for state in mgr._sessions.values():
        assert "token" not in state
    for raw in tokens:
        assert all(raw not in str(e) for e in events)


def test_sweep_purges_expired(mgr):
    t1 = login_ok(mgr, user_id="a", ttl_seq=10)
    t2 = login_ok(mgr, user_id="b", ttl_seq=100)
    assert mgr.sweep(10) == 1
    assert mgr.validate(t1.token, 11) is None
    assert mgr.validate(t2.token, 11) is not None
    assert mgr.sweep(200) == 1
    assert mgr.active_count() == 0
