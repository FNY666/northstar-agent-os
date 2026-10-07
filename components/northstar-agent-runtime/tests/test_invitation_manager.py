"""Tests for invitation_manager: 15 cases."""

import sys
import os
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from invitation_manager import (
    InvitationManager,
    InviteParams,
    AcceptParams,
    Decision,
)


def make_manager(audit_log, allowed_invites=frozenset({("admin", "member")})):
    def can_invite(inviter, role, scope):
        if (inviter, role) in allowed_invites:
            return True, "ok"
        return False, "not permitted"

    return InvitationManager(
        inviter_can_invite=can_invite,
        audit_sink=lambda e: audit_log.append(e),
    )


def valid_params(**kw):
    base = dict(
        invitee_id="user-1",
        invited_by="admin",
        role="member",
        scope=("org:a",),
        ttl_seq=100,
        issued_at_seq=0,
        nonce="n1",
    )
    base.update(kw)
    return InviteParams(**base)


def test_invite_success():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params())
    assert d.allowed
    assert d.reason == "invited"
    assert len(log) == 1
    assert log[0]["event"]["action"] == "invite"
    assert log[0]["event"]["type"] == "audit.ndjson/1"


def test_invite_rejects_unknown_role():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params(role="superuser"))
    assert not d.allowed
    assert "unknown role" in d.reason


def test_invite_rejects_empty_invitee():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params(invitee_id=""))
    assert not d.allowed
    assert "invitee_id" in d.reason


def test_invite_rejects_unauthorized_inviter():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params(invited_by="mallory"))
    assert not d.allowed
    assert "not authorized" in d.reason


def test_invite_rejects_duplicate_pending():
    log = []
    m = make_manager(log)
    d1 = m.invite(valid_params())
    d2 = m.invite(valid_params())
    assert d1.allowed
    assert not d2.allowed
    assert d2.reason == "duplicate pending invitation"


def test_invite_allows_same_invitee_different_role():
    log = []
    m = make_manager(
        log, allowed_invites=frozenset({("admin", "member"), ("admin", "viewer")})
    )
    d1 = m.invite(valid_params(role="member"))
    d2 = m.invite(valid_params(role="viewer"))
    assert d1.allowed
    assert d2.allowed


def test_invite_rejects_nonpositive_ttl():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params(ttl_seq=0))
    assert not d.allowed
    assert "ttl_seq" in d.reason


def test_accept_success():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params())
    token = d.payload["record"]["invitation_id"]
    a = m.accept(token, AcceptParams(invitee_id="user-1", now_seq=10))
    assert a.allowed
    assert a.reason == "accepted"
    assert a.payload["record"]["state"] == "accepted"
    assert [e["event"]["action"] for e in log] == ["invite", "accept"]


def test_accept_rejects_unknown_token():
    log = []
    m = make_manager(log)
    a = m.accept("inv-nope", AcceptParams(invitee_id="user-1", now_seq=1))
    assert not a.allowed
    assert a.reason == "unknown invitation"


def test_accept_rejects_invitee_mismatch():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params())
    token = d.payload["record"]["invitation_id"]
    a = m.accept(token, AcceptParams(invitee_id="user-2", now_seq=1))
    assert not a.allowed
    assert a.reason == "invitee mismatch"


def test_accept_after_expiry_marks_expired():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params(ttl_seq=5))
    token = d.payload["record"]["invitation_id"]
    a = m.accept(token, AcceptParams(invitee_id="user-1", now_seq=6))
    assert not a.allowed
    assert a.reason == "invitation expired"
    rec = m.get(token)
    assert rec.state == "expired"


def test_accept_rejects_double_accept():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params())
    token = d.payload["record"]["invitation_id"]
    assert m.accept(token, AcceptParams(invitee_id="user-1", now_seq=1)).allowed
    second = m.accept(token, AcceptParams(invitee_id="user-1", now_seq=2))
    assert not second.allowed
    assert "not pending" in second.reason


def test_expire_success():
    log = []
    m = make_manager(log)
    d = m.invite(valid_params())
    token = d.payload["record"]["invitation_id"]
    e = m.expire(token, now_seq=3)
    assert e.allowed
    assert e.payload["record"]["state"] == "expired"
    assert log[-1]["event"]["action"] == "expire"


def test_expire_rejects_unknown_token():
    log = []
    m = make_manager(log)
    e = m.expire("inv-nope", now_seq=3)
    assert not e.allowed
    assert e.reason == "unknown invitation"


def test_pending_for_lists_pending_only():
    log = []
    m = make_manager(
        log, allowed_invites=frozenset({("admin", "member"), ("admin", "viewer")})
    )
    d1 = m.invite(valid_params(role="member"))
    d2 = m.invite(valid_params(role="viewer"))
    assert len(m.pending_for("user-1")) == 2
    t1 = d1.payload["record"]["invitation_id"]
    m.accept(t1, AcceptParams(invitee_id="user-1", now_seq=1))
    remaining = m.pending_for("user-1")
    assert len(remaining) == 1
    assert next(iter(remaining)).role == "viewer"


def test_decision_round_trip():
    d = Decision(True, "ok", {"k": "v"})
    blob = d.to_dict()
    back = Decision.from_dict(blob)
    assert back.allowed is True
    assert back.reason == "ok"
    assert back.payload == {"k": "v"}


def _run_all():
    fns = sorted(
        (v for k, v in globals().items()
         if k.startswith("test_") and callable(v)),
        key=lambda f: f.__name__
    )
    passed, failed = 0, 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _run_all()
