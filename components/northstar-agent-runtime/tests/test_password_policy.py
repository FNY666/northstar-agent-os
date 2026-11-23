"""Targeted tests for password_policy (NIST 800-63B shape, simulated)."""

import pytest

from password_policy import (
    MODULE_VERSION,
    NIST_MAX_SUPPORTED,
    NIST_MIN_LENGTH,
    PASSWORD_POLICY_SCHEMA,
    PolicyDecision,
    PolicyRules,
    PasswordPolicy,
    password_policy_audit_event,
)


def test_strong_passphrase_accepted():
    p = PasswordPolicy()
    d = p.check("correct-horse-battery-staple-2026!", seq=1)
    assert isinstance(d, PolicyDecision)
    assert d.accepted is True
    assert d.reasons == ()
    assert d.schema == PASSWORD_POLICY_SCHEMA


def test_too_short_rejected_with_reason():
    p = PasswordPolicy()
    d = p.check("abc", seq=1)
    assert not d.accepted
    assert any(r.startswith("too-short") for r in d.reasons)


def test_nist_min_length_default_is_eight():
    assert NIST_MIN_LENGTH == 8
    rules = PolicyRules()
    assert rules.min_length == 8
    p = PasswordPolicy()
    assert p.check("abcdefgh", seq=1, screen_breach=False).accepted  # exactly min length
    assert not p.check("abcdefg", seq=2, screen_breach=False).accepted  # one short


def test_too_long_rejected():
    p = PasswordPolicy()
    d = p.check("x" * 200, seq=1, screen_breach=False)
    assert not d.accepted
    assert any(r.startswith("too-long") for r in d.reasons)


def test_breach_corpus_hit_rejects():
    p = PasswordPolicy()
    assert p.breach("password") is True
    assert p.breach("qwerty") is True
    d = p.check("password", seq=1)
    assert not d.accepted
    assert "breach-hit" in d.reasons


def test_breach_miss_for_strong_value():
    p = PasswordPolicy()
    assert p.breach("correct-horse-battery-staple-2026!") is False


def test_history_reuse_rejected():
    p = PasswordPolicy()
    pw = "unique-enrollment-value-99$"
    p.history(pw, seq=1)
    assert p.check_history(pw) is True
    d = p.check(pw, seq=2)
    assert not d.accepted
    assert "history-hit" in d.reasons


def test_history_stores_digest_not_plaintext():
    p = PasswordPolicy()
    pw = "never-store-me-plaintext-7!"
    digest = p.history(pw, seq=1)
    assert pw not in repr(p._history)
    assert digest in p._history
    assert len(digest) == 64


def test_username_substring_rejected():
    p = PasswordPolicy()
    d = p.check("super-alice-wonderland-42", seq=1, username="alice", screen_breach=False)
    assert not d.accepted
    assert "contains-username" in d.reasons


def test_repeat_run_ceiling():
    rules = PolicyRules(max_repeat_run=3)
    p = PasswordPolicy(rules)
    d = p.check("abbbb-cdef-ghij", seq=1, screen_breach=False)
    assert not d.accepted
    assert any(r.startswith("repeat-run") for r in d.reasons)


def test_composition_flags_off_by_default_nist():
    rules = PolicyRules()
    assert not (rules.require_upper or rules.require_lower or rules.require_digit or rules.require_symbol)
    p = PasswordPolicy()
    assert p.check("alllowercasewords-here-ok", seq=1, screen_breach=False).accepted


def test_composition_flags_enforceable_when_pinned():
    rules = PolicyRules(require_upper=True, require_digit=True)
    p = PasswordPolicy(rules)
    d = p.check("nouppercase-nodigits-here", seq=1, screen_breach=False)
    assert not d.accepted
    assert "missing-upper" in d.reasons
    assert "missing-digit" in d.reasons
    ok = p.check("HasUpper-And-9-Digits", seq=2, screen_breach=False)
    assert ok.accepted


def test_fail_closed_on_bad_inputs():
    p = PasswordPolicy()
    with pytest.raises(TypeError):
        p.check(None, seq=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        p.check(True, seq=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        p.check(b"bytes", seq=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        p.check("valid-password-ok", seq=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        p.breach(123)  # type: ignore[arg-type]


def test_rule_pin_validation():
    with pytest.raises(ValueError):
        PolicyRules(min_length=0)
    with pytest.raises(ValueError):
        PolicyRules(max_length=32)  # below NIST_MAX_SUPPORTED
    with pytest.raises(ValueError):
        PolicyRules(min_length=20, max_length=10)
    with pytest.raises(TypeError):
        PolicyRules(min_length=True)  # type: ignore[arg-type]


def test_audit_events_are_digest_only_and_schema_pinned():
    p = PasswordPolicy()
    p.check("password", seq=7)
    p.history("another-strong-value-55$", seq=8)
    for event in p.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert event["event"] == "password-policy"
        assert "password" not in str(event).lower().replace("password-policy", "")
        assert len(event["digest"]) == 64
    ev = password_policy_audit_event("checked", "a" * 64, 9)
    assert ev["audit_seq"] == 9
    with pytest.raises(ValueError):
        password_policy_audit_event("nope", "a" * 64, 1)
