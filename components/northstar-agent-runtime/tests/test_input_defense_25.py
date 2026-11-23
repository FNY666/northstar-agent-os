"""Tests for input_defense_25."""
import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


mod = _load("input_defense_25")

def test_issue_verify():
    p = mod.MockCaptchaProvider()
    ch, ans = p.issue()
    assert p.verify(ch.challenge_id, ans) is True


def test_wrong_answer():
    p = mod.MockCaptchaProvider()
    ch, _ = p.issue()
    assert p.verify(ch.challenge_id, "nope") is False


def test_replay_rejected():
    p = mod.MockCaptchaProvider()
    ch, ans = p.issue()
    assert p.verify(ch.challenge_id, ans) is True
    assert p.verify(ch.challenge_id, ans) is False


def test_require_captcha():
    p = mod.MockCaptchaProvider()
    ch, ans = p.issue()
    assert mod.require_captcha(p, ch.challenge_id, ans) is True
    ch2, _ = p.issue()
    try:
        mod.require_captcha(p, ch2.challenge_id, "bad")
    except mod.InputDefenseError:
        return
    raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

