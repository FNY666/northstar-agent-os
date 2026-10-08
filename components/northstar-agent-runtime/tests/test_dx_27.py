"""Tests for dx_27. changelog."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_27")

def _log():
    log = dx.Changelog()
    log.add(dx.ChangelogEntry("fix", "gate", "block recursive bombs"))
    log.add(dx.ChangelogEntry("feat", "dx", "code actions"))
    log.add(dx.ChangelogEntry("fix", "", "typo"))
    return log


def test_grouped_render():
    out = _log().render()
    assert out.index("## Added") < out.index("## Fixed")
    assert "- **gate:** block recursive bombs" in out


def test_counts():
    log = _log()
    assert log.count("fix") == 2
    assert log.count() == 3


def test_unknown_type_raises():
    log = dx.Changelog()
    with pytest.raises(dx.ChangelogError):
        log.add(dx.ChangelogEntry("chore", "x", "y"))


def test_empty_message_raises():
    log = dx.Changelog()
    with pytest.raises(dx.ChangelogError):
        log.add(dx.ChangelogEntry("fix", "x", ""))


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX27_CHANGELOG_VERSION == "dx-changelog.v1"
