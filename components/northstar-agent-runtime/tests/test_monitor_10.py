"""Tests for monitor_10 (threat intel feeds)."""
import importlib.util, sys, time
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


ti = _load("monitor_10")


def test_add_remove_list():
    feed = ti.IntelFeed("f")
    feed.add(ti.Ioc("ip", "1.2.3.4", "s"))
    feed.add(ti.Ioc("domain", "evil.example", "s"))
    assert feed.count() == 2
    assert len(feed.list("domain")) == 1
    assert feed.remove("ip", "1.2.3.4") is True
    assert feed.count() == 1


def test_expiry():
    feed = ti.IntelFeed("f")
    old = ti.Ioc("hash", "ab" * 32, "s", ttl_s=1)
    old.last_seen_ns = time.time_ns() - 5_000_000_000
    feed.add(old)
    assert feed.purge_expired() == 1
    assert feed.count() == 0


def test_bad_ioc():
    import pytest

    with pytest.raises(ti.IntelError):
        ti.Ioc("ip", "999.1.1.1", "s")
    with pytest.raises(ti.IntelError):
        ti.Ioc("bogus", "x", "s")


def test_bad_list_type():
    import pytest

    feed = ti.IntelFeed("f")
    with pytest.raises(ti.IntelError):
        feed.list("bogus")


def test_stdlib_only():
    assert ti.stdlib_only() is True
