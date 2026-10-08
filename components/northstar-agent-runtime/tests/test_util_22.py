"""util_22 tests."""

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


m = _load("util_22")

def test_parse_and_epoch():
    import datetime
    dt = m.parse_iso("2026-10-09T12:30:00Z")
    assert dt.year == 2026
    assert m.to_epoch(datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)) == 0


def test_day_math():
    import datetime
    dt = m.parse_iso("2026-10-09T12:30:00Z")
    assert m.start_of_day(dt).hour == 0
    assert m.add_days(dt, 1).day == 10


def test_weekend():
    import datetime
    assert m.is_weekend(datetime.datetime(2026, 10, 10)) is True
    assert m.is_weekend(datetime.datetime(2026, 10, 9)) is False


def test_today_iso():
    import datetime
    assert m.today_iso() == datetime.date.today().isoformat()


def test_stdlib_only():
    assert m.stdlib_only() is True
