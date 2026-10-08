"""Tests for tool_system_17."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_17")
import pytest

def _ledger():
    ledger = m.BillingLedger(default_cost_cents=5)
    ledger.set_cost("search", 10)
    return ledger

def test_cost_table_and_fallback():
    ledger = _ledger()
    assert ledger.cost_for("search") == 10
    assert ledger.cost_for("unknown") == 5

def test_record_and_totals():
    ledger = _ledger()
    ledger.record("search", run_id="r1")
    ledger.record("search", run_id="r1")
    ledger.record("unknown", run_id="r1")
    assert ledger.total_cost("search") == 20
    assert ledger.total_cost("unknown") == 5
    assert ledger.total_all() == 25
    assert ledger.call_count("search") == 2
    assert ledger.call_count() == 3

def test_invoice():
    ledger = _ledger()
    ledger.record("search", run_id="r1")
    ledger.record("search", run_id="r1")
    ledger.record("unknown", run_id="r2")
    inv = ledger.invoice("r1")
    assert inv.currency == "USD"
    assert inv.total_cents == 20
    assert [(l.tool, l.calls, l.cost_cents) for l in inv.lines] == [
        ("search", 2, 20)
    ]
    empty = ledger.invoice("r9")
    assert empty.total_cents == 0 and empty.lines == []

def test_negative_cost():
    ledger = _ledger()
    with pytest.raises(m.ToolSystem17Error):
        ledger.set_cost("x", -1)
    with pytest.raises(m.ToolSystem17Error):
        m.BillingLedger(default_cost_cents=-1)

def test_stdlib():
    assert m.stdlib_only() is True
