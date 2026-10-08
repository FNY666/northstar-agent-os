"""Tests for dx_02 mock REPL."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_02")


def test_echo():
    r = dx.MockREPL().eval_line("echo hi there")
    assert r.ok and r.output == "hi there"


def test_unknown_command_is_error_result():
    r = dx.MockREPL().eval_line("frobnicate")
    assert not r.ok and "unknown command" in r.output


def test_exit_stops_script():
    repl = dx.MockREPL()
    out = repl.run_script(["echo a", "exit", "echo b"])
    assert len(out) == 2
    assert out[-1].output == "bye"


def test_history_builtin():
    repl = dx.MockREPL()
    repl.eval_line("echo one")
    r = repl.eval_line("history")
    assert "echo one" in r.output


def test_custom_command():
    repl = dx.MockREPL()
    repl.register("double", lambda argv: str(int(argv[1]) * 2))
    assert repl.eval_line("double 21").output == "42"


def test_handler_exception_is_error_result():
    repl = dx.MockREPL()
    repl.register("boom", lambda argv: 1 / 0)
    r = repl.eval_line("boom")
    assert not r.ok and "ZeroDivisionError" in r.output


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX02_REPL_VERSION == "dx-repl.v1"
