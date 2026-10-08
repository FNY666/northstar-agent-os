"""Tests for dx_01 CLI framework."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_01")


def _app():
    app = dx.CLIApp("ns")

    @app.command("ping", help="ping", arguments=[{"flags": ["--count"], "type": int, "default": 1}])
    def _ping(args):
        return 0 if args["count"] > 0 else 2

    return app


def test_dispatch_ok():
    assert _app().run(["ping"]) == 0
    assert _app().run(["ping", "--count", "5"]) == 0


def test_handler_return_code():
    assert _app().run(["ping", "--count", "0"]) == 2


def test_unknown_command_raises():
    import pytest
    with pytest.raises(dx.CLIError):
        _app().run(["nope"])


def test_duplicate_command_raises():
    import pytest
    app = dx.CLIApp("ns")

    @app.command("x")
    def _x(a):
        return 0

    with pytest.raises(dx.CLIError):
        @app.command("x")
        def _x2(a):
            return 0


def test_help_lists_commands():
    assert "ping" in _app().help_text()


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX01_CLI_VERSION == "dx-cli.v1"
