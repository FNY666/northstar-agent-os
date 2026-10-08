"""Tests for dx_11 mock LSP server."""
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

dx = _load("dx_11")


def _init():
    srv = dx.MockLSPServer()
    r = srv.handle({"id": 1, "method": "initialize", "params": {}})
    assert "capabilities" in r["result"]
    return srv


def test_not_initialized_errors():
    srv = dx.MockLSPServer()
    r = srv.handle({"id": 1, "method": "completion", "params": {}})
    assert r["error"]["code"] == -32002


def test_method_not_found():
    srv = _init()
    r = srv.handle({"id": 2, "method": "bogus", "params": {}})
    assert r["error"]["code"] == -32601


def test_custom_handler():
    srv = _init()
    srv.on("completion", lambda p: [{"label": "print"}])
    r = srv.handle({"id": 2, "method": "completion", "params": {}})
    assert r["result"] == [{"label": "print"}]


def test_did_open_tracks_docs():
    srv = _init()
    srv.handle({"method": "textDocument/didOpen",
                "params": {"uri": "file:///a.py", "text": "x = 1"}})
    assert srv.documents["file:///a.py"] == "x = 1"


def test_shutdown_blocks_further():
    srv = _init()
    srv.handle({"id": 1, "method": "shutdown", "params": {}})
    r = srv.handle({"id": 2, "method": "completion", "params": {}})
    assert r["error"]["code"] == -32600


def test_malformed_message_raises():
    srv = _init()
    with pytest.raises(dx.LSPError):
        srv.handle({"params": {}})


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX11_LSP_VERSION == "dx-lsp.v1"
