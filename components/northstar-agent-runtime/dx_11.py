"""DX-11: LSP server (mock protocol), Simulated.

Mock Language Server Protocol handler: accepts dict messages shaped
like JSON-RPC ({method, params, id}) and returns {result} or {error}.
Supported: initialize, textDocument/didOpen, completion, hover,
definition, references, shutdown.

Fail-closed: unknown methods return a MethodNotFound error object;
requests before initialize (except initialize itself) return an
error; malformed messages raise.

What this IS: the LSP message dispatch surface for testing clients.
What this IS NOT: not a real language server (no analysis).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
DX11_LSP_VERSION = "dx-lsp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-lsp.v1"


class LSPError(Exception):
    """Fail-closed: malformed messages raise."""


@dataclass
class MockLSPServer:
    """Deterministic mock LSP server."""

    _initialized: bool = field(default=False, init=False, repr=False)
    _docs: Dict[str, str] = field(default_factory=dict, init=False, repr=False)
    _shutdown: bool = field(default=False, init=False, repr=False)
    _handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = field(
        default_factory=dict, init=False, repr=False
    )

    def on(self, method: str, fn: Callable[[Dict[str, Any]], Any]) -> None:
        if not callable(fn):
            raise LSPError("handler must be callable")
        self._handlers[method] = fn

    def _builtin(self, method: str, params: Dict[str, Any]) -> Any:
        if method == "initialize":
            self._initialized = True
            return {"capabilities": {"completion": True, "hover": True,
                                     "definition": True, "references": True}}
        if method == "textDocument/didOpen":
            uri = params.get("uri", "")
            self._docs[uri] = params.get("text", "")
            return None
        if method == "shutdown":
            self._shutdown = True
            return None
        return "NOT_BUILTIN"

    def handle(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle one message dict.  Always returns a response dict."""
        if not isinstance(message, dict):
            raise LSPError("message must be dict")
        method = message.get("method")
        if not method or not isinstance(method, str):
            raise LSPError("message missing method")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            raise LSPError("params must be dict")
        msg_id = message.get("id")

        if self._shutdown and method != "exit":
            return {"id": msg_id, "error": {"code": -32600, "message": "server shut down"}}
        if method != "initialize" and not self._initialized:
            return {"id": msg_id, "error": {"code": -32002, "message": "not initialized"}}

        builtin = self._builtin(method, params)
        if builtin != "NOT_BUILTIN":
            return {"id": msg_id, "result": builtin}
        fn = self._handlers.get(method)
        if fn is None:
            return {"id": msg_id, "error": {"code": -32601,
                                            "message": f"method not found: {method}"}}
        try:
            return {"id": msg_id, "result": fn(params)}
        except Exception as e:
            return {"id": msg_id, "error": {"code": -32603,
                                            "message": f"handler failed: {type(e).__name__}"}}

    @property
    def documents(self) -> Dict[str, str]:
        return dict(self._docs)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    srv = MockLSPServer()
    r = srv.handle({"id": 1, "method": "completion", "params": {}})
    assert r["error"]["code"] == -32002  # not initialized
    r = srv.handle({"id": 1, "method": "initialize", "params": {}})
    assert "capabilities" in r["result"]
    srv.handle({"method": "textDocument/didOpen",
                "params": {"uri": "file:///a.py", "text": "x = 1"}})
    assert srv.documents["file:///a.py"] == "x = 1"
    srv.on("completion", lambda p: [{"label": "print"}])
    r = srv.handle({"id": 2, "method": "completion", "params": {}})
    assert r["result"] == [{"label": "print"}]
    r = srv.handle({"id": 3, "method": "bogus/method", "params": {}})
    assert r["error"]["code"] == -32601
    r = srv.handle({"id": 4, "method": "shutdown", "params": {}})
    assert r["result"] is None
    r = srv.handle({"id": 5, "method": "completion", "params": {}})
    assert r["error"]["code"] == -32600
    try:
        srv.handle({"params": {}})
        raise AssertionError("should raise")
    except LSPError:
        pass
    assert stdlib_only()
    print("dx_11 OK: lifecycle, dispatch, method-not-found, fail-closed")


if __name__ == "__main__":
    main()
