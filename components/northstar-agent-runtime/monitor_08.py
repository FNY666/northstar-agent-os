"""SIEM integration: CEF format builder (mock), Simulated.

Builds Common Event Format (CEF) syslog messages for shipping gate
decisions, denials, and anomalies to a SIEM:
CEF:Version|Vendor|Product|Version|Signature ID|Name|Severity|extensions

Extensions are key=value pairs with proper escaping of |, =, and \\.

What this IS: the event-serialization layer; host forwards the
rendered string to syslog.

What this IS NOT:
* Not a syslog sender -- no network. Host ships it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Dict

#: Module version.
MONITOR_08_VERSION = "monitor-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-08.v1"

_VALID_SEVERITIES = {str(i) for i in range(0, 11)}


class CefError(Exception):
    """Fail-closed."""


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")


@dataclass(frozen=True)
class CefEvent:
    vendor: str = "Northstar"
    product: str = "AgentOS"
    product_version: str = "1.0"
    signature_id: str = ""
    name: str = ""
    severity: str = "5"
    extensions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.signature_id or not self.name:
            raise CefError("signature_id and name required")
        if self.severity not in _VALID_SEVERITIES:
            raise CefError(f"severity must be 0-10, got {self.severity!r}")
        for k in self.extensions:
            if not isinstance(k, str) or not k or any(c in k for c in "|= "):
                raise CefError(f"bad extension key {k!r}")

    def render(self) -> str:
        header = (
            f"CEF:0|{_escape(self.vendor)}|{_escape(self.product)}|"
            f"{_escape(self.product_version)}|{_escape(self.signature_id)}|"
            f"{_escape(self.name)}|{self.severity}|"
        )
        ext = " ".join(
            f"{k}={_escape(str(v))}" for k, v in self.extensions.items()
        )
        return header + ext


def gate_denial_cef(tool: str, gate: str, reason: str) -> str:
    """Convenience builder for a gate denial event."""
    if not tool or not gate:
        raise CefError("tool and gate required")
    return CefEvent(
        signature_id="gate-deny",
        name="Gate denied tool call",
        severity="8",
        extensions={"dvc": "northstar", "act": "deny", "tool": tool, "gate": gate, "msg": reason},
    ).render()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    msg = gate_denial_cef("exec", "authorize", "rm -rf blocked")
    assert msg.startswith("CEF:0|Northstar|AgentOS|")
    assert "act=deny" in msg and "tool=exec" in msg
    # Escaping.
    e = CefEvent(
        signature_id="x", name="a|b=c\\d", severity="3",
        extensions={"k": "v|w"},
    )
    rendered = e.render()
    assert "a\\|b\\=c\\\\d" in rendered and "k=v\\|w" in rendered
    try:
        CefEvent(signature_id="x", name="y", severity="99")
        raise AssertionError("should raise")
    except CefError:
        pass
    try:
        CefEvent(signature_id="", name="y")
        raise AssertionError("should raise")
    except CefError:
        pass
    assert stdlib_only()
    print("monitor-08 OK: CEF render, escaping, fail-closed, stdlib")


if __name__ == "__main__":
    main()
