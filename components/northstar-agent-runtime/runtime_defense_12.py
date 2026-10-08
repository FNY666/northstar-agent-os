"""Runtime defense 12: proxy enforcement (config), Simulated.

Forces all egress through an HTTP(S) proxy: proxy env config, no-direct
fallback, and CONNECT allowlist.  Direct connections are denied by
policy (companion to the network policy module).

What this IS: proxy enforcement config + URL allow check.
What this IS NOT: an actual proxy server.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import FrozenSet, Tuple
from urllib.parse import urlparse

#: Module version.
RUNTIME_DEFENSE_12_VERSION = "runtime-defense-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.runtime-defense-12.v1"


class ProxyError(Exception):
    """Fail-closed: bad proxy config raises."""


@dataclass(frozen=True)
class ProxyConfig:
    """Enforced proxy configuration."""

    proxy_url: str  # e.g. "http://proxy.internal:3128"
    no_direct: bool = True  # direct connections denied
    connect_allowlist: FrozenSet[str] = frozenset()  # allowed CONNECT hosts

    def __post_init__(self):
        parsed = urlparse(self.proxy_url)
        if parsed.scheme not in ("http", "https"):
            raise ProxyError(f"bad proxy scheme in {self.proxy_url!r}")
        if not parsed.hostname or not parsed.port:
            raise ProxyError(f"proxy needs host:port: {self.proxy_url!r}")

    def env(self) -> dict:
        """Environment for proxied processes."""
        return {
            "http_proxy": self.proxy_url,
            "https_proxy": self.proxy_url,
            "HTTP_PROXY": self.proxy_url,
            "HTTPS_PROXY": self.proxy_url,
            "no_proxy": "localhost,127.0.0.1",
        }

    def check_connect(self, host: str, port: int) -> Tuple[bool, str]:
        """Check a CONNECT request against the allowlist."""
        if port not in (80, 443):
            return False, f"port {port} not allowed for CONNECT"
        h = host.strip().lower().rstrip(".")
        for entry in self.connect_allowlist:
            if entry.startswith("*."):
                suffix = entry[2:]
                if h == suffix or h.endswith("." + suffix):
                    return True, f"CONNECT allowed: {h}"
            elif h == entry:
                return True, f"CONNECT allowed: {h}"
        return False, f"CONNECT denied: {h}"


def build_config(proxy_url: str, connect_allowlist=()) -> ProxyConfig:
    """Build proxy config.  Empty allowlist -> all CONNECT denied."""
    return ProxyConfig(
        proxy_url=proxy_url,
        connect_allowlist=frozenset(
            h.strip().lower().rstrip(".") for h in connect_allowlist
        ),
    )


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing", "urllib"}
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
    cfg = build_config("http://proxy.internal:3128", ["api.example.com", "*.cdn.net"])
    env = cfg.env()
    assert env["https_proxy"] == "http://proxy.internal:3128"
    assert cfg.no_direct is True
    ok, _ = cfg.check_connect("api.example.com", 443)
    assert ok is True
    ok, _ = cfg.check_connect("x.cdn.net", 443)
    assert ok is True
    ok, _ = cfg.check_connect("evil.com", 443)
    assert ok is False
    ok, _ = cfg.check_connect("api.example.com", 22)
    assert ok is False

    try:
        build_config("ftp://proxy:21")
        raise AssertionError("should raise")
    except ProxyError:
        pass
    try:
        build_config("http://proxy-no-port")
        raise AssertionError("should raise")
    except ProxyError:
        pass

    assert stdlib_only()
    print("runtime-defense-12 OK: proxy config, CONNECT allowlist, stdlib")


if __name__ == "__main__":
    main()
