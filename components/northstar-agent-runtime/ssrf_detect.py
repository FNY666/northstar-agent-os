"""Detect literal non-public HTTP(S) destinations in untrusted output.

This helper is a signal for review, not an egress control. It does not resolve
hostnames or make network requests. It canonicalizes both standard IP literals
and legacy IPv4 numeric forms understood by common libc resolvers, but cannot
prove that a hostname is safe; callers must enforce destination policy at the
actual connection boundary.
"""
from __future__ import annotations

import ast
from ipaddress import ip_address
from pathlib import Path
import socket
from urllib.parse import urlsplit

VERSION = "ssrf-detect.v2"


def is_private_url(url: str) -> bool:
    """Return whether an HTTP(S) URL names localhost or a non-global IP.

    User information, ports, IPv6 brackets, and URL syntax are parsed by the
    standard URL parser. Hostnames other than localhost are deliberately not
    resolved here: DNS policy and rebinding protection belong at connect time.
    """
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return False
        host = parsed.hostname
    except ValueError:
        return False
    if not host:
        return False

    host = host.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return not ip_address(host).is_global
    except ValueError:
        # inet_aton parses legacy IPv4 forms accepted by common system
        # resolvers (127.1, integer, octal, hex). Keep this local-only: it
        # canonicalizes a literal and never resolves a hostname.
        try:
            return not ip_address(socket.inet_aton(host)).is_global
        except (OSError, ValueError):
            return False


def stdlib_only() -> bool:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "ipaddress", "pathlib", "socket", "urllib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] not in allowed for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    assert is_private_url("http://127.0.0.1/")
    assert is_private_url("http://192.168.1.1/")
    assert not is_private_url("https://example.com/")
    assert stdlib_only()
    print("ssrf-detect OK")


if __name__ == "__main__":
    main()
