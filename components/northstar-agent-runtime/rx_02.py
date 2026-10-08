"""IPv4 address matcher

What this IS: strict dotted-quad IPv4 validation (each octet 0-255).

What this IS NOT: an IPv6 matcher -- see rx-03.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_02_VERSION = "rx-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-02.v1"

IPV4_RE = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
def is_ipv4(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return IPV4_RE.fullmatch(text) is not None

def find_ipv4s(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return IPV4_RE.findall(text)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    assert is_ipv4("192.168.0.1")
    assert is_ipv4("255.255.255.255")
    assert not is_ipv4("999.1.1.1")
    assert not is_ipv4("1.2.3")
    assert find_ipv4s("ping 10.0.0.1 and 8.8.8.8") == ["10.0.0.1", "8.8.8.8"]
    assert stdlib_only()
    print("02-ipv4 OK")


if __name__ == "__main__":
    main()
