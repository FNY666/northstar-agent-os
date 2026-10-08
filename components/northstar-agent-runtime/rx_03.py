"""IPv6 address matcher

What this IS: a practical IPv6 matcher covering full and compressed forms.

What this IS NOT: an RFC-4291 pedant -- zone IDs and IPv4-mapped tails are not covered.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_03_VERSION = "rx-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-03.v1"

IPV6_RE = re.compile(r'(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:)*::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}')
def is_ipv6(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return IPV6_RE.fullmatch(text) is not None

def find_ipv6s(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return IPV6_RE.findall(text)


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
    assert is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert is_ipv6("::1")
    assert not is_ipv6("12345::")
    assert not is_ipv6("not-an-ip")
    assert find_ipv6s("host ::1 here") == ["::1"]
    assert stdlib_only()
    print("03-ipv6 OK")


if __name__ == "__main__":
    main()
