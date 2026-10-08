"""MAC address matcher

What this IS: a colon/dash-separated MAC-48 matcher.

What this IS NOT: an EUI-64 matcher.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_11_VERSION = "rx-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-11.v1"

MAC_RE = re.compile(r'(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
def is_mac(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return MAC_RE.fullmatch(text) is not None

def find_macs(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return MAC_RE.findall(text)


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
    assert is_mac("00:1A:2b:3C:4d:5E")
    assert is_mac("aa-bb-cc-dd-ee-ff")
    assert not is_mac("00:1A:2B:3C:4D")
    assert not is_mac("00:1A:2B:3C:4D:5E:6F")
    assert find_macs("mac 00:1A:2b:3C:4d:5E ok") == ["00:1A:2b:3C:4d:5E"]
    assert stdlib_only()
    print("11-mac OK")


if __name__ == "__main__":
    main()
