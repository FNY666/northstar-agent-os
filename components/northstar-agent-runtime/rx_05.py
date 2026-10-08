"""E.164 phone number matcher

What this IS: a matcher for international phone numbers in E.164 form.

What this IS NOT: a phone-number validator for a specific country.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_05_VERSION = "rx-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-05.v1"

E164_RE = re.compile(r'\\+[1-9][0-9]{6,14}')
def is_e164(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return E164_RE.fullmatch(text) is not None

def find_phones(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return E164_RE.findall(text)


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
    assert is_e164("+14155552671")
    assert is_e164("+8613800138000")
    assert not is_e164("4155552671")
    assert not is_e164("+0123")
    assert find_phones("call +14155552671 now") == ["+14155552671"]
    assert stdlib_only()
    print("05-e164 OK")


if __name__ == "__main__":
    main()
