"""Credit card number + Luhn matcher

What this IS: a 13-19 digit card-number matcher with a Luhn check digit validation.

What this IS NOT: a PCI-compliant handler -- never log real card numbers.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_12_VERSION = "rx-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-12.v1"

CC_RE = re.compile(r'\\d{13,19}')
def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def is_card_number(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CC_RE.fullmatch(text) is not None and _luhn_ok(text)

def find_card_numbers(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return [m for m in CC_RE.findall(text) if _luhn_ok(m)]


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
    assert is_card_number("4111111111111111")
    assert is_card_number("5500005555555559")
    assert not is_card_number("4111111111111112")
    assert not is_card_number("123")
    assert find_card_numbers("card 4111111111111111 ok") == ["4111111111111111"]
    assert stdlib_only()
    print("12-cc_luhn OK")


if __name__ == "__main__":
    main()
