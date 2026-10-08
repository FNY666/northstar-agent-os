"""XML comment matcher

What this IS: a matcher for <!-- ... --> comments (no nested dashes).

What this IS NOT: an XML parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_18_VERSION = "rx-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-18.v1"

XML_COMMENT_RE = re.compile(r'<!--[^-]*(?:-(?!->)[^-]*)*-->')
def is_xml_comment(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return XML_COMMENT_RE.fullmatch(text) is not None

def find_xml_comments(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return XML_COMMENT_RE.findall(text)


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
    assert is_xml_comment("<!-- hi -->")
    assert is_xml_comment("<!--a-->")
    assert not is_xml_comment("<!-- bad -- comment -->")
    assert not is_xml_comment("<!-- unclosed")
    assert find_xml_comments("x <!-- a --> y <!-- b -->") == ["<!-- a -->", "<!-- b -->"]
    assert stdlib_only()
    print("18-xml_comment OK")


if __name__ == "__main__":
    main()
