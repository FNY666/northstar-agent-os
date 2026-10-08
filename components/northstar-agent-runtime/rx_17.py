"""HTML tag extractor

What this IS: an extractor for simple HTML open/close/self-closing tags.

What this IS NOT: an HTML parser -- nested content is not parsed.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_17_VERSION = "rx-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-17.v1"

HTML_TAG_RE = re.compile(r'</?[A-Za-z][A-Za-z0-9]*(?:\\s+[A-Za-z_:][A-Za-z0-9_.:-]*(?:\\s*=\\s*(?:\"[^\"]*\"|\\'[^\\']*\\'|[^\\s>]+))?)*\\s*/?>')
def find_tags(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HTML_TAG_RE.findall(text)

def strip_tags(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HTML_TAG_RE.sub("", text)


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
    assert find_tags("<div><p>hi</p></div>") == ["<div>", "<p>", "</p>", "</div>"]
    assert strip_tags("<b>bold</b>") == "bold"
    assert find_tags("<br/>") == ["<br/>"]
    assert find_tags("no tags") == []
    assert strip_tags("plain") == "plain"
    assert stdlib_only()
    print("17-html_tag OK")


if __name__ == "__main__":
    main()
