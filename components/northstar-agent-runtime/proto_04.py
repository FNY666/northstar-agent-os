"""XML parser/validator (stdlib ElementTree).

What this IS: parser/validator for XML.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete XML implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

#: Module version.
PROTO_04_VERSION = "proto-04-xml.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-04-xml.v1"


class Proto04Error(Exception):
    """Fail-closed."""


def parse_xml(text: str):
    """Parse XML. Returns the root Element. Raises Proto04Error."""
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise Proto04Error("invalid XML: %s" % exc)


def xml_to_dict(elem) -> dict:
    """Convert an Element to a nested dict."""
    node = {"tag": elem.tag, "attrib": dict(elem.attrib)}
    children = [xml_to_dict(c) for c in elem]
    text = (elem.text or "").strip()
    if children:
        node["children"] = children
    if text:
        node["text"] = text
    return node


def root_tag(text: str) -> str:
    """Return the root tag name."""
    return parse_xml(text).tag


def validate_xml(text: str) -> tuple:
    """Validate XML well-formedness. Returns (ok, reason)."""
    try:
        parse_xml(text)
    except Proto04Error as exc:
        return False, str(exc)
    return True, "well-formed XML"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "xml"}
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
    root = parse_xml('<a x="1"><b>hi</b></a>')
    assert root_tag('<a x="1"><b>hi</b></a>') == "a"
    d = xml_to_dict(root)
    assert d["attrib"] == {"x": "1"} and d["children"][0]["text"] == "hi"
    ok, _ = validate_xml("<a><b></a>")
    assert ok is False

    assert stdlib_only()
    print("proto-04 (xml): OK")


if __name__ == "__main__":
    main()
