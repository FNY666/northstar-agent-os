"""SVG exfiltration defense: active content hidden in vector images, Simulated.

Detects (case-insensitive):
- <script> tags embedded in SVG
- <foreignObject> (HTML smuggling vector)
- Event-handler attributes (onload=, onclick=, onerror=, ...)
- xlink:href / href pointing at http(s)/data:
- <image> with an external href
- <iframe>, <embed>, <object> tags inside SVG

What this IS:
* A gate-layer regex scan over SVG text before it is rendered or stored.
* Detection only -- it flags active-content constructs and returns snippets.

What this IS NOT:
* Not an SVG/XML parser -- no DOM, no namespace resolution.
* Not a sanitizer -- the host decides whether to strip or reject.
"""

from __future__ import annotations

import ast
import re
from typing import Any

#: Module version.
OUT_DEF_49_VERSION = "out-def-49.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-49.v1"


class OutDef49Error(Exception):
    """Fail-closed."""


#: Maximum evidence snippet length.
_SNIPPET_LEN = 80

_EXT = r"(?:https?:|data:)"

#: (label, pattern) pairs, all matched case-insensitively.
_SVG_PATTERNS: list = [
    ("<script> tag", re.compile(r"<\s*script[\s>]", re.IGNORECASE)),
    ("<foreignObject> tag", re.compile(r"<\s*foreignobject[\s>]", re.IGNORECASE)),
    (
        "event-handler attribute",
        re.compile(r"\son\w+\s*=", re.IGNORECASE),
    ),
    (
        "href/xlink:href to http(s)/data:",
        re.compile(
            r"(?:xlink:href|href)\s*=\s*['\"]\s*" + _EXT, re.IGNORECASE
        ),
    ),
    (
        "<image> with external href",
        re.compile(
            r"<\s*image\b[^>]*?(?:xlink:href|href)\s*=\s*['\"]\s*" + _EXT,
            re.IGNORECASE,
        ),
    ),
    ("<iframe> tag", re.compile(r"<\s*iframe[\s>]", re.IGNORECASE)),
    ("<embed> tag", re.compile(r"<\s*embed[\s>]", re.IGNORECASE)),
    ("<object> tag", re.compile(r"<\s*object[\s>]", re.IGNORECASE)),
]


def detect_svg_exfil(svg: str) -> tuple[bool, str, list]:
    """Scan SVG text for exfil/active-content constructs.

    Returns (threat_found, reason, evidence). threat_found=True means exfil
    was detected. Matching is case-insensitive; snippets truncated to 80 chars.
    Raises OutDef49Error (fail-closed) on malformed input.
    """
    if not isinstance(svg, str):
        raise OutDef49Error(f"expected str, got {type(svg).__name__}")
    evidence: list = []
    for label, pattern in _SVG_PATTERNS:
        for match in pattern.finditer(svg):
            evidence.append(
                {"pattern": label, "snippet": match.group(0)[:_SNIPPET_LEN]}
            )
    if evidence:
        return (
            True,
            f"{len(evidence)} suspicious SVG construct(s) detected",
            evidence,
        )
    return False, "svg clean", []


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
    # <script> tag (mixed case).
    found, _, _ = detect_svg_exfil('<svg><ScRiPt>alert(1)</ScRiPt></svg>')
    assert found is True

    # <foreignObject>.
    found, _, _ = detect_svg_exfil(
        '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"/></foreignObject></svg>'
    )
    assert found is True

    # Event-handler attribute.
    found, _, _ = detect_svg_exfil('<svg><circle ONLOAD="evil()"/></svg>')
    assert found is True

    # xlink:href to http.
    found, _, _ = detect_svg_exfil(
        '<svg><a xlink:href="https://evil.example/x"><text>hi</text></a></svg>'
    )
    assert found is True

    # <image> with external href.
    found, _, _ = detect_svg_exfil(
        '<svg><image href="data:image/png;base64,AAAA"/></svg>'
    )
    assert found is True

    # <iframe> / <embed> / <object>.
    for tag in ("iframe", "embed", "object"):
        found, _, _ = detect_svg_exfil(f"<svg><{tag} src='x'/></svg>")
        assert found is True, tag

    # Clean SVG passes (xmlns http:// is not an href).
    found, reason, _ = detect_svg_exfil(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<circle cx="5" cy="5" r="4" fill="red"/></svg>'
    )
    assert found is False, reason

    # Fail-closed on malformed input.
    try:
        detect_svg_exfil(123)  # type: ignore[arg-type]
    except OutDef49Error:
        pass
    else:
        raise AssertionError("expected OutDef49Error")

    assert stdlib_only()
    print("out-def-49 OK: script, foreignObject, handlers, hrefs, embeds, stdlib")


if __name__ == "__main__":
    main()
