"""CSS exfiltration defense: data smuggled in stylesheets, Simulated.

Detects:
- url(data:...) embedded payloads
- url(http...)/url(//...) external references
- expression(...) dynamic CSS (IE-era script injection)
- @import with http(s)/protocol-relative URLs
- behavior: (HTC component loading) and -moz-binding (XBL binding)

What this IS:
* A gate-layer regex scan over CSS text before it is rendered or stored.
* Detection only -- it flags suspicious constructs and returns snippets.

What this IS NOT:
* Not a CSS parser -- no stylesheet AST, no cascade resolution.
* Not a URL allowlister -- the host decides which origins are permitted.
"""

from __future__ import annotations

import ast
import re
from typing import Any

#: Module version.
OUT_DEF_47_VERSION = "out-def-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-47.v1"


class OutDef47Error(Exception):
    """Fail-closed."""


#: Maximum evidence snippet length.
_SNIPPET_LEN = 80

#: Long encoded payloads smuggled via the content: property.
_LONG_CONTENT_LEN = 64

#: (label, pattern) pairs scanned case-insensitively over the CSS text.
_CSS_PATTERNS: list = [
    ("url(data:...)", re.compile(r"url\(\s*['\"]?\s*data:", re.IGNORECASE)),
    (
        "external url()",
        re.compile(r"url\(\s*['\"]?\s*(?:https?:|//)", re.IGNORECASE),
    ),
    ("expression()", re.compile(r"\bexpression\s*\(", re.IGNORECASE)),
    (
        "@import with http",
        re.compile(r"@import\b[^;]*?(?:https?:|//)", re.IGNORECASE),
    ),
    ("behavior:", re.compile(r"\bbehavior\s*:", re.IGNORECASE)),
    ("-moz-binding", re.compile(r"-moz-binding", re.IGNORECASE)),
    (
        "content: with long encoded string",
        re.compile(
            r"\bcontent\s*:\s*['\"][^'\"]{" + str(_LONG_CONTENT_LEN) + r",}['\"]",
            re.IGNORECASE,
        ),
    ),
]


def detect_css_exfil(css: str) -> tuple[bool, str, list]:
    """Scan CSS text for exfil constructs.

    Returns (threat_found, reason, evidence). threat_found=True means exfil
    was detected. Evidence snippets are truncated to 80 chars.
    Raises OutDef47Error (fail-closed) on malformed input.
    """
    if not isinstance(css, str):
        raise OutDef47Error(f"expected str, got {type(css).__name__}")
    evidence: list = []
    for label, pattern in _CSS_PATTERNS:
        for match in pattern.finditer(css):
            evidence.append(
                {"pattern": label, "snippet": match.group(0)[:_SNIPPET_LEN]}
            )
    if evidence:
        return (
            True,
            f"{len(evidence)} suspicious CSS construct(s) detected",
            evidence,
        )
    return False, "css clean", []


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
    # url(data:...) payload.
    found, _, evidence = detect_css_exfil(
        ".x { background: url(data:image/png;base64,iVBORw0KGgo=); }"
    )
    assert found is True
    assert evidence[0]["pattern"] == "url(data:...)"
    assert len(evidence[0]["snippet"]) <= _SNIPPET_LEN

    # External url().
    found, _, _ = detect_css_exfil('.x { background: url("https://evil.example/a.png"); }')
    assert found is True

    # expression().
    found, _, _ = detect_css_exfil(".x { width: expression(alert(1)); }")
    assert found is True

    # behavior: and -moz-binding.
    found, _, _ = detect_css_exfil(".x { behavior: url(evil.htc); -moz-binding: url(evil.xml#x); }")
    assert found is True

    # @import with http.
    found, _, _ = detect_css_exfil('@import url("http://evil.example/a.css");')
    assert found is True

    # content: with long encoded string.
    found, _, _ = detect_css_exfil('.x::after { content: "' + "Q" * 70 + '"; }')
    assert found is True

    # Clean CSS passes.
    found, reason, _ = detect_css_exfil(
        'body { color: red; font-size: 14px; } .x::after { content: "ok"; }'
    )
    assert found is False, reason

    # Fail-closed on malformed input.
    try:
        detect_css_exfil(b"not str")  # type: ignore[arg-type]
    except OutDef47Error:
        pass
    else:
        raise AssertionError("expected OutDef47Error")

    assert stdlib_only()
    print("out-def-47 OK: data-url, external url, expression, import, behavior, stdlib")


if __name__ == "__main__":
    main()
