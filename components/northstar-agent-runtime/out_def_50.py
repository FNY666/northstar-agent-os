"""MathML exfiltration defense: payloads hidden in math markup, Simulated.

Detects (case-insensitive regex):
- <annotation> with an encoding other than MathML presentation/content/text
  (flags text/html, application/*, image/*, ...)
- <annotation-xml> with a non-MathML encoding
- href= / xlink:href= attributes on MathML elements
- <mglyph> with a src attribute (external glyph loading)
- <maction> with a nonstandard actiontype

What this IS:
* A gate-layer regex scan over MathML text before it is rendered or stored.
* Detection only -- it flags annotation smuggling and returns snippets.

What this IS NOT:
* Not a MathML/XML parser -- no DOM, no schema validation.
* Not a renderer policy -- the host decides whether to strip or reject.
"""

from __future__ import annotations

import ast
import re
from typing import Any

#: Module version.
OUT_DEF_50_VERSION = "out-def-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-50.v1"


class OutDef50Error(Exception):
    """Fail-closed."""


#: Maximum evidence snippet length.
_SNIPPET_LEN = 80

#: Encodings considered benign on <annotation>.
_BENIGN_ANNOTATION_ENCODING = frozenset(
    {
        "mathmlpresentation",
        "mathmlcontent",
        "text",
        "application/mathml-presentation+xml",
        "application/mathml-content+xml",
        "application/mathml+xml",
    }
)

#: actiontype values defined by the MathML spec for <maction>.
_STANDARD_ACTIONTYPES = frozenset({"toggle", "statusline", "tooltip"})

_ANNOTATION_RE = re.compile(
    r"<\s*annotation\b[^>]*?encoding\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE
)
_ANNOTATION_XML_RE = re.compile(
    r"<\s*annotation-xml\b[^>]*?encoding\s*=\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_HREF_RE = re.compile(
    r"<\s*(?:math|mrow|mi|mo|mn|ms|mtext|mfrac|msqrt|mroot|mstyle|mpadded|mphantom|mfenced|menclose|msub|msup|msubsup|munder|mover|munderover|mmultiscripts|mtable|mtr|mtd|maction)[^>]*?\b(?:xlink:href|href)\s*=\s*['\"]",
    re.IGNORECASE,
)
_MGLYPH_SRC_RE = re.compile(
    r"<\s*mglyph\b[^>]*?\bsrc\s*=", re.IGNORECASE
)
_MACTION_TYPE_RE = re.compile(
    r"<\s*maction\b[^>]*?actiontype\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE
)


def detect_mathml_exfil(mml: str) -> tuple[bool, str, list]:
    """Scan MathML text for exfil constructs.

    Returns (threat_found, reason, evidence). threat_found=True means exfil
    was detected. Matching is case-insensitive; snippets truncated to 80 chars.
    Raises OutDef50Error (fail-closed) on malformed input.
    """
    if not isinstance(mml, str):
        raise OutDef50Error(f"expected str, got {type(mml).__name__}")
    evidence: list = []

    for match in _ANNOTATION_RE.finditer(mml):
        encoding = match.group(1).strip().lower()
        if encoding not in _BENIGN_ANNOTATION_ENCODING:
            evidence.append(
                {
                    "pattern": f"<annotation> with suspicious encoding '{match.group(1)}'",
                    "snippet": match.group(0)[:_SNIPPET_LEN],
                }
            )

    for match in _ANNOTATION_XML_RE.finditer(mml):
        encoding = match.group(1).strip().lower()
        if "mathml" not in encoding:
            evidence.append(
                {
                    "pattern": f"<annotation-xml> with non-MathML encoding '{match.group(1)}'",
                    "snippet": match.group(0)[:_SNIPPET_LEN],
                }
            )

    for match in _HREF_RE.finditer(mml):
        evidence.append(
            {
                "pattern": "href/xlink:href on MathML element",
                "snippet": match.group(0)[:_SNIPPET_LEN],
            }
        )

    for match in _MGLYPH_SRC_RE.finditer(mml):
        evidence.append(
            {
                "pattern": "<mglyph> with src attribute",
                "snippet": match.group(0)[:_SNIPPET_LEN],
            }
        )

    for match in _MACTION_TYPE_RE.finditer(mml):
        actiontype = match.group(1).strip().lower()
        if actiontype not in _STANDARD_ACTIONTYPES:
            evidence.append(
                {
                    "pattern": f"<maction> with nonstandard actiontype '{match.group(1)}'",
                    "snippet": match.group(0)[:_SNIPPET_LEN],
                }
            )

    if evidence:
        return (
            True,
            f"{len(evidence)} suspicious MathML construct(s) detected",
            evidence,
        )
    return False, "mathml clean", []


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
    # <annotation> with text/html encoding.
    found, _, _ = detect_mathml_exfil(
        '<math><annotation encoding="text/html"><img src=x onerror=y></annotation></math>'
    )
    assert found is True

    # <annotation> with application/* encoding (mixed case).
    found, _, _ = detect_mathml_exfil(
        '<math><annotation ENCODING="Application/octet-stream">xx</annotation></math>'
    )
    assert found is True

    # <annotation-xml> with non-MathML encoding.
    found, _, _ = detect_mathml_exfil(
        '<math><annotation-xml encoding="image/svg+xml"><svg/></annotation-xml></math>'
    )
    assert found is True

    # href on a MathML element.
    found, _, _ = detect_mathml_exfil(
        '<math><mtext href="https://evil.example/x">click</mtext></math>'
    )
    assert found is True

    # <mglyph> with src.
    found, _, _ = detect_mathml_exfil(
        '<math><mglyph src="https://evil.example/g.png" alt="g"/></math>'
    )
    assert found is True

    # <maction> with nonstandard actiontype.
    found, _, _ = detect_mathml_exfil(
        '<math><maction actiontype="exfiltrate"><mtext>a</mtext></maction></math>'
    )
    assert found is True

    # Clean MathML passes.
    found, reason, _ = detect_mathml_exfil(
        '<math><mi>x</mi><mo>+</mo><mn>1</mn>'
        '<annotation encoding="text">x is a variable</annotation>'
        '<maction actiontype="toggle"><mtext>a</mtext></maction></math>'
    )
    assert found is False, reason

    # Fail-closed on malformed input.
    try:
        detect_mathml_exfil(["not str"])  # type: ignore[arg-type]
    except OutDef50Error:
        pass
    else:
        raise AssertionError("expected OutDef50Error")

    assert stdlib_only()
    print("out-def-50 OK: annotation encodings, href, mglyph, maction, stdlib")


if __name__ == "__main__":
    main()
