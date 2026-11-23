"""PDF metadata scrubber: /Info dictionary entries, Simulated.

Cleans:
- /Author, /Creator, /Producer authorship strings
- /CreationDate, /ModDate timestamps
- /Title, /Subject, /Keywords descriptors
Values may be parenthesized strings or <hex> literals.

What this IS:
* Gate-layer scrubbing of document-identifying PDF metadata.

What this IS NOT:
* Not a PDF parser -- regex over latin-1 text, no xref/trailer handling.
* Not an anonymity guarantee -- page content is untouched.
"""

from __future__ import annotations

import ast
import re

#: Module version.
OUT_DEF_41_VERSION = "out-def-41.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-41.v1"


class OutDef41Error(Exception):
    """Fail-closed."""


#: /Info keys scrubbed, in canonical order.
_PDF_META_KEYS = (
    "Author",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Title",
    "Subject",
    "Keywords",
)


def _key_pattern(key: str) -> re.Pattern[str]:
    """Regex matching `/Key <value>` where value is a string or hex literal."""
    return re.compile(
        r"/" + re.escape(key) + r"\b\s*(?:\((?:\\.|[^()\\])*\)|<[0-9A-Fa-f\s]*>)"
    )


def clean_pdf_metadata(data: bytes) -> tuple[bytes, list]:
    """Remove /Info metadata entries. Returns (cleaned_bytes, removed_keys).

    Malformed input never raises: returns (original_bytes, []) fail-closed.
    """
    try:
        text = data.decode("latin-1")
        removed: list[str] = []
        for key in _PDF_META_KEYS:
            text, n = _key_pattern(key).subn("", text)
            if n:
                removed.append(key)
        return text.encode("latin-1"), removed
    except Exception:
        return data, []


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re"}
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
    pdf = (
        b"%PDF-1.4\n1 0 obj\n<< /Author (John Doe) /Creator (Acme \\(Ltd\\))"
        b" /Title <FEFF0041> /Pages 2 0 R >>\nendobj\n"
    )
    cleaned, removed = clean_pdf_metadata(pdf)
    assert set(removed) == {"Author", "Creator", "Title"}, removed
    assert b"John Doe" not in cleaned
    assert b"FEFF0041" not in cleaned
    assert b"/Pages" in cleaned

    # Clean input unchanged.
    clean = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    out, removed = clean_pdf_metadata(clean)
    assert out == clean and removed == []

    # Malformed: unclosed string, stray bytes -- no raise.
    out, removed = clean_pdf_metadata(b"/Author (unclosed\xff\xfe")
    assert removed == []
    out, removed = clean_pdf_metadata(b"")
    assert out == b"" and removed == []

    assert stdlib_only()
    print("out-def-41 OK: pdf metadata, malformed-safe, stdlib")


if __name__ == "__main__":
    main()
