"""Document property stripping defense (D-OUT-040), Simulated.

Detects:
- Sensitive document properties (author, creator, last_modified_by, email,
  company, template, revision, keywords, comments, subject) present with
  non-empty values -- the classic "who wrote this / where from" leak.
Cleans:
- strip_doc_props(): keeps only explicitly allow-listed keys, returns
  (cleaned_dict, removed_key_list).

What this IS:
* A gate-layer allow-list filter for document metadata before sharing/export.

What this IS NOT:
* Not an Office/PDF metadata parser -- it operates on plain dicts.
* Not a content redactor -- document body text is out of scope.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

#: Module version.
OUT_DEF_40_VERSION = "out-def-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-40.v1"

#: Document properties treated as sensitive for exfiltration purposes.
SENSITIVE_PROPS: Set[str] = {
    "author",
    "creator",
    "last_modified_by",
    "email",
    "company",
    "template",
    "revision",
    "keywords",
    "comments",
    "subject",
}


def _non_empty(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def detect_doc_props(props: Dict[str, object]) -> Tuple[bool, str]:
    """Return (threat, reason).

    threat is True when any sensitive property is present with a non-empty
    value.
    """
    hits = sorted(
        key
        for key, value in (props or {}).items()
        if key in SENSITIVE_PROPS and _non_empty(value)
    )
    if hits:
        return True, "sensitive doc props present: %s" % ", ".join(hits)
    return False, "ok"


def strip_doc_props(
    props: Dict[str, object], keep: Optional[Set[str]] = None
) -> Tuple[Dict[str, object], List[str]]:
    """Return (cleaned, removed_keys): only `keep` keys survive."""
    keep_set = set(keep) if keep else set()
    cleaned = {k: v for k, v in (props or {}).items() if k in keep_set}
    removed = [k for k in (props or {}) if k not in keep_set]
    return cleaned, removed


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    # Sensitive props with values: threat.
    threat, reason = detect_doc_props(
        {"title": "Q3", "author": "mallory", "company": "Evil Corp"}
    )
    assert threat is True
    assert "author" in reason and "company" in reason

    # Sensitive key present but empty: clean.
    threat, _ = detect_doc_props({"author": "   ", "title": "Q3"})
    assert threat is False

    # No sensitive props: clean.
    threat, _ = detect_doc_props({"title": "Q3", "pages": 10})
    assert threat is False

    # Non-string truthy sensitive value (revision=3) counts.
    threat, _ = detect_doc_props({"revision": 3})
    assert threat is True

    # strip keeps only the keep-list.
    cleaned, removed = strip_doc_props(
        {"title": "Q3", "author": "mallory", "subject": "leak"},
        keep={"title"},
    )
    assert cleaned == {"title": "Q3"}
    assert sorted(removed) == ["author", "subject"]

    # Default keep=None strips everything.
    cleaned, removed = strip_doc_props({"title": "Q3"})
    assert cleaned == {} and removed == ["title"]

    assert stdlib_only()
    print("out-def-40 OK: doc-prop detect, strip, stdlib")


if __name__ == "__main__":
    main()
