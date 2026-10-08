"""DX-10: Snippets (code snippets), Simulated.

Snippet registry with tab stops: ${1:name} placeholders expand with
supplied values; ${0} marks the final cursor.  Expansion is strict:
every tab stop must be filled, unknown snippet names raise.

Fail-closed: missing tab-stop values raise; duplicate tab-stop
numbers with different defaults raise at registration.

What this IS: deterministic snippet expansion.
What this IS NOT: not an editor integration.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Set

#: Module version.
DX10_SNIPPETS_VERSION = "dx-snippets.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-snippets.v1"

TABSTOP_RE = re.compile(r"\$\{(\d+)(?::([^}]*))?\}")


class SnippetError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Snippet:
    trigger: str
    body: str
    description: str = ""


class SnippetStore:
    """Registry + strict expander."""

    def __init__(self) -> None:
        self._snippets: Dict[str, Snippet] = {}

    def add(self, snippet: Snippet) -> None:
        if not snippet.trigger or not snippet.trigger.strip():
            raise SnippetError("trigger required")
        # duplicate tab-stop numbers must agree on default
        defaults: Dict[str, str] = {}
        for num, default in TABSTOP_RE.findall(snippet.body):
            default = default or ""
            if num in defaults and defaults[num] != default:
                raise SnippetError(
                    f"tab stop ${num} has conflicting defaults"
                )
            defaults[num] = default
        self._snippets[snippet.trigger] = snippet

    @staticmethod
    def tab_stops(body: str) -> Set[str]:
        return {num for num, _ in TABSTOP_RE.findall(body)} - {"0"}

    def expand(self, trigger: str, values: Dict[str, str]) -> str:
        """Expand a snippet.  values maps tab-stop number -> text."""
        snip = self._snippets.get(trigger)
        if snip is None:
            raise SnippetError(f"unknown snippet '{trigger}'")
        needed = self.tab_stops(snip.body)
        missing = needed - set(values)
        if missing:
            raise SnippetError(f"missing tab stops: {sorted(missing)}")
        unknown = set(values) - needed - {"0"}
        if unknown:
            raise SnippetError(f"unknown tab stops: {sorted(unknown)}")

        def repl(m: re.Match) -> str:
            num, default = m.group(1), m.group(2) or ""
            return str(values.get(num, default))

        return TABSTOP_RE.sub(repl, snip.body)

    @property
    def triggers(self) -> List[str]:
        return sorted(self._snippets)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "re", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    store = SnippetStore()
    store.add(Snippet("for", "for ${1:i} in ${2:items}:\n    ${0:pass}"))
    out = store.expand("for", {"1": "k", "2": "rows"})
    assert out == "for k in rows:\n    pass"
    try:
        store.expand("for", {"1": "k"})
        raise AssertionError("should raise")
    except SnippetError:
        pass
    try:
        store.expand("nope", {})
        raise AssertionError("should raise")
    except SnippetError:
        pass
    try:
        store.add(Snippet("bad", "${1:a} ${1:b}"))
        raise AssertionError("should raise")
    except SnippetError:
        pass
    assert stdlib_only()
    print("dx_10 OK: expand, strict tab stops, fail-closed")


if __name__ == "__main__":
    main()
