"""DX-09: Templates (string templates), Simulated.

Named string-template registry with strict rendering: every
{{placeholder}} must be supplied, unknown keys raise, and leftover
placeholders raise.  Templates can be listed and validated without
rendering.

Fail-closed: render with missing/extra keys raises; unknown template
raises.

What this IS: a strict named-template store.
What this IS NOT: not a logic-full templating engine (no loops/ifs).
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Set

#: Module version.
DX09_TEMPLATES_VERSION = "dx-templates.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-templates.v1"

PH_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


class TemplateError(Exception):
    """Fail-closed."""


class TemplateStore:
    """Named strict templates."""

    def __init__(self) -> None:
        self._templates: Dict[str, str] = {}

    def add(self, name: str, body: str) -> None:
        if not name or not name.strip():
            raise TemplateError("template name required")
        if not isinstance(body, str):
            raise TemplateError("body must be str")
        self._templates[name] = body

    def remove(self, name: str) -> None:
        if name not in self._templates:
            raise TemplateError(f"unknown template '{name}'")
        del self._templates[name]

    @staticmethod
    def placeholders(body: str) -> Set[str]:
        return set(PH_RE.findall(body))

    def validate(self, name: str) -> Set[str]:
        """Return the placeholder set for a template (no rendering)."""
        if name not in self._templates:
            raise TemplateError(f"unknown template '{name}'")
        return self.placeholders(self._templates[name])

    def render(self, name: str, context: Dict[str, str]) -> str:
        body = self._templates.get(name)
        if body is None:
            raise TemplateError(f"unknown template '{name}'")
        needed = self.placeholders(body)
        missing = needed - set(context)
        if missing:
            raise TemplateError(f"missing keys: {sorted(missing)}")
        unknown = set(context) - needed
        if unknown:
            raise TemplateError(f"unknown keys: {sorted(unknown)}")
        out = PH_RE.sub(lambda m: str(context[m.group(1)]), body)
        if self.placeholders(out):
            raise TemplateError("unrendered placeholders remain")
        return out

    @property
    def names(self) -> List[str]:
        return sorted(self._templates)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    store = TemplateStore()
    store.add("greet", "hello {{name}}, welcome to {{place}}!")
    assert store.render("greet", {"name": "ada", "place": "ns"}) == "hello ada, welcome to ns!"
    assert store.validate("greet") == {"name", "place"}
    try:
        store.render("greet", {"name": "ada"})
        raise AssertionError("should raise")
    except TemplateError:
        pass
    try:
        store.render("greet", {"name": "a", "place": "b", "x": "1"})
        raise AssertionError("should raise")
    except TemplateError:
        pass
    store.remove("greet")
    try:
        store.render("greet", {})
        raise AssertionError("should raise")
    except TemplateError:
        pass
    assert stdlib_only()
    print("dx_09 OK: add/render/validate/remove, strict keys")


if __name__ == "__main__":
    main()
