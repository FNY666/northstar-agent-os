"""DX-07: Code generation (template), Simulated.

Deterministic code generator: takes a named template with {{placeholders}}
and a mapping, renders code.  Placeholders must all be provided and no
extras are silently dropped -- unknown placeholders in the mapping raise.

Fail-closed: missing placeholder raises; unrendered {{...}} left in
output raises instead of shipping broken code.

What this IS: strict placeholder rendering for codegen.
What this IS NOT: not an LLM code generator.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Dict, List, Set

#: Module version.
DX07_CODEGEN_VERSION = "dx-codegen.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-codegen.v1"

PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


class CodegenError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Template:
    name: str
    body: str


class CodeGenerator:
    """Strict template-based code generator."""

    def __init__(self) -> None:
        self._templates: Dict[str, Template] = {}

    def add(self, template: Template) -> None:
        if not template.name:
            raise CodegenError("template name required")
        self._templates[template.name] = template

    @staticmethod
    def placeholders(body: str) -> Set[str]:
        return set(PLACEHOLDER_RE.findall(body))

    def generate(self, name: str, mapping: Dict[str, str]) -> str:
        """Render a template.  Raises on missing or unknown keys."""
        tmpl = self._templates.get(name)
        if tmpl is None:
            raise CodegenError(f"unknown template '{name}'")
        needed = self.placeholders(tmpl.body)
        missing = needed - set(mapping)
        if missing:
            raise CodegenError(f"missing placeholders: {sorted(missing)}")
        unknown = set(mapping) - needed
        if unknown:
            raise CodegenError(f"unknown mapping keys: {sorted(unknown)}")

        def repl(m: re.Match) -> str:
            return str(mapping[m.group(1)])

        out = PLACEHOLDER_RE.sub(repl, tmpl.body)
        leftover = self.placeholders(out)
        if leftover:
            raise CodegenError(f"unrendered placeholders remain: {sorted(leftover)}")
        return out

    @property
    def templates(self) -> List[str]:
        return sorted(self._templates)


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
    gen = CodeGenerator()
    gen.add(Template("gate", "def {{name}}_gate():\n    return {{decision}}\n"))
    out = gen.generate("gate", {"name": "auth", "decision": "True"})
    assert out == "def auth_gate():\n    return True\n"
    try:
        gen.generate("gate", {"name": "x"})
        raise AssertionError("should raise")
    except CodegenError:
        pass
    try:
        gen.generate("gate", {"name": "x", "decision": "y", "extra": "z"})
        raise AssertionError("should raise")
    except CodegenError:
        pass
    try:
        gen.generate("missing", {})
        raise AssertionError("should raise")
    except CodegenError:
        pass
    assert stdlib_only()
    print("dx_07 OK: strict rendering, missing/unknown keys fail-closed")


if __name__ == "__main__":
    main()
