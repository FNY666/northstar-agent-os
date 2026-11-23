"""Tool documentation generator: markdown from specs, Simulated.

DocGenerator validates tool specs (name, description, args schema
dict, examples) and renders markdown docs via plain string building --
no real templating engine.  Backticks in user-supplied content are
escaped so generated code fences stay intact.  render_index() builds a
simple index page over a list of specs.

What this IS:
* Deterministic markdown rendering from validated specs (Simulated).

What this IS NOT:
* Not a templating engine -- plain string building only.
* Not a doc server -- returns strings, serves nothing.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, List

#: Module version.
TOOL_SYSTEM_25_VERSION = "tool-system-25.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-25.v1"


class ToolSystem25Error(Exception):
    """Fail-closed."""


REQUIRED_FIELDS = ("name", "description", "args", "examples")


def _esc(text: str) -> str:
    """Escape backslashes and backticks in user-supplied content."""
    return text.replace("\\", "\\\\").replace("`", "\\`")


class DocGenerator:
    """Renders markdown docs from tool specs (Simulated)."""

    def validate(self, spec: Dict[str, Any]) -> None:
        for field_name in REQUIRED_FIELDS:
            if field_name not in spec:
                raise ToolSystem25Error(
                    f"spec missing field '{field_name}'"
                )
        if not isinstance(spec["name"], str) or not spec["name"]:
            raise ToolSystem25Error("spec 'name' must be a non-empty str")
        if not isinstance(spec["description"], str):
            raise ToolSystem25Error("spec 'description' must be a str")
        if not isinstance(spec["args"], dict):
            raise ToolSystem25Error("spec 'args' must be a dict")
        if not isinstance(spec["examples"], list):
            raise ToolSystem25Error("spec 'examples' must be a list")

    def render(self, spec: Dict[str, Any]) -> str:
        """Render one tool's markdown doc."""
        self.validate(spec)
        lines: List[str] = [
            f"# {_esc(spec['name'])}",
            "",
            _esc(spec["description"]),
            "",
            "## Arguments",
            "",
        ]
        if spec["args"]:
            lines.append("| Name | Type |")
            lines.append("| ---- | ---- |")
            for arg, typ in spec["args"].items():
                lines.append(f"| {_esc(str(arg))} | {_esc(str(typ))} |")
        else:
            lines.append("_No arguments._")
        lines.extend(["", "## Examples", ""])
        for example in spec["examples"]:
            lines.append("```")
            lines.append(_esc(str(example)))
            lines.append("```")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def render_index(self, tools: List[Dict[str, Any]]) -> str:
        """Render an index page linking to each tool's doc."""
        lines: List[str] = ["# Tool Index", ""]
        for spec in tools:
            self.validate(spec)
            anchor = re.sub(
                r"[^a-z0-9-]", "", spec["name"].lower().replace(" ", "-")
            )
            lines.append(
                f"- [{_esc(spec['name'])}](#{anchor}) -- "
                f"{_esc(spec['description'])}"
            )
        return "\n".join(lines) + "\n"


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


def _spec() -> Dict[str, Any]:
    return {
        "name": "search",
        "description": "Search the web for `docs`.",
        "args": {"query": "str", "limit": "int"},
        "examples": ["search(query='cats')"],
    }


def main() -> None:
    dg = DocGenerator()
    doc = dg.render(_spec())
    assert doc.startswith("# search\n")
    assert "Search the web for \\`docs\\`." in doc
    assert "| query | str |" in doc
    assert "```\nsearch(query='cats')\n```" in doc
    index = dg.render_index([_spec(), {
        "name": "files",
        "description": "File tools.",
        "args": {},
        "examples": [],
    }])
    assert index.startswith("# Tool Index\n")
    assert "- [search](#search) -- Search the web" in index
    assert "- [files](#files) -- File tools." in index
    # Missing field.
    bad = dict(_spec())
    del bad["examples"]
    try:
        dg.render(bad)
        raise AssertionError("should raise")
    except ToolSystem25Error:
        pass
    # Wrong types.
    try:
        dg.render({**_spec(), "args": ["query"]})
        raise AssertionError("should raise")
    except ToolSystem25Error:
        pass
    assert stdlib_only()
    print("tool_system_25 OK: render, index, validate")


if __name__ == "__main__":
    main()
