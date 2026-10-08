"""DX-08: Scaffolding (project generator), Simulated.

Generates an in-memory project tree (path -> file content) from a
spec: project name, module list, and per-file templates rendered with
strict placeholder rules (see dx_07).

Fail-closed: invalid project/module names raise; duplicate paths
raise; nothing is written to disk by this module (caller decides).

What this IS: deterministic project-tree generation.
What this IS NOT: not a filesystem writer.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List

#: Module version.
DX08_SCAFFOLD_VERSION = "dx-scaffold.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-scaffold.v1"

NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


class ScaffoldError(Exception):
    """Fail-closed."""


@dataclass
class ProjectSpec:
    name: str
    modules: List[str] = field(default_factory=list)
    with_tests: bool = True
    with_readme: bool = True


BASE_MAIN = '''"""{{project}} entrypoint."""

from {{project}} import core


def main() -> None:
    core.run()


if __name__ == "__main__":
    main()
'''

BASE_CORE = '''"""Core logic for {{project}}."""


def run() -> str:
    return "{{project}} ok"
'''

BASE_TEST = '''"""Tests for {{module}}."""


def test_smoke() -> None:
    assert True
'''

BASE_README = "# {{project}}\n\nGenerated scaffold.\n"


def _render(body: str, mapping: Dict[str, str]) -> str:
    out = body
    for k, v in mapping.items():
        out = out.replace("{{" + k + "}}", v)
    if "{{" in out:
        raise ScaffoldError("unrendered placeholder remains")
    return out


def scaffold(spec: ProjectSpec) -> Dict[str, str]:
    """Generate {path: content}.  Raises on invalid spec."""
    if not NAME_RE.match(spec.name):
        raise ScaffoldError(f"invalid project name '{spec.name}'")
    for mod in spec.modules:
        if not NAME_RE.match(mod):
            raise ScaffoldError(f"invalid module name '{mod}'")
    if len(set(spec.modules)) != len(spec.modules):
        raise ScaffoldError("duplicate module names")

    tree: Dict[str, str] = {}
    root = spec.name
    mapping = {"project": spec.name}

    def put(path: str, content: str) -> None:
        if path in tree:
            raise ScaffoldError(f"duplicate path '{path}'")
        tree[path] = content

    put(f"{root}/__init__.py", f'"""{spec.name} package."""\n')
    put(f"{root}/__main__.py", _render(BASE_MAIN, mapping))
    put(f"{root}/core.py", _render(BASE_CORE, mapping))
    for mod in spec.modules:
        put(f"{root}/{mod}.py", f'"""{mod} module."""\n')
        if spec.with_tests:
            put(f"tests/test_{mod}.py", _render(BASE_TEST, {"module": mod}))
    if spec.with_tests:
        put("tests/__init__.py", "")
    if spec.with_readme:
        put("README.md", _render(BASE_README, mapping))
    return tree


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
    tree = scaffold(ProjectSpec(name="myapp", modules=["gates", "ledger"]))
    assert "myapp/__main__.py" in tree
    assert "myapp/gates.py" in tree
    assert "tests/test_ledger.py" in tree
    assert "README.md" in tree
    assert "{{" not in tree["myapp/__main__.py"]
    try:
        scaffold(ProjectSpec(name="bad-name", modules=[]))
        raise AssertionError("should raise")
    except ScaffoldError:
        pass
    try:
        scaffold(ProjectSpec(name="ok", modules=["a", "a"]))
        raise AssertionError("should raise")
    except ScaffoldError:
        pass
    assert stdlib_only()
    print("dx_08 OK: tree generation, strict names, no disk writes")


if __name__ == "__main__":
    main()
