"""Module layout guarantees: names resolve, versions do not drift, packaging holds.

These tests pin the two structural promises of this component:

1. ``tools`` is a *package* (``tools/__init__.py`` plus the ``verify_invariants``
   harness as a submodule), so both ``import tools`` and
   ``import tools.verify_invariants`` work. A module and a directory that share a
   name cannot both exist - that was the bug this layout removes.
2. The version printed by the CLI, declared in ``pyproject.toml``, and imported
   from ``_version`` are one value, so ``pip install .`` and ``python -m cli``
   can never disagree about what is installed.
"""
from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import _version
import tools
import tools.verify_invariants  # noqa: F401  - must stay importable as a submodule

COMPONENT = Path(__file__).resolve().parents[1]


class ToolsPackageLayoutTests(unittest.TestCase):
    def test_tools_is_a_package_with_an_init(self):
        self.assertTrue(tools.__file__.endswith("tools/__init__.py"), tools.__file__)
        self.assertTrue(hasattr(tools, "__path__"), "a package exposes __path__")

    def test_the_invariants_harness_imports_as_a_submodule(self):
        # The harness doubles as a module: this import must not raise, which is
        # exactly what failed before the layout fix ('tools' is not a package).
        self.assertTrue(tools.verify_invariants.COMPONENT.is_dir())

    def test_registry_names_still_resolve_from_the_package(self):
        from tools import ToolRegistry, build_default_registry

        self.assertEqual(len(build_default_registry().names()), 6)
        self.assertTrue(issubclass(ToolRegistry, object))


class VersionSingleSourceTests(unittest.TestCase):
    def test_pyproject_version_matches_version_module(self):
        pyproject = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], _version.__version__)

    def test_the_console_script_points_at_the_cli_entry(self):
        pyproject = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["scripts"]["northstar-agent-runtime"], "cli:main")

    def test_install_without_extras_stays_offline_importable(self):
        # No hard dependency may sneak into pyproject: the scripted provider and
        # the deterministic suite must keep running on a bare interpreter.
        pyproject = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["dependencies"], [])
        extras = pyproject["project"]["optional-dependencies"]
        self.assertIn("anthropic", extras)
        self.assertIn("tracing", extras)


if __name__ == "__main__":
    unittest.main()
