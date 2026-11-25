"""Tests for the conservative Core/Labs static inventory."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "classify-runtime-modules.py"
SPEC = importlib.util.spec_from_file_location("runtime_module_inventory", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeModuleInventoryTests(unittest.TestCase):
    def make_runtime(self, parent: Path) -> Path:
        runtime = parent / "runtime"
        package = runtime / "package"
        package.mkdir(parents=True)
        (runtime / "cli.py").write_text("import package\nimport spec_source\n", encoding="utf-8")
        (package / "__init__.py").write_text(
            "from .worker import run\n", encoding="utf-8"
        )
        (package / "relative_plugin.py").write_text("enabled = True\n", encoding="utf-8")
        (package / "keyword_plugin.py").write_text("enabled = True\n", encoding="utf-8")
        (package / "worker.py").write_text(
            "from importlib import import_module as load_module\n"
            "import os\n"
            "plugin = load_module('optional')\n"
            "dynamic_plugin = load_module(os.getenv('NORTHSTAR_PLUGIN'))\n"
            "relative_plugin = load_module('.relative_plugin', 'package')\n"
            "keyword_plugin = load_module('.keyword_plugin', package=__package__)\n"
            "def run():\n    return plugin, dynamic_plugin, relative_plugin, keyword_plugin\n",
            encoding="utf-8",
        )
        (runtime / "aliased_importlib.py").write_text(
            "import importlib as il\n"
            "plugin = il.import_module(name='optional')\n",
            encoding="utf-8",
        )
        (runtime / "aliased_builtin.py").write_text(
            "from builtins import __import__ as load\n"
            "plugin = load('optional')\n",
            encoding="utf-8",
        )
        (runtime / "spec_source.py").write_text(
            "import importlib.util as iu\n"
            "spec = iu.spec_from_file_location('spec_target', 'spec_target.py')\n",
            encoding="utf-8",
        )
        (runtime / "spec_target.py").write_text("enabled = True\n", encoding="utf-8")
        (runtime / "optional.py").write_text("enabled = True\n", encoding="utf-8")
        (runtime / "orphan.py").write_text("unused = True\n", encoding="utf-8")
        return runtime

    def test_relative_and_literal_dynamic_imports_are_reachable(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = MODULE.inventory(self.make_runtime(Path(directory)), ("cli",))
        self.assertEqual(payload["runtime_root"], "runtime")
        self.assertEqual(payload["missing_roots"], [])
        self.assertEqual(payload["parse_errors"], {})
        self.assertEqual(
            payload["core_reachable"],
            [
                "cli",
                "optional",
                "package",
                "package.keyword_plugin",
                "package.relative_plugin",
                "package.worker",
                "spec_source",
                "spec_target",
            ],
        )
        self.assertEqual(
            payload["review_required"],
            ["aliased_builtin", "aliased_importlib", "orphan"],
        )
        self.assertEqual(payload["summary"]["dynamic_import_sites"], 7)
        dynamic_calls = {
            module: [site["call"] for site in sites]
            for module, sites in payload["literal_and_dynamic_imports"].items()
        }
        self.assertEqual(
            dynamic_calls["package.worker"],
            ["importlib.import_module"] * 4,
        )
        self.assertEqual(dynamic_calls["aliased_importlib"], ["importlib.import_module"])
        self.assertEqual(dynamic_calls["aliased_builtin"], ["__import__"])
        self.assertEqual(
            dynamic_calls["spec_source"],
            ["importlib.util.spec_from_file_location"],
        )
        unknown_sites = [
            site
            for site in payload["literal_and_dynamic_imports"]["package.worker"]
            if site["literal"] is None
        ]
        self.assertEqual(len(unknown_sites), 1, "computed module names remain review-only")
        self.assertEqual(
            payload["modules"]["package.worker"]["import_path"],
            ["cli", "package", "package.worker"],
        )
        self.assertEqual(
            payload["modules"]["optional"]["import_path"],
            ["cli", "package", "package.worker", "optional"],
        )
        self.assertEqual(
            payload["modules"]["package.relative_plugin"]["import_path"],
            ["cli", "package", "package.worker", "package.relative_plugin"],
        )

    def test_inventory_digest_does_not_depend_on_checkout_path(self):
        payloads = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                payloads.append(MODULE.inventory(self.make_runtime(Path(directory)), ("cli",)))
        self.assertEqual(payloads[0]["inventory_sha256"], payloads[1]["inventory_sha256"])

    def test_inventory_digest_tracks_source_changes_even_when_imports_do_not_change(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = self.make_runtime(Path(directory))
            before = MODULE.inventory(runtime, ("cli",))
            (runtime / "orphan.py").write_text("unused = False" + chr(10), encoding="utf-8")
            after = MODULE.inventory(runtime, ("cli",))

        self.assertEqual(before["modules"]["orphan"]["imports"], after["modules"]["orphan"]["imports"])
        self.assertNotEqual(before["inventory_sha256"], after["inventory_sha256"])
        self.assertNotEqual(
            before["modules"]["orphan"]["source_sha256"],
            after["modules"]["orphan"]["source_sha256"],
        )

    def test_atomic_write_emits_complete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            payload = MODULE.inventory(self.make_runtime(parent), ("cli",))
            destination = parent / "reports" / "inventory.json"
            MODULE.atomic_write(destination, payload)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), payload)


if __name__ == "__main__":
    unittest.main()
