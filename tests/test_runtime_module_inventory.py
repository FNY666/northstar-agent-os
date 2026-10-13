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
        (runtime / "cli.py").write_text("import package\n", encoding="utf-8")
        (package / "__init__.py").write_text(
            "from .worker import run\n", encoding="utf-8"
        )
        (package / "worker.py").write_text(
            "import importlib\n"
            "plugin = importlib.import_module('optional')\n"
            "def run():\n    return plugin\n",
            encoding="utf-8",
        )
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
            ["cli", "optional", "package", "package.worker"],
        )
        self.assertEqual(payload["review_required"], ["orphan"])
        self.assertEqual(payload["summary"]["dynamic_import_sites"], 1)
        self.assertEqual(
            payload["modules"]["package.worker"]["import_path"],
            ["cli", "package", "package.worker"],
        )
        self.assertEqual(
            payload["modules"]["optional"]["import_path"],
            ["cli", "package", "package.worker", "optional"],
        )

    def test_inventory_digest_does_not_depend_on_checkout_path(self):
        payloads = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                payloads.append(MODULE.inventory(self.make_runtime(Path(directory)), ("cli",)))
        self.assertEqual(payloads[0]["inventory_sha256"], payloads[1]["inventory_sha256"])

    def test_atomic_write_emits_complete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            payload = MODULE.inventory(self.make_runtime(parent), ("cli",))
            destination = parent / "reports" / "inventory.json"
            MODULE.atomic_write(destination, payload)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), payload)


if __name__ == "__main__":
    unittest.main()
