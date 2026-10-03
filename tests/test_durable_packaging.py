"""Durable-run packaging must include internal modules imported at runtime."""
from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components" / "northstar-durable-run"


class DurablePackagingTests(unittest.TestCase):
    def test_every_runtime_python_module_is_in_py_modules(self) -> None:
        config = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))
        declared = set(config["tool"]["setuptools"]["py-modules"])
        source_modules = {path.stem for path in COMPONENT.glob("*.py") if path.name != "__init__.py"}
        missing = sorted(source_modules - declared)
        required = {"blob_store", "event_migration", "tool_ledger"}
        self.assertTrue(required.issubset(declared), f"missing required modules: {sorted(required - declared)}")
        self.assertEqual(missing, [], f"wheel omits importable runtime modules: {missing}")

    def test_blob_store_required_by_event_store_is_packaged(self) -> None:
        config = tomllib.loads((COMPONENT / "pyproject.toml").read_text(encoding="utf-8"))
        declared = set(config["tool"]["setuptools"]["py-modules"])
        self.assertIn("blob_store", declared)
        self.assertTrue((COMPONENT / "blob_store.py").is_file())


if __name__ == "__main__":
    unittest.main()
