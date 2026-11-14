#!/usr/bin/env python3
"""Run one component's test suite in an isolated process.

Usage: run_component_tests.py <component-name>

Isolation matters: several components ship a tests/test_contract.py, so
discovering them in a single process causes module-name collisions.
"""
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMPONENTS = ROOT / "components"

if len(sys.argv) != 2:
    print("usage: run_component_tests.py <component-name>")
    sys.exit(2)

name = sys.argv[1]
component = COMPONENTS / name
tests_dir = component / "tests"
if not tests_dir.is_dir():
    print(f"{name}: NO_TESTS")
    sys.exit(0)

paths = [ROOT, COMPONENTS, component]
for sibling in sorted(COMPONENTS.iterdir()):
    if sibling.is_dir():
        paths.append(sibling)
for p in reversed(paths):
    sys.path.insert(0, str(p))

# Tests that spawn subprocesses do NOT inherit the runner's sys.path. Without
# exporting PYTHONPATH the child only sees COMPONENT_ROOT, so any import that
# crosses components (e.g. route_ledger -> ... -> authorization, which lives in
# northstar-host) raises ModuleNotFoundError, the child exits 1, and the
# parent's assertEqual(child.returncode, 0) fails. That is a deterministic path
# defect, not a load-sensitive flake.
os.environ["PYTHONPATH"] = os.pathsep.join(str(p) for p in paths)

loader = unittest.TestLoader()
suite = loader.discover(str(tests_dir), pattern="test_*.py", top_level_dir=str(tests_dir))
result = unittest.TextTestRunner(verbosity=0).run(suite)
print(f"COMPONENT={name} run={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
sys.exit(0 if result.wasSuccessful() else 1)
