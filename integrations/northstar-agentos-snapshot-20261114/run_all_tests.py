#!/usr/bin/env python3
"""Run the entire Northstar test suite with correct component paths.

Each component's tests assume their sibling/parent components are importable.
This runner adds every component directory (and subdirectories) to sys.path,
then discovers and runs all unittest test modules.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMPONENTS = ROOT / "components"

# Every component dir and its parent, so cross-component imports resolve.
paths = [ROOT, COMPONENTS]
for component in sorted(COMPONENTS.iterdir()):
    if component.is_dir():
        paths.append(component)
        for sub in sorted(component.iterdir()):
            if sub.is_dir() and sub.name not in {"__pycache__", "tests"}:
                paths.append(sub)

for p in reversed(paths):
    sys.path.insert(0, str(p))

loader = unittest.TestLoader()
suite = unittest.TestSuite()
for component in sorted(COMPONENTS.iterdir()):
    tests_dir = component / "tests"
    if tests_dir.is_dir():
        discovered = loader.discover(str(tests_dir), pattern="test_*.py", top_level_dir=str(tests_dir))
        suite.addTests(discovered)

result = unittest.TextTestRunner(verbosity=1).run(suite)
print()
print(f"TOTAL: run={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
sys.exit(0 if result.wasSuccessful() else 1)
