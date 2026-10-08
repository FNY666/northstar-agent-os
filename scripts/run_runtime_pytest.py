"""Run pytest-native runtime tests, leaving TestCase execution to unittest CI.

Native pytest discovery (not an import or filename whitelist) owns functions,
plain classes, fixtures and parameterization. Collection errors remain failures,
but valid tests still run. This scoped plugin does not alter ordinary pytest use.
"""
from pathlib import Path
import sys
import unittest

import pytest

RUNTIME = Path(__file__).resolve().parents[1] / "components" / "northstar-agent-runtime"


class NativeTestsOnly:
    @pytest.hookimpl(tryfirst=True)
    def pytest_pycollect_makeitem(self, collector, name, obj):
        # First-result hook: [] declines collection, None delegates to pytest.
        # Actual inheritance handles aliases and indirect TestCase subclasses.
        if isinstance(obj, type):
            if issubclass(obj, unittest.TestCase):
                return []
            module_obj = getattr(collector, "obj", None)
            # Pytest's default class collector also sees imported domain classes
            # whose names start with Test*. They are not test declarations in
            # this module; skip only this imported-class case, not local classes.
            if hasattr(module_obj, "__file__") and obj.__module__ != module_obj.__name__:
                return []
        return None


def main(argv=None):
    # Match python -m pytest from the runtime directory, including offline imports.
    sys.path.insert(0, str(RUNTIME))
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        args = [str(RUNTIME / "tests"), "-q"]
    # Project tests use test_*; pytest's broader 'test' prefix would also
    # miscollect an imported business API named testimonial_existence_gate.
    return int(pytest.main(
        [*args, "-o", "python_functions=test_*", "--continue-on-collection-errors"],
        plugins=[NativeTestsOnly()],
    ))


if __name__ == "__main__":
    raise SystemExit(main())
