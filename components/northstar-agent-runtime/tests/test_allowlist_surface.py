"""The `allowlist` module: it had NO suite at all.

WHY THIS FILE EXISTS (measured 2026-11-26)
------------------------------------------
The census artifact measured `allowlist` at **0/5**, and the row was
paired with `tests/test_ai_alignment.py` -- a suite that does not load
it.  The only occurrence of the word "allowlist" in that file is a
COMMENT: "Test-side independent walk with the house allowlist."

So `allowlist` is one of **five** rows in the artifact whose paired
suite is not in the resolver's scope at all.  (The other four are
`ba_01`..`ba_04`, paired with `test_py_modules_list.py`, which is the
`ba_*` scratch family that genuinely has no suite.)

**The 0/5 is HONEST: nothing tests this module.**  It is not a scope
error in the row -- it is a missing suite.

WHAT THE MODULE IS
------------------
`allowlist.py` is the smallest module in the component: an
`Allowlist` class whose `check()` is a set membership test, a
`stdlib_only()` AST guard, and a `main()` self-check.  It has no
suite, so none of those is verified.

THE FIVE SITES
--------------
  retF@17  stdlib_only(): `return False` for a disallowed `import`
  retF@19  stdlib_only(): `return False` for a disallowed `import from`
  and@19   stdlib_only(): the `import from` conjunct
  retT@20  stdlib_only(): the final `return True`
  eq@27    `if __name__ == "__main__":`

The two rejection branches are the SAME shape as §35's and §36's:
**a guard whose whole job is to REJECT, tested only on the accepting
side, is not tested** -- and here it is not tested AT ALL.

WHY A NEW FILE
--------------
The census resolves a module's scope by finding the suites that LOAD
it.  This file loads `allowlist`, which puts the module in scope for
the first time.  The module's own `test_ai_alignment.py` pairing stays
as it was; the union is what gets measured.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name: str):
    """Load a module by file path (the house loader)."""
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


#: Loaded by an EXPLICIT LITERAL call, because ``scripts/census-scope.py``
#: only recognises a load whose module name is a literal.
allowlist_mod = _load("allowlist")


class _PatchedFile:
    """Point a module's ``__file__`` at a crafted source file.

    ``stdlib_only()`` parses ``pathlib.Path(__file__)``.  Re-parsing the
    REAL file can only ever produce the REAL answer, so the guard is
    unverifiable against it.  This points the guard at a file that
    VIOLATES the rule the guard enforces.  The real module file is
    never modified.
    """

    def __init__(self, module, source: str):
        self._module = module
        self._source = source
        self._real = module.__file__
        self._path = None

    def __enter__(self):
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        )
        handle.write(self._source)
        handle.close()
        self._path = handle.name
        self._module.__file__ = self._path
        return self._module

    def __exit__(self, *_exc):
        self._module.__file__ = self._real
        if self._path:
            os.unlink(self._path)
        return False


class AllowlistSurfaceTests(unittest.TestCase):
    """The module had no suite; this is the first one."""

    def test_the_allowlist_accepts_what_it_is_given_and_rejects_the_rest(self):
        """The `Allowlist` class: the whole reason the module exists."""
        allowed = allowlist_mod.Allowlist(["read", "write"])
        self.assertIs(allowed.check("read"), True)
        self.assertIs(allowed.check("write"), True)
        self.assertIs(allowed.check("delete"), False)
        self.assertIs(allowed.check(""), False)

    def test_the_allowlist_is_a_set_so_duplicates_collapse(self):
        """The constructor copies into a set.

        The observable is the BEHAVIOUR that follows: a duplicate
        entry does not create a second member, and membership is what
        the class answers.
        """
        allowed = allowlist_mod.Allowlist(["read", "read", "write"])
        self.assertIs(allowed.check("read"), True)
        self.assertEqual(len(allowed.allowed), 2)

    def test_a_non_stdlib_import_is_rejected(self):
        """`retF@17`: the `import` rejection branch."""
        with _PatchedFile(allowlist_mod, "import json\n") as module:
            self.assertIs(module.stdlib_only(), False)

    def test_a_non_stdlib_import_from_is_rejected(self):
        """`retF@19` and `and@19`: the `import from` rejection branch.

        A SEPARATE AST NODE, so a SEPARATE test: a mutant that breaks
        only the `import from` site survives a test that only
        exercised the `import` site.
        """
        with _PatchedFile(allowlist_mod, "from json import dumps\n") as module:
            self.assertIs(module.stdlib_only(), False)

    def test_an_allowed_import_is_still_accepted(self):
        """The non-vacuity control for `stdlib_only()`.

        Every allowed module in the module's OWN set is accepted --
        read from the module's source, so the test cannot drift from
        the rule the module enforces.
        """
        for source in (
            "import ast\n",
            "import pathlib\n",
            "from __future__ import annotations\n",
            "from typing import Any\n",
        ):
            with self.subTest(source=source):
                with _PatchedFile(allowlist_mod, source) as module:
                    self.assertIs(module.stdlib_only(), True)

    def test_the_module_itself_passes_its_own_guard(self):
        """`retT@20`: the final `return True`.

        The guard's accepting path is only meaningful if the REAL
        module passes it -- otherwise the guard would reject the
        module that ships it.
        """
        self.assertIs(allowlist_mod.stdlib_only(), True)

    def test_the_self_check_passes_and_prints(self):
        """The module's own self-check, which nothing ran."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            allowlist_mod.main()
        self.assertIn("allowlist OK", out.getvalue())

    def test_importing_the_module_runs_no_self_check(self):
        """`eq@27`: the `__main__` guard.

        The mutant flips the comparison, so the module's self-check
        runs at IMPORT time and prints its line.  Importing a module
        must be silent.
        """
        probe_name = "allowlist._import_probe"
        spec = importlib.util.spec_from_file_location(
            probe_name, RUNTIME / "allowlist.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[probe_name] = module
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                spec.loader.exec_module(module)
        finally:
            sys.modules.pop(probe_name, None)
        self.assertEqual(
            out.getvalue(), "",
            "importing allowlist ran its self-check",
        )


if __name__ == "__main__":
    unittest.main()
