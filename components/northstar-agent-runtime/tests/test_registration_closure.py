"""The registration closure: every runtime module on disk is registered.

BACKGROUND (measured 2026-11-16)
--------------------------------
`runtime_registration.py` is the component's single source of truth for
which modules are runtime modules.  It has to agree with TWO other views:

    registry  <->  pyproject.toml's `py-modules`  <->  the `*.py` on disk

and `assert_registration_matches_disk()` is the check that enforces the
three-way agreement.  It currently FAILS on this repository:

    $ PYTHONPATH=. python3 -c "import runtime_registration as rr; \\
          rr.assert_registration_matches_disk()"
    RegistrationError: runtime module registration does not match the disk:
      module(s) on disk but not in the registry: merged_tree_review;
      module(s) on disk but not in py-modules: merged_tree_review

So `merged_tree_review.py` -- the module the `merged-tree-review` slice
delivered -- was never registered, and `test_runner.py` was never declared
in `py-modules`.  Two consequences, both measured:

  * `tests/test_runtime_registration.py` fails 3 of its 37 methods, so the
    `runtime-registration` slice's own TESTS_RAN check fails;
  * `tests/test_module_layout.py::test_every_module_is_installed` fails, so
    the packaging half of the promise is broken too.

These tests pin the closure itself, so the gap cannot reopen silently.

WHY THE GAP EXISTS -- the mechanism this file also pins
---------------------------------------------------------
The registry is a hand-maintained tuple.  A slice that adds a module must
remember to add three things (the module, the registry entry, the
`py-modules` line) and nothing enforces the remembering.  That is exactly
the "recurrence guard" the `runtime-registration-closure` taskbook asks for:
a test that fails the moment a module is added without being registered.

So this file asserts, on the REAL repository:

  1. the three-way check passes;
  2. every module on disk is in the registry and in `py-modules`;
  3. every registry entry is on disk and in `py-modules`;
  4. `merged_tree_review` and `test_runner` -- the two modules this slice
     closed -- are registered with well-formed metadata;
  5. the registry stays sorted and duplicate-free;
  6. a NEW module dropped on disk is caught (in a tmpdir, never in the
     working tree);
  7. the guard is not vacuous: it must FAIL when the registration is
     removed.

Written BEFORE the fix (TDD): each test below must fail first.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

for _cached in Path(__file__).resolve().parents[1].glob(
    "__pycache__/runtime_registration.*.pyc"
):
    _cached.unlink(missing_ok=True)

import runtime_registration
from runtime_registration import (
    REGISTRY,
    RegistrationError,
    assert_registration_matches_disk,
    declared_py_modules,
    modules_on_disk,
    package_members_on_disk,
    registered_module_names,
    registration_for,
)

COMPONENT = Path(runtime_registration.__file__).resolve().parent

# The module this slice closed.  `merged_tree_review` was delivered by the
# merged-tree-review slice and never registered.
#
# NOTE: `test_runner.py` also sits in the component directory, but it is a
# TEST file, and both views exclude `test_`-prefixed files by design (see
# `runtime_registration.NON_RUNTIME_MODULES` and the identical rule in
# `tests/test_module_layout.py`).  So it must NOT be registered -- the
# first draft of this test wrongly asserted that it should, and the check
# caught it.  `test_a_test_prefixed_file_is_not_a_runtime_module` below pins
# the correct behaviour.
CLOSED_MODULES = ("merged_tree_review",)


class RegistrationClosureTests(unittest.TestCase):
    """The three views agree, on the real repository."""

    def test_the_three_way_check_passes_on_the_current_repository(self):
        """registry <-> py-modules <-> disk all agree."""
        names = assert_registration_matches_disk()
        self.assertEqual(len(names), len(REGISTRY))
        self.assertIn("runtime_registration", names)

    def test_every_module_on_disk_is_in_the_registry(self):
        """Forward direction: nothing on disk escapes registration."""
        on_disk = set(modules_on_disk())
        registered = set(registered_module_names())
        self.assertEqual(
            set(),
            on_disk - registered,
            "module(s) on disk but not registered: %s"
            % sorted(on_disk - registered),
        )

    def test_every_module_on_disk_is_installed(self):
        """The packaging half: every module is declared for installation.

        The package members are the exception, and a deliberate one: they
        are installed by ``packages.find``, not by ``py-modules``.  The
        rule is that every module is INSTALLED, by one mechanism or the
        other.
        """
        on_disk = set(modules_on_disk())
        installed = set(declared_py_modules()) | set(package_members_on_disk())
        self.assertEqual(
            set(),
            on_disk - installed,
            "module(s) on disk but not installed: %s"
            % sorted(on_disk - installed),
        )

    def test_every_registry_entry_is_on_disk(self):
        """Reverse direction: the registry does not name a phantom module."""
        registered = set(registered_module_names())
        on_disk = set(modules_on_disk())
        self.assertEqual(
            set(),
            registered - on_disk,
            "module(s) registered but not on disk: %s"
            % sorted(registered - on_disk),
        )

    def test_every_registry_entry_is_installed(self):
        """The registry and the installed surface are the same set."""
        registered = set(registered_module_names())
        installed = set(declared_py_modules()) | set(package_members_on_disk())
        self.assertEqual(
            set(),
            registered - installed,
            "module(s) registered but not installed: %s"
            % sorted(registered - installed),
        )

    def test_merged_tree_review_is_registered(self):
        """The module the merged-tree-review slice delivered is registered."""
        record = registration_for("merged_tree_review")
        self.assertEqual("merged_tree_review", record.module)
        self.assertTrue(record.slice_slug)
        self.assertRegex(record.registered_on, r"^\d{4}-\d{2}-\d{2}$")
        self.assertTrue(record.description)

    def test_a_test_prefixed_file_is_not_a_runtime_module(self):
        """`test_runner.py` is a TEST file: both views must exclude it.

        The first draft of this file asserted that `test_runner` should be
        registered and declared.  That was WRONG: the module directory
        excludes `test_`-prefixed files, and `tests/test_module_layout.py`
        excludes exactly the same ones, so the two views agree by
        construction.  Registering it would have put the registry and the
        layout test permanently out of step.
        """
        on_disk = set(modules_on_disk())
        declared = set(declared_py_modules())
        registered = set(registered_module_names())
        self.assertNotIn("test_runner", on_disk)
        self.assertNotIn("test_runner", declared)
        self.assertNotIn("test_runner", registered)

    def test_the_two_views_exclude_the_same_files(self):
        """The registry's exclusions and the layout test's must agree.

        `runtime_registration.NON_RUNTIME_MODULES` and the literal set in
        `tests/test_module_layout.py` are two hand-maintained copies of
        the same rule.  If they drift, the registry's "the two views agree
        by construction" claim becomes false.
        """
        layout = Path(__file__).resolve().parents[1] / "tests" / "test_module_layout.py"
        text = layout.read_text(encoding="utf-8")
        for name in runtime_registration.NON_RUNTIME_MODULES:
            with self.subTest(name=name):
                self.assertIn(
                    '"%s"' % name,
                    text,
                    "%s is excluded by the registry but not by the layout "
                    "test; the two exclusion sets have drifted" % name,
                )

    def test_both_closed_modules_are_now_registered(self):
        """The closure, stated as one fact."""
        registered = set(registered_module_names())
        for module in CLOSED_MODULES:
            with self.subTest(module=module):
                self.assertIn(module, registered)

    def test_the_registry_is_sorted_by_module_name(self):
        """The registry is read in order; the order is by module name."""
        names = [r.module for r in REGISTRY]
        self.assertEqual(sorted(names), names)

    def test_the_registry_has_no_duplicate_module_names(self):
        names = [r.module for r in REGISTRY]
        self.assertEqual(len(names), len(set(names)))

    def test_the_registry_registers_itself(self):
        self.assertIn("runtime_registration", set(registered_module_names()))


class RegistrationGuardTests(unittest.TestCase):
    """The guard must be real: it must fail when the registration is wrong."""

    def test_a_new_module_on_disk_is_caught(self):
        """Dropping a module on disk without registering it must be caught.

        The plant happens in a TMPDIR, never in the working tree.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            component = tmp / "component"
            component.mkdir()
            (component / "a_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "b_module.py").write_text("x = 1\n", encoding="utf-8")
            (component / "pyproject.toml").write_text(
                '[tool.setuptools]\npy-modules = [\n  "a_module",\n  "b_module",\n]\n',
                encoding="utf-8",
            )
            # `b_module` is on disk and in py-modules but NOT registered.
            with self.assertRaises(RegistrationError) as ctx:
                runtime_registration.assert_registration_matches_disk(
                    component=component,
                    pyproject=component / "pyproject.toml",
                    registry=(
                        runtime_registration._registration(
                            "a_module", "runtime", "2026-11-16", "A module."
                        ),
                    ),
                )
            self.assertIn("b_module", str(ctx.exception))

    def test_the_guard_is_not_vacuous(self):
        """A registry that omits a real module must make the check FAIL.

        This is the test that stops the guard from being a rubber stamp: it
        removes a registration the repository actually has and asserts the
        check notices.
        """
        full = list(REGISTRY)
        self.assertGreater(len(full), 1)
        trimmed = tuple(r for r in full if r.module != "runtime_registration")
        self.assertNotEqual(len(full), len(trimmed))
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            component = tmp / "component"
            component.mkdir()
            (component / "runtime_registration.py").write_text("x = 1\n", encoding="utf-8")
            (component / "pyproject.toml").write_text(
                '[tool.setuptools]\npy-modules = [\n  "runtime_registration",\n]\n',
                encoding="utf-8",
            )
            with self.assertRaises(RegistrationError) as ctx:
                runtime_registration.assert_registration_matches_disk(
                    component=component,
                    pyproject=component / "pyproject.toml",
                    registry=trimmed,
                )
            self.assertIn("runtime_registration", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
