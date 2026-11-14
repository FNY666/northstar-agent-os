"""The runtime module registry is complete, and the check that keeps it so.

``tests/test_module_layout.py`` already asserts the *packaging* half of the
promise: every top-level module is in ``py-modules``.  These tests assert the
*registry* half -- that ``runtime_registration.py`` names every module, with
the metadata the registry promises, and that the three-way check
(registry <-> pyproject <-> disk) fails loudly and **by name** when they
disagree.

The negative cases run against a temporary directory, never the working
tree: planting a file in the checkout would leave the next test run dirty.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import runtime_registration
from runtime_registration import (
    REGISTRY,
    Registration,
    RegistrationError,
    assert_registration_matches_disk,
    declared_py_modules,
    modules_on_disk,
    registered_module_names,
    registered_modules,
    registration_for,
)

COMPONENT = Path(runtime_registration.__file__).resolve().parent


class RegistryShapeTests(unittest.TestCase):
    """The registry itself: it is data, it is complete, it is immutable."""

    def test_every_registered_module_is_declared_in_py_modules(self):
        """Forward direction, item by item: the registry is a subset of py-modules.

        Every single module name in the registry is checked -- not a sample
        -- so a newly forgotten registration cannot hide behind a passing
        spot check.
        """
        declared = set(declared_py_modules())
        for record in REGISTRY:
            self.assertIn(
                record.module,
                declared,
                "module %r is in the registry but not in py-modules" % record.module,
            )

    def test_every_py_modules_entry_is_in_the_registry(self):
        """Reverse direction: a py-modules entry the registry does not know is a miss.

        This is the direction that catches the next slice: the slice adds a
        module to ``py-modules`` but forgets to register it here.
        """
        registered = set(registered_module_names())
        for name in declared_py_modules():
            self.assertIn(
                name,
                registered,
                "py-modules declares %r but the registry does not name it" % name,
            )

    def test_every_registered_module_exists_on_disk(self):
        """The registry names files, so every name must be a file that exists."""
        on_disk = set(modules_on_disk())
        for record in REGISTRY:
            self.assertIn(
                record.module,
                on_disk,
                "registry names %r but no such module is on disk" % record.module,
            )

    def test_the_registry_has_no_duplicate_module_names(self):
        names = [record.module for record in REGISTRY]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        self.assertEqual(duplicates, [], "duplicate registry entries: %s" % duplicates)

    def test_the_registry_is_sorted_by_module_name(self):
        names = [record.module for record in REGISTRY]
        self.assertEqual(names, sorted(names))

    def test_the_registry_covers_every_module_on_disk(self):
        """The registry is not a subset of the disk: it is the disk."""
        self.assertEqual(
            sorted(set(registered_module_names())), sorted(set(modules_on_disk()))
        )

    def test_the_registry_registers_itself(self):
        """A registry that forgets itself is a registry with a hole in it."""
        self.assertIn("runtime_registration", registered_module_names())
        record = registration_for("runtime_registration")
        self.assertEqual(record.module, "runtime_registration")
        self.assertTrue(record.slice_slug)
        self.assertTrue(record.description)


class RegistryMetadataTests(unittest.TestCase):
    """Each record carries the four fields the registry promises."""

    def test_every_record_has_a_non_empty_slice_slug(self):
        for record in REGISTRY:
            self.assertTrue(
                record.slice_slug.strip(),
                "registry entry %r has no slice slug" % record.module,
            )

    def test_every_record_has_a_non_empty_description(self):
        for record in REGISTRY:
            self.assertTrue(
                record.description.strip(),
                "registry entry %r has no description" % record.module,
            )

    def test_every_record_has_an_iso_registration_date(self):
        for record in REGISTRY:
            self.assertRegex(
                record.registered_on,
                r"^\d{4}-\d{2}-\d{2}$",
                "registry entry %r has a non-ISO date %r"
                % (record.module, record.registered_on),
            )

    def test_registration_rejects_a_missing_required_field(self):
        """A record without a slug, a date or a description is refused."""
        for kwargs in (
            {"slice_slug": "", "registered_on": "2026-11-14", "description": "d"},
            {"slice_slug": "s", "registered_on": "", "description": "d"},
            {"slice_slug": "s", "registered_on": "2026-11-14", "description": "  "},
            {"slice_slug": None, "registered_on": "2026-11-14", "description": "d"},
        ):
            with self.assertRaises(ValueError):
                Registration("a_module", **kwargs)

    def test_registration_rejects_a_malformed_date(self):
        with self.assertRaises(ValueError):
            Registration("a_module", "s", "14-11-2026", "d")

    def test_registration_rejects_a_non_identifier_module_name(self):
        with self.assertRaises(ValueError):
            Registration("not a module", "s", "2026-11-14", "d")


class RegistryImmutabilityTests(unittest.TestCase):
    """The registry cannot be edited in place."""

    def test_the_registry_tuple_cannot_be_mutated(self):
        with self.assertRaises(TypeError):
            REGISTRY[0] = registration_for("cli")

    def test_a_record_attribute_cannot_be_reassigned(self):
        record = REGISTRY[0]
        with self.assertRaises(AttributeError):
            record.module = "hijacked"

    def test_a_record_attribute_cannot_be_deleted(self):
        record = REGISTRY[0]
        with self.assertRaises(AttributeError):
            del record.module

    def test_registered_modules_returns_the_same_immutable_tuple(self):
        self.assertIs(registered_modules(), registered_modules())
        self.assertIsInstance(registered_modules(), tuple)


class RegistrationQueryTests(unittest.TestCase):
    """The query helpers answer what they promise."""

    def test_registration_for_an_unregistered_module_raises_and_names_it(self):
        with self.assertRaises(KeyError) as caught:
            registration_for("no_such_module_exists")
        self.assertIn("no_such_module_exists", str(caught.exception))

    def test_declared_py_modules_reads_the_real_pyproject(self):
        declared = declared_py_modules()
        self.assertIn("cli", declared)
        self.assertIn("runtime_registration", declared)

    def test_modules_on_disk_excludes_the_layout_test_exclusions(self):
        on_disk = modules_on_disk()
        self.assertNotIn("setup", on_disk)
        self.assertNotIn("conftest", on_disk)
        self.assertFalse([name for name in on_disk if name.startswith("test_")])


if __name__ == "__main__":
    unittest.main()


class ThreeWayCheckTests(unittest.TestCase):
    """``assert_registration_matches_disk`` passes here and fails by name there."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="b173-registration-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # A miniature component: one module on disk, declared in pyproject,
        # and registered.  The three agree until a test breaks one of them.
        self.module_path = self.tmp / "alpha_module.py"
        self.module_path.write_text('"""Alpha."""\n', encoding="utf-8")
        self.pyproject = self.tmp / "pyproject.toml"
        self.pyproject.write_text(
            "[tool.setuptools]\n"
            'py-modules = ["alpha_module"]\n',
            encoding="utf-8",
        )
        self.registry = (
            Registration("alpha_module", "test-slice", "2026-11-14", "Alpha module."),
        )

    def _check(self):
        return assert_registration_matches_disk(
            component=self.tmp, pyproject=self.pyproject, registry=self.registry
        )

    def test_the_check_passes_when_the_three_views_agree(self):
        self.assertEqual(self._check(), ("alpha_module",))

    def test_a_module_on_disk_that_is_not_registered_is_named(self):
        """The recurrence case: a new slice adds a file and forgets to register it."""
        (self.tmp / "forgotten_module.py").write_text('"""Nope."""\n', encoding="utf-8")
        with self.assertRaises(RegistrationError) as caught:
            self._check()
        message = str(caught.exception)
        self.assertIn("forgotten_module", message)
        self.assertIn("not in the registry", message)

    def test_a_module_on_disk_that_is_not_in_py_modules_is_named(self):
        """The packaging case: the file exists but the wheel would not ship it."""
        (self.tmp / "unpackaged_module.py").write_text('"""Nope."""\n', encoding="utf-8")
        self.registry = self.registry + (
            Registration("cli", "test-slice", "2026-11-14", "CLI entry point."),
        )
        with self.assertRaises(RegistrationError) as caught:
            self._check()
        message = str(caught.exception)
        self.assertIn("unpackaged_module", message)
        self.assertIn("not in py-modules", message)

    def test_a_registry_entry_that_is_not_on_disk_is_named(self):
        """The stale-registry case: the module was deleted but still registered."""
        self.module_path.unlink()
        with self.assertRaises(RegistrationError) as caught:
            self._check()
        message = str(caught.exception)
        self.assertIn("alpha_module", message)
        self.assertIn("not on disk", message)

    def test_a_py_modules_entry_that_is_not_registered_is_named(self):
        """The half-registered case: declared for packaging, missing from the registry."""
        self.pyproject.write_text(
            "[tool.setuptools]\n"
            'py-modules = ["alpha_module", "half_registered_module"]\n',
            encoding="utf-8",
        )
        (self.tmp / "half_registered_module.py").write_text('"""Nope."""\n', encoding="utf-8")
        with self.assertRaises(RegistrationError) as caught:
            self._check()
        message = str(caught.exception)
        self.assertIn("half_registered_module", message)

    def test_a_missing_pyproject_is_reported_as_a_registration_error(self):
        with self.assertRaises(RegistrationError):
            assert_registration_matches_disk(
                component=self.tmp,
                pyproject=self.tmp / "no_such_pyproject.toml",
                registry=self.registry,
            )

    def test_a_pyproject_without_py_modules_is_reported_as_a_registration_error(self):
        (self.tmp / "empty.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")
        with self.assertRaises(RegistrationError):
            assert_registration_matches_disk(
                component=self.tmp, pyproject=self.tmp / "empty.toml", registry=self.registry
            )

    def test_the_registration_error_is_catchable_as_an_assertion(self):
        """Callers that only know about assertions still catch the failure."""
        self.assertTrue(issubclass(RegistrationError, AssertionError))
        (self.tmp / "forgotten_module.py").write_text('"""Nope."""\n', encoding="utf-8")
        with self.assertRaises(AssertionError):
            self._check()


class RealRepositoryCheckTests(unittest.TestCase):
    """The check must pass on the real repository, not only on a miniature."""

    def test_the_check_passes_on_the_current_repository(self):
        names = assert_registration_matches_disk()
        self.assertEqual(len(names), len(REGISTRY))
        self.assertIn("runtime_registration", names)

    def test_the_check_names_the_module_that_the_taskbook_forgot(self):
        """The registry now knows the module the batch left unregistered."""
        record = registration_for("refusal_row")
        self.assertEqual(record.module, "refusal_row")
        self.assertTrue(record.slice_slug)
        self.assertRegex(record.registered_on, r"^\d{4}-\d{2}-\d{2}$")

    def test_the_check_agrees_with_the_layout_test(self):
        """The registry and ``tests/test_module_layout.py`` see the same disk."""
        self.assertEqual(set(modules_on_disk()), set(registered_module_names()))
