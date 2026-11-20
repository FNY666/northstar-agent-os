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

# A stale ``__pycache__/runtime_registration.*.pyc`` makes Python import the
# *previous* source of this module when the source changed without changing
# size or second-resolution mtime -- which is exactly what a mutation probe
# does.  Drop the cached bytecode before the import below so the tests always
# run the source that is on disk right now.
for _cached in Path(__file__).resolve().parents[1].glob(
    "__pycache__/runtime_registration.*.pyc"
):
    _cached.unlink(missing_ok=True)

import runtime_registration
from runtime_registration import (
    REGISTRY,
    Registration,
    RegistrationError,
    assert_registration_matches_disk,
    declared_py_modules,
    modules_on_disk,
    package_members_on_disk,
    registered_module_names,
    registered_modules,
    registration_for,
)

COMPONENT = Path(runtime_registration.__file__).resolve().parent


class RegistryShapeTests(unittest.TestCase):
    """The registry itself: it is data, it is complete, it is immutable."""

    def test_every_registered_module_is_declared_for_installation(self):
        """Forward direction, item by item: the registry is a subset of the installed surface.

        Every single module name in the registry is checked -- not a sample
        -- so a newly forgotten registration cannot hide behind a passing
        spot check.

        The installed surface has TWO halves: the flat ``py-modules`` array
        and the package members that ``packages.find`` installs.  Before
        this slice the check compared against ``py-modules`` alone, so the
        22 package members could not pass it -- the registry could not name
        them at all, because the constructor rejected a dotted name.
        """
        installed = set(declared_py_modules()) | set(package_members_on_disk())
        for record in REGISTRY:
            self.assertIn(
                record.module,
                installed,
                "module %r is in the registry but not installed" % record.module,
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


class ImportableModuleNameGuardTests(unittest.TestCase):
    """The double guard in ``_is_importable_module_name`` -- both halves.

    The guard is one line with two halves joined by ``or``::

        if not isinstance(name, str) or not name:
            return False

    The first half is a **type** check and the second is an **emptiness**
    check.  A suite that only feeds one of the two cannot tell this guard
    apart from a single-check guard, so a fault that swaps the connective
    (``or`` -> ``and``) or flips the returned constant (``False`` ->
    ``True``) survives it.  Each half is therefore driven separately here.

    The guard is reached **directly** on purpose.  ``Registration.__init__``
    rejects a missing or blank module name with a ``ValueError`` before it
    ever calls the guard, so the public constructor cannot reach it with a
    value that tells the two halves apart.
    """

    def _is_importable(self, name):
        return runtime_registration._is_importable_module_name(name)

    def test_a_truthy_non_string_is_not_an_importable_module_name(self):
        """The type half, with the emptiness half taking the other branch.

        ``or`` short-circuits on the type check: a non-string is refused
        without the emptiness check ever being consulted.  With ``and``
        instead, a *truthy* non-string would fall through to the identifier
        scan below the guard -- and a non-string has no ``.split``, so the
        mutated guard raises instead of refusing the name.
        """
        for value in (42, 3.5, True, [1], ("a",), object()):
            with self.subTest(value=value):
                self.assertFalse(self._is_importable(value))

    def test_a_falsy_non_string_is_not_an_importable_module_name(self):
        """The type half with a falsy value: refused on the type alone."""
        for value in (None, 0, 0.0, [], (), {}, b"", False):
            with self.subTest(value=value):
                self.assertFalse(self._is_importable(value))

    def test_an_empty_name_is_not_an_importable_module_name(self):
        """The emptiness half: the type check passes, the emptiness check fires.

        A name that *is* a string but is empty reaches the second half of
        the guard.  If the guard's ``return False`` were flipped to
        ``return True``, an empty name would be accepted -- and the
        registry would then name a module with no file behind it.
        """
        self.assertFalse(self._is_importable(""))

    def test_a_blank_name_is_not_an_importable_module_name(self):
        """A blank name is not importable either -- the name has to carry a segment."""
        self.assertFalse(self._is_importable("   "))
        self.assertFalse(self._is_importable("."))
        self.assertFalse(self._is_importable("a..b"))

    def test_a_real_flat_module_name_is_importable(self):
        """The happy path of the first half: a flat module name is accepted."""
        self.assertTrue(self._is_importable("runtime_registration"))

    def test_a_real_package_member_name_is_importable(self):
        """The happy path of the second half: a dotted package member is accepted."""
        self.assertTrue(self._is_importable("tools.shell"))

    def test_the_constructor_refuses_the_names_the_guard_refuses(self):
        """The public surface refuses them too, with the registry's own error."""
        for name in ("", "not a module", 42, None):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    Registration(name, "a-slice", "2026-11-14", "A module.")


class RegistrationEqualityTests(unittest.TestCase):
    """A registry record compares by value, and hashes like its value.

    These are not decoration: the three-way check and the negative cases
    compare records and build sets of them, so a broken ``__eq__`` or
    ``__hash__`` would make a genuinely broken registry look consistent.
    """

    def _record(self, module="a_module"):
        return Registration(module, "a-slice", "2026-11-14", "A module.")

    def test_two_records_with_the_same_fields_are_equal(self):
        self.assertEqual(self._record(), self._record())

    def test_records_differing_in_any_field_are_not_equal(self):
        base = self._record()
        self.assertNotEqual(base, self._record("other_module"))
        self.assertNotEqual(
            base, Registration("a_module", "other-slice", "2026-11-14", "A module.")
        )
        self.assertNotEqual(
            base, Registration("a_module", "a-slice", "2026-01-01", "A module.")
        )
        self.assertNotEqual(
            base, Registration("a_module", "a-slice", "2026-11-14", "Another.")
        )

    def test_a_record_is_not_equal_to_a_non_record(self):
        self.assertNotEqual(self._record(), "a_module")
        self.assertNotEqual(self._record(), None)

    def test_equal_records_hash_equally(self):
        self.assertEqual(hash(self._record()), hash(self._record()))

    def test_a_record_can_live_in_a_set_without_collapsing_distinct_records(self):
        members = {self._record(), self._record(), self._record("other_module")}
        self.assertEqual(len(members), 2)

    def test_a_record_reports_its_fields_as_a_dict(self):
        self.assertEqual(
            self._record().as_dict(),
            {
                "module": "a_module",
                "slice_slug": "a-slice",
                "registered_on": "2026-11-14",
                "description": "A module.",
            },
        )
