"""The registration closure must cover the *installed* surface, not just the flat one.

`runtime_registration.py` is the runtime's single source of truth for which
modules are runtime modules.  It has to agree with two other views:

    registry  <->  pyproject.toml's `py-modules`  <->  the `*.py` on disk

and `assert_registration_matches_disk()` is the check that enforces the
three-way agreement.

**All three views were blind to the package members.**

`py-modules` lists *flat* module names only -- a package's members cannot
appear there.  setuptools installs them through a second mechanism:

    [tool.setuptools.packages.find]
    where = ["."]
    include = ["providers*", "tools*"]

So the runtime ships **22** package members (`providers.*`, `tools.*`) that
`pip install .` puts on the path, that `from tools.shell import ...` imports,
and that **no view of the registration closure could see**.

(That was the count when this slice was written.  It is now **23**: the
`runtime-data-files` slice added `policy`, a real package carrying the
data files the runtime reads at runtime.  The live assertions below are
re-measured; the prose above is left as the record of the state this
slice found.)

Measured before the fix:

    registry: 1613   flat py-modules: 1613   package members: 22
    installed surface: 1635
    installed but not in the registry: 22

The 22 are not incidental.  They include `tools.shell` (the sandboxed shell
executor), `tools.sandbox`, `tools.seccomp`, `tools.pledge` (the tool pledge
semantics) and `providers.base` -- the provider base class every provider
derives from.  These are the runtime's most load-bearing modules, and the
registry that is supposed to name "every runtime module" did not name one of
them.

Worse: the registry could not name them even if it wanted to.  The
constructor rejected a dotted name outright:

    ValueError: module name 'tools.shell' is not an importable identifier

so the gap was not an omission -- it was a hole in the registry's ability to
express a package member at all.

The closure slice that built the registry (`runtime-registration-closure`)
framed it as *top-level* modules, and says so: "the importable top-level
name (the file stem)".  That framing is what made the gap invisible -- a
package member is importable, and it is a runtime module, but it is not
top-level.

These tests pin the fixed invariant:

* the registry names every **installed** module, package members included;
* the registry can express a package member at all;
* the closure check names an unregistered package member by name;
* the layout test's rule -- "every module is installed" -- covers packages.

They are written against the real repository, so they fail when the
invariant is broken, not when a copy of it is.
"""
from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import runtime_registration as rr

COMPONENT = Path(rr.__file__).resolve().parent
RUNTIME = "northstar-agent-runtime"


def _installed_package_members(component: Path) -> set[str]:
    """The package members the packaging configuration installs.

    Read from ``pyproject.toml``'s ``packages.find.include`` patterns, so
    this follows the configuration rather than a hand-maintained list.
    """
    data = tomllib.loads((component / "pyproject.toml").read_text(encoding="utf-8"))
    include = data["tool"]["setuptools"]["packages"]["find"]["include"]
    stems = {pattern.rstrip("*") for pattern in include}
    found: set[str] = set()
    for stem in sorted(stems):
        package_dir = component / stem
        if not (package_dir / "__init__.py").is_file():
            continue
        found.add(f"{stem}.__init__")
        for path in sorted(package_dir.glob("*.py")):
            if path.name != "__init__.py":
                found.add(f"{stem}.{path.stem}")
    return found


class InstalledSurfaceRegistrationTests(unittest.TestCase):
    """The invariant: the registration closure covers what is installed."""

    def test_every_installed_package_member_is_registered(self):
        # The load-bearing truth.  Before the fix these 22 were installed
        # and unregistered at the same time.
        members = _installed_package_members(COMPONENT)
        # RE-MEASURED 2026-11-16: the `runtime-data-files` slice made
        # `policy` a real package (it carries the data files the runtime
        # reads at runtime), so there are now 23 package members.
        self.assertEqual(
            len(members),
            23,
            "the installed package members: " + ", ".join(sorted(members)),
        )
        registered = set(rr.registered_module_names())
        unregistered = sorted(members - registered)
        self.assertEqual(
            unregistered,
            [],
            "installed package members that the registry does not name:\n  "
            + "\n  ".join(unregistered),
        )

    def test_the_name_check_answers_for_a_name_directly(self):
        # The helper is the gate, so pin it DIRECTLY.  Reached only through
        # the constructor, its behaviour is masked by the earlier
        # "missing required field" guard: an empty name is rejected there
        # for being empty, so a broken gate would never show.  Calling the
        # helper itself is what makes the gate's own rules observable.
        self.assertTrue(rr._is_importable_module_name("tools.shell"))
        self.assertTrue(rr._is_importable_module_name("cli"))
        self.assertTrue(rr._is_importable_module_name("a.b.c"))
        self.assertFalse(rr._is_importable_module_name(""))
        self.assertFalse(rr._is_importable_module_name("tools."))
        self.assertFalse(rr._is_importable_module_name(".shell"))
        self.assertFalse(rr._is_importable_module_name("tools..shell"))
        self.assertFalse(rr._is_importable_module_name("tools/shell"))
        self.assertFalse(rr._is_importable_module_name("tools shell"))
        self.assertFalse(rr._is_importable_module_name(None))
        self.assertFalse(rr._is_importable_module_name(42))

    def test_a_registry_record_with_a_missing_field_is_refused(self):
        # The metadata gate.  Pinned here because the slice's file is what
        # the mutation probe runs against, and this is the gate that decides
        # whether a registry entry is well-formed.
        for kwargs in (
            {"slice_slug": "", "registered_on": "2026-11-14", "description": "d"},
            {"slice_slug": "s", "registered_on": "", "description": "d"},
            {"slice_slug": "s", "registered_on": "2026-11-14", "description": "  "},
            {"slice_slug": None, "registered_on": "2026-11-14", "description": "d"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    rr._registration("a_module", **kwargs)

    def test_two_records_are_equal_only_when_every_field_matches(self):
        # The value-equality of a record.  The registry is compared field by
        # field when the closure check looks for a match, so a broken
        # equality would make a genuinely different record look identical.
        base = rr._registration("a_module", "a-slice", "2026-11-14", "A module.")
        same = rr._registration("a_module", "a-slice", "2026-11-14", "A module.")
        self.assertEqual(base, same)
        self.assertEqual(hash(base), hash(same))
        self.assertNotEqual(
            base, rr._registration("other_module", "a-slice", "2026-11-14", "A module.")
        )
        self.assertNotEqual(
            base, rr._registration("a_module", "other-slice", "2026-11-14", "A module.")
        )
        self.assertNotEqual(
            base, rr._registration("a_module", "a-slice", "2026-11-16", "A module.")
        )
        self.assertNotEqual(
            base, rr._registration("a_module", "a-slice", "2026-11-14", "Another.")
        )

    def test_registration_for_finds_the_right_record(self):
        # The lookup.  It must return the record for the module that was
        # asked for -- not merely *a* record from the registry.
        shell = rr.registration_for("tools.shell")
        self.assertEqual(shell.module, "tools.shell")
        base = rr.registration_for("providers.base")
        self.assertEqual(base.module, "providers.base")
        self.assertNotEqual(shell.as_dict(), base.as_dict())
        with self.assertRaises(KeyError) as caught:
            rr.registration_for("no_such_module_exists")
        self.assertIn("no_such_module_exists", str(caught.exception))

    def test_the_registry_can_express_a_package_member(self):
        # The hole in the registry's *ability*, not just its contents.
        # A dotted name used to be refused outright.
        record = rr._registration("tools.shell", "a-slice", "2026-11-16", "A description")
        self.assertEqual(record.module, "tools.shell")
        self.assertEqual(record.as_dict()["module"], "tools.shell")

    def test_the_registry_rejects_a_name_that_is_not_importable(self):
        # Loosening the check must not let anything through: an empty
        # segment, a keyword, a path, or a name with whitespace are all
        # still refused.
        for bad in ("", "tools.", ".shell", "tools..shell", "tools/shell", "tools shell"):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    rr._registration(bad, "a-slice", "2026-11-16", "A description.")

    def test_a_nested_name_is_structurally_allowed_but_must_exist(self):
        # ``a.b.c`` is a *valid* Python name (a nested package member), so
        # the structural check must accept it -- this component has no
        # nested packages, but that is the closure check's business, not
        # the constructor's.  The two responsibilities are kept apart.
        record = rr._registration("a.b.c", "a-slice", "2026-11-16", "A description.")
        self.assertEqual(record.module, "a.b.c")
        # The *closure* check is what notices that no such module exists.
        with self.assertRaises(rr.RegistrationError) as caught:
            rr.assert_registration_matches_disk(
                component=COMPONENT,
                pyproject=COMPONENT / "pyproject.toml",
                registry=rr.REGISTRY
                + (rr._registration("a.b.c", "a-slice", "2026-11-16", "Ghost."),),
            )
        self.assertIn("a.b.c", str(caught.exception))

    def test_the_three_way_check_passes_on_the_real_repository(self):
        # The closure check must still pass after the fix.  It is the check
        # that has to learn about packages, not one that gets weakened.
        names = rr.assert_registration_matches_disk()
        self.assertIn("runtime_registration", names)

    def test_the_installed_surface_is_larger_than_the_flat_one(self):
        # The three views agree -- so the registry "covered" 1615 modules.
        # The installed surface is 1638, and the difference is exactly the
        # 23 package members.  The registry now covers both halves.
        flat = set(rr.declared_py_modules())
        members = _installed_package_members(COMPONENT)
        installed = flat | members
        # RE-MEASURED 2026-11-16: `policy` joined the package members
        # (the `runtime-data-files` slice), so 22 -> 23 and 1635 -> 1636.
        self.assertEqual(len(flat), 1618)
        self.assertEqual(len(members), 23)
        self.assertEqual(len(installed), 1641)
        registered = set(rr.registered_module_names())
        self.assertEqual(
            registered,
            installed,
            "the registry must be exactly the installed surface",
        )

    def test_the_check_names_an_unregistered_package_member(self):
        # A guard that fails without naming the module is a guard nobody can
        # act on.  The existing check names a *flat* module; it must name a
        # package member too.
        self.assertTrue(
            hasattr(rr, "assert_registration_matches_installed"),
            "the registration module has no installed-surface check",
        )
        with self.assertRaises(rr.RegistrationError) as caught:
            rr.assert_registration_matches_installed(
                component=COMPONENT,
                pyproject=COMPONENT / "pyproject.toml",
                registry=tuple(
                    record
                    for record in rr.REGISTRY
                    if record.module != "tools.shell"
                ),
            )
        message = str(caught.exception)
        self.assertIn("tools.shell", message)
        self.assertIn("installed", message)

    def test_the_layout_test_rule_covers_the_packages(self):
        # `tests/test_module_layout.py::test_every_module_is_installed` says
        # "every module is installed".  It read `py-modules` and the flat
        # `*.py` files, so the rule it stated could not cover a package
        # member.  The layout test must learn about packages too.
        source = (COMPONENT / "tests" / "test_module_layout.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "packages",
            source,
            "the layout test does not mention packages at all, so its "
            "'every module is installed' rule cannot cover a package member",
        )

    def test_the_package_members_the_registry_names_are_the_ones_on_disk(self):
        # The registry must not name a package member that does not exist.
        registered = {
            record.module
            for record in rr.REGISTRY
            if "." in record.module
        }
        on_disk = _installed_package_members(COMPONENT)
        self.assertEqual(registered, on_disk)


if __name__ == "__main__":
    unittest.main()
