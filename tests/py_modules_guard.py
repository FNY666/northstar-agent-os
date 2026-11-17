"""The rule that every component's ``py-modules`` list is sorted and unique.

This module holds the LOGIC; the tests that use it are
``tests/test_py_modules_sorted.py`` (repository level) and
``components/northstar-agent-runtime/tests/test_py_modules_list.py``
(component level).

WHY A MODULE AND NOT A TEST
---------------------------
The rule is about a repository-wide invariant, so it needs one
implementation that both test files can call.  A second copy would drift,
and a copy that drifts is how "the guard is not a rubber stamp" stops
being true.  This mirrors ``tests/docbuild.py``, which is the model of the
installed surface for the same reason.

WHAT THE RULE IS
----------------
``[tool.setuptools] py-modules`` is the array that says which flat modules
``pip install .`` puts on the path.  It must be:

* **sorted** -- so that adding a module is a one-line diff instead of a
  reshuffle of the file;
* **free of duplicates** -- so that the array says what it means to say.
  A repeated name is harmless to the wheel (setuptools deduplicates) but
  it makes the array a lie about the surface, and every reader that
  ``set()``s the list -- which is what the runtime's own layout test
  does -- is blind to it.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

#: The repository root: this file lives in ``tests/``.
ROOT = Path(__file__).resolve().parents[1]

#: Where the components live.
COMPONENTS = ROOT / "components"


def read_py_modules(component: Path) -> list[str] | None:
    """The ``py-modules`` array of a component, or None if it has none.

    A component without a ``pyproject.toml``, or with a ``pyproject.toml``
    that declares no ``py-modules``, has nothing for this rule to say.
    """
    pyproject = component / "pyproject.toml"
    if not pyproject.is_file():
        return None
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    setuptools = data.get("tool", {}).get("setuptools", {})
    if not isinstance(setuptools, dict):
        return None
    modules = setuptools.get("py-modules")
    if modules is None:
        return None
    return list(modules)


def components_with_py_modules() -> list[tuple[str, list[str]]]:
    """Every component that declares a ``py-modules`` array, by name."""
    found: list[tuple[str, list[str]]] = []
    for component in sorted(COMPONENTS.iterdir()):
        if not component.is_dir():
            continue
        modules = read_py_modules(component)
        if modules is None:
            continue
        found.append((component.name, modules))
    return found


def first_inversion(modules: list[str]) -> tuple[str, str] | None:
    """The first adjacent pair that is out of order, or None if sorted.

    The pair is returned rather than a boolean so a failure message can
    name the two modules that are in the wrong order.
    """
    for index in range(len(modules) - 1):
        if modules[index] > modules[index + 1]:
            return (modules[index], modules[index + 1])
    return None


def duplicates(modules: list[str]) -> list[str]:
    """The names that appear more than once, sorted.

    Sorted, so a failure message is stable across runs.
    """
    seen: set[str] = set()
    repeated: set[str] = set()
    for module in modules:
        if module in seen:
            repeated.add(module)
        seen.add(module)
    return sorted(repeated)


def repeated_lines(pyproject: Path) -> list[str]:
    """The quoted lines a ``pyproject.toml`` repeats.

    The TOML array is parsed as a list, so a repeated NAME is visible to
    :func:`duplicates`.  This catches the other case: a repeated LINE that
    TOML still parses -- which a merge conflict marker or a bad edit can
    leave behind.
    """
    lines = [
        line.strip()
        for line in pyproject.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith('"')
    ]
    seen: set[str] = set()
    repeated: set[str] = set()
    for line in lines:
        if line in seen:
            repeated.add(line)
        seen.add(line)
    return sorted(repeated)


def sortedness_problems(component: Path, modules: list[str]) -> list[str]:
    """Everything wrong with one component's ``py-modules`` list."""
    problems: list[str] = []
    if modules != sorted(modules):
        inversion = first_inversion(modules)
        problems.append(
            "%s: the py-modules list must stay sorted; the first "
            "out-of-order pair is %r" % (component.name, inversion)
        )
    repeated = duplicates(modules)
    if repeated:
        problems.append(
            "%s: duplicate entries in py-modules: %s" % (component.name, repeated)
        )
    return problems
