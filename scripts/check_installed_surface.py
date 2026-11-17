#!/usr/bin/env python3
"""check_installed_surface.py -- import every module an installed
distribution ships.

Usage::

    python scripts/check_installed_surface.py <distribution-name>

WHY THIS EXISTS.

Every wheel-shipping component in this repository has a CI "packaging
smoke" step:  it installs the wheel, moves to a directory that is not the
source tree, and imports the component's modules.  That step is what
proves the INSTALLED SURFACE works -- that the wheel ships what it claims
and that the modules import from anywhere.

Those steps used to name their modules by hand.  A hand-written list goes
stale the moment a module is added, and the modules it omits are exactly
the ones nothing checks.  Measured on 2026-11-17, before this script
existed: the runtime's smoke step reached 66 of the runtime's 1636
installed modules, and three shipped modules could be deleted from the
wheel -- with syntax errors in the ones that remained -- while CI stayed
green.

This script takes the distribution's OWN metadata instead.  It asks
``importlib.metadata`` which modules the installed distribution ships and
imports every one of them.  Nothing is listed by hand, so a module cannot
be left out by omission, and a module that leaves the wheel is caught.

EXIT STATUS.

    0   every module the distribution ships imported successfully
    1   at least one module failed to import
    2   the distribution is not installed, or it ships no modules

WHY DISCOVERY AND NOT A LIST.

The set of modules a wheel ships is determined by the packaging
configuration at build time, not by anything written down next to the CI
workflow.  Asking the installed distribution is the only way to ask the
question that actually matters:  "what can a user of this wheel
actually import?"
"""
from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import sys
from pathlib import PurePosixPath


def distribution_modules(name: str) -> set[str]:
    """The importable module names an installed distribution ships.

    A flat module is ``cli.py`` -> ``cli``;  a package member is
    ``tools/shell.py`` -> ``tools.shell``;  and a package itself is
    ``tools/__init__.py`` -> ``tools``.

    Files outside the distribution's own tree (a ``.dist-info`` directory,
    a data file installed outside ``site-packages``) are not modules and
    are skipped.
    """
    try:
        distribution = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        raise LookupError(name)
    modules: set[str] = set()
    for entry in distribution.files or ():
        parts = PurePosixPath(str(entry)).parts
        if not parts:
            continue
        # A path that escapes the distribution root is not a module.
        if parts[0] in (".", "..") or ".." in parts:
            continue
        if parts[0].endswith(".dist-info") or parts[0].endswith(".data"):
            continue
        filename = parts[-1]
        if filename.endswith(".py"):
            stem = filename[: -len(".py")]
            if stem == "__init__":
                modules.add(".".join(parts[:-1]))
            else:
                modules.add(".".join(parts[:-1] + (stem,)))
    return {module for module in modules if module}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import every module an installed distribution ships."
    )
    parser.add_argument("distribution", help="the installed distribution's name")
    arguments = parser.parse_args(argv)

    try:
        modules = distribution_modules(arguments.distribution)
    except LookupError:
        print(
            "check_installed_surface: the distribution %r is not installed"
            % arguments.distribution,
            file=sys.stderr,
        )
        return 2
    if not modules:
        print(
            "check_installed_surface: the distribution %r ships no modules"
            % arguments.distribution,
            file=sys.stderr,
        )
        return 2

    failures: list[tuple[str, str]] = []
    for module in sorted(modules):
        try:
            importlib.import_module(module)
        except BaseException as error:  # noqa: BLE001 - report every failure
            failures.append((module, "%s: %s" % (type(error).__name__, error)))

    if failures:
        print(
            "check_installed_surface: %d of %d modules of %r failed to import"
            % (len(failures), len(modules), arguments.distribution),
            file=sys.stderr,
        )
        for module, reason in failures:
            print("  %s: %s" % (module, reason), file=sys.stderr)
        return 1
    print(
        "check_installed_surface: %s -- %d modules imported OK"
        % (arguments.distribution, len(modules))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
