"""Single source of truth for the runtime version.

Import this module (never re-declare the string) wherever a version is printed
or compared. The component is **unreleased**; ``0.1.0.dev0`` is the
development version, and a plain release version is only set when the release
readiness gate (docs/guides/releasing-and-versioning.md) has been passed —
tests/test_release.py keeps every component's version aligned.
"""

__version__ = "0.1.0.dev0"
